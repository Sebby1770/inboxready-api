from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from datetime import UTC, datetime
from email.utils import parseaddr
import re
from typing import Any

import dns.exception
import dns.resolver
import httpx

from inboxready_api.models import (
    AuditCheck,
    DomainAuditRequest,
    DomainAuditResponse,
    ProviderMatch,
    Recommendation,
)
from inboxready_api.services.free_email import free_email_warning_message, is_free_email_domain
from inboxready_api.services.provider_detection import detect_providers
from inboxready_api.settings import Settings

DMARC_REFERENCE = "https://dmarc.org/"
GOOGLE_REFERENCE = "https://support.google.com/a/answer/81126?hl=en-AL"
YAHOO_REFERENCE = "https://senders.yahooinc.com/faqs/"
SPF_EXPAND_MAX_DEPTH = 3
ResolveTxt = Callable[[str], list[str]] | Mapping[str, list[str]]


def audit_domain(request: DomainAuditRequest, settings: Settings) -> DomainAuditResponse:
    domain = normalize_domain(request.domain)
    resolver = dns.resolver.Resolver()

    root_txt = query_records(resolver, domain, "TXT")
    mx_records = query_records(resolver, domain, "MX")

    raw_evidence = root_txt + mx_records
    providers = detect_providers(raw_evidence)

    selectors = collect_selectors(request.selectors, providers)
    checks: dict[str, AuditCheck] = {}
    recommendations: list[Recommendation] = []

    mx_check = build_mx_check(mx_records)
    checks["mx"] = mx_check
    recommendations.extend(recommendations_for_check("mx", mx_check))

    def resolve_txt(name: str) -> list[str]:
        return query_records(resolver, name, "TXT")

    spf_check = build_spf_check(root_txt, resolve_txt=resolve_txt)
    checks["spf"] = spf_check
    recommendations.extend(recommendations_for_check("spf", spf_check))

    dmarc_records = query_records(resolver, f"_dmarc.{domain}", "TXT")
    dmarc_check = build_dmarc_check(dmarc_records)
    checks["dmarc"] = dmarc_check
    recommendations.extend(recommendations_for_check("dmarc", dmarc_check))

    dkim_check = build_dkim_check(resolver, domain, selectors, request.selectors)
    checks["dkim"] = dkim_check
    recommendations.extend(recommendations_for_check("dkim", dkim_check))

    mta_sts_records = query_records(resolver, f"_mta-sts.{domain}", "TXT")
    mta_sts_check = build_mta_sts_check(domain, mta_sts_records, settings)
    checks["mta_sts"] = mta_sts_check
    recommendations.extend(recommendations_for_check("mta_sts", mta_sts_check))

    tls_rpt_records = query_records(resolver, f"_smtp._tls.{domain}", "TXT")
    tls_rpt_check = build_tls_rpt_check(tls_rpt_records)
    checks["tls_rpt"] = tls_rpt_check
    recommendations.extend(recommendations_for_check("tls_rpt", tls_rpt_check))

    bimi_records = query_records(resolver, f"default._bimi.{domain}", "TXT")
    http_client: httpx.Client | None = None
    try:
        if any(record.lower().startswith("v=bimi1") and "l=" in record.lower() for record in bimi_records):
            http_client = httpx.Client(
                timeout=settings.http_timeout_seconds,
                headers={"User-Agent": settings.user_agent},
                follow_redirects=True,
            )
        bimi_check = build_bimi_check(bimi_records, checks["dmarc"], http_client=http_client)
    finally:
        if http_client is not None:
            http_client.close()
    checks["bimi"] = bimi_check
    recommendations.extend(recommendations_for_check("bimi", bimi_check))

    caa_records = query_records(resolver, domain, "CAA")
    caa_check = build_caa_check(caa_records)
    checks["caa"] = caa_check
    recommendations.extend(recommendations_for_check("caa", caa_check))

    providers = append_expected_provider_warnings(providers, request.expected_providers, recommendations)

    if is_free_email_domain(domain):
        checks["sending_domain"] = AuditCheck(
            status="warn",
            summary=free_email_warning_message(domain),
            details={"free_or_disposable": True},
        )
        recommendations.append(
            Recommendation(
                severity="medium",
                code="free-email-domain",
                message=free_email_warning_message(domain),
                details=(
                    "Use a domain you own for transactional or bulk sending. "
                    "Free mailbox providers cannot be customized for SPF/DKIM as a brand domain."
                ),
            )
        )

    score = score_checks(checks)
    overall_status = derive_overall_status(checks)

    return DomainAuditResponse(
        domain=domain,
        score=score,
        overall_status=overall_status,
        checked_at=datetime.now(UTC).isoformat(),
        providers=providers,
        checks=checks,
        recommendations=dedupe_recommendations(recommendations),
        references=[DMARC_REFERENCE, GOOGLE_REFERENCE, YAHOO_REFERENCE],
    )


def normalize_domain(value: str) -> str:
    domain = value.strip().lower()
    domain = re.sub(r"^https?://", "", domain)
    domain = domain.strip("/")
    if "/" in domain:
        domain = domain.split("/", maxsplit=1)[0]
    return domain


def query_records(
    resolver: dns.resolver.Resolver,
    name: str,
    record_type: str,
) -> list[str]:
    try:
        answers = resolver.resolve(name, record_type)
    except (
        dns.resolver.NXDOMAIN,
        dns.resolver.NoAnswer,
        dns.resolver.NoNameservers,
        dns.exception.Timeout,
    ):
        return []

    results: list[str] = []
    for answer in answers:
        text = answer.to_text().strip()
        if record_type == "TXT":
            text = strip_outer_quotes(text).replace('" "', "")
        results.append(text)
    return results


def strip_outer_quotes(value: str) -> str:
    if value.startswith('"') and value.endswith('"'):
        return value[1:-1]
    return value


def collect_selectors(explicit_selectors: Iterable[str], providers: list[ProviderMatch]) -> list[str]:
    selectors = {selector.strip() for selector in explicit_selectors if selector.strip()}
    for provider in providers:
        selectors.update(provider.suggested_selectors)
    return sorted(selectors)


def build_mx_check(mx_records: list[str]) -> AuditCheck:
    if not mx_records:
        return AuditCheck(
            status="fail",
            summary="No MX records found.",
            details={"records": []},
        )

    return AuditCheck(
        status="pass",
        summary=f"Found {len(mx_records)} MX record(s).",
        details={"records": mx_records},
    )


def build_spf_check(
    root_txt_records: list[str],
    resolve_txt: ResolveTxt | None = None,
) -> AuditCheck:
    spf_records = [record for record in root_txt_records if record.lower().startswith("v=spf1")]

    if not spf_records:
        return AuditCheck(
            status="fail",
            summary="No SPF record found.",
            details={"records": []},
        )

    if len(spf_records) > 1:
        return AuditCheck(
            status="fail",
            summary="Multiple SPF records found. SPF should be published once.",
            details={"records": spf_records},
        )

    record = spf_records[0]
    parsed = parse_spf_record(record)
    status = "pass"
    summary = "SPF record is present."

    if parsed["estimated_dns_lookups"] >= 10:
        status = "fail"
        summary = "SPF likely exceeds the 10 DNS lookup limit."
    elif parsed["estimated_dns_lookups"] >= 8:
        status = "warn"
        summary = "SPF is close to the 10 DNS lookup limit."
    elif parsed["all_mechanism"] in {"?all", "+all"}:
        status = "warn"
        summary = "SPF exists but the terminal policy is weak."

    details: dict[str, Any] = dict(parsed)
    if resolve_txt is not None:
        tree = expand_spf(record, resolve_txt)
        details["include_tree"] = tree
        details["resolved_dns_lookups"] = tree["resolved_lookups"]

    return AuditCheck(
        status=status,
        summary=summary,
        details=details,
    )


def parse_spf_record(record: str) -> dict[str, object]:
    tokens = record.split()
    lookup_tokens = []
    all_mechanism = None

    for token in tokens[1:]:
        normalized = token.lstrip("+-~?")
        if normalized in {"a", "mx", "ptr"} or normalized.startswith(("a:", "mx:", "include:", "exists:")):
            lookup_tokens.append(token)
        if token.startswith("redirect="):
            lookup_tokens.append(token)
        if normalized.endswith("all"):
            all_mechanism = token

    includes = [token for token in tokens if token.lstrip("+-~?").startswith("include:")]

    return {
        "record": record,
        "estimated_dns_lookups": len(lookup_tokens),
        "lookup_terms": lookup_tokens,
        "include_count": len(includes),
        "includes": includes,
        "all_mechanism": all_mechanism,
    }


def _as_txt_resolver(resolve_txt: ResolveTxt) -> Callable[[str], list[str]]:
    if callable(resolve_txt):
        return resolve_txt

    zone = resolve_txt

    def lookup(name: str) -> list[str]:
        if name in zone:
            return list(zone[name])
        wanted = name.lower().rstrip(".")
        for key, value in zone.items():
            if str(key).lower().rstrip(".") == wanted:
                return list(value)
        return []

    return lookup


def _spf_mechanism_domain(token: str) -> str | None:
    raw = token.lstrip("+-~?")
    if raw.lower().startswith("include:"):
        return raw.split(":", 1)[1].strip().rstrip(".").lower() or None
    if raw.lower().startswith("redirect="):
        return raw.split("=", 1)[1].strip().rstrip(".").lower() or None
    return None


def _first_spf_record(records: list[str]) -> str | None:
    for record in records:
        if record.lower().startswith("v=spf1"):
            return record
    return None


def expand_spf(
    record: str,
    resolve_txt: ResolveTxt,
    *,
    max_depth: int = SPF_EXPAND_MAX_DEPTH,
) -> dict[str, Any]:
    """Recursively follow include: and redirect= using an injected TXT resolver.

    Counts resolved lookups only (each include/redirect that is actually queried).
    Detects cycles along the current expansion path. Depth is capped at ``max_depth``
    (default 3) from the original record.
    """

    resolver = _as_txt_resolver(resolve_txt)
    return _expand_spf(
        record,
        resolver,
        max_depth=max_depth,
        depth=0,
        trail=(),
    )


def _expand_spf(
    record: str,
    resolve_txt: Callable[[str], list[str]],
    *,
    max_depth: int,
    depth: int,
    trail: tuple[str, ...],
) -> dict[str, Any]:
    includes: list[dict[str, Any]] = []
    redirect: dict[str, Any] | None = None
    resolved_lookups = 0
    cycle = False
    truncated = False

    for token in record.split()[1:]:
        mechanism = "include" if token.lstrip("+-~?").lower().startswith("include:") else None
        if token.lower().startswith("redirect=") or token.lstrip("+-~?").lower().startswith("redirect="):
            mechanism = "redirect"
        if mechanism is None:
            continue

        domain = _spf_mechanism_domain(token)
        node: dict[str, Any] = {
            "mechanism": mechanism,
            "term": token,
            "domain": domain,
            "cycle": False,
            "truncated": False,
            "missing": False,
            "record": None,
            "children": None,
        }
        if not domain:
            node["missing"] = True
            if mechanism == "redirect":
                redirect = node
            else:
                includes.append(node)
            continue

        if domain in trail:
            node["cycle"] = True
            cycle = True
            if mechanism == "redirect":
                redirect = node
            else:
                includes.append(node)
            continue

        if depth >= max_depth:
            node["truncated"] = True
            truncated = True
            if mechanism == "redirect":
                redirect = node
            else:
                includes.append(node)
            continue

        resolved_lookups += 1
        try:
            answers = list(resolve_txt(domain) or [])
        except Exception:
            answers = []
        child_record = _first_spf_record(answers)
        if child_record is None:
            node["missing"] = True
        else:
            node["record"] = child_record
            child = _expand_spf(
                child_record,
                resolve_txt,
                max_depth=max_depth,
                depth=depth + 1,
                trail=trail + (domain,),
            )
            node["children"] = child
            resolved_lookups += int(child["resolved_lookups"])
            if child["cycle"]:
                node["cycle"] = True
                cycle = True
            if child["truncated"]:
                node["truncated"] = True
                truncated = True

        if mechanism == "redirect":
            redirect = node
        else:
            includes.append(node)

    return {
        "record": record,
        "depth": depth,
        "resolved_lookups": resolved_lookups,
        "cycle": cycle,
        "truncated": truncated,
        "includes": includes,
        "redirect": redirect,
    }


def build_dmarc_check(dmarc_records: list[str]) -> AuditCheck:
    records = [record for record in dmarc_records if record.lower().startswith("v=dmarc1")]

    if not records:
        return AuditCheck(
            status="fail",
            summary="No DMARC record found.",
            details={"records": []},
        )

    record = records[0]
    tags = parse_semicolon_tags(record)
    policy = (tags.get("p") or "none").lower()
    subdomain_policy = tags.get("sp")
    percentage = tags.get("pct")
    adkim = tags.get("adkim")
    aspf = tags.get("aspf")
    rua = extract_mailto_targets(tags.get("rua"))
    ruf = extract_mailto_targets(tags.get("ruf"))

    details: dict[str, Any] = {
        "record": record,
        "policy": policy,
        "p": policy,
        "sp": subdomain_policy.lower() if subdomain_policy else None,
        "subdomain_policy": subdomain_policy.lower() if subdomain_policy else None,
        "pct": percentage,
        "percentage": percentage,
        "adkim": adkim.lower() if adkim else None,
        "aspf": aspf.lower() if aspf else None,
        "rua": rua,
        "ruf": ruf,
        "mailto_targets": {"rua": rua, "ruf": ruf},
    }

    if not rua:
        return AuditCheck(
            status="fail",
            summary="DMARC record is present but has no rua aggregate reporting address.",
            details=details,
        )

    if policy == "none":
        return AuditCheck(
            status="warn",
            summary="DMARC p=none does not meet 2024 Gmail/Yahoo bulk-sender requirements.",
            details=details,
        )

    return AuditCheck(
        status="pass",
        summary="DMARC record is present.",
        details=details,
    )


def build_dkim_check(
    resolver: dns.resolver.Resolver,
    domain: str,
    selectors: list[str],
    explicit_selectors: list[str],
) -> AuditCheck:
    if not selectors:
        return AuditCheck(
            status="warn",
            summary="No DKIM selectors were provided or inferred, so DKIM could not be verified.",
            details={"selectors_checked": [], "matches": []},
        )

    matches: list[dict[str, object]] = []
    for selector in selectors:
        txt_records = query_records(resolver, f"{selector}._domainkey.{domain}", "TXT")
        cname_records = query_records(resolver, f"{selector}._domainkey.{domain}", "CNAME")
        if txt_records or cname_records:
            matches.append(
                {
                    "selector": selector,
                    "txt_records": txt_records,
                    "cname_records": cname_records,
                }
            )

    if matches:
        return AuditCheck(
            status="pass",
            summary=f"Verified DKIM on {len(matches)} selector(s).",
            details={
                "selectors_checked": selectors,
                "matches": matches,
            },
        )

    if explicit_selectors:
        return AuditCheck(
            status="fail",
            summary="None of the requested DKIM selectors resolved.",
            details={"selectors_checked": selectors, "matches": []},
        )

    return AuditCheck(
        status="warn",
        summary="Could not verify DKIM with inferred selectors.",
        details={"selectors_checked": selectors, "matches": []},
    )


def build_mta_sts_check(domain: str, records: list[str], settings: Settings) -> AuditCheck:
    valid_records = [record for record in records if record.lower().startswith("v=stsv1")]

    if not valid_records:
        return AuditCheck(
            status="info",
            summary="No MTA-STS TXT record found.",
            details={"records": []},
        )

    record = valid_records[0]
    details: dict[str, object] = {"record": record}
    policy_url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
    details["policy_url"] = policy_url

    try:
        with httpx.Client(
            timeout=settings.http_timeout_seconds,
            headers={"User-Agent": settings.user_agent},
            follow_redirects=True,
        ) as client:
            response = client.get(policy_url)
            if response.status_code == 200:
                policy = parse_mta_sts_policy(response.text)
                details["policy"] = policy
                status = "pass" if policy.get("mode") == "enforce" else "warn"
                summary = "MTA-STS record and policy file found."
                if status == "warn":
                    summary = "MTA-STS exists but is not in enforce mode."
                return AuditCheck(status=status, summary=summary, details=details)
            details["policy_fetch_status"] = response.status_code
    except httpx.HTTPError as exc:
        details["policy_fetch_error"] = str(exc)

    return AuditCheck(
        status="warn",
        summary="MTA-STS TXT record exists, but the policy file could not be verified.",
        details=details,
    )


def parse_mta_sts_policy(policy_text: str) -> dict[str, object]:
    parsed: dict[str, object] = {"raw": policy_text}
    for line in policy_text.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", maxsplit=1)
        key = key.strip().lower()
        value = value.strip()
        if key == "mx":
            parsed.setdefault("mx", []).append(value)
        else:
            parsed[key] = value
    return parsed


def build_tls_rpt_check(records: list[str]) -> AuditCheck:
    valid_records = [record for record in records if record.lower().startswith("v=tlsrptv1")]

    if not valid_records:
        return AuditCheck(
            status="info",
            summary="No TLS-RPT record found.",
            details={"records": []},
        )

    record = valid_records[0]
    tags = parse_semicolon_tags(record)

    return AuditCheck(
        status="pass",
        summary="TLS-RPT record is present.",
        details={
            "record": record,
            "rua": extract_mailto_targets(tags.get("rua")),
        },
    )


def probe_bimi_asset(url: str, http_client: Any) -> dict[str, Any]:
    """HEAD, then GET if needed. Never called without an injected client in tests."""

    result: dict[str, Any] = {
        "url": url,
        "ok": False,
        "content_type": None,
        "bytes": 0,
        "status_code": None,
        "error": None,
    }

    def _read_response(response: Any) -> None:
        status_code = getattr(response, "status_code", None)
        try:
            result["status_code"] = int(status_code) if status_code is not None else None
        except (TypeError, ValueError):
            result["status_code"] = None
        headers = getattr(response, "headers", None) or {}
        content_type = None
        try:
            content_type = headers.get("content-type") or headers.get("Content-Type")
        except Exception:
            content_type = None
        if content_type:
            result["content_type"] = str(content_type)
        content_length = None
        try:
            content_length = headers.get("content-length") or headers.get("Content-Length")
        except Exception:
            content_length = None
        if content_length is not None and str(content_length).isdigit():
            result["bytes"] = int(content_length)
        content = getattr(response, "content", None)
        if isinstance(content, (bytes, bytearray, str)):
            result["bytes"] = len(content)
        code = result["status_code"]
        result["ok"] = isinstance(code, int) and 200 <= code < 300

    try:
        response = http_client.head(url)
        _read_response(response)
    except Exception as exc:  # pragma: no cover - client-specific
        result["error"] = str(exc)

    needs_get = (
        not result["ok"]
        or not result["content_type"]
        or result["status_code"] in {405, 501}
    )
    if needs_get:
        try:
            response = http_client.get(url)
            _read_response(response)
            if result["ok"]:
                result["error"] = None
        except Exception as exc:
            result["error"] = str(exc)

    return result


def _is_svg_or_xml(content_type: str | None) -> bool:
    if not content_type:
        return False
    lowered = content_type.lower()
    return "svg" in lowered or "xml" in lowered


def build_bimi_check(
    records: list[str],
    dmarc_check: AuditCheck,
    http_client: Any | None = None,
) -> AuditCheck:
    valid_records = [record for record in records if record.lower().startswith("v=bimi1")]

    if not valid_records:
        return AuditCheck(
            status="info",
            summary="No BIMI record found.",
            details={"records": []},
        )

    record = valid_records[0]
    tags = parse_semicolon_tags(record)
    logo_url = (tags.get("l") or "").strip() or None
    authority_url = (tags.get("a") or "").strip() or None
    dmarc_policy = str(dmarc_check.details.get("policy") or "")
    status = "pass" if dmarc_policy in {"quarantine", "reject"} else "warn"
    summary = "BIMI record is present."
    if status == "warn":
        summary = "BIMI record exists, but DMARC is not yet at quarantine or reject."

    details: dict[str, Any] = {
        "record": record,
        "logo_url": logo_url,
        "authority_url": authority_url,
        "dmarc_policy": dmarc_policy,
    }

    if logo_url and http_client is not None:
        asset = probe_bimi_asset(logo_url, http_client)
        details["asset"] = asset
        if not asset.get("ok"):
            status = "warn"
            summary = "BIMI logo URL is missing or could not be fetched."
        elif _is_svg_or_xml(asset.get("content_type")):
            if status == "pass":
                summary = "BIMI record and SVG/XML logo are present."
        else:
            status = "warn"
            summary = "BIMI logo URL did not return SVG or XML."
    elif not logo_url:
        details["asset"] = None
        if status == "pass":
            status = "warn"
            summary = "BIMI record exists but has no l= logo URL."

    return AuditCheck(
        status=status,
        summary=summary,
        details=details,
    )


def build_caa_check(records: list[str], *, nxdomain: bool = False) -> AuditCheck:
    parsed: list[dict[str, str]] = []
    issue_tags: list[str] = []
    for raw in records:
        flags, tag, value = _parse_caa_line(raw)
        entry = {"flags": flags, "tag": tag, "value": value, "raw": raw}
        parsed.append(entry)
        if tag == "issue" and value:
            issue_tags.append(value)

    if nxdomain or not records:
        summary = "No CAA records published (NXDOMAIN)." if nxdomain else "No CAA records found."
        return AuditCheck(
            status="info",
            summary=summary,
            details={
                "records": records,
                "issue": issue_tags,
                "parsed": parsed,
                "nxdomain": nxdomain,
            },
        )

    return AuditCheck(
        status="pass",
        summary=f"Found {len(issue_tags)} CAA issue tag(s).",
        details={
            "records": records,
            "issue": issue_tags,
            "parsed": parsed,
            "nxdomain": False,
        },
    )


def _parse_caa_line(raw: str) -> tuple[str, str, str]:
    match = re.match(
        r'^\s*(?P<flags>\d+)\s+(?P<tag>\S+)\s+"?(?P<value>[^"]*)"?\s*$',
        raw.strip(),
    )
    if match:
        return match.group("flags"), match.group("tag").lower(), match.group("value").strip()
    parts = raw.split(None, 2)
    if len(parts) >= 2:
        value = parts[2].strip().strip('"') if len(parts) > 2 else ""
        return parts[0], parts[1].lower(), value
    return "0", "", raw.strip()


def parse_semicolon_tags(record: str) -> dict[str, str]:
    tags: dict[str, str] = {}
    for segment in record.split(";"):
        segment = segment.strip()
        if "=" not in segment:
            continue
        key, value = segment.split("=", maxsplit=1)
        tags[key.strip().lower()] = value.strip()
    return tags


def extract_mailto_targets(raw_value: str | None) -> list[str]:
    if not raw_value:
        return []

    mailboxes: list[str] = []
    for candidate in raw_value.split(","):
        text = candidate.strip()
        if text.lower().startswith("mailto:"):
            text = text[7:]
        text = text.split("!", 1)[0].strip()
        _, address = parseaddr(text)
        if address.lower().startswith("mailto:"):
            address = address[7:]
        if address:
            mailboxes.append(address)
    return mailboxes


def score_checks(checks: dict[str, AuditCheck]) -> int:
    weights = {
        "mx": 10,
        "spf": 25,
        "dmarc": 25,
        "dkim": 20,
        "mta_sts": 8,
        "tls_rpt": 6,
        "bimi": 6,
    }
    status_scores = {
        "pass": 1.0,
        "warn": 0.6,
        "info": 0.5,
        "fail": 0.0,
    }

    # Only score core auth checks so optional advisories (e.g. free-email) don't distort totals.
    scored_keys = [key for key in weights if key in checks]
    total_weight = sum(weights[key] for key in scored_keys) or 1
    earned = 0.0
    for key in scored_keys:
        earned += weights[key] * status_scores[checks[key].status]
    return int(round((earned / total_weight) * 100))


def derive_overall_status(checks: dict[str, AuditCheck]) -> str:
    critical_failures = [checks[name].status == "fail" for name in ("mx", "spf", "dmarc", "dkim")]
    if any(critical_failures):
        return "fail"
    if any(check.status == "warn" for check in checks.values()):
        return "warn"
    return "pass"


def recommendations_for_check(name: str, check: AuditCheck) -> list[Recommendation]:
    if name == "mx" and check.status == "fail":
        return [
            Recommendation(
                severity="high",
                code="mx-missing",
                message="Publish MX records for the domain before sending production mail.",
                details="Without MX records, mailbox routing and receiving posture are incomplete.",
            )
        ]

    if name == "spf":
        if check.status == "fail" and not check.details.get("records"):
            return [
                Recommendation(
                    severity="high",
                    code="spf-missing",
                    message="Add a single SPF record for the domain.",
                    details="Google and Yahoo both expect authenticated sending for modern bulk email programs.",
                )
            ]
        if check.status == "fail":
            return [
                Recommendation(
                    severity="high",
                    code="spf-lookup-limit",
                    message="Reduce SPF complexity to stay below the 10 DNS lookup limit.",
                    details="Flatten includes or split traffic across subdomains/providers where appropriate.",
                )
            ]
        if check.status == "warn":
            return [
                Recommendation(
                    severity="medium",
                    code="spf-weak-policy",
                    message="Tighten the SPF policy or simplify it before it breaks at scale.",
                    details="A soft policy or near-limit record usually becomes an operational issue later.",
                )
            ]

    if name == "dmarc":
        if check.status == "fail":
            if check.details.get("record"):
                return [
                    Recommendation(
                        severity="high",
                        code="dmarc-rua-missing",
                        message="Add a DMARC rua mailbox so aggregate reports have somewhere to go.",
                        details="Gmail and Yahoo expect bulk senders to publish DMARC with reporting.",
                    )
                ]
            return [
                Recommendation(
                    severity="high",
                    code="dmarc-missing",
                    message="Publish a DMARC record, even if you start with p=none.",
                    details="DMARC is now baseline email infrastructure for modern senders.",
                )
            ]
        if check.status == "warn":
            return [
                Recommendation(
                    severity="medium",
                    code="dmarc-monitoring-only",
                    message="DMARC p=none does not meet 2024 Gmail/Yahoo bulk-sender requirements.",
                    details="Move toward quarantine or reject after validating legitimate senders.",
                )
            ]

    if name == "dkim":
        if check.status == "fail":
            return [
                Recommendation(
                    severity="high",
                    code="dkim-unverified",
                    message="The requested DKIM selectors did not resolve.",
                    details="Double-check selector names and whether your provider uses CNAME-based delegation.",
                )
            ]
        if check.status == "warn":
            return [
                Recommendation(
                    severity="medium",
                    code="dkim-unconfirmed",
                    message="DKIM could not be confirmed automatically.",
                    details="Provide known selectors or add provider-specific selectors to verify signing correctly.",
                )
            ]

    if name == "mta_sts" and check.status == "warn":
        return [
            Recommendation(
                severity="low",
                code="mta-sts-incomplete",
                message="Finish MTA-STS by publishing a reachable policy file and moving to enforce mode when ready.",
                details="This is a trust and transport-hardening improvement, not a blocker for MVP.",
            )
        ]

    if name == "tls_rpt" and check.status == "info":
        return [
            Recommendation(
                severity="low",
                code="tls-rpt-missing",
                message="Add TLS-RPT if you want visibility into TLS delivery failures.",
                details="Useful for monitoring but not required to launch.",
            )
        ]

    if name == "bimi" and check.status == "warn":
        recs: list[Recommendation] = []
        asset = check.details.get("asset")
        if isinstance(asset, dict) and not asset.get("ok"):
            recs.append(
                Recommendation(
                    severity="low",
                    code="bimi-asset-missing",
                    message="Host a publicly reachable SVG/XML logo at the BIMI l= URL.",
                    details="BIMI records without a fetchable logo will not display a brand mark.",
                )
            )
        if str(check.details.get("dmarc_policy") or "") not in {"quarantine", "reject"}:
            recs.append(
                Recommendation(
                    severity="low",
                    code="bimi-dmarc-prereq",
                    message="Move DMARC to quarantine or reject before relying on BIMI.",
                    details="Mailbox providers generally require stronger DMARC posture before showing logos.",
                )
            )
        return recs

    return []


def append_expected_provider_warnings(
    providers: list[ProviderMatch],
    expected_providers: list[str],
    recommendations: list[Recommendation],
) -> list[ProviderMatch]:
    detected_names = {provider.name.lower() for provider in providers}
    for expected in expected_providers:
        if expected.strip().lower() not in detected_names:
            recommendations.append(
                Recommendation(
                    severity="medium",
                    code="provider-not-detected",
                    message=f"Expected provider '{expected}' was not detected from DNS evidence.",
                    details="This may indicate incomplete setup, different routing, or a provider fingerprint gap.",
                )
            )
    return providers


def dedupe_recommendations(items: list[Recommendation]) -> list[Recommendation]:
    seen: set[str] = set()
    deduped: list[Recommendation] = []
    for item in items:
        if item.code in seen:
            continue
        seen.add(item.code)
        deduped.append(item)
    return deduped
