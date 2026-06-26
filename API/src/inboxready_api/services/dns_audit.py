from __future__ import annotations

from collections.abc import Iterable
from datetime import UTC, datetime
from email.utils import parseaddr

import dns.exception
import dns.resolver

from inboxready_api.models import (
    AuditCheck,
    DomainAuditRequest,
    DomainAuditResponse,
    ProviderMatch,
    Recommendation,
)
from inboxready_api.domain_validation import normalize_domain
from inboxready_api.services.provider_detection import detect_providers
from inboxready_api.settings import Settings

DMARC_REFERENCE = "https://dmarc.org/"
GOOGLE_REFERENCE = "https://support.google.com/a/answer/81126?hl=en-AL"
YAHOO_REFERENCE = "https://senders.yahooinc.com/faqs/"


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

    spf_check = build_spf_check(root_txt)
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
    bimi_check = build_bimi_check(bimi_records, checks["dmarc"])
    checks["bimi"] = bimi_check
    recommendations.extend(recommendations_for_check("bimi", bimi_check))

    providers = append_expected_provider_warnings(providers, request.expected_providers, recommendations)
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


def build_spf_check(root_txt_records: list[str]) -> AuditCheck:
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

    return AuditCheck(
        status=status,
        summary=summary,
        details=parsed,
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
    policy = tags.get("p", "none").lower()
    rua = tags.get("rua")
    status = "pass"
    summary = "DMARC record is present."

    if policy == "none":
        status = "warn"
        summary = "DMARC is present but still in monitoring mode."

    if not rua:
        summary = f"{summary} No aggregate reporting mailbox is configured."

    return AuditCheck(
        status=status,
        summary=summary,
        details={
            "record": record,
            "policy": policy,
            "subdomain_policy": tags.get("sp"),
            "percentage": tags.get("pct"),
            "rua": extract_mailto_targets(rua),
            "ruf": extract_mailto_targets(tags.get("ruf")),
        },
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
        import httpx

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


def build_bimi_check(records: list[str], dmarc_check: AuditCheck) -> AuditCheck:
    valid_records = [record for record in records if record.lower().startswith("v=bimi1")]

    if not valid_records:
        return AuditCheck(
            status="info",
            summary="No BIMI record found.",
            details={"records": []},
        )

    dmarc_policy = str(dmarc_check.details.get("policy") or "")
    status = "pass" if dmarc_policy in {"quarantine", "reject"} else "warn"
    summary = "BIMI record is present."
    if status == "warn":
        summary = "BIMI record exists, but DMARC is not yet at quarantine or reject."

    return AuditCheck(
        status=status,
        summary=summary,
        details={
            "record": valid_records[0],
        },
    )


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
        _, address = parseaddr(candidate.strip())
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

    total_weight = sum(weights.values())
    earned = 0.0
    for key, weight in weights.items():
        earned += weight * status_scores[checks[key].status]
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
                    message="DMARC exists but is still set to monitoring mode.",
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
        return [
            Recommendation(
                severity="low",
                code="bimi-dmarc-prereq",
                message="Move DMARC to quarantine or reject before relying on BIMI.",
                details="Mailbox providers generally require stronger DMARC posture before showing logos.",
            )
        ]

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
