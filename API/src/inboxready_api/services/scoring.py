"""The scoring table, and the only copy of it.

``/v1/scoring`` publishes these numbers and
:func:`inboxready_api.services.dns_audit.score_checks` scores with them, so a
customer who reproduces our arithmetic gets our answer. They used to be two
separate tables that had silently drifted apart — the endpoint advertised MX at
15 points and a warn multiplier of 0.55 while the scorer used 10 and 0.6 — so a
score could never be reproduced from the published document.
``test_scoring_document_matches_the_scorer`` now fails if they diverge again.
"""

from __future__ import annotations

#: Relative weight of each check. Scores are normalised by the weights of the
#: checks actually present, so a missing optional check cannot deflate a score.
CHECK_WEIGHTS: dict[str, int] = {
    "mx": 10,
    "spf": 25,
    "dmarc": 25,
    "dkim": 20,
    "mta_sts": 8,
    "tls_rpt": 6,
    "bimi": 6,
}

#: What each status is worth, as a fraction of the check's weight.
STATUS_SCORE: dict[str, float] = {
    "pass": 1.0,
    "warn": 0.6,
    "info": 0.5,
    "fail": 0.0,
}


def scoring_document() -> dict[str, object]:
    """Public description of how overall scores are derived."""

    return {
        "version": "0.6",
        "max_score": 100,
        "weights": dict(CHECK_WEIGHTS),
        "total_weight": sum(CHECK_WEIGHTS.values()),
        "status_multipliers": dict(STATUS_SCORE),
        "notes": [
            "Score = 100 * sum(weight * status_multiplier) / sum(weight), "
            "over the checks present in the response.",
            "Only the seven weighted checks count. Advisory checks such as "
            "sending_domain do not change the number.",
            "A check that is absent is excluded from both sums rather than "
            "scored as a failure.",
            "Recommendations do not change the numeric score directly.",
        ],
    }
