"""Documented scoring weights for domain readiness checks."""

from __future__ import annotations

# Weights sum to 100. Used for documentation and optional re-score helpers.
CHECK_WEIGHTS: dict[str, int] = {
    "mx": 15,
    "spf": 20,
    "dmarc": 25,
    "dkim": 20,
    "mta_sts": 8,
    "tls_rpt": 6,
    "bimi": 6,
}

STATUS_SCORE: dict[str, float] = {
    "pass": 1.0,
    "warn": 0.55,
    "fail": 0.0,
    "info": 0.7,
}


def scoring_document() -> dict[str, object]:
    """Public description of how overall scores are derived."""

    return {
        "version": "0.3",
        "max_score": 100,
        "weights": CHECK_WEIGHTS,
        "status_multipliers": STATUS_SCORE,
        "notes": [
            "Each check contributes weight * status_multiplier * 100 / total_weight.",
            "Missing checks are treated as fail (0).",
            "Recommendations do not change the numeric score directly.",
        ],
    }
