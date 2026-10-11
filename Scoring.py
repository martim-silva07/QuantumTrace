from __future__ import annotations

from typing import Any

TIER_WEIGHTS = {
    "critical": 10,
    "medium": 4,
    "unknown": 2,
    "safe": 0,
}

GRADES = [
    (80, "F", "Severe quantum risk — urgent migration"),
    (60, "D", "High risk — plan migration in the short term"),
    (40, "C", "Moderate risk — include in the migration roadmap"),
    (20, "B", "Low risk — good posture, maintain vigilance"),
    (0, "A", "Strong posture — largely post-quantum/secure"),
]


def compute_score(assets: list[dict[str, Any]]) -> dict[str, Any]:
    total = len(assets)
    counts = {"critical": 0, "medium": 0, "safe": 0, "unknown": 0}
    for a in assets:
        tier = a.get("risk_tier") or "unknown"
        counts[tier if tier in counts else "unknown"] += 1

    if total == 0:
        return {"score": 0, "grade": "A", "label": "No cryptographic assets detected", "total_assets": 0, "counts": counts}

    weighted = sum(counts[t] * w for t, w in TIER_WEIGHTS.items())
    score = round(100 * weighted / (10 * total))
    grade, label = next((g, l) for threshold, g, l in GRADES if score >= threshold)

    return {"score": score, "grade": grade, "label": label, "total_assets": total, "counts": counts}


def breakdown_by_source(assets: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    by_source: dict[str, list[dict[str, Any]]] = {}
    for a in assets:
        by_source.setdefault(a.get("source", "unknown"), []).append(a)
    return {src: compute_score(items) for src, items in by_source.items()}
