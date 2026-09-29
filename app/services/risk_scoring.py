"""
Risk scoring service.
Computes a transparent, documented risk score for alerts.
"""
from __future__ import annotations

from typing import Dict

SEVERITY_BASE: Dict[str, float] = {
    "critical": 80.0,
    "high": 60.0,
    "medium": 40.0,
    "low": 20.0,
}

RULE_WEIGHT: Dict[str, float] = {
    "RULE_A_BRUTE_FORCE": 1.0,
    "RULE_B_SUSPICIOUS_ACTIVITY": 0.85,
    "RULE_C_ACCESS_DENIED": 0.75,
    "RULE_D_EVENT_BURST": 0.6,
    "RULE_E_COMBINATION": 1.2,
}


def compute_risk_score(
    severity: str,
    rule_id: str,
    event_count: int,
    anomaly_score: float = 0.0,
) -> float:
    """
    Compute risk score (0–100) based on:
    - Severity base
    - Rule-specific weight
    - Number of supporting events (capped)
    - Optional anomaly score contribution

    This is a heuristic scoring system. It is NOT a calibrated probability.
    """
    base = SEVERITY_BASE.get(severity.lower(), 30.0)
    rule_weight = RULE_WEIGHT.get(rule_id, 1.0)
    event_bonus = min(15.0, event_count * 1.5)
    anomaly_bonus = min(10.0, anomaly_score * 0.1)
    score = (base + event_bonus + anomaly_bonus) * rule_weight
    return round(min(100.0, max(0.0, score)), 2)
