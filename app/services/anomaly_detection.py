"""
ML-based anomaly detection using Isolation Forest.

Extracts safe features from security events and returns anomaly scores.
IMPORTANT: Anomaly scores are NOT proof of malicious activity. They indicate
statistical deviation from baseline and require human investigation.
"""
from __future__ import annotations

import json
import logging
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

logger = logging.getLogger(__name__)

RANDOM_SEED = 42
MIN_EVENTS_FOR_TRAINING = 20


def _make_aware(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def _extract_features(events: list) -> Optional[Tuple[np.ndarray, List[str]]]:
    """
    Extract numerical feature vectors per source IP.
    Returns (feature_matrix, ip_list) or None if insufficient data.
    """
    if not events or len(events) < MIN_EVENTS_FOR_TRAINING:
        return None

    by_ip: Dict[str, list] = defaultdict(list)
    for evt in events:
        ip = evt.source_ip or "unknown"
        by_ip[ip].append(evt)

    if len(by_ip) < 3:
        return None

    rows: List[List[float]] = []
    ips: List[str] = []

    for ip, ip_events in by_ip.items():
        total = len(ip_events)
        failures = sum(1 for e in ip_events if e.auth_result == "failure")
        denials = sum(1 for e in ip_events if e.auth_result == "denied")
        successes = sum(1 for e in ip_events if e.auth_result == "success")
        distinct_users = len({e.username for e in ip_events if e.username})
        distinct_types = len({e.event_type for e in ip_events})

        failure_ratio = failures / total if total > 0 else 0.0
        denial_ratio = denials / total if total > 0 else 0.0

        # Time spread in minutes
        timestamps = sorted(_make_aware(e.timestamp) for e in ip_events)
        time_spread = (timestamps[-1] - timestamps[0]).total_seconds() / 60.0 if len(timestamps) > 1 else 0.0

        rows.append([
            float(total),
            float(failures),
            float(denials),
            float(successes),
            float(distinct_users),
            float(distinct_types),
            failure_ratio,
            denial_ratio,
            time_spread,
        ])
        ips.append(ip)

    if len(rows) < 3:
        return None

    return np.array(rows, dtype=np.float32), ips


def run_anomaly_detection(events: list) -> Dict[str, Any]:
    """
    Run Isolation Forest on events grouped by source IP.

    Returns:
        {
          "status": "ok" | "insufficient_data" | "disabled" | "error",
          "message": str,
          "anomalies": [{"source_ip": str, "anomaly_score": float, "is_anomaly": bool}],
          "model_info": str,
        }
    """
    try:
        from sklearn.ensemble import IsolationForest
        from sklearn.preprocessing import StandardScaler
    except ImportError:
        return {
            "status": "disabled",
            "message": "scikit-learn not available",
            "anomalies": [],
            "model_info": "IsolationForest disabled",
        }

    extracted = _extract_features(events)
    if extracted is None:
        return {
            "status": "insufficient_data",
            "message": (
                f"Need at least {MIN_EVENTS_FOR_TRAINING} events and 3 distinct source IPs. "
                "Anomaly detection skipped."
            ),
            "anomalies": [],
            "model_info": "IsolationForest (insufficient data)",
        }

    X, ips = extracted

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    model = IsolationForest(
        n_estimators=100,
        contamination=0.1,
        random_state=RANDOM_SEED,
    )
    model.fit(X_scaled)

    raw_scores = model.decision_function(X_scaled)   # higher = more normal
    predictions = model.predict(X_scaled)              # -1 = anomaly, 1 = normal

    # Normalize score to 0–100 (higher = more anomalous)
    min_score, max_score = raw_scores.min(), raw_scores.max()
    range_score = max_score - min_score if max_score != min_score else 1.0
    normalized = [(max_score - s) / range_score * 100.0 for s in raw_scores]

    anomalies = []
    for ip, score, pred, norm in zip(ips, raw_scores, predictions, normalized):
        anomalies.append({
            "source_ip": ip,
            "anomaly_score": round(float(norm), 2),
            "is_anomaly": bool(pred == -1),
        })

    anomaly_count = sum(1 for a in anomalies if a["is_anomaly"])
    return {
        "status": "ok",
        "message": (
            f"Analyzed {len(ips)} source IPs. "
            f"{anomaly_count} flagged as statistical anomalies. "
            "NOTE: These scores indicate statistical deviation, not confirmed malicious activity."
        ),
        "anomalies": anomalies,
        "model_info": "IsolationForest (n_estimators=100, contamination=0.1, seed=42)",
    }
