"""
SentinelAI — Deterministic Threat Detection Engine

Rule registry with five detection categories:
  A. Repeated authentication failures (brute force)
  B. Suspicious account activity (fail-then-succeed)
  C. Access denied patterns
  D. Unusual activity volume (event burst)
  E. Suspicious event combinations
"""
from __future__ import annotations

import json
import logging
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy.orm import Session

from app.config import get_settings
from app.models.event import SecurityEvent

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Detection Result
# ---------------------------------------------------------------------------

@dataclass
class DetectionResult:
    rule_id: str
    rule_name: str
    description: str
    severity: str
    risk_score: float
    source_ip: Optional[str]
    username: Optional[str]
    resource: Optional[str]
    evidence_summary: str
    recommended_steps: str
    event_ids: List[str]
    dedup_key: str


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _make_aware(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


# ---------------------------------------------------------------------------
# Rule A — Brute Force (Repeated Auth Failures)
# ---------------------------------------------------------------------------

def detect_brute_force(
    events: List[SecurityEvent],
    threshold: int,
    window_seconds: int,
) -> List[DetectionResult]:
    """Identify repeated login failures per (source_ip, username) within window."""
    results: List[DetectionResult] = []
    # Group failures
    failures: Dict[Tuple[str, str], List[SecurityEvent]] = defaultdict(list)
    for evt in events:
        if evt.event_type in ("login", "login_failure") and evt.auth_result == "failure":
            key = (evt.source_ip or "unknown_ip", evt.username or "unknown_user")
            failures[key].append(evt)

    for (ip, user), fail_events in failures.items():
        fail_events.sort(key=lambda e: _make_aware(e.timestamp))
        # Sliding window
        triggered: List[SecurityEvent] = []
        for i, evt in enumerate(fail_events):
            window_start = _make_aware(evt.timestamp) - timedelta(seconds=window_seconds)
            window_group = [
                e for e in fail_events
                if _make_aware(e.timestamp) >= window_start and _make_aware(e.timestamp) <= _make_aware(evt.timestamp)
            ]
            if len(window_group) >= threshold and set(e.id for e in window_group) - set(e.id for e in triggered):
                triggered = window_group
                first_ts = _make_aware(window_group[0].timestamp).isoformat()
                last_ts = _make_aware(window_group[-1].timestamp).isoformat()
                dedup = f"brute_force:{ip}:{user}:{first_ts[:16]}"
                results.append(DetectionResult(
                    rule_id="RULE_A_BRUTE_FORCE",
                    rule_name="Repeated Authentication Failures",
                    description=(
                        f"{len(window_group)} failed login attempts for account '{user}' "
                        f"from {ip} within {window_seconds}s"
                    ),
                    severity="high",
                    risk_score=min(95.0, 50.0 + len(window_group) * 5.0),
                    source_ip=ip if ip != "unknown_ip" else None,
                    username=user if user != "unknown_user" else None,
                    resource=None,
                    evidence_summary=(
                        f"OBSERVED: {len(window_group)} consecutive login failures.\n"
                        f"Account: {user} | Source IP: {ip}\n"
                        f"First failure: {first_ts} | Last failure: {last_ts}\n"
                        f"Event IDs: {[e.id for e in window_group]}"
                    ),
                    recommended_steps=(
                        "1. Verify whether these attempts are from a known user or system.\n"
                        "2. Check if the account was locked automatically.\n"
                        "3. Inspect source IP reputation and geolocation.\n"
                        "4. Review associated successful logins after this sequence.\n"
                        "5. Notify the account holder if a real user is involved."
                    ),
                    event_ids=[e.id for e in window_group],
                    dedup_key=dedup,
                ))
                break  # one alert per (ip, user) per detection run

    return results


# ---------------------------------------------------------------------------
# Rule B — Suspicious Account Activity (fail-then-succeed)
# ---------------------------------------------------------------------------

def detect_suspicious_account_activity(
    events: List[SecurityEvent],
    failure_threshold: int = 3,
    window_seconds: int = 600,
) -> List[DetectionResult]:
    """Detect sequences of failures followed quickly by a success."""
    results: List[DetectionResult] = []
    by_user: Dict[str, List[SecurityEvent]] = defaultdict(list)
    for evt in events:
        if evt.event_type in ("login", "login_failure") and evt.username:
            by_user[evt.username].append(evt)

    for user, user_events in by_user.items():
        user_events.sort(key=lambda e: _make_aware(e.timestamp))
        for i, evt in enumerate(user_events):
            if evt.auth_result == "success":
                window_start = _make_aware(evt.timestamp) - timedelta(seconds=window_seconds)
                preceding_failures = [
                    e for e in user_events[:i]
                    if e.auth_result == "failure" and _make_aware(e.timestamp) >= window_start
                ]
                if len(preceding_failures) >= failure_threshold:
                    all_ids = [e.id for e in preceding_failures] + [evt.id]
                    dedup = f"susp_activity:{user}:{_make_aware(evt.timestamp).isoformat()[:16]}"
                    results.append(DetectionResult(
                        rule_id="RULE_B_SUSPICIOUS_ACTIVITY",
                        rule_name="Suspicious Account Activity",
                        description=(
                            f"Account '{user}' had {len(preceding_failures)} failures "
                            f"followed by a success within {window_seconds}s — warrants investigation"
                        ),
                        severity="medium",
                        risk_score=min(80.0, 40.0 + len(preceding_failures) * 7.0),
                        source_ip=evt.source_ip,
                        username=user,
                        resource=evt.resource,
                        evidence_summary=(
                            f"OBSERVED: {len(preceding_failures)} login failures then a successful "
                            f"authentication for '{user}'.\n"
                            f"Success at: {_make_aware(evt.timestamp).isoformat()}\n"
                            f"This pattern may indicate a successful brute-force; requires investigation.\n"
                            f"Note: This does NOT confirm compromise."
                        ),
                        recommended_steps=(
                            "1. Contact the user to confirm they authenticated at this time.\n"
                            "2. Review session activity following the successful login.\n"
                            "3. Check for anomalous data access or privilege use.\n"
                            "4. Consider requiring MFA if not already enforced."
                        ),
                        event_ids=all_ids,
                        dedup_key=dedup,
                    ))
                    break

    return results


# ---------------------------------------------------------------------------
# Rule C — Access Denied Patterns
# ---------------------------------------------------------------------------

def detect_access_denied(
    events: List[SecurityEvent],
    threshold: int,
    window_seconds: int,
) -> List[DetectionResult]:
    """Detect repeated authorization failures against resources."""
    results: List[DetectionResult] = []
    denied: Dict[Tuple[str, str], List[SecurityEvent]] = defaultdict(list)
    for evt in events:
        if evt.auth_result == "denied" or evt.event_type == "access_denied":
            key = (evt.source_ip or "unknown_ip", evt.resource or "unknown_resource")
            denied[key].append(evt)

    for (ip, resource), deny_events in denied.items():
        if len(deny_events) >= threshold:
            deny_events.sort(key=lambda e: _make_aware(e.timestamp))
            for i, evt in enumerate(deny_events):
                window_start = _make_aware(evt.timestamp) - timedelta(seconds=window_seconds)
                window_group = [
                    e for e in deny_events
                    if _make_aware(e.timestamp) >= window_start and _make_aware(e.timestamp) <= _make_aware(evt.timestamp)
                ]
                if len(window_group) >= threshold:
                    first_ts = _make_aware(window_group[0].timestamp)
                    last_ts = _make_aware(window_group[-1].timestamp)
                    dedup = f"access_denied:{ip}:{resource[:50]}:{first_ts.isoformat()[:16]}"
                    results.append(DetectionResult(
                        rule_id="RULE_C_ACCESS_DENIED",
                        rule_name="Repeated Access Denied",
                        description=(
                            f"{len(window_group)} access-denied events for resource '{resource}' "
                            f"from {ip} in {window_seconds}s"
                        ),
                        severity="medium",
                        risk_score=min(75.0, 35.0 + len(window_group) * 4.0),
                        source_ip=ip if ip != "unknown_ip" else None,
                        username=window_group[0].username,
                        resource=resource if resource != "unknown_resource" else None,
                        evidence_summary=(
                            f"OBSERVED: {len(window_group)} access-denied events.\n"
                            f"Source: {ip} | Target resource: {resource}\n"
                            f"Timespan: {first_ts.isoformat()} to {last_ts.isoformat()}"
                        ),
                        recommended_steps=(
                            "1. Confirm whether the source IP is a legitimate system.\n"
                            "2. Review what resource is being targeted and its sensitivity.\n"
                            "3. Check for privilege escalation attempts after the denials.\n"
                            "4. Review access control policies for the target resource."
                        ),
                        event_ids=[e.id for e in window_group],
                        dedup_key=dedup,
                    ))
                    break

    return results


# ---------------------------------------------------------------------------
# Rule D — Event Burst / Volume Anomaly
# ---------------------------------------------------------------------------

def detect_event_burst(
    events: List[SecurityEvent],
    threshold: int,
    window_seconds: int,
) -> List[DetectionResult]:
    """Detect unusual bursts of events from a single source."""
    results: List[DetectionResult] = []
    by_ip: Dict[str, List[SecurityEvent]] = defaultdict(list)
    for evt in events:
        if evt.source_ip:
            by_ip[evt.source_ip].append(evt)

    for ip, ip_events in by_ip.items():
        ip_events.sort(key=lambda e: _make_aware(e.timestamp))
        if len(ip_events) < threshold:
            continue
        # Sliding window check
        for i in range(len(ip_events)):
            t_start = _make_aware(ip_events[i].timestamp)
            t_end = t_start + timedelta(seconds=window_seconds)
            burst = [e for e in ip_events if t_start <= _make_aware(e.timestamp) <= t_end]
            if len(burst) >= threshold:
                dedup = f"burst:{ip}:{t_start.isoformat()[:16]}"
                results.append(DetectionResult(
                    rule_id="RULE_D_EVENT_BURST",
                    rule_name="Unusual Activity Volume",
                    description=(
                        f"{len(burst)} events from {ip} within {window_seconds}s "
                        f"(threshold: {threshold})"
                    ),
                    severity="medium",
                    risk_score=min(70.0, 30.0 + min(len(burst), 100) * 0.4),
                    source_ip=ip,
                    username=None,
                    resource=None,
                    evidence_summary=(
                        f"OBSERVED: {len(burst)} events from {ip} in {window_seconds}s.\n"
                        f"Event types: {Counter(e.event_type for e in burst).most_common(3)}"
                    ),
                    recommended_steps=(
                        "1. Determine if this IP runs automated processes.\n"
                        "2. Review event types in the burst for sensitive actions.\n"
                        "3. Consider rate-limiting or blocking if no legitimate reason found.\n"
                        "4. Cross-reference with brute-force or access-denied alerts."
                    ),
                    event_ids=[e.id for e in burst[:50]],
                    dedup_key=dedup,
                ))
                break  # one alert per IP

    return results


# ---------------------------------------------------------------------------
# Rule E — Suspicious Event Combinations
# ---------------------------------------------------------------------------

SUSPICIOUS_COMBINATIONS: List[Dict[str, Any]] = [
    {
        "name": "Privilege Escalation After Repeated Failures",
        "description": "Login failures followed by privilege escalation",
        "types": ["login_failure", "privilege_escalation"],
        "window_seconds": 900,
        "severity": "critical",
        "risk_score": 90.0,
    },
    {
        "name": "Data Export After Access Denied",
        "description": "Access denied events followed by a data export",
        "types": ["access_denied", "data_export"],
        "window_seconds": 600,
        "severity": "high",
        "risk_score": 80.0,
    },
]


def detect_suspicious_combinations(
    events: List[SecurityEvent],
) -> List[DetectionResult]:
    """Detect configured multi-event-type suspicious sequences."""
    results: List[DetectionResult] = []
    events_sorted = sorted(events, key=lambda e: _make_aware(e.timestamp))

    for combo in SUSPICIOUS_COMBINATIONS:
        types = combo["types"]
        window = combo["window_seconds"]
        by_user: Dict[str, List[SecurityEvent]] = defaultdict(list)
        for evt in events_sorted:
            if evt.event_type in types and evt.username:
                by_user[evt.username].append(evt)

        for user, user_events in by_user.items():
            has_first = any(e.event_type == types[0] for e in user_events)
            has_second = any(e.event_type == types[1] for e in user_events)
            if not (has_first and has_second):
                continue
            first_events = [e for e in user_events if e.event_type == types[0]]
            second_events = [e for e in user_events if e.event_type == types[1]]
            for second_evt in second_events:
                t2 = _make_aware(second_evt.timestamp)
                related = [e for e in first_events if t2 - timedelta(seconds=window) <= _make_aware(e.timestamp) <= t2]
                if related:
                    all_ids = [e.id for e in related] + [second_evt.id]
                    dedup = f"combo:{combo['name']}:{user}:{t2.isoformat()[:16]}"
                    results.append(DetectionResult(
                        rule_id="RULE_E_COMBINATION",
                        rule_name=combo["name"],
                        description=combo["description"],
                        severity=combo["severity"],
                        risk_score=combo["risk_score"],
                        source_ip=second_evt.source_ip,
                        username=user,
                        resource=second_evt.resource,
                        evidence_summary=(
                            f"OBSERVED: {combo['description']} for user '{user}'.\n"
                            f"Preceding events ({types[0]}): {len(related)}\n"
                            f"Triggering event ({types[1]}) at: {t2.isoformat()}"
                        ),
                        recommended_steps=(
                            "1. Immediately review the account's recent activity.\n"
                            "2. Escalate to senior analyst for manual review.\n"
                            "3. Consider temporary account suspension pending investigation.\n"
                            "4. Preserve all relevant logs for forensic analysis."
                        ),
                        event_ids=all_ids,
                        dedup_key=dedup,
                    ))
                    break

    return results


# ---------------------------------------------------------------------------
# Main Engine Entry Point
# ---------------------------------------------------------------------------

def run_detection(db: Session, lookback_seconds: int = 86400) -> List[DetectionResult]:
    """Run all detection rules on recent events. Returns list of DetectionResults."""
    settings = get_settings()
    since = _utc_now() - timedelta(seconds=lookback_seconds)

    events: List[SecurityEvent] = (
        db.query(SecurityEvent)
        .filter(SecurityEvent.timestamp >= since)
        .all()
    )
    logger.info("Detection engine: analyzing %d events from last %ds", len(events), lookback_seconds)

    if not events:
        return []

    results: List[DetectionResult] = []
    results.extend(detect_brute_force(
        events,
        threshold=settings.brute_force_threshold,
        window_seconds=settings.brute_force_window_seconds,
    ))
    results.extend(detect_suspicious_account_activity(events))
    results.extend(detect_access_denied(
        events,
        threshold=settings.access_denied_threshold,
        window_seconds=settings.access_denied_window_seconds,
    ))
    results.extend(detect_event_burst(
        events,
        threshold=settings.event_burst_threshold,
        window_seconds=settings.event_burst_window_seconds,
    ))
    results.extend(detect_suspicious_combinations(events))

    logger.info("Detection engine: generated %d raw results", len(results))
    return results
