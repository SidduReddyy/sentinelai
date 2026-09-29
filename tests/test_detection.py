"""Tests — detection engine rules."""
from datetime import datetime, timedelta, timezone
from typing import List

from app.services.detection import (
    detect_brute_force,
    detect_suspicious_account_activity,
    detect_access_denied,
    detect_event_burst,
)


def _make_event(event_type="login", auth_result="failure", ip="192.0.2.1", user="alice", minutes_ago=0):
    """Helper to create a mock SecurityEvent-like object."""
    class FakeEvent:
        pass
    e = FakeEvent()
    e.id = f"fake-{minutes_ago}-{user}-{auth_result}"
    e.event_type = event_type
    e.auth_result = auth_result
    e.source_ip = ip
    e.username = user
    e.resource = "/test"
    ts = datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)
    e.timestamp = ts
    return e


# --- Rule A Tests ---

def test_brute_force_detected():
    events = [_make_event("login_failure", "failure", minutes_ago=i) for i in range(6)]
    results = detect_brute_force(events, threshold=5, window_seconds=300)
    assert len(results) >= 1
    assert results[0].rule_id == "RULE_A_BRUTE_FORCE"
    assert results[0].severity == "high"


def test_brute_force_below_threshold():
    events = [_make_event("login_failure", "failure", minutes_ago=i) for i in range(4)]
    results = detect_brute_force(events, threshold=5, window_seconds=300)
    assert len(results) == 0


def test_brute_force_ignores_successes():
    failures = [_make_event("login_failure", "failure", minutes_ago=i) for i in range(3)]
    successes = [_make_event("login", "success", minutes_ago=i) for i in range(10)]
    results = detect_brute_force(failures + successes, threshold=5, window_seconds=300)
    # Not enough failures
    assert len(results) == 0


def test_brute_force_empty_events():
    results = detect_brute_force([], threshold=5, window_seconds=300)
    assert results == []


# --- Rule B Tests ---

def test_suspicious_activity_detected():
    failures = [_make_event("login_failure", "failure", minutes_ago=i+1) for i in range(3)]
    success = [_make_event("login", "success", minutes_ago=0)]
    results = detect_suspicious_account_activity(failures + success, failure_threshold=3)
    assert len(results) >= 1
    assert results[0].rule_id == "RULE_B_SUSPICIOUS_ACTIVITY"


def test_suspicious_activity_only_failures():
    events = [_make_event("login_failure", "failure", minutes_ago=i) for i in range(5)]
    results = detect_suspicious_account_activity(events, failure_threshold=3)
    assert len(results) == 0


def test_suspicious_activity_success_no_failures():
    events = [_make_event("login", "success", minutes_ago=i) for i in range(5)]
    results = detect_suspicious_account_activity(events, failure_threshold=3)
    assert len(results) == 0


# --- Rule C Tests ---

def test_access_denied_detected():
    events = [_make_event("access_denied", "denied", minutes_ago=i * 0.2) for i in range(12)]
    results = detect_access_denied(events, threshold=10, window_seconds=300)
    assert len(results) >= 1
    assert results[0].rule_id == "RULE_C_ACCESS_DENIED"


def test_access_denied_below_threshold():
    events = [_make_event("access_denied", "denied", minutes_ago=i) for i in range(5)]
    results = detect_access_denied(events, threshold=10, window_seconds=300)
    assert len(results) == 0


# --- Rule D Tests ---

def test_event_burst_detected():
    events = [_make_event("login", "success", ip="203.0.113.1", minutes_ago=0) for _ in range(55)]
    results = detect_event_burst(events, threshold=50, window_seconds=60)
    assert len(results) >= 1
    assert results[0].rule_id == "RULE_D_EVENT_BURST"


def test_event_burst_below_threshold():
    events = [_make_event("login", "success", ip="203.0.113.2", minutes_ago=0) for _ in range(10)]
    results = detect_event_burst(events, threshold=50, window_seconds=60)
    assert len(results) == 0


def test_detection_dedup_key_populated():
    events = [_make_event("login_failure", "failure", minutes_ago=i) for i in range(6)]
    results = detect_brute_force(events, threshold=5, window_seconds=300)
    assert len(results) > 0
    assert results[0].dedup_key != ""


def test_detection_evidence_contains_facts():
    events = [_make_event("login_failure", "failure", minutes_ago=i) for i in range(6)]
    results = detect_brute_force(events, threshold=5, window_seconds=300)
    assert len(results) > 0
    evidence = results[0].evidence_summary
    assert "OBSERVED" in evidence
    assert "alice" in evidence or "192.0.2.1" in evidence
