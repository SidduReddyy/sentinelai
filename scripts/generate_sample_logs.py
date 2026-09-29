"""
Generate synthetic security event data for demonstration.

ALL data is completely synthetic:
- Documentation-range IP addresses (192.0.2.x, 198.51.100.x, 203.0.113.x)
- Fictional usernames, hostnames, and resources
- No real passwords, keys, or private information
- Deterministic seed for reproducibility
"""
from __future__ import annotations

import json
import random
import csv
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List, Dict, Any

SEED = 42
random.seed(SEED)

# Documentation-range IPs (RFC 5737)
INTERNAL_IPS = [f"10.0.1.{i}" for i in range(1, 20)]
EXTERNAL_IPS = [
    "192.0.2.10", "192.0.2.45", "192.0.2.78",
    "198.51.100.5", "198.51.100.23", "198.51.100.99",
    "203.0.113.7", "203.0.113.42", "203.0.113.155",
]

USERNAMES = [
    "alice.johnson", "bob.smith", "carol.white", "dave.brown",
    "eve.davis", "frank.miller", "grace.wilson", "hank.moore",
    "ivan.taylor", "jane.anderson", "svc_backup", "svc_monitor",
]

HOSTNAMES = [
    "web-srv-01", "db-srv-01", "auth-srv-01", "api-gw-01",
    "jump-host-01", "log-srv-01", "backup-srv-01",
]

RESOURCES = [
    "/api/v1/users", "/api/v1/admin", "/api/v1/reports",
    "/internal/config", "/db/backup", "/admin/panel",
    "/api/v1/data/export", "/auth/reset",
]

NOW = datetime(2026, 9, 29, 6, 0, 0, tzinfo=timezone.utc)


def _ts(minutes_ago: int, jitter: int = 0) -> str:
    offset = timedelta(minutes=minutes_ago + random.randint(-jitter, jitter))
    return (NOW - offset).isoformat()


def _event(
    event_type: str,
    auth_result: str,
    source_ip: str,
    username: str,
    hostname: str,
    resource: str,
    timestamp: str,
    severity: str = "low",
    action: str = "",
    synthetic: bool = True,
) -> Dict[str, Any]:
    return {
        "event_id": f"SYNTH-{random.randint(100000, 999999)}",
        "timestamp": timestamp,
        "source_ip": source_ip,
        "username": username,
        "event_type": event_type,
        "action": action or event_type,
        "auth_result": auth_result,
        "hostname": hostname,
        "resource": resource,
        "severity": severity,
        "raw_message": f"[SYNTHETIC] {event_type} by {username} from {source_ip}",
        "is_synthetic": synthetic,
    }


def generate_events() -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = []

    # --- Normal background traffic (no detections triggered) ---
    for i in range(80):
        user = random.choice(USERNAMES[:8])
        ip = random.choice(INTERNAL_IPS)
        events.append(_event(
            event_type="login",
            auth_result="success",
            source_ip=ip,
            username=user,
            hostname=random.choice(HOSTNAMES),
            resource="/api/v1/users",
            timestamp=_ts(random.randint(60, 1400), jitter=5),
            severity="low",
            action="user_login",
        ))

    # --- Occasional legitimate failures ---
    for i in range(15):
        user = random.choice(USERNAMES[:6])
        ip = random.choice(INTERNAL_IPS)
        events.append(_event(
            event_type="login_failure",
            auth_result="failure",
            source_ip=ip,
            username=user,
            hostname="auth-srv-01",
            resource="/auth/login",
            timestamp=_ts(random.randint(100, 800), jitter=10),
            severity="low",
        ))

    # --- DETECTION A trigger: Brute force (5+ failures in 5 min) ---
    brute_ip = "203.0.113.7"
    brute_user = "alice.johnson"
    base_min = 30
    for i in range(8):
        events.append(_event(
            event_type="login_failure",
            auth_result="failure",
            source_ip=brute_ip,
            username=brute_user,
            hostname="auth-srv-01",
            resource="/auth/login",
            timestamp=_ts(base_min, jitter=1),
            severity="medium",
        ))
        base_min -= 1

    # --- DETECTION B trigger: Failures then success ---
    susp_ip = "198.51.100.23"
    susp_user = "bob.smith"
    base_min = 50
    for i in range(4):
        events.append(_event(
            event_type="login_failure",
            auth_result="failure",
            source_ip=susp_ip,
            username=susp_user,
            hostname="auth-srv-01",
            resource="/auth/login",
            timestamp=_ts(base_min - i, jitter=1),
            severity="medium",
        ))
    events.append(_event(
        event_type="login",
        auth_result="success",
        source_ip=susp_ip,
        username=susp_user,
        hostname="auth-srv-01",
        resource="/auth/login",
        timestamp=_ts(45),
        severity="high",
    ))

    # --- DETECTION C trigger: Repeated access denied ---
    denied_ip = "192.0.2.78"
    denied_user = "carol.white"
    denied_resource = "/api/v1/admin"
    for i in range(12):
        events.append(_event(
            event_type="access_denied",
            auth_result="denied",
            source_ip=denied_ip,
            username=denied_user,
            hostname="api-gw-01",
            resource=denied_resource,
            timestamp=_ts(20 - i // 2, jitter=1),
            severity="medium",
        ))

    # --- DETECTION D trigger: Event burst from one IP ---
    burst_ip = "203.0.113.42"
    for i in range(60):
        events.append(_event(
            event_type=random.choice(["login", "api_call", "file_access"]),
            auth_result=random.choice(["success", "failure"]),
            source_ip=burst_ip,
            username=random.choice(USERNAMES[:4]),
            hostname=random.choice(HOSTNAMES),
            resource=random.choice(RESOURCES),
            timestamp=_ts(10, jitter=0),
            severity="medium",
        ))

    # --- DETECTION E trigger: Privilege escalation after failures ---
    priv_user = "dave.brown"
    priv_ip = "198.51.100.5"
    for i in range(3):
        events.append(_event(
            event_type="login_failure",
            auth_result="failure",
            source_ip=priv_ip,
            username=priv_user,
            hostname="auth-srv-01",
            resource="/auth/login",
            timestamp=_ts(15 - i, jitter=1),
            severity="medium",
        ))
    events.append(_event(
        event_type="privilege_escalation",
        auth_result="success",
        source_ip=priv_ip,
        username=priv_user,
        hostname="db-srv-01",
        resource="/internal/config",
        timestamp=_ts(12),
        severity="critical",
        action="sudo_escalation",
    ))

    # --- Extra data export events ---
    for user in ["alice.johnson", "frank.miller"]:
        events.append(_event(
            event_type="data_export",
            auth_result="success",
            source_ip=random.choice(INTERNAL_IPS),
            username=user,
            hostname="backup-srv-01",
            resource="/db/backup",
            timestamp=_ts(random.randint(200, 400), jitter=20),
            severity="low",
        ))

    random.shuffle(events)
    return events


def save_json(events: List[Dict[str, Any]], path: Path) -> None:
    path.write_text(json.dumps(events, indent=2, default=str))
    print(f"Saved {len(events)} events to {path}")


def save_csv(events: List[Dict[str, Any]], path: Path) -> None:
    if not events:
        return
    fieldnames = list(events[0].keys())
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(events)
    print(f"Saved {len(events)} events to {path}")


if __name__ == "__main__":
    data_dir = Path(__file__).parent.parent / "data"
    data_dir.mkdir(exist_ok=True)
    events = generate_events()
    save_json(events, data_dir / "sample_logs.json")
    save_csv(events, data_dir / "sample_logs.csv")
    print(f"\nGenerated {len(events)} synthetic events.")
    print("Each detection rule should be triggered by this dataset.")
