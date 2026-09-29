"""Tests — alert management and RBAC enforcement."""

VALID_EVENT = {
    "timestamp": "2026-09-01T10:00:00Z",
    "source_ip": "192.0.2.10",
    "username": "alice",
    "event_type": "login_failure",
    "auth_result": "failure",
    "severity": "medium",
    "is_synthetic": True,
}


def _seed_alert(client, analyst_headers):
    """Ingest brute-force events, run detection, return first alert ID."""
    events = [{**VALID_EVENT, "event_id": f"BF-{i}", "timestamp": f"2026-09-01T10:0{i}:00Z"} for i in range(6)]
    client.post("/events/ingest", json=events, headers=analyst_headers)
    client.post("/alerts/run-detection", headers=analyst_headers)
    alerts = client.get("/alerts", headers=analyst_headers).json()
    return alerts[0]["id"] if alerts else None


def test_alert_listing(client, analyst_headers, viewer_headers):
    _seed_alert(client, analyst_headers)
    resp = client.get("/alerts", headers=viewer_headers)
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


def test_alert_stats(client, analyst_headers, viewer_headers):
    _seed_alert(client, analyst_headers)
    resp = client.get("/alerts/stats", headers=viewer_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "total" in data


def test_viewer_cannot_update_alert(client, analyst_headers, viewer_headers):
    alert_id = _seed_alert(client, analyst_headers)
    if alert_id is None:
        return  # no alert created, skip
    resp = client.patch(f"/alerts/{alert_id}", json={"status": "resolved"}, headers=viewer_headers)
    assert resp.status_code == 403


def test_analyst_can_update_alert(client, analyst_headers):
    alert_id = _seed_alert(client, analyst_headers)
    if alert_id is None:
        return
    resp = client.patch(f"/alerts/{alert_id}", json={"status": "investigating"}, headers=analyst_headers)
    assert resp.status_code == 200
    assert resp.json()["status"] == "investigating"


def test_invalid_status_rejected(client, analyst_headers):
    alert_id = _seed_alert(client, analyst_headers)
    if alert_id is None:
        return
    resp = client.patch(f"/alerts/{alert_id}", json={"status": "hacked"}, headers=analyst_headers)
    assert resp.status_code == 422


def test_add_note_analyst(client, analyst_headers):
    alert_id = _seed_alert(client, analyst_headers)
    if alert_id is None:
        return
    resp = client.post(f"/alerts/{alert_id}/notes", json={"note": "Investigating this alert"}, headers=analyst_headers)
    assert resp.status_code == 201


def test_viewer_cannot_add_note(client, analyst_headers, viewer_headers):
    alert_id = _seed_alert(client, analyst_headers)
    if alert_id is None:
        return
    resp = client.post(f"/alerts/{alert_id}/notes", json={"note": "Sneaky note"}, headers=viewer_headers)
    assert resp.status_code == 403


def test_alert_deduplication(client, analyst_headers):
    """Running detection twice should not double alerts with same dedup_key."""
    events = [{**VALID_EVENT, "event_id": f"DUP-{i}", "timestamp": f"2026-09-01T10:0{i}:00Z"} for i in range(6)]
    client.post("/events/ingest", json=events, headers=analyst_headers)
    r1 = client.post("/alerts/run-detection", headers=analyst_headers).json()
    r2 = client.post("/alerts/run-detection", headers=analyst_headers).json()
    # Second run should create 0 new alerts (all deduped)
    assert r2["new_alerts_created"] == 0


def test_nonexistent_alert(client, viewer_headers):
    resp = client.get("/alerts/nonexistent-id-12345", headers=viewer_headers)
    assert resp.status_code == 404


def test_unauthenticated_alerts(client):
    resp = client.get("/alerts")
    assert resp.status_code == 401
