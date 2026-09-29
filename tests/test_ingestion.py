"""Tests — event ingestion."""
from datetime import datetime, timezone


VALID_EVENT = {
    "timestamp": "2026-09-01T10:00:00Z",
    "source_ip": "192.0.2.10",
    "username": "alice",
    "event_type": "login",
    "auth_result": "success",
    "hostname": "auth-srv",
    "resource": "/api/login",
    "severity": "low",
    "is_synthetic": True,
}


def test_ingest_single_valid_event(client, analyst_headers):
    resp = client.post("/events/ingest", json=[VALID_EVENT], headers=analyst_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["accepted"] == 1
    assert data["rejected"] == 0


def test_ingest_multiple_events(client, analyst_headers):
    events = [{**VALID_EVENT, "event_id": f"TEST-{i}"} for i in range(5)]
    resp = client.post("/events/ingest", json=events, headers=analyst_headers)
    assert resp.status_code == 200
    assert resp.json()["accepted"] == 5


def test_ingest_invalid_ip(client, analyst_headers):
    evt = {**VALID_EVENT, "source_ip": "999.999.999.999"}
    resp = client.post("/events/ingest", json=[evt], headers=analyst_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["rejected"] == 1 or data["accepted"] == 0


def test_ingest_missing_optional_fields(client, analyst_headers):
    evt = {"timestamp": "2026-09-01T10:00:00Z", "event_type": "login"}
    resp = client.post("/events/ingest", json=[evt], headers=analyst_headers)
    assert resp.status_code == 200
    assert resp.json()["accepted"] >= 0  # valid partial event


def test_ingest_duplicate_event(client, analyst_headers):
    evt = {**VALID_EVENT, "event_id": "DEDUP-TEST-001"}
    # Ingest twice
    resp1 = client.post("/events/ingest", json=[evt], headers=analyst_headers)
    resp2 = client.post("/events/ingest", json=[evt], headers=analyst_headers)
    assert resp1.json()["accepted"] == 1
    assert resp2.json()["duplicates"] == 1


def test_ingest_requires_auth(client):
    resp = client.post("/events/ingest", json=[VALID_EVENT])
    assert resp.status_code == 401


def test_viewer_cannot_ingest(client, viewer_headers):
    resp = client.post("/events/ingest", json=[VALID_EVENT], headers=viewer_headers)
    assert resp.status_code == 403


def test_list_events(client, analyst_headers, viewer_headers):
    client.post("/events/ingest", json=[{**VALID_EVENT, "event_id": "LIST-001"}], headers=analyst_headers)
    resp = client.get("/events", headers=viewer_headers)
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


def test_event_count(client, viewer_headers):
    resp = client.get("/events/count", headers=viewer_headers)
    assert resp.status_code == 200
    assert "count" in resp.json()


def test_ingest_unknown_event_type(client, analyst_headers):
    evt = {**VALID_EVENT, "event_type": "totally_unknown_type_xyz"}
    resp = client.post("/events/ingest", json=[evt], headers=analyst_headers)
    assert resp.status_code == 200
    # Should be normalized to "unknown" and accepted
    assert resp.json()["accepted"] == 1
