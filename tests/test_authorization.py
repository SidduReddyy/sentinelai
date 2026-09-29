"""Tests — authorization and security controls."""


def test_settings_no_secrets_exposed(client, viewer_headers):
    resp = client.get("/settings/config", headers=viewer_headers)
    assert resp.status_code == 200
    data = resp.json()
    # Sensitive keys must not appear
    resp_text = resp.text.lower()
    assert "api_key" not in resp_text or "ai_api_key" not in resp_text
    assert "secret_key" not in resp_text
    assert "password" not in resp_text


def test_viewer_cannot_delete_demo_data(client, viewer_headers):
    resp = client.delete("/settings/demo-data", headers=viewer_headers)
    assert resp.status_code == 403


def test_analyst_cannot_delete_demo_data(client, analyst_headers):
    resp = client.delete("/settings/demo-data", headers=analyst_headers)
    assert resp.status_code == 403


def test_admin_can_delete_demo_data(client, admin_headers):
    resp = client.delete("/settings/demo-data", headers=admin_headers)
    assert resp.status_code == 200


def test_no_token_rejected(client):
    for endpoint in ["/events", "/alerts", "/analytics/summary", "/settings/config"]:
        resp = client.get(endpoint)
        assert resp.status_code == 401, f"Expected 401 for {endpoint}, got {resp.status_code}"


def test_invalid_token_rejected(client):
    headers = {"Authorization": "Bearer this-is-not-a-valid-token"}
    resp = client.get("/events", headers=headers)
    assert resp.status_code == 401


def test_viewer_cannot_ingest(client, viewer_headers):
    resp = client.post("/events/ingest", json=[], headers=viewer_headers)
    assert resp.status_code == 403


def test_viewer_cannot_run_detection(client, viewer_headers):
    resp = client.post("/alerts/run-detection", headers=viewer_headers)
    assert resp.status_code == 403


def test_input_validation_empty_username(client):
    resp = client.post("/auth/login", json={"username": "", "password": "pass"})
    assert resp.status_code in (401, 422)


def test_input_validation_no_body(client):
    resp = client.post("/auth/login")
    assert resp.status_code == 422
