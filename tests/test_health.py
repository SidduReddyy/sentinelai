"""Tests — health check and application startup."""
def test_health(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert "service" in data
    # Health should not expose sensitive info
    resp_text = resp.text
    assert "password" not in resp_text.lower()
    assert "secret" not in resp_text.lower()
