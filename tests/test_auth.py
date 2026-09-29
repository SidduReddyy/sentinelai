"""Tests — authentication flows."""


def test_login_success(client):
    resp = client.post("/auth/login", json={"username": "test_admin", "password": "AdminPass123!"})
    assert resp.status_code == 200
    data = resp.json()
    assert "access_token" in data
    assert data["role"] == "admin"
    assert data["username"] == "test_admin"


def test_login_wrong_password(client):
    resp = client.post("/auth/login", json={"username": "test_admin", "password": "wrong"})
    assert resp.status_code == 401


def test_login_nonexistent_user(client):
    resp = client.post("/auth/login", json={"username": "nobody", "password": "pass"})
    assert resp.status_code == 401


def test_me_endpoint(client, admin_headers):
    resp = client.get("/auth/me", headers=admin_headers)
    assert resp.status_code == 200
    assert resp.json()["username"] == "test_admin"


def test_me_unauthenticated(client):
    resp = client.get("/auth/me")
    assert resp.status_code == 401


def test_create_user_admin(client, admin_headers):
    resp = client.post("/auth/users", json={
        "username": "new_analyst",
        "email": "new@example.com",
        "password": "NewPass123!",
        "role": "analyst",
    }, headers=admin_headers)
    assert resp.status_code == 201
    assert resp.json()["username"] == "new_analyst"


def test_create_user_viewer_forbidden(client, viewer_headers):
    resp = client.post("/auth/users", json={
        "username": "bad_user",
        "email": "bad@example.com",
        "password": "Bad123!",
        "role": "viewer",
    }, headers=viewer_headers)
    assert resp.status_code == 403


def test_list_users_admin(client, admin_headers):
    resp = client.get("/auth/users", headers=admin_headers)
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


def test_list_users_viewer_forbidden(client, viewer_headers):
    resp = client.get("/auth/users", headers=viewer_headers)
    assert resp.status_code == 403


def test_password_not_in_response(client, admin_headers):
    resp = client.get("/auth/users", headers=admin_headers)
    for user in resp.json():
        assert "password" not in user
        assert "hashed_password" not in user
