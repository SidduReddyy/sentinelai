"""
Pytest configuration and shared fixtures.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base, get_db
from app.main import app
from app.models.user import User
from app.security.passwords import hash_password

TEST_DB_URL = "sqlite:///./test_sentinelai.db"

test_engine = create_engine(TEST_DB_URL, connect_args={"check_same_thread": False})
TestSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)


def override_get_db():
    db = TestSessionLocal()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture(autouse=True)
def setup_test_db():
    """Create tables and seed test users before each test; drop after."""
    from app.models import alert, audit, event, user  # noqa
    Base.metadata.create_all(bind=test_engine)

    db = TestSessionLocal()
    try:
        # Seed test users
        users = [
            User(username="test_admin", email="admin@test.local", hashed_password=hash_password("AdminPass123!"), role="admin", is_active=True),
            User(username="test_analyst", email="analyst@test.local", hashed_password=hash_password("AnalystPass123!"), role="analyst", is_active=True),
            User(username="test_viewer", email="viewer@test.local", hashed_password=hash_password("ViewerPass123!"), role="viewer", is_active=True),
        ]
        for u in users:
            db.add(u)
        db.commit()
    finally:
        db.close()

    yield

    Base.metadata.drop_all(bind=test_engine)


@pytest.fixture
def client():
    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()


def _token(client, username: str, password: str) -> str:
    resp = client.post("/auth/login", json={"username": username, "password": password})
    assert resp.status_code == 200, f"Login failed: {resp.text}"
    return resp.json()["access_token"]


@pytest.fixture
def admin_token(client):
    return _token(client, "test_admin", "AdminPass123!")


@pytest.fixture
def analyst_token(client):
    return _token(client, "test_analyst", "AnalystPass123!")


@pytest.fixture
def viewer_token(client):
    return _token(client, "test_viewer", "ViewerPass123!")


@pytest.fixture
def admin_headers(admin_token):
    return {"Authorization": f"Bearer {admin_token}"}


@pytest.fixture
def analyst_headers(analyst_token):
    return {"Authorization": f"Bearer {analyst_token}"}


@pytest.fixture
def viewer_headers(viewer_token):
    return {"Authorization": f"Bearer {viewer_token}"}
