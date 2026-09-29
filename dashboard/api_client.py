"""
Dashboard API client — communicates with the SentinelAI FastAPI backend.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

import requests
import streamlit as st

logger = logging.getLogger(__name__)

BACKEND_URL = "http://localhost:8000"
TIMEOUT = 10


def _headers() -> Dict[str, str]:
    token = st.session_state.get("token")
    if token:
        return {"Authorization": f"Bearer {token}"}
    return {}


def _get(path: str, params: Optional[Dict] = None) -> Any:
    try:
        resp = requests.get(f"{BACKEND_URL}{path}", headers=_headers(), params=params, timeout=TIMEOUT)
        resp.raise_for_status()
        return resp.json()
    except requests.exceptions.ConnectionError:
        st.error("⚠️ Cannot connect to backend. Ensure `uvicorn app.main:app --reload` is running.")
        return None
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 401:
            st.warning("Session expired. Please log in again.")
            st.session_state.clear()
        elif e.response.status_code == 403:
            st.error("Access denied — insufficient permissions.")
        else:
            st.error(f"Backend error: {e.response.status_code}")
        return None
    except Exception as e:
        st.error(f"Request failed: {e}")
        return None


def _post(path: str, json: Any = None, params: Optional[Dict] = None) -> Any:
    try:
        resp = requests.post(f"{BACKEND_URL}{path}", headers=_headers(), json=json, params=params, timeout=TIMEOUT)
        resp.raise_for_status()
        return resp.json()
    except requests.exceptions.ConnectionError:
        st.error("⚠️ Cannot connect to backend.")
        return None
    except requests.exceptions.HTTPError as e:
        st.error(f"API error: {e.response.status_code} — {e.response.text[:200]}")
        return None


def _patch(path: str, json: Any = None) -> Any:
    try:
        resp = requests.patch(f"{BACKEND_URL}{path}", headers=_headers(), json=json, timeout=TIMEOUT)
        resp.raise_for_status()
        return resp.json()
    except requests.exceptions.HTTPError as e:
        st.error(f"API error: {e.response.status_code} — {e.response.text[:200]}")
        return None


def _delete(path: str) -> Any:
    try:
        resp = requests.delete(f"{BACKEND_URL}{path}", headers=_headers(), timeout=TIMEOUT)
        resp.raise_for_status()
        return resp.json()
    except requests.exceptions.HTTPError as e:
        st.error(f"API error: {e.response.status_code} — {e.response.text[:200]}")
        return None


# --- Auth ---
def login(username: str, password: str) -> Optional[Dict]:
    try:
        resp = requests.post(
            f"{BACKEND_URL}/auth/login",
            json={"username": username, "password": password},
            timeout=TIMEOUT,
        )
        if resp.status_code == 200:
            return resp.json()
        st.error("Invalid credentials")
        return None
    except Exception as e:
        st.error(f"Login failed: {e}")
        return None


def get_me() -> Optional[Dict]:
    return _get("/auth/me")


# --- Analytics ---
def get_summary() -> Optional[Dict]:
    return _get("/analytics/summary")


def get_event_timeline(days: int = 7) -> Optional[List]:
    return _get("/analytics/event-timeline", params={"days": days})


def get_alert_severity_distribution() -> Optional[List]:
    return _get("/analytics/alert-severity-distribution")


def get_event_type_distribution() -> Optional[List]:
    return _get("/analytics/event-type-distribution")


def get_top_source_ips(limit: int = 10) -> Optional[List]:
    return _get("/analytics/top-source-ips", params={"limit": limit})


# --- Events ---
def get_events(skip: int = 0, limit: int = 50, **filters) -> Optional[List]:
    params = {"skip": skip, "limit": limit}
    params.update({k: v for k, v in filters.items() if v})
    return _get("/events", params=params)


def get_event_count() -> Optional[int]:
    result = _get("/events/count")
    return result.get("count") if result else None


# --- Alerts ---
def get_alerts(skip: int = 0, limit: int = 50, **filters) -> Optional[List]:
    params = {"skip": skip, "limit": limit}
    params.update({k: v for k, v in filters.items() if v})
    return _get("/alerts", params=params)


def get_alert_stats() -> Optional[Dict]:
    return _get("/alerts/stats")


def get_alert(alert_id: str) -> Optional[Dict]:
    return _get(f"/alerts/{alert_id}")


def update_alert(alert_id: str, status: str = None, assigned_to: str = None) -> Optional[Dict]:
    body = {}
    if status:
        body["status"] = status
    if assigned_to:
        body["assigned_to"] = assigned_to
    return _patch(f"/alerts/{alert_id}", json=body)


def add_note(alert_id: str, note: str) -> Optional[Dict]:
    return _post(f"/alerts/{alert_id}/notes", json={"note": note})


def get_notes(alert_id: str) -> Optional[List]:
    return _get(f"/alerts/{alert_id}/notes")


def get_investigations(alert_id: str) -> Optional[List]:
    return _get(f"/alerts/{alert_id}/investigations")


def run_detection(lookback_seconds: int = 86400) -> Optional[Dict]:
    return _post(f"/alerts/run-detection", params={"lookback_seconds": lookback_seconds})


# --- Investigation ---
def generate_investigation(alert_id: str) -> Optional[Dict]:
    return _post("/investigations", json={"alert_id": alert_id})


# --- Settings ---
def get_config() -> Optional[Dict]:
    return _get("/settings/config")


def reset_demo_data() -> Optional[Dict]:
    return _delete("/settings/demo-data")


# --- Health ---
def health_check() -> bool:
    try:
        resp = requests.get(f"{BACKEND_URL}/health", timeout=5)
        return resp.status_code == 200
    except Exception:
        return False
