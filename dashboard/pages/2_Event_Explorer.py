"""Page 2 — Event Explorer"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

import streamlit as st
import pandas as pd

from dashboard.api_client import get_events, get_event_count
from dashboard.styles import apply_global_styles, section_header, severity_badge

st.set_page_config(page_title="Event Explorer — SentinelAI", page_icon="🔍", layout="wide")
apply_global_styles()

if "token" not in st.session_state:
    st.warning("Please sign in from the Home page.")
    st.stop()

section_header("🔍 Event Explorer", "Search and filter security events")

# --- Filters ---
with st.expander("🔎 Filters", expanded=True):
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        event_type = st.selectbox("Event Type", ["", "login", "login_failure", "access_denied", "privilege_escalation", "file_access", "data_export", "api_call", "network_connection"])
    with c2:
        auth_result = st.selectbox("Auth Result", ["", "success", "failure", "denied"])
    with c3:
        source_ip = st.text_input("Source IP", placeholder="e.g. 203.0.113.7")
    with c4:
        username = st.text_input("Username", placeholder="e.g. alice.johnson")

page_size = 50
page = st.number_input("Page", min_value=1, value=1, step=1)
skip = (page - 1) * page_size

events = get_events(
    skip=skip,
    limit=page_size,
    event_type=event_type or None,
    auth_result=auth_result or None,
    source_ip=source_ip or None,
    username=username or None,
)

total = get_event_count()
st.markdown(f"**{total or '?'} total events** | Showing page {page} ({skip+1}–{skip+page_size})")

if events:
    df = pd.DataFrame(events)
    display_cols = ["timestamp", "event_type", "auth_result", "source_ip", "username", "hostname", "resource", "severity"]
    df = df[[c for c in display_cols if c in df.columns]]
    df["timestamp"] = df["timestamp"].astype(str).str[:19]

    st.dataframe(
        df,
        use_container_width=True,
        column_config={
            "timestamp": st.column_config.TextColumn("Timestamp", width=160),
            "event_type": st.column_config.TextColumn("Type", width=140),
            "auth_result": st.column_config.TextColumn("Auth Result", width=100),
            "source_ip": st.column_config.TextColumn("Source IP", width=120),
            "username": st.column_config.TextColumn("Username", width=140),
            "severity": st.column_config.TextColumn("Severity", width=80),
        },
        hide_index=True,
    )

    # Event detail
    st.markdown("---")
    st.markdown("#### 🔎 Event Detail")
    selected_id = st.text_input("Enter event row ID to inspect (copy from table):")
    if selected_id:
        matching = [e for e in events if e.get("id") == selected_id.strip()]
        if matching:
            st.json(matching[0])
        else:
            st.warning("Event not found on this page.")
else:
    st.info("No events found with the current filters. Try loading demo data from Settings.")
