"""Page 3 — Threat Alerts"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

import json
import streamlit as st
import pandas as pd

from dashboard.api_client import get_alerts, get_alert, get_alert_stats, update_alert, add_note, get_notes, run_detection
from dashboard.styles import apply_global_styles, section_header, severity_badge, status_badge, metric_card

st.set_page_config(page_title="Threat Alerts — SentinelAI", page_icon="🚨", layout="wide")
apply_global_styles()

if "token" not in st.session_state:
    st.warning("Please sign in from the Home page.")
    st.stop()

role = st.session_state.get("role", "viewer")

section_header("🚨 Threat Alerts", "Prioritized security alerts with risk scores")

# --- Stats Bar ---
stats = get_alert_stats()
if stats:
    c1, c2, c3, c4, c5 = st.columns(5)
    with c1: metric_card("Total Alerts", stats.get("total", 0))
    with c2: metric_card("New", stats["by_status"].get("new", 0), color="#00BFFF")
    with c3: metric_card("Investigating", stats["by_status"].get("investigating", 0), color="#FFD700")
    with c4: metric_card("Critical", stats["by_severity"].get("critical", 0), color="#FF4444")
    with c5: metric_card("High", stats["by_severity"].get("high", 0), color="#FF8C00")

st.markdown("---")

# --- Filters ---
col1, col2, col3 = st.columns(3)
with col1:
    status_filter = st.selectbox("Status", ["", "new", "investigating", "resolved", "false_positive"])
with col2:
    severity_filter = st.selectbox("Severity", ["", "critical", "high", "medium", "low"])
with col3:
    username_filter = st.text_input("Username filter")

if role in ("admin", "analyst"):
    if st.button("⚡ Run Detection Engine Now"):
        result = run_detection()
        if result:
            st.success(f"Detection complete: {result['detections_found']} findings, {result['new_alerts_created']} new alerts created")
            st.rerun()

alerts = get_alerts(
    limit=50,
    status=status_filter or None,
    severity=severity_filter or None,
    username=username_filter or None,
)

if not alerts:
    st.info("No alerts found. Load demo data from Settings and run the detection engine.")
    st.stop()

# --- Alert List ---
for alert in alerts:
    sev = alert.get("severity", "low")
    stat = alert.get("status", "new")
    score = alert.get("risk_score", 0)
    rule = alert.get("rule_name", "Unknown")
    created = alert.get("created_at", "")[:19].replace("T", " ")
    aid = alert.get("id", "")

    border_color = {"critical": "#FF4444", "high": "#FF8C00", "medium": "#FFD700", "low": "#00C8C8"}.get(sev, "#1e3050")

    with st.expander(
        f"{rule} | {sev.upper()} | Risk: {score:.0f} | {created}",
        expanded=False,
    ):
        col_a, col_b = st.columns([3, 1])
        with col_a:
            st.markdown(
                f"{severity_badge(sev)}&nbsp;&nbsp;{status_badge(stat)}",
                unsafe_allow_html=True,
            )
            st.markdown(f"**Source IP:** {alert.get('source_ip', 'N/A')}  |  **Username:** {alert.get('username', 'N/A')}")
            st.markdown(f"**Alert ID:** `{aid}`")
            evidence = alert.get("evidence_summary", "")
            if evidence:
                st.markdown("**Evidence:**")
                st.code(evidence, language="text")
            steps = alert.get("recommended_steps", "")
            if steps:
                st.markdown("**Recommended Steps:**")
                st.markdown(steps)

        with col_b:
            if role in ("admin", "analyst"):
                new_status = st.selectbox(
                    "Update Status",
                    ["new", "investigating", "resolved", "false_positive"],
                    index=["new", "investigating", "resolved", "false_positive"].index(stat) if stat in ["new", "investigating", "resolved", "false_positive"] else 0,
                    key=f"status_{aid}",
                )
                if st.button("Update", key=f"update_{aid}"):
                    result = update_alert(aid, status=new_status)
                    if result:
                        st.success("Updated!")
                        st.rerun()

        # Notes
        st.markdown("**Investigation Notes:**")
        notes = get_notes(aid)
        if notes:
            for note in notes:
                st.markdown(
                    f'<div style="background:#0d1628;padding:8px 12px;border-radius:6px;margin:4px 0;border-left:3px solid #1e3050">'
                    f'<span style="color:#00d4ff;font-size:0.8em">{note["author"]}</span> '
                    f'<span style="color:#8892a4;font-size:0.75em">{note["created_at"][:19]}</span><br>'
                    f'<span style="color:#e2e8f0">{note["note"]}</span></div>',
                    unsafe_allow_html=True,
                )

        if role in ("admin", "analyst"):
            new_note = st.text_area("Add Note", key=f"note_input_{aid}", height=80)
            if st.button("Add Note", key=f"note_btn_{aid}"):
                if new_note.strip():
                    add_note(aid, new_note.strip())
                    st.success("Note added!")
                    st.rerun()
