"""
Page 1 — Security Overview
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd

from dashboard.api_client import (
    get_summary, get_event_timeline, get_alert_severity_distribution,
    get_event_type_distribution, get_alerts, get_top_source_ips, run_detection
)
from dashboard.styles import apply_global_styles, metric_card, severity_badge, status_badge, section_header

st.set_page_config(page_title="Security Overview — SentinelAI", page_icon="📊", layout="wide")
apply_global_styles()

if "token" not in st.session_state:
    st.warning("Please sign in from the Home page.")
    st.stop()

# Sidebar
with st.sidebar:
    st.markdown("### 🛡️ SentinelAI")
    st.markdown(f"**User:** {st.session_state.get('username', '')}")
    st.markdown(f"**Role:** `{st.session_state.get('role', '')}`")
    st.divider()
    days = st.slider("Timeline Window (days)", 1, 30, 7)
    if st.button("🔄 Refresh Data"):
        st.rerun()
    if st.session_state.get("role") in ("admin", "analyst"):
        st.divider()
        if st.button("⚡ Run Detection Engine"):
            result = run_detection()
            if result:
                st.success(f"Found {result['detections_found']} detections, created {result['new_alerts_created']} alerts")

section_header("📊 Security Overview", "Real-time threat landscape")

# --- Metrics Row ---
summary = get_summary()
if summary:
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        metric_card("Total Events", summary.get("total_events", 0), color="#00d4ff")
    with c2:
        metric_card("Open Alerts", summary.get("open_alerts", 0), color="#FFD700")
    with c3:
        metric_card("High/Critical Alerts", summary.get("high_severity_alerts", 0), color="#FF4444")
    with c4:
        last = summary.get("last_ingestion", "Never")
        if last and last != "Never":
            last = last[:19].replace("T", " ")
        metric_card("Last Ingestion", last or "Never", color="#00FF88")
else:
    st.warning("Could not load summary metrics. Is the backend running and demo data loaded?")

st.markdown("---")

# --- Charts Row ---
col_left, col_right = st.columns([3, 2])

with col_left:
    st.markdown("#### 📈 Event Volume Timeline")
    timeline = get_event_timeline(days=days)
    if timeline:
        df = pd.DataFrame(timeline)
        fig = px.area(
            df, x="date", y="count",
            color_discrete_sequence=["#00d4ff"],
            template="plotly_dark",
        )
        fig.update_layout(
            paper_bgcolor="#1a2035", plot_bgcolor="#1a2035",
            margin=dict(l=0, r=0, t=10, b=0),
            xaxis=dict(showgrid=False, color="#8892a4"),
            yaxis=dict(showgrid=True, gridcolor="#1e3050", color="#8892a4"),
            showlegend=False,
        )
        fig.update_traces(fillcolor="rgba(0,212,255,0.15)", line_color="#00d4ff")
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No timeline data available. Load demo data in Settings.")

with col_right:
    st.markdown("#### 🎯 Alert Severity Distribution")
    severity_data = get_alert_severity_distribution()
    if severity_data and any(d["count"] > 0 for d in severity_data):
        df_sev = pd.DataFrame(severity_data)
        color_map = {"critical": "#FF4444", "high": "#FF8C00", "medium": "#FFD700", "low": "#00C8C8"}
        fig2 = px.pie(
            df_sev, values="count", names="severity",
            color="severity", color_discrete_map=color_map,
            template="plotly_dark",
            hole=0.5,
        )
        fig2.update_layout(
            paper_bgcolor="#1a2035",
            margin=dict(l=0, r=0, t=10, b=0),
            legend=dict(font=dict(color="#8892a4")),
        )
        st.plotly_chart(fig2, use_container_width=True)
    else:
        st.info("No alerts yet. Run the Detection Engine.")

# --- Second Row ---
col_a, col_b = st.columns([2, 3])

with col_a:
    st.markdown("#### 📂 Event Type Distribution")
    type_data = get_event_type_distribution()
    if type_data:
        df_type = pd.DataFrame(type_data).head(8)
        fig3 = px.bar(
            df_type, x="count", y="event_type", orientation="h",
            color="count", color_continuous_scale=["#003366", "#00d4ff"],
            template="plotly_dark",
        )
        fig3.update_layout(
            paper_bgcolor="#1a2035", plot_bgcolor="#1a2035",
            margin=dict(l=0, r=0, t=10, b=0),
            yaxis=dict(showgrid=False, color="#8892a4"),
            xaxis=dict(showgrid=True, gridcolor="#1e3050", color="#8892a4"),
            coloraxis_showscale=False,
            showlegend=False,
        )
        st.plotly_chart(fig3, use_container_width=True)
    else:
        st.info("No event data.")

with col_b:
    st.markdown("#### 🚨 Recent Alerts")
    alerts = get_alerts(limit=8)
    if alerts:
        for a in alerts:
            sev = a.get("severity", "low")
            stat = a.get("status", "new")
            rule = a.get("rule_name", "Unknown")
            created = a.get("created_at", "")[:19].replace("T", " ")
            score = a.get("risk_score", 0)
            st.markdown(
                f'<div style="background:#1a2035;padding:10px 16px;border-radius:8px;border-left:3px solid #1e3050;margin:4px 0;display:flex;justify-content:space-between;align-items:center">'
                f'<div><span style="color:#e2e8f0;font-size:0.9em">{rule}</span><br>'
                f'<span style="color:#8892a4;font-size:0.75em">{created}</span></div>'
                f'<div style="text-align:right">{severity_badge(sev)}&nbsp;{status_badge(stat)}<br>'
                f'<span style="color:#8892a4;font-size:0.75em">Risk: {score:.0f}</span></div>'
                f'</div>',
                unsafe_allow_html=True,
            )
    else:
        st.info("No alerts. Load demo data and run detection.")

# --- Top Source IPs ---
st.markdown("---")
st.markdown("#### 🌐 Top Source IPs")
ips = get_top_source_ips(limit=10)
if ips:
    df_ips = pd.DataFrame(ips)
    fig4 = px.bar(
        df_ips, x="source_ip", y="count",
        color="count", color_continuous_scale=["#003366", "#00d4ff"],
        template="plotly_dark",
    )
    fig4.update_layout(
        paper_bgcolor="#1a2035", plot_bgcolor="#1a2035",
        margin=dict(l=0, r=0, t=10, b=0),
        xaxis=dict(showgrid=False, color="#8892a4"),
        yaxis=dict(showgrid=True, gridcolor="#1e3050", color="#8892a4"),
        coloraxis_showscale=False,
    )
    st.plotly_chart(fig4, use_container_width=True)
else:
    st.info("No IP data available.")
