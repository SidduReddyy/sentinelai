"""Page 5 — Reports"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

import json
import io
import csv
import streamlit as st
import pandas as pd

from dashboard.api_client import get_alerts, get_events, get_summary, get_alert_stats
from dashboard.styles import apply_global_styles, section_header

st.set_page_config(page_title="Reports — SentinelAI", page_icon="📄", layout="wide")
apply_global_styles()

if "token" not in st.session_state:
    st.warning("Please sign in from the Home page.")
    st.stop()

section_header("📄 Reports & Exports", "Export data for offline analysis and reporting")

tab1, tab2, tab3 = st.tabs(["📊 Incident Summary", "🚨 Alert Export", "🔍 Event Export"])

with tab1:
    st.markdown("#### Incident Summary Report")
    summary = get_summary()
    stats = get_alert_stats()

    if summary and stats:
        st.markdown(f"""
**SentinelAI Security Report**
Generated: {pd.Timestamp.now().strftime('%Y-%m-%d %H:%M UTC')}

| Metric | Value |
|--------|-------|
| Total Events | {summary.get('total_events', 0)} |
| Total Alerts | {summary.get('total_alerts', 0)} |
| Open Alerts | {summary.get('open_alerts', 0)} |
| High/Critical Alerts | {summary.get('high_severity_alerts', 0)} |
| New | {stats['by_status'].get('new', 0)} |
| Investigating | {stats['by_status'].get('investigating', 0)} |
| Resolved | {stats['by_status'].get('resolved', 0)} |
| False Positive | {stats['by_status'].get('false_positive', 0)} |
""")

        report_text = f"""SentinelAI Security Report
Generated: {pd.Timestamp.now().strftime('%Y-%m-%d %H:%M UTC')}
Total Events: {summary.get('total_events', 0)}
Total Alerts: {summary.get('total_alerts', 0)}
Open Alerts: {summary.get('open_alerts', 0)}
High/Critical: {summary.get('high_severity_alerts', 0)}
Alert Status: New={stats['by_status'].get('new',0)}, Investigating={stats['by_status'].get('investigating',0)}, Resolved={stats['by_status'].get('resolved',0)}, FP={stats['by_status'].get('false_positive',0)}
Alert Severity: Critical={stats['by_severity'].get('critical',0)}, High={stats['by_severity'].get('high',0)}, Medium={stats['by_severity'].get('medium',0)}, Low={stats['by_severity'].get('low',0)}
"""
        st.download_button("📥 Download Text Report", report_text, file_name="sentinelai_report.txt", mime="text/plain")
    else:
        st.info("No data available. Load demo data from Settings.")

with tab2:
    st.markdown("#### Alert Export")
    sev_filter = st.selectbox("Severity Filter", ["all", "critical", "high", "medium", "low"])
    alerts = get_alerts(limit=500, severity=None if sev_filter == "all" else sev_filter)
    if alerts:
        # Sanitize — remove event_ids raw JSON for export clarity
        safe_alerts = []
        for a in alerts:
            row = {k: v for k, v in a.items() if k not in ("event_ids",)}
            safe_alerts.append(row)

        df = pd.DataFrame(safe_alerts)
        st.dataframe(df[["created_at","rule_name","severity","status","source_ip","username","risk_score"]], use_container_width=True, hide_index=True)

        csv_buf = io.StringIO()
        df.to_csv(csv_buf, index=False)
        st.download_button("📥 Download CSV", csv_buf.getvalue(), file_name="sentinelai_alerts.csv", mime="text/csv")

        json_export = json.dumps(safe_alerts, indent=2, default=str)
        st.download_button("📥 Download JSON", json_export, file_name="sentinelai_alerts.json", mime="application/json")
    else:
        st.info("No alerts to export.")

with tab3:
    st.markdown("#### Event Export")
    event_type_filter = st.selectbox("Event Type Filter", ["", "login", "login_failure", "access_denied", "privilege_escalation"])
    events = get_events(limit=500, event_type=event_type_filter or None)
    if events:
        df_ev = pd.DataFrame(events)
        safe_cols = [c for c in ["timestamp","event_type","auth_result","source_ip","username","hostname","resource","severity","is_synthetic"] if c in df_ev.columns]
        st.dataframe(df_ev[safe_cols], use_container_width=True, hide_index=True)

        csv_buf = io.StringIO()
        df_ev[safe_cols].to_csv(csv_buf, index=False)
        st.download_button("📥 Download Events CSV", csv_buf.getvalue(), file_name="sentinelai_events.csv", mime="text/csv")
    else:
        st.info("No events to export.")
