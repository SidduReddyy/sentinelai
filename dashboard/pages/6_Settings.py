"""Page 6 — Settings"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

import streamlit as st

from dashboard.api_client import get_config, reset_demo_data, run_detection, health_check
from dashboard.styles import apply_global_styles, section_header, info_banner

st.set_page_config(page_title="Settings — SentinelAI", page_icon="⚙️", layout="wide")
apply_global_styles()

if "token" not in st.session_state:
    st.warning("Please sign in from the Home page.")
    st.stop()

role = st.session_state.get("role", "viewer")
section_header("⚙️ Settings", "Application configuration and administration")

tab1, tab2, tab3 = st.tabs(["🔧 Detection Config", "🤖 AI Status", "🗄️ Data Management"])

with tab1:
    st.markdown("#### Detection Thresholds (Read from .env)")
    config = get_config()
    if config:
        col1, col2 = st.columns(2)
        with col1:
            st.markdown(f"**Brute Force Threshold:** `{config.get('brute_force_threshold')}` failures")
            st.markdown(f"**Brute Force Window:** `{config.get('brute_force_window_seconds')}` seconds")
            st.markdown(f"**Access Denied Threshold:** `{config.get('access_denied_threshold')}` denials")
        with col2:
            st.markdown(f"**Access Denied Window:** `{config.get('access_denied_window_seconds')}` seconds")
            st.markdown(f"**Event Burst Threshold:** `{config.get('event_burst_threshold')}` events")
            st.markdown(f"**Event Burst Window:** `{config.get('event_burst_window_seconds')}` seconds")

        info_banner("To change thresholds, update the .env file and restart the backend.", "info")
    else:
        st.error("Cannot load config — backend not reachable.")

    st.markdown("---")
    st.markdown("#### 🏥 System Health")
    backend_ok = health_check()
    if backend_ok:
        st.success("✅ Backend API: Healthy")
    else:
        st.error("❌ Backend API: Not reachable")

with tab2:
    st.markdown("#### AI Provider Status")
    config = get_config()
    if config:
        provider = config.get("ai_provider", "none")
        configured = config.get("ai_configured", False)
        if configured:
            st.success(f"✅ AI Provider: **{provider}** — Configured and active")
        else:
            st.info(f"ℹ️ AI Provider: **{provider}** — Local fallback active (no API key set)")
            st.markdown("""
**To enable an LLM provider:**
1. Copy `.env.example` to `.env`
2. Set `AI_PROVIDER=openai` (or `anthropic`)
3. Set `AI_API_KEY=your-key-here`
4. Set `AI_MODEL=gpt-3.5-turbo` (or your preferred model)
5. Restart the backend
            """)
            info_banner("Core functionality works completely without an AI provider.", "info")

with tab3:
    st.markdown("#### Demo Data Management")

    if role in ("admin",):
        st.markdown("**Load Demo Data**")
        st.markdown("Run this command in a terminal:")
        st.code("cd sentinelai && source venv/bin/activate && python scripts/seed_demo_data.py", language="bash")

        st.markdown("---")
        st.markdown("**Run Detection Engine**")
        if st.button("⚡ Run Detection Now", key="run_det_btn"):
            result = run_detection()
            if result:
                st.success(f"Detection complete: {result['detections_found']} findings, {result['new_alerts_created']} new alerts")

        st.markdown("---")
        st.markdown("**⚠️ Reset Demo Data**")
        st.warning("This will delete ALL synthetic events and alerts. This action cannot be undone.")
        confirm = st.checkbox("I understand this will delete demo data permanently")
        if confirm:
            if st.button("🗑️ Reset Demo Data", key="reset_demo"):
                result = reset_demo_data()
                if result:
                    st.success(result.get("message", "Demo data deleted."))
    else:
        info_banner("Admin role required to manage data.", "warning")
        st.markdown("**Load Demo Data** (Admin must run this command):")
        st.code("cd sentinelai && source venv/bin/activate && python scripts/seed_demo_data.py", language="bash")
