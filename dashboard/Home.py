"""
SentinelAI Dashboard — Home / Login Page
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import streamlit as st

from dashboard.api_client import login, get_me, health_check
from dashboard.styles import apply_global_styles

st.set_page_config(
    page_title="SentinelAI — Cybersecurity Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)
apply_global_styles()


def show_login():
    st.markdown("""
    <div style="text-align:center;padding:40px 0 20px">
        <div style="font-size:3.5em">🛡️</div>
        <h1 style="font-size:2.5em;background:linear-gradient(135deg,#00d4ff,#007bff);-webkit-background-clip:text;-webkit-text-fill-color:transparent;margin:0">SentinelAI</h1>
        <p style="color:#8892a4;font-size:1.1em;margin-top:8px">AI-Powered Cybersecurity Threat Detection & Investigation</p>
    </div>
    """, unsafe_allow_html=True)

    backend_ok = health_check()
    if not backend_ok:
        st.error("⚠️ Backend is not reachable. Run: `uvicorn app.main:app --reload` in the sentinelai directory.")
        st.code("cd sentinelai && source venv/bin/activate && uvicorn app.main:app --reload", language="bash")
        return

    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        st.markdown('<div style="background:#1a2035;padding:32px;border-radius:16px;border:1px solid #1e3050">', unsafe_allow_html=True)
        st.markdown("### 🔐 Sign In")
        username = st.text_input("Username", key="login_username", placeholder="Enter username")
        password = st.text_input("Password", key="login_password", type="password", placeholder="Enter password")
        if st.button("Sign In", use_container_width=True, key="sign_in_btn"):
            if username and password:
                result = login(username, password)
                if result:
                    st.session_state["token"] = result["access_token"]
                    st.session_state["role"] = result["role"]
                    st.session_state["username"] = result["username"]
                    st.success(f"Welcome, {result['username']}!")
                    st.rerun()
            else:
                st.warning("Please enter credentials.")
        st.markdown("</div>", unsafe_allow_html=True)
        st.markdown("""
        <div style="text-align:center;margin-top:16px;color:#8892a4;font-size:0.85em">
            Default admin: <code style="color:#00d4ff">admin</code> / <code style="color:#00d4ff">ChangeMe123!</code>
        </div>
        """, unsafe_allow_html=True)


def show_home():
    with st.sidebar:
        st.markdown(f"### 🛡️ SentinelAI")
        st.markdown(f"**User:** {st.session_state.get('username', '')}")
        st.markdown(f"**Role:** `{st.session_state.get('role', '')}`")
        st.divider()
        st.markdown("#### Navigation")
        st.page_link("pages/1_Security_Overview.py", label="📊 Security Overview", icon="📊")
        st.page_link("pages/2_Event_Explorer.py", label="🔍 Event Explorer", icon="🔍")
        st.page_link("pages/3_Threat_Alerts.py", label="🚨 Threat Alerts", icon="🚨")
        st.page_link("pages/4_AI_Investigator.py", label="🤖 AI Investigator", icon="🤖")
        st.page_link("pages/5_Reports.py", label="📄 Reports", icon="📄")
        st.page_link("pages/6_Settings.py", label="⚙️ Settings", icon="⚙️")
        st.divider()
        if st.button("🚪 Sign Out", key="signout_btn"):
            st.session_state.clear()
            st.rerun()

    st.markdown("""
    <div style="padding:20px 0">
        <h1>🛡️ SentinelAI</h1>
        <p style="font-size:1.1em">AI-Powered Cybersecurity Threat Detection & Investigation Platform</p>
    </div>
    """, unsafe_allow_html=True)

    col1, col2, col3 = st.columns(3)
    with col1:
        st.markdown("""<div style="background:#1a2035;padding:24px;border-radius:12px;border:1px solid #1e3050;text-align:center">
        <div style="font-size:2em">📊</div>
        <div style="color:#00d4ff;font-weight:600;margin:8px 0">Security Overview</div>
        <div style="color:#8892a4;font-size:0.9em">Live threat dashboard with charts and metrics</div>
        </div>""", unsafe_allow_html=True)
    with col2:
        st.markdown("""<div style="background:#1a2035;padding:24px;border-radius:12px;border:1px solid #1e3050;text-align:center">
        <div style="font-size:2em">🤖</div>
        <div style="color:#00d4ff;font-weight:600;margin:8px 0">AI Investigator</div>
        <div style="color:#8892a4;font-size:0.9em">AI-assisted incident investigation and analysis</div>
        </div>""", unsafe_allow_html=True)
    with col3:
        st.markdown("""<div style="background:#1a2035;padding:24px;border-radius:12px;border:1px solid #1e3050;text-align:center">
        <div style="font-size:2em">🚨</div>
        <div style="color:#00d4ff;font-weight:600;margin:8px 0">Threat Alerts</div>
        <div style="color:#8892a4;font-size:0.9em">Prioritized alerts with risk scores and evidence</div>
        </div>""", unsafe_allow_html=True)

    st.markdown("---")
    st.markdown("**→ Use the sidebar to navigate to any page.**")
    st.markdown("**→ Go to Settings to load demo data if the database is empty.**")


# --- Main ---
if "token" not in st.session_state:
    show_login()
else:
    show_home()
