"""Shared UI components and styling."""
from __future__ import annotations

import streamlit as st

SEVERITY_COLORS = {
    "critical": "#FF4444",
    "high": "#FF8C00",
    "medium": "#FFD700",
    "low": "#00C8C8",
}

STATUS_COLORS = {
    "new": "#00BFFF",
    "investigating": "#FFD700",
    "resolved": "#00FF88",
    "false_positive": "#808080",
}


def severity_badge(severity: str) -> str:
    color = SEVERITY_COLORS.get(severity.lower() if severity else "low", "#808080")
    return f'<span style="background:{color};color:#000;padding:2px 8px;border-radius:4px;font-size:0.8em;font-weight:bold">{severity.upper() if severity else "N/A"}</span>'


def status_badge(status: str) -> str:
    color = STATUS_COLORS.get(status.lower() if status else "new", "#808080")
    label = status.replace("_", " ").title() if status else "New"
    return f'<span style="background:{color};color:#000;padding:2px 8px;border-radius:4px;font-size:0.8em;font-weight:bold">{label}</span>'


def metric_card(label: str, value: str | int, delta: str = "", color: str = "#00BFFF") -> None:
    st.markdown(
        f"""
        <div style="background:#1a2035;border-left:4px solid {color};padding:16px 20px;border-radius:8px;margin:4px 0">
            <div style="color:#8892a4;font-size:0.8em;text-transform:uppercase;letter-spacing:1px">{label}</div>
            <div style="color:{color};font-size:2em;font-weight:700;margin:4px 0">{value}</div>
            {f'<div style="color:#8892a4;font-size:0.8em">{delta}</div>' if delta else ''}
        </div>
        """,
        unsafe_allow_html=True,
    )


def section_header(title: str, subtitle: str = "") -> None:
    st.markdown(f"## {title}")
    if subtitle:
        st.markdown(f"<p style='color:#8892a4;margin-top:-12px'>{subtitle}</p>", unsafe_allow_html=True)


def info_banner(text: str, kind: str = "info") -> None:
    colors = {"info": "#00BFFF", "warning": "#FFD700", "error": "#FF4444", "success": "#00FF88"}
    color = colors.get(kind, "#00BFFF")
    st.markdown(
        f'<div style="border-left:4px solid {color};background:#1a2035;padding:10px 16px;border-radius:0 8px 8px 0;margin:8px 0">{text}</div>',
        unsafe_allow_html=True,
    )


def apply_global_styles() -> None:
    st.markdown("""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');

    html, body, [class*="css"] {
        font-family: 'Inter', -apple-system, sans-serif !important;
    }

    .stApp {
        background: linear-gradient(135deg, #0a0f1e 0%, #0d1628 100%);
    }

    .stSidebar {
        background: #0d1628 !important;
        border-right: 1px solid #1e3050 !important;
    }

    .stSidebar .stMarkdown h1, .stSidebar .stMarkdown h2, .stSidebar .stMarkdown h3 {
        color: #00d4ff !important;
    }

    h1 { color: #00d4ff !important; font-weight: 700 !important; }
    h2 { color: #e2e8f0 !important; font-weight: 600 !important; }
    h3 { color: #cbd5e0 !important; }
    p, li { color: #a0aec0 !important; }

    .stDataFrame { background: #1a2035 !important; border-radius: 8px !important; }
    .stDataFrame th { background: #0d1628 !important; color: #00d4ff !important; }

    .stButton > button {
        background: linear-gradient(135deg, #0056b3, #007bff) !important;
        color: white !important;
        border: none !important;
        border-radius: 6px !important;
        font-weight: 500 !important;
        transition: all 0.2s ease !important;
    }
    .stButton > button:hover {
        transform: translateY(-1px) !important;
        box-shadow: 0 4px 12px rgba(0, 123, 255, 0.4) !important;
    }

    .stSelectbox, .stTextInput, .stTextArea {
        background: #1a2035 !important;
    }

    div[data-testid="stMetricValue"] {
        color: #00d4ff !important;
        font-weight: 700 !important;
    }

    .stAlert { border-radius: 8px !important; }

    code, pre {
        font-family: 'JetBrains Mono', monospace !important;
        background: #1a2035 !important;
        color: #00ff88 !important;
    }

    hr { border-color: #1e3050 !important; }

    .stTabs [data-baseweb="tab-list"] { background: #1a2035 !important; border-radius: 8px; }
    .stTabs [data-baseweb="tab"] { color: #8892a4 !important; }
    .stTabs [aria-selected="true"] { color: #00d4ff !important; }

    footer { visibility: hidden; }
    #MainMenu { visibility: hidden; }
    </style>
    """, unsafe_allow_html=True)
