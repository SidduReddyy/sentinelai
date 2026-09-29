# 🛡️ SentinelAI — AI-Powered Cybersecurity Threat Detection & Investigation Platform

[![CI/CD Pipeline](https://img.shields.io/badge/CI%2FCD-GitHub_Actions-2088FF?logo=github-actions&logoColor=white)](.github/workflows/tests.yml)
[![FastAPI](https://img.shields.io/badge/Backend-FastAPI-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![Streamlit](https://img.shields.io/badge/Frontend-Streamlit-FF4B4B?logo=streamlit&logoColor=white)](https://streamlit.io)
[![Python 3.11+](https://img.shields.io/badge/Python-3.11%20%7C%203.12%20%7C%203.13-3776AB?logo=python&logoColor=white)](https://python.org)
[![Tests](https://img.shields.io/badge/Tests-61%20Passed-brightgreen)](tests/)
[![Security](https://img.shields.io/badge/Security-RBAC%20%2B%20JWT%20%2B%20Bcrypt-red)](docs/ARCHITECTURE.md)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

SentinelAI is an end-to-end, enterprise-ready cybersecurity threat detection, triage, and incident response platform. Combining rule-based temporal sliding windows, unsupervised machine learning (Isolation Forest), and an automated AI forensic investigator, SentinelAI empowers SOC teams to detect, triage, and remediate cyber incidents in seconds.

---

## 🌟 Key Capabilities

- **⚡ High-Throughput Telemetry Ingestion**: Batch JSON, CSV upload, and streaming REST API ingestion with strict schema validation, UTC timestamp canonicalization, and deduplication.
- **🎯 Multi-Rule Correlation Engine**: Heuristic correlation across temporal sliding windows:
  - `RULE_A_BRUTE_FORCE`: Rapid authentication failure clusters.
  - `RULE_B_SUSPICIOUS_ACTIVITY`: Multi-failure sequences followed by unexpected success (password spraying / credential compromise).
  - `RULE_C_ACCESS_DENIED`: Repeated 403 / authorization rejections against protected resources.
  - `RULE_D_EVENT_BURST`: High-frequency origin request surges and scanning activity.
- **🤖 Machine Learning Anomaly Detection**: Unsupervised Scikit-Learn `IsolationForest` behavioral baseline model identifying multi-dimensional statistical deviations.
- **🧠 AI Investigation Copilot**: Automatically synthesizes security alerts into structured forensic reports, identifying root causes, MITRE ATT&CK techniques, timeline reconstruction, and containment action plans. Works out-of-the-box with Anthropic Claude, OpenAI, Gemini, or a built-in zero-dependency local deterministic security engine.
- **🔒 Role-Based Access Control (RBAC)**: Fine-grained permissions for `admin`, `analyst`, and `viewer` roles secured with native bcrypt password hashing and HMAC-SHA256 JWT tokens.
- **📊 Real-Time SOC Operations Console**: Premium dark-mode Streamlit dashboard with Plotly charts, live threat severity donuts, incident triage queues, analyst notebook, and exportable reports (CSV & JSON).
- **📋 Immutable Audit Trail**: All authentication events, alert modifications, status transitions, and administrative actions are logged in tamper-evident audit tables.

---

## 🏛️ System Architecture

```
                                +-----------------------------+
                                |    Log Sources / Sensors    |
                                +-----------------------------+
                                               |
                                     JSON / CSV / REST API
                                               v
+------------------------------------------------------------------------------------------+
|                                    SentinelAI Core API                                   |
|                                                                                          |
|   +-----------------------+     +------------------------+     +---------------------+   |
|   |  Ingestion & Parsing  | --> | Normalization & Dedup  | --> | Data Redaction      |   |
|   +-----------------------+     +------------------------+     +---------------------+   |
|                                                                             |            |
|                                                                             v            |
|   +----------------------------------------------------------------------------------+   |
|   |                              Detection Pipeline                                  |   |
|   |   - Rule A: Brute Force                 - Rule D: Velocity Bursts                |   |
|   |   - Rule B: Fail-Then-Succeed           - Rule E: ML Isolation Forest            |   |
|   |   - Rule C: Access Denied Clusters                                               |   |
|   +----------------------------------------------------------------------------------+   |
|                                         |                                                |
|                                         v                                                |
|   +-----------------------+     +------------------------+     +---------------------+   |
|   | Alert State Machine   | <-> | AI Investigation Agent | <-> | Tamper Audit Log    |   |
|   +-----------------------+     +------------------------+     +---------------------+   |
+------------------------------------------------------------------------------------------+
                               |                                 ^
                               v                                 |
           +----------------------------------------+            |
           |      SQLite / PostgreSQL Storage       |            |
           +----------------------------------------+            |
                               |                                 |
                               +------------+                    |
                                            v                    v
                               +----------------------------------------+
                               |     Streamlit SOC Management Console   |
                               +----------------------------------------+
```

---

## 🚀 Quickstart Guide

### 1. Prerequisites
- Python 3.11+
- Virtual environment (`venv`) or Docker

### 2. Local Setup

```bash
# Clone the repository
git clone https://github.com/SidduReddyy/sentinelai.git
cd sentinelai

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Seed demonstration security datasets and run detections
python scripts/seed_demo_data.py
```

### 3. Run the Services

**Terminal 1 — Start FastAPI Backend:**
```bash
source venv/bin/activate
uvicorn app.main:app --reload --port 8000
```
Backend API will be available at: `http://localhost:8000` (Swagger UI at `/docs`)

**Terminal 2 — Start Streamlit SOC Console:**
```bash
source venv/bin/activate
streamlit run dashboard/Home.py --server.port 8501
```
SOC Console will open automatically at: `http://localhost:8501`

---

## 👥 Default Demo Credentials

The platform is pre-seeded with three operational user profiles:

| Role | Username | Password | Permissions |
| :--- | :--- | :--- | :--- |
| **Admin** | `admin` | `AdminPassword123!` | Full control, user administration, demo data reset |
| **Analyst** | `analyst` | `AnalystPassword123!` | Ingest telemetry, run detections, triage alerts, run AI investigations |
| **Viewer** | `viewer` | `ViewerPassword123!` | Read-only access to overview, telemetry search, and reports |

---

## 🐳 Docker Deployment

To launch the complete platform using Docker Compose:

```bash
# Build and run containers
docker-compose up --build
```

- **FastAPI Backend**: `http://localhost:8000`
- **Streamlit SOC Console**: `http://localhost:8501`

---

## 🧪 Automated Testing

SentinelAI includes an extensive test suite covering unit tests, integration tests, detection engines, security RBAC, and AI hallucination guardrails:

```bash
# Run the test suite
pytest tests/ -v
```

**Test Suite Coverage Summary:**
- `tests/test_health.py`: Application startup and database readiness.
- `tests/test_auth.py`: JWT generation, password hashing, and user creation.
- `tests/test_authorization.py`: Multi-role RBAC enforcement and secret leakage prevention.
- `tests/test_ingestion.py`: Telemetry ingestion, error handling, batching, and deduplication.
- `tests/test_detection.py`: Sliding window correlation rules, thresholds, and evidence isolation.
- `tests/test_alerts.py`: Alert state transitions, notes, and analyst workflows.
- `tests/test_investigation.py`: AI fallback generation, zero-hallucination checks, and prompt injection defense.

**Result**: `61 passed in 42.19s` ✅

---

## 📖 Documentation Directory

- [System Architecture](docs/ARCHITECTURE.md)
- [REST API Reference](docs/API_DOCUMENTATION.md)
- [Threat Detection Rules](docs/DETECTION_RULES.md)

---

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
