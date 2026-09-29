# SentinelAI — System Architecture

SentinelAI is an enterprise-grade AI-powered cybersecurity threat detection, alert management, and incident investigation platform. It provides end-to-end security operations center (SOC) capabilities from raw telemetry ingestion to automated AI-assisted investigation and case disposition.

---

## 1. System Overview Diagram

```
+---------------------------------------------------------------------------------+
|                                SentinelAI Platform                              |
+---------------------------------------------------------------------------------+
                                      |
       +------------------------------+------------------------------+
       |                                                             |
       v                                                             v
+-------------------------------+                     +-------------------------------+
|      FastAPI REST API         |                     |      Streamlit SOC Console    |
|      (Port 8000)              | <------------------ |      (Port 8501)              |
+-------------------------------+    REST API + JWT   +-------------------------------+
       |                                                             |
       +---> Authentication & RBAC (Admin / Analyst / Viewer)        +---> Security Overview
       +---> Event Ingestion & Normalization Engine                  +---> Event Explorer
       +---> Correlation & Rule-Based Detection Engine               +---> Threat Alerts
       +---> Isolation Forest ML Anomaly Detection                   +---> AI Investigator
       +---> LLM & Local Fallback AI Investigation Engine            +---> Compliance Reports
       +---> Tamper-Evident Audit Logging                            +---> Settings & Demo Control
       |
       v
+---------------------------------------------------------------+
|                      SQLite / PostgreSQL                      |
|  - Users (bcrypt hashed)                                      |
|  - SecurityEvents (normalized, indexed)                       |
|  - Alerts (deduplicated, triage lifecycle, notes)             |
|  - Investigations (AI generated, grounded in evidence)         |
|  - AuditLogs (actor, action, resource, IP)                    |
+---------------------------------------------------------------+
```

---

## 2. Core Subsystems

### 2.1 Ingestion & Telemetry Processing
- **Multi-Format Ingestion**: Supports batch JSON, single events, CSV imports, and API payload streaming.
- **Data Normalization**: Converts heterogeneous timestamps to timezone-aware UTC ISO8601 strings and validates IP addresses, event types, auth results, and severities.
- **Deduplication**: SHA-256 fingerprinting and event ID caching prevent double-counting telemetry during bulk re-ingestion.
- **Sanitization & Redaction**: Sensitive attributes such as credentials, access tokens, and sensitive internal paths are scrubbed or masked prior to database persistence and prompt construction.

### 2.2 Detection Engine
The detection engine operates both in real-time on ingested event batches and periodically across historic sliding windows:
1. **Rule A — Brute Force Attacks**: Aggregates authentication failures per source IP and username over configurable sliding windows (default: >= 5 failures in 300 seconds).
2. **Rule B — Suspicious Account Activity**: Detects sequences where multiple failed authentication attempts are immediately followed by a successful login, signaling potential password spraying or credential compromise.
3. **Rule C — Access Denied Clusters**: Evaluates repeated HTTP/RPC 403 or privilege denied events against protected resources within a defined timeframe.
4. **Rule D — Event Burst / Spike Detection**: Flags abnormal velocity anomalies exceeding baseline request thresholds (e.g., > 50 events in 60 seconds from a single origin).
5. **Rule E — Unsupervised Machine Learning**: Scikit-Learn `IsolationForest` model trained on hourly frequency and failure distributions to detect statistical outliers without explicit rules.

### 2.3 Alert Lifecycle & Triage Management
- Alerts transition through standard SOC states: `open` -> `investigating` -> `resolved` / `false_positive`.
- Deduplication keys (`dedup_key`) group identical temporal incident clusters to prevent alert fatigue.
- Analysts and administrators can append timestamped investigation notes and adjust alert statuses with full RBAC protection.

### 2.4 AI Investigation Service
- **Provider Support**: Seamless support for Anthropic Claude, OpenAI GPT-4o, and Gemini models.
- **Zero-Dependency Local Fallback**: When external LLM API keys are not provided or network is offline, a deterministic security expert fallback generates complete investigation reports.
- **Grounded Factuality**: Prompts and fallback generators only cite ingested event IDs and telemetry attributes. Zero hallucinated indicator enrichment.
- **Prompt Injection Defense**: Raw event values are strictly treated as untrusted data inputs and wrapped in sandboxed JSON schema delimiters.

### 2.5 Security, RBAC & Auditability
- **Role-Based Access Control**:
  - `admin`: Full system control, user provisioning, config management, demo reset.
  - `analyst`: Ingest events, trigger detections, manage alerts, write notes, generate AI investigations.
  - `viewer`: Read-only access to overview dashboards, reports, and search queries.
- **Token Security**: Stateless JWT (JSON Web Tokens) signed using HMAC-SHA256 with expiration enforcement.
- **Tamper-Evident Audit Logging**: System actions, logins, status changes, and administrative actions are logged with actor, timestamp, IP, and event payloads.
