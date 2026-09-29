# SentinelAI — Threat Detection Rules

SentinelAI implements a multi-layer threat detection engine combining deterministic heuristic correlation, behavioral temporal sliding windows, and machine learning anomaly detection.

---

## Rule Summary Matrix

| Rule ID | Rule Name | MITRE ATT&CK | Default Severity | Window / Threshold |
| :--- | :--- | :--- | :--- | :--- |
| `RULE_A_BRUTE_FORCE` | Repeated Authentication Failures | T1110.001 (Password Guessing) | `HIGH` | >= 5 failures in 300s per (IP, User) |
| `RULE_B_SUSPICIOUS_ACTIVITY` | Suspicious Account Activity (Fail-Then-Succeed) | T1110 (Brute Force / Credential Stuffing) | `CRITICAL` | >= 3 failures followed by success in 600s |
| `RULE_C_ACCESS_DENIED` | Repeated Access Denied | T1078 (Valid Accounts), T1069 | `MEDIUM` | >= 10 denials in 300s per (IP, Resource) |
| `RULE_D_EVENT_BURST` | Event Velocity Spike / Burst | T1499 (Endpoint Denial of Service) | `MEDIUM` | >= 50 events in 60s per Source IP |
| `RULE_E_ML_ANOMALY` | Isolation Forest Behavioral Anomaly | T1087, T1020 | `MEDIUM` | Outlier score (contamination: 5%) |

---

## Detailed Rule Specifications

### 1. `RULE_A_BRUTE_FORCE` — Repeated Authentication Failures
- **Description**: Identifies automated or dictionary-based password attacks targeting individual user accounts from specific network origins.
- **Trigger Conditions**:
  - `event_type` in `["login", "login_failure"]`
  - `auth_result == "failure"`
  - Count of matching events >= 5 within a sliding window of 300 seconds for the same `(source_ip, username)` tuple.
- **Forensic Evidence Included**: List of event IDs, source IP, username, timestamps of first and last failures.
- **Recommended Remediation**:
  1. Inspect network perimeter firewall rules to block abusive source IP.
  2. Temporarily lock the targeted account or trigger an out-of-band password reset.
  3. Verify Multi-Factor Authentication (MFA) enforcement on the identity provider.

---

### 2. `RULE_B_SUSPICIOUS_ACTIVITY` — Fail-Then-Succeed Pattern
- **Description**: Catches successful logins that occur immediately following multiple failures. This signature strongly correlates with successful brute-force attempts, dictionary exhaustion, or unauthorized credential possession.
- **Trigger Conditions**:
  - Sequence of >= 3 `auth_result == "failure"` events within 600 seconds.
  - Followed by `auth_result == "success"` for the same user account.
- **Forensic Evidence Included**: All preceding failure event IDs, the successful login event ID, source IPs, and timeline.
- **Recommended Remediation**:
  1. Contact the employee/user immediately to confirm authorization of the login session.
  2. Invalidate active user sessions and refresh tokens.
  3. Inspect subsequent API and resource access logs during the active session.

---

### 3. `RULE_C_ACCESS_DENIED` — Repeated Access Denied
- **Description**: Detects repeated unauthorized authorization requests against protected API routes, sensitive databases, or endpoints. Indicates enumeration or privilege escalation attempts.
- **Trigger Conditions**:
  - `auth_result == "denied"` or `event_type == "access_denied"`.
  - Count >= 10 events within 300 seconds for a `(source_ip, resource)` pair.
- **Recommended Remediation**:
  1. Validate access control list (ACL) and role policies for the target endpoint.
  2. Determine if the source is an internal automated service with misconfigured credentials.
  3. Block external origins probing internal admin resources.

---

### 4. `RULE_D_EVENT_BURST` — High Velocity Event Burst
- **Description**: Monitors anomalous telemetry surges from a single IP address, potentially indicating web scraping, vulnerability scanning, automated crawling, or resource exhaustion attacks.
- **Trigger Conditions**:
  - Count of any events >= 50 within 60 seconds from the same `source_ip`.
- **Recommended Remediation**:
  1. Apply rate-limiting (e.g., token bucket / leaky bucket) at the API gateway.
  2. Inspect HTTP User-Agent strings and payload bodies for scanner signatures (e.g., Nikto, sqlmap, Nuclei).

---

### 5. `RULE_E_ML_ANOMALY` — Unsupervised Isolation Forest
- **Description**: Leverages machine learning (`sklearn.ensemble.IsolationForest`) to evaluate multi-dimensional event distributions (request frequency, failure ratio, unique resources accessed per hour) to detect statistical anomalies without predefined thresholds.
- **Trigger Conditions**:
  - Feature vector falls within the 5th percentile anomaly decision function boundary.
