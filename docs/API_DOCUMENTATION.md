# SentinelAI — REST API Documentation

Base URL: `http://localhost:8000`  
Interactive OpenAPI Swagger Docs: `http://localhost:8000/docs`  
ReDoc Reference: `http://localhost:8000/redoc`

All endpoints except `/health` and `/auth/login` require an `Authorization: Bearer <TOKEN>` header.

---

## 1. Authentication & Users

### `POST /auth/login`
Authenticates a user and issues a signed JWT access token.
- **Access**: Public
- **Request Body**:
```json
{
  "username": "admin",
  "password": "AdminPassword123!"
}
```
- **Response `200 OK`**:
```json
{
  "access_token": "eyJhbGciOi...",
  "token_type": "bearer",
  "role": "admin",
  "username": "admin"
}
```

### `GET /auth/me`
Retrieves details of the currently authenticated identity.
- **Access**: Authenticated (`admin`, `analyst`, `viewer`)
- **Response `200 OK`**:
```json
{
  "id": "c1f8e...",
  "username": "admin",
  "email": "admin@sentinelai.internal",
  "role": "admin",
  "is_active": true
}
```

### `POST /auth/users`
Creates a new user profile.
- **Access**: `admin` only
- **Request Body**:
```json
{
  "username": "analyst2",
  "email": "analyst2@example.com",
  "password": "SecurePassword123!",
  "role": "analyst"
}
```

---

## 2. Event Ingestion & Search

### `POST /events/ingest`
Ingests an array of security telemetry events.
- **Access**: `analyst`, `admin`
- **Request Body**:
```json
[
  {
    "timestamp": "2026-09-29T12:00:00Z",
    "source_ip": "198.51.100.45",
    "username": "jdoe",
    "event_type": "login_failure",
    "auth_result": "failure",
    "resource": "/api/v1/login"
  }
]
```
- **Response `200 OK`**:
```json
{
  "accepted": 1,
  "rejected": 0,
  "duplicates": 0,
  "errors": [],
  "message": "Ingestion complete"
}
```

### `GET /events`
Queries ingested events with filtering and pagination.
- **Access**: Authenticated (`admin`, `analyst`, `viewer`)
- **Query Parameters**:
  - `skip` (int, default 0)
  - `limit` (int, default 50, max 500)
  - `event_type` (string, optional)
  - `auth_result` (string, optional)
  - `source_ip` (string, optional)
  - `username` (string, optional)
  - `severity` (string, optional)

---

## 3. Alerts & Threat Detection

### `POST /alerts/detect`
Executes detection rules across all ingested events and generates alerts.
- **Access**: `analyst`, `admin`
- **Response `200 OK`**: List of detected alert summaries.

### `GET /alerts`
Retrieves list of threat alerts with filtering.
- **Access**: Authenticated (`admin`, `analyst`, `viewer`)
- **Query Parameters**: `status`, `severity`, `skip`, `limit`

### `PATCH /alerts/{alert_id}/status`
Updates an alert's triage status.
- **Access**: `analyst`, `admin`
- **Request Body**:
```json
{
  "status": "investigating"
}
```

### `POST /alerts/{alert_id}/notes`
Adds an analyst triage or forensic note.
- **Access**: `analyst`, `admin`
- **Request Body**:
```json
{
  "note": "IP 198.51.100.45 confirmed blocked on upstream firewall."
}
```

---

## 4. AI Investigations

### `POST /investigations/{alert_id}/generate`
Generates a structured AI investigation for the given alert.
- **Access**: `analyst`, `admin`
- **Response `200 OK`**:
```json
{
  "id": "inv-001",
  "alert_id": "alt-001",
  "summary": "Multiple failed authentication attempts detected for jdoe...",
  "attack_vector": "Credential Brute-Force",
  "confidence_score": 0.88,
  "recommended_actions": [
    "Verify account status and enforce MFA",
    "Block source IP on network perimeter"
  ],
  "timeline": [...],
  "model_used": "local-security-expert"
}
```

---

## 5. Analytics & System

### `GET /analytics/overview`
High-level SOC operational metrics (event count, alert counts by severity, top attacking IPs).
- **Access**: Authenticated

### `POST /settings/reset-demo`
Clears database telemetry and reloads fresh synthetic demonstration datasets.
- **Access**: `admin` only
