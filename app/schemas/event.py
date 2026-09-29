"""Pydantic schemas for SecurityEvent."""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator
import ipaddress


ALLOWED_EVENT_TYPES = {
    "login", "logout", "login_failure", "access_denied", "privilege_escalation",
    "file_access", "network_connection", "configuration_change", "user_created",
    "user_deleted", "password_change", "data_export", "api_call", "scan_detected",
    "malware_detected", "system_event", "unknown",
}

ALLOWED_AUTH_RESULTS = {"success", "failure", "denied", "unknown", ""}
ALLOWED_SEVERITIES = {"low", "medium", "high", "critical", ""}


class EventCreate(BaseModel):
    event_id: Optional[str] = Field(None, max_length=128)
    timestamp: datetime
    source_ip: Optional[str] = Field(None, max_length=45)
    username: Optional[str] = Field(None, max_length=128)
    event_type: str = Field(..., max_length=64)
    action: Optional[str] = Field(None, max_length=128)
    auth_result: Optional[str] = Field(None, max_length=32)
    hostname: Optional[str] = Field(None, max_length=255)
    resource: Optional[str] = Field(None, max_length=512)
    severity: Optional[str] = Field(None, max_length=16)
    raw_message: Optional[str] = Field(None, max_length=4096)
    extra_data: Optional[Dict[str, Any]] = None
    is_synthetic: bool = False

    @field_validator("source_ip")
    @classmethod
    def validate_ip(cls, v: Optional[str]) -> Optional[str]:
        if v is None or v == "":
            return None
        try:
            ipaddress.ip_address(v)
        except ValueError:
            raise ValueError(f"Invalid IP address: {v!r}")
        return v

    @field_validator("event_type")
    @classmethod
    def validate_event_type(cls, v: str) -> str:
        v = v.lower().strip()
        if v not in ALLOWED_EVENT_TYPES:
            return "unknown"
        return v

    @field_validator("auth_result")
    @classmethod
    def validate_auth_result(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        v = v.lower().strip()
        return v if v in ALLOWED_AUTH_RESULTS else "unknown"

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        v = v.lower().strip()
        return v if v in ALLOWED_SEVERITIES else None


class EventOut(BaseModel):
    id: str
    event_id: Optional[str]
    timestamp: datetime
    source_ip: Optional[str]
    username: Optional[str]
    event_type: str
    action: Optional[str]
    auth_result: Optional[str]
    hostname: Optional[str]
    resource: Optional[str]
    severity: Optional[str]
    raw_message: Optional[str]
    ingested_at: datetime
    is_synthetic: bool
    anomaly_score: Optional[float]
    is_anomaly: bool

    model_config = {"from_attributes": True}


class IngestionResult(BaseModel):
    accepted: int = 0
    rejected: int = 0
    duplicates: int = 0
    errors: List[str] = []
    message: str = ""
