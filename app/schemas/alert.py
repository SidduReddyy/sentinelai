"""Pydantic schemas for Alert and Notes."""
from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, Field

ALLOWED_STATUSES = {"new", "investigating", "resolved", "false_positive"}


class AlertOut(BaseModel):
    id: str
    rule_id: str
    rule_name: str
    description: Optional[str]
    severity: str
    risk_score: float
    status: str
    source_ip: Optional[str]
    username: Optional[str]
    resource: Optional[str]
    event_ids: Optional[str]
    evidence_summary: Optional[str]
    recommended_steps: Optional[str]
    assigned_to: Optional[str]
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class AlertUpdate(BaseModel):
    status: Optional[str] = Field(None, max_length=32)
    assigned_to: Optional[str] = Field(None, max_length=128)

    def validate_status(self) -> None:
        if self.status and self.status not in ALLOWED_STATUSES:
            raise ValueError(f"Invalid status: {self.status!r}")


class NoteCreate(BaseModel):
    note: str = Field(..., min_length=1, max_length=4096)


class NoteOut(BaseModel):
    id: str
    alert_id: str
    author: str
    note: str
    created_at: datetime

    model_config = {"from_attributes": True}


class InvestigationOut(BaseModel):
    id: str
    alert_id: str
    generated_by: str
    summary: str
    created_at: datetime
    created_by: Optional[str]

    model_config = {"from_attributes": True}
