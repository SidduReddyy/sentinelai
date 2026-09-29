"""Pydantic schemas for AI investigation."""
from __future__ import annotations

from pydantic import BaseModel


class InvestigationRequest(BaseModel):
    alert_id: str


class InvestigationResponse(BaseModel):
    alert_id: str
    generated_by: str
    summary: str
    ai_configured: bool
