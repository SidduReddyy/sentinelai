"""SQLAlchemy model — Alert and AlertNote."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, Float, Integer, String, Text

from app.database import Base


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    rule_id = Column(String(64), index=True, nullable=False)
    rule_name = Column(String(128), nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(String(16), index=True, nullable=False)
    risk_score = Column(Float, default=0.0, nullable=False)
    status = Column(String(32), index=True, default="new", nullable=False)
    source_ip = Column(String(45), index=True, nullable=True)
    username = Column(String(128), index=True, nullable=True)
    resource = Column(String(512), nullable=True)
    event_ids = Column(Text, nullable=True)          # JSON list of event IDs
    evidence_summary = Column(Text, nullable=True)
    recommended_steps = Column(Text, nullable=True)
    assigned_to = Column(String(128), nullable=True)
    created_at = Column(DateTime(timezone=True), default=_now_utc, index=True)
    updated_at = Column(DateTime(timezone=True), default=_now_utc, onupdate=_now_utc)
    resolved_at = Column(DateTime(timezone=True), nullable=True)
    dedup_key = Column(String(256), index=True, nullable=True)  # for deduplication


class AlertNote(Base):
    __tablename__ = "alert_notes"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    alert_id = Column(String(36), index=True, nullable=False)
    author = Column(String(128), nullable=False)
    note = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), default=_now_utc)


class InvestigationSummary(Base):
    __tablename__ = "investigation_summaries"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    alert_id = Column(String(36), index=True, nullable=False)
    generated_by = Column(String(32), nullable=False)  # "local_fallback" | "llm:<provider>"
    summary = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), default=_now_utc)
    created_by = Column(String(128), nullable=True)
