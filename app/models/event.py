"""SQLAlchemy model — SecurityEvent."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, Float, Integer, String, Text

from app.database import Base


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


class SecurityEvent(Base):
    __tablename__ = "security_events"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    event_id = Column(String(128), unique=True, index=True, nullable=True)
    timestamp = Column(DateTime(timezone=True), index=True, nullable=False)
    source_ip = Column(String(45), index=True, nullable=True)
    username = Column(String(128), index=True, nullable=True)
    event_type = Column(String(64), index=True, nullable=False)
    action = Column(String(128), nullable=True)
    auth_result = Column(String(32), nullable=True)  # success/failure/denied
    hostname = Column(String(255), nullable=True)
    resource = Column(String(512), nullable=True)
    severity = Column(String(16), nullable=True)     # low/medium/high/critical
    raw_message = Column(Text, nullable=True)
    extra_data = Column(Text, nullable=True)         # JSON string
    source_file = Column(String(256), nullable=True)
    ingested_at = Column(DateTime(timezone=True), default=_now_utc, nullable=False)
    is_synthetic = Column(Boolean, default=False, nullable=False)
    anomaly_score = Column(Float, nullable=True)
    is_anomaly = Column(Boolean, default=False, nullable=False)
