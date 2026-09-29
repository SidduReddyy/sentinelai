"""SQLAlchemy model — AuditLog."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, String, Text

from app.database import Base


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    timestamp = Column(DateTime(timezone=True), default=_now_utc, index=True)
    actor = Column(String(128), index=True, nullable=True)   # username or "system"
    action = Column(String(128), index=True, nullable=False)
    resource_type = Column(String(64), nullable=True)
    resource_id = Column(String(128), nullable=True)
    details = Column(Text, nullable=True)                    # JSON
    ip_address = Column(String(45), nullable=True)
    result = Column(String(16), nullable=False, default="success")  # success|failure
