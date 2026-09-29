"""
Audit logging service — records security-relevant actions to the database.
"""
from __future__ import annotations

import json
import logging
from typing import Any, Dict, Optional

from sqlalchemy.orm import Session

from app.models.audit import AuditLog

logger = logging.getLogger(__name__)


def record(
    db: Session,
    action: str,
    actor: Optional[str] = "system",
    resource_type: Optional[str] = None,
    resource_id: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
    ip_address: Optional[str] = None,
    result: str = "success",
) -> None:
    """Write an audit record to the database."""
    try:
        entry = AuditLog(
            actor=actor,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            details=json.dumps(details) if details else None,
            ip_address=ip_address,
            result=result,
        )
        db.add(entry)
        db.commit()
    except Exception:
        db.rollback()
        logger.exception("Failed to write audit record for action=%s actor=%s", action, actor)
