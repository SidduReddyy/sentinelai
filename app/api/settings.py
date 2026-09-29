"""Settings API — safe config exposure, demo data management."""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.config import get_settings
from app.database import get_db
from app.models.alert import Alert, AlertNote, InvestigationSummary
from app.models.audit import AuditLog
from app.models.event import SecurityEvent
from app.models.user import User
from app.security.permissions import require_admin, require_viewer
from app.services import audit

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/settings", tags=["Settings"])


@router.get("/config")
def get_config(current_user: User = Depends(require_viewer)):
    """Return safe configuration — no secrets."""
    settings = get_settings()
    return {
        "ai_provider": settings.ai_provider,
        "ai_configured": settings.ai_configured,
        "brute_force_threshold": settings.brute_force_threshold,
        "brute_force_window_seconds": settings.brute_force_window_seconds,
        "access_denied_threshold": settings.access_denied_threshold,
        "access_denied_window_seconds": settings.access_denied_window_seconds,
        "event_burst_threshold": settings.event_burst_threshold,
        "event_burst_window_seconds": settings.event_burst_window_seconds,
    }


@router.delete("/demo-data")
def reset_demo_data(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    """Admin-only: delete all synthetic demonstration data."""
    deleted_events = db.query(SecurityEvent).filter(SecurityEvent.is_synthetic == True).delete()
    # Clean orphaned alerts
    db.query(Alert).delete()
    db.query(AlertNote).delete()
    db.query(InvestigationSummary).delete()
    db.commit()
    audit.record(db, "demo_data_reset", actor=current_user.username, details={"deleted_events": deleted_events})
    return {"message": f"Deleted {deleted_events} synthetic events and all alerts.", "deleted_events": deleted_events}
