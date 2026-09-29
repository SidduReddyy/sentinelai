"""Alerts API — listing, filtering, status updates, notes."""
from __future__ import annotations

import json
import logging
from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.alert import Alert, AlertNote, InvestigationSummary
from app.models.user import User
from app.schemas.alert import AlertOut, AlertUpdate, NoteCreate, NoteOut, InvestigationOut
from app.security.permissions import get_current_user, require_analyst, require_viewer
from app.services import audit
from app.services.alert_management import update_alert_status, add_note
from app.services.detection import run_detection
from app.services.alert_management import create_alerts_from_detections

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/alerts", tags=["Alerts"])


@router.get("", response_model=List[AlertOut])
def list_alerts(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=500),
    status: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    source_ip: Optional[str] = Query(None),
    username: Optional[str] = Query(None),
    since: Optional[datetime] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_viewer),
):
    q = db.query(Alert)
    if status:
        q = q.filter(Alert.status == status)
    if severity:
        q = q.filter(Alert.severity == severity)
    if source_ip:
        q = q.filter(Alert.source_ip == source_ip)
    if username:
        q = q.filter(Alert.username.ilike(f"%{username}%"))
    if since:
        q = q.filter(Alert.created_at >= since)
    return q.order_by(Alert.created_at.desc()).offset(skip).limit(limit).all()


@router.get("/stats")
def alert_stats(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_viewer),
):
    total = db.query(Alert).count()
    by_status = {s: db.query(Alert).filter(Alert.status == s).count() for s in ["new", "investigating", "resolved", "false_positive"]}
    by_severity = {s: db.query(Alert).filter(Alert.severity == s).count() for s in ["critical", "high", "medium", "low"]}
    return {"total": total, "by_status": by_status, "by_severity": by_severity}


@router.get("/{alert_id}", response_model=AlertOut)
def get_alert(
    alert_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_viewer),
):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


@router.patch("/{alert_id}", response_model=AlertOut)
def update_alert(
    alert_id: str,
    body: AlertUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """Update alert status/assignment. Analyst+ required."""
    if body.status:
        from app.schemas.alert import ALLOWED_STATUSES
        if body.status not in ALLOWED_STATUSES:
            raise HTTPException(status_code=422, detail=f"Invalid status: {body.status!r}")
    alert = update_alert_status(
        db,
        alert_id=alert_id,
        new_status=body.status or db.query(Alert).filter(Alert.id == alert_id).first().status,
        actor=current_user.username,
        assigned_to=body.assigned_to,
    )
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    audit.record(
        db, "alert_status_update", actor=current_user.username,
        resource_type="alert", resource_id=alert_id,
        details={"new_status": body.status}
    )
    return alert


@router.post("/{alert_id}/notes", response_model=NoteOut, status_code=201)
def add_alert_note(
    alert_id: str,
    body: NoteCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    note = add_note(db, alert_id=alert_id, author=current_user.username, note_text=body.note)
    if note is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    return note


@router.get("/{alert_id}/notes", response_model=List[NoteOut])
def get_alert_notes(
    alert_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_viewer),
):
    return db.query(AlertNote).filter(AlertNote.alert_id == alert_id).all()


@router.get("/{alert_id}/investigations", response_model=List[InvestigationOut])
def get_alert_investigations(
    alert_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_viewer),
):
    return db.query(InvestigationSummary).filter(InvestigationSummary.alert_id == alert_id).order_by(InvestigationSummary.created_at.desc()).all()


@router.post("/run-detection")
def trigger_detection(
    lookback_seconds: int = Query(86400, ge=60, le=604800),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """Manually trigger the detection engine."""
    detections = run_detection(db, lookback_seconds=lookback_seconds)
    created = create_alerts_from_detections(db, detections)
    audit.record(db, "detection_run", actor=current_user.username, details={"detections": len(detections), "new_alerts": created})
    return {"detections_found": len(detections), "new_alerts_created": created}
