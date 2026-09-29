"""Events API — ingestion, listing, filtering, detail."""
from __future__ import annotations

import logging
from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Body, Depends, File, HTTPException, Query, UploadFile, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.event import SecurityEvent
from app.models.user import User
from app.schemas.event import EventCreate, EventOut, IngestionResult
from app.security.permissions import get_current_user, require_analyst, require_viewer
from app.services.ingestion import ingest_csv_bytes, ingest_events, ingest_json_bytes

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/events", tags=["Events"])


@router.post("/ingest", response_model=IngestionResult, status_code=200)
def ingest_api(
    events: List[Dict[str, Any]] = Body(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """Ingest events via API (analyst+ required)."""
    return ingest_events(db, events, source_file="api")


@router.post("/upload/json", response_model=IngestionResult)
async def upload_json(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    data = await file.read()
    return ingest_json_bytes(db, data, source_file=file.filename)


@router.post("/upload/csv", response_model=IngestionResult)
async def upload_csv(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    data = await file.read()
    return ingest_csv_bytes(db, data, source_file=file.filename)


@router.get("", response_model=List[EventOut])
def list_events(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=500),
    event_type: Optional[str] = Query(None),
    auth_result: Optional[str] = Query(None),
    source_ip: Optional[str] = Query(None),
    username: Optional[str] = Query(None),
    since: Optional[datetime] = Query(None),
    until: Optional[datetime] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_viewer),
):
    q = db.query(SecurityEvent)
    if event_type:
        q = q.filter(SecurityEvent.event_type == event_type)
    if auth_result:
        q = q.filter(SecurityEvent.auth_result == auth_result)
    if source_ip:
        q = q.filter(SecurityEvent.source_ip == source_ip)
    if username:
        q = q.filter(SecurityEvent.username.ilike(f"%{username}%"))
    if since:
        q = q.filter(SecurityEvent.timestamp >= since)
    if until:
        q = q.filter(SecurityEvent.timestamp <= until)
    return q.order_by(SecurityEvent.timestamp.desc()).offset(skip).limit(limit).all()


@router.get("/count")
def count_events(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_viewer),
):
    return {"count": db.query(SecurityEvent).count()}


@router.get("/{event_id}", response_model=EventOut)
def get_event(
    event_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_viewer),
):
    evt = db.query(SecurityEvent).filter(SecurityEvent.id == event_id).first()
    if evt is None:
        raise HTTPException(status_code=404, detail="Event not found")
    return evt
