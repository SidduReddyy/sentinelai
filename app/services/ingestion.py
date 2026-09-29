"""
Event ingestion service — handles JSON, CSV, and API submissions.
"""
from __future__ import annotations

import csv
import io
import json
import logging
from typing import Any, Dict, List

from sqlalchemy.orm import Session

from app.models.event import SecurityEvent
from app.schemas.event import EventCreate, IngestionResult
from app.services.normalization import normalize_event

logger = logging.getLogger(__name__)

MAX_EVENTS_PER_BATCH = 10_000
MAX_FILE_BYTES = 50 * 1024 * 1024  # 50 MB


def _persist_event(db: Session, event: EventCreate, source_file: str | None = None) -> str:
    """Persist a validated event to the database, return 'ok' | 'duplicate'."""
    if event.event_id:
        existing = db.query(SecurityEvent).filter(
            SecurityEvent.event_id == event.event_id
        ).first()
        if existing:
            return "duplicate"

    extra_json = json.dumps(event.extra_data) if event.extra_data else None
    db_event = SecurityEvent(
        event_id=event.event_id,
        timestamp=event.timestamp,
        source_ip=event.source_ip,
        username=event.username,
        event_type=event.event_type,
        action=event.action,
        auth_result=event.auth_result,
        hostname=event.hostname,
        resource=event.resource,
        severity=event.severity,
        raw_message=event.raw_message,
        extra_data=extra_json,
        source_file=source_file,
        is_synthetic=event.is_synthetic,
    )
    db.add(db_event)
    return "ok"


def ingest_events(
    db: Session,
    raw_events: List[Dict[str, Any]],
    source_file: str | None = None,
) -> IngestionResult:
    """Normalize and persist a list of raw event dicts."""
    result = IngestionResult()

    if len(raw_events) > MAX_EVENTS_PER_BATCH:
        result.errors.append(f"Batch too large: {len(raw_events)} events (max {MAX_EVENTS_PER_BATCH})")
        result.rejected = len(raw_events)
        result.message = "Batch rejected — too many events"
        return result

    for i, raw in enumerate(raw_events):
        try:
            event = normalize_event(dict(raw))
            status = _persist_event(db, event, source_file)
            if status == "duplicate":
                result.duplicates += 1
            else:
                result.accepted += 1
        except Exception as exc:
            result.rejected += 1
            result.errors.append(f"Row {i}: {str(exc)[:200]}")

    try:
        db.commit()
    except Exception:
        db.rollback()
        raise

    result.message = (
        f"Processed {result.accepted + result.rejected + result.duplicates} events: "
        f"{result.accepted} accepted, {result.rejected} rejected, {result.duplicates} duplicates"
    )
    return result


def ingest_json_bytes(db: Session, data: bytes, source_file: str | None = None) -> IngestionResult:
    """Parse JSON bytes and ingest."""
    if len(data) > MAX_FILE_BYTES:
        r = IngestionResult()
        r.errors.append("File too large")
        return r
    try:
        parsed = json.loads(data.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        r = IngestionResult()
        r.errors.append(f"JSON parse error: {exc}")
        return r
    if isinstance(parsed, dict):
        parsed = [parsed]
    if not isinstance(parsed, list):
        r = IngestionResult()
        r.errors.append("Expected a JSON array or object")
        return r
    return ingest_events(db, parsed, source_file)


def ingest_csv_bytes(db: Session, data: bytes, source_file: str | None = None) -> IngestionResult:
    """Parse CSV bytes and ingest."""
    if len(data) > MAX_FILE_BYTES:
        r = IngestionResult()
        r.errors.append("File too large")
        return r
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        text = data.decode("latin-1")
    reader = csv.DictReader(io.StringIO(text))
    rows: List[Dict[str, Any]] = [dict(row) for row in reader]
    if not rows:
        r = IngestionResult()
        r.errors.append("CSV file is empty or has no data rows")
        return r
    return ingest_events(db, rows, source_file)
