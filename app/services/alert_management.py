"""
Alert management service — creates, deduplicates, and updates alerts.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import List, Optional

from sqlalchemy.orm import Session

from app.models.alert import Alert, AlertNote, InvestigationSummary
from app.services.detection import DetectionResult
from app.services.risk_scoring import compute_risk_score

logger = logging.getLogger(__name__)


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def create_alerts_from_detections(
    db: Session,
    detections: List[DetectionResult],
) -> int:
    """Persist new alerts from detection results. Returns count of new alerts created."""
    created = 0
    for det in detections:
        # Deduplication — skip if same dedup_key already exists
        existing = db.query(Alert).filter(Alert.dedup_key == det.dedup_key).first()
        if existing:
            logger.debug("Dedup: skipping alert for dedup_key=%s", det.dedup_key)
            continue

        risk_score = compute_risk_score(
            severity=det.severity,
            rule_id=det.rule_id,
            event_count=len(det.event_ids),
        )

        alert = Alert(
            rule_id=det.rule_id,
            rule_name=det.rule_name,
            description=det.description,
            severity=det.severity,
            risk_score=risk_score,
            status="new",
            source_ip=det.source_ip,
            username=det.username,
            resource=det.resource,
            event_ids=json.dumps(det.event_ids),
            evidence_summary=det.evidence_summary,
            recommended_steps=det.recommended_steps,
            dedup_key=det.dedup_key,
        )
        db.add(alert)
        created += 1

    if created > 0:
        try:
            db.commit()
        except Exception:
            db.rollback()
            raise
    logger.info("Alert management: created %d new alerts", created)
    return created


def update_alert_status(
    db: Session,
    alert_id: str,
    new_status: str,
    actor: str,
    assigned_to: Optional[str] = None,
) -> Optional[Alert]:
    """Update alert status and optionally assign it."""
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if alert is None:
        return None
    alert.status = new_status
    alert.updated_at = _now_utc()
    if assigned_to is not None:
        alert.assigned_to = assigned_to
    if new_status == "resolved":
        alert.resolved_at = _now_utc()
    db.commit()
    db.refresh(alert)
    return alert


def add_note(
    db: Session,
    alert_id: str,
    author: str,
    note_text: str,
) -> Optional[AlertNote]:
    """Add an investigation note to an alert."""
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if alert is None:
        return None
    note = AlertNote(alert_id=alert_id, author=author, note=note_text)
    db.add(note)
    db.commit()
    db.refresh(note)
    return note


def save_investigation_summary(
    db: Session,
    alert_id: str,
    summary: str,
    generated_by: str,
    created_by: Optional[str] = None,
) -> InvestigationSummary:
    inv = InvestigationSummary(
        alert_id=alert_id,
        generated_by=generated_by,
        summary=summary,
        created_by=created_by,
    )
    db.add(inv)
    db.commit()
    db.refresh(inv)
    return inv
