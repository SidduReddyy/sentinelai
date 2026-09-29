"""
Investigation service — coordinates alert evidence retrieval and AI summarization.
"""
from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from app.models.alert import Alert, AlertNote, InvestigationSummary
from app.models.event import SecurityEvent
from app.services.ai_provider import generate_investigation
from app.services.alert_management import save_investigation_summary

logger = logging.getLogger(__name__)


def get_alert_evidence(db: Session, alert_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve an alert and its associated events as a dict."""
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if alert is None:
        return None

    event_ids: List[str] = []
    if alert.event_ids:
        try:
            event_ids = json.loads(alert.event_ids)
        except json.JSONDecodeError:
            pass

    events = db.query(SecurityEvent).filter(SecurityEvent.id.in_(event_ids)).all()
    notes = db.query(AlertNote).filter(AlertNote.alert_id == alert_id).all()

    return {
        "alert": {
            "id": alert.id,
            "rule_id": alert.rule_id,
            "rule_name": alert.rule_name,
            "description": alert.description,
            "severity": alert.severity,
            "risk_score": alert.risk_score,
            "status": alert.status,
            "source_ip": alert.source_ip,
            "username": alert.username,
            "resource": alert.resource,
            "evidence_summary": alert.evidence_summary,
            "recommended_steps": alert.recommended_steps,
        },
        "events": [
            {
                "id": e.id,
                "timestamp": e.timestamp.isoformat() if e.timestamp else None,
                "event_type": e.event_type,
                "auth_result": e.auth_result,
                "source_ip": e.source_ip,
                "username": e.username,
                "resource": e.resource,
            }
            for e in events
        ],
        "notes": [{"author": n.author, "note": n.note, "created_at": n.created_at.isoformat()} for n in notes],
    }


def investigate_alert(
    db: Session,
    alert_id: str,
    requester: str,
) -> Optional[Dict[str, str]]:
    """Generate and persist an investigation summary for an alert."""
    evidence = get_alert_evidence(db, alert_id)
    if evidence is None:
        return None

    result = generate_investigation(evidence["alert"], evidence["events"])
    save_investigation_summary(
        db,
        alert_id=alert_id,
        summary=result["summary"],
        generated_by=result["generated_by"],
        created_by=requester,
    )
    return result
