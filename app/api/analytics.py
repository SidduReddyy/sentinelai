"""Analytics API — dashboard stats, trend data."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.alert import Alert
from app.models.event import SecurityEvent
from app.models.user import User
from app.security.permissions import require_viewer

router = APIRouter(prefix="/analytics", tags=["Analytics"])


def _utc_now():
    return datetime.now(timezone.utc)


@router.get("/summary")
def dashboard_summary(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_viewer),
) -> Dict[str, Any]:
    total_events = db.query(SecurityEvent).count()
    total_alerts = db.query(Alert).count()
    open_alerts = db.query(Alert).filter(Alert.status.in_(["new", "investigating"])).count()
    high_severity = db.query(Alert).filter(Alert.severity.in_(["high", "critical"]), Alert.status != "resolved").count()
    last_event = db.query(func.max(SecurityEvent.ingested_at)).scalar()

    return {
        "total_events": total_events,
        "total_alerts": total_alerts,
        "open_alerts": open_alerts,
        "high_severity_alerts": high_severity,
        "last_ingestion": last_event.isoformat() if last_event else None,
    }


@router.get("/event-timeline")
def event_timeline(
    days: int = Query(7, ge=1, le=90),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_viewer),
) -> List[Dict[str, Any]]:
    since = _utc_now() - timedelta(days=days)
    events = db.query(SecurityEvent).filter(SecurityEvent.timestamp >= since).all()
    # Group by date
    by_date: Dict[str, int] = {}
    for evt in events:
        date_str = evt.timestamp.strftime("%Y-%m-%d") if evt.timestamp else "unknown"
        by_date[date_str] = by_date.get(date_str, 0) + 1
    return [{"date": d, "count": c} for d, c in sorted(by_date.items())]


@router.get("/alert-severity-distribution")
def alert_severity_distribution(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_viewer),
) -> List[Dict[str, Any]]:
    result = []
    for sev in ["critical", "high", "medium", "low"]:
        count = db.query(Alert).filter(Alert.severity == sev).count()
        result.append({"severity": sev, "count": count})
    return result


@router.get("/event-type-distribution")
def event_type_distribution(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_viewer),
) -> List[Dict[str, Any]]:
    events = db.query(SecurityEvent.event_type).all()
    from collections import Counter
    counts = Counter(e[0] for e in events)
    return [{"event_type": k, "count": v} for k, v in counts.most_common(10)]


@router.get("/top-source-ips")
def top_source_ips(
    limit: int = Query(10, ge=1, le=50),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_viewer),
) -> List[Dict[str, Any]]:
    events = db.query(SecurityEvent.source_ip).filter(SecurityEvent.source_ip.isnot(None)).all()
    from collections import Counter
    counts = Counter(e[0] for e in events)
    return [{"source_ip": k, "count": v} for k, v in counts.most_common(limit)]
