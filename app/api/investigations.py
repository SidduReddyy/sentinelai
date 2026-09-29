"""Investigations API — generate AI summaries for alerts."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.config import get_settings
from app.database import get_db
from app.models.user import User
from app.schemas.investigation import InvestigationRequest, InvestigationResponse
from app.security.permissions import require_analyst
from app.services.investigation import investigate_alert

router = APIRouter(prefix="/investigations", tags=["Investigations"])


@router.post("", response_model=InvestigationResponse)
def generate_investigation(
    body: InvestigationRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    result = investigate_alert(db, alert_id=body.alert_id, requester=current_user.username)
    if result is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    settings = get_settings()
    return InvestigationResponse(
        alert_id=body.alert_id,
        generated_by=result["generated_by"],
        summary=result["summary"],
        ai_configured=settings.ai_configured,
    )
