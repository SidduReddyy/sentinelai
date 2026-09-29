"""Health check endpoint."""
from fastapi import APIRouter

router = APIRouter(tags=["Health"])


@router.get("/health")
def health_check():
    """Return application health status. Does not expose sensitive information."""
    return {"status": "ok", "service": "SentinelAI"}
