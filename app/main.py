"""
SentinelAI — FastAPI Application Entry Point
"""
from __future__ import annotations

import logging
import sys

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import get_settings
from app.database import init_db

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    stream=sys.stdout,
)
logger = logging.getLogger(__name__)

settings = get_settings()

app = FastAPI(
    title="SentinelAI",
    description="AI-Powered Cybersecurity Threat Detection & Investigation Platform",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS — restrict to configured origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routers
from app.api.health import router as health_router
from app.api.auth import router as auth_router
from app.api.events import router as events_router
from app.api.alerts import router as alerts_router
from app.api.analytics import router as analytics_router
from app.api.investigations import router as investigations_router
from app.api.settings import router as settings_router

app.include_router(health_router)
app.include_router(auth_router)
app.include_router(events_router)
app.include_router(alerts_router)
app.include_router(analytics_router)
app.include_router(investigations_router)
app.include_router(settings_router)


@app.on_event("startup")
async def startup_event():
    logger.info("SentinelAI starting — initializing database...")
    init_db()
    logger.info("SentinelAI ready.")
