"""
SentinelAI — Database engine and session management.
"""
from __future__ import annotations

import logging
from typing import Generator

from sqlalchemy import create_engine, event
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.config import get_settings

logger = logging.getLogger(__name__)

settings = get_settings()

# SQLite-specific: enable WAL mode and foreign-key enforcement
engine = create_engine(
    settings.database_url,
    connect_args={"check_same_thread": False},
    echo=False,
)


@event.listens_for(engine, "connect")
def _set_sqlite_pragma(dbapi_conn, _connection_record) -> None:
    cursor = dbapi_conn.cursor()
    cursor.execute("PRAGMA journal_mode=WAL;")
    cursor.execute("PRAGMA foreign_keys=ON;")
    cursor.close()


SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    """Declarative base for all ORM models."""


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency — yields a database session and closes it on exit."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    """Create all tables and seed initial data."""
    # Import models so their metadata is registered
    from app.models import alert, audit, event, user  # noqa: F401

    Base.metadata.create_all(bind=engine)
    logger.info("Database tables created / verified.")
    _seed_initial_admin()


def _seed_initial_admin() -> None:
    """Create initial demo accounts (admin, analyst, viewer) if not present."""
    from app.models.user import User
    from app.security.passwords import hash_password

    db = SessionLocal()
    try:
        s = get_settings()
        demo_users = [
            (s.initial_admin_username, s.initial_admin_email, s.initial_admin_password, "admin"),
            ("analyst", "analyst@sentinelai.internal", "AnalystPassword123!", "analyst"),
            ("viewer", "viewer@sentinelai.internal", "ViewerPassword123!", "viewer"),
        ]
        for uname, uemail, upass, urole in demo_users:
            if not db.query(User).filter(User.username == uname).first():
                user_obj = User(
                    username=uname,
                    email=uemail,
                    hashed_password=hash_password(upass),
                    role=urole,
                    is_active=True,
                )
                db.add(user_obj)
                logger.info("Demo user '%s' (%s) seeded.", uname, urole)
        db.commit()
    except Exception:
        db.rollback()
        logger.exception("Failed to seed demo users.")
    finally:
        db.close()
