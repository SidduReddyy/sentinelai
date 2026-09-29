"""Role-based permission helpers and FastAPI dependencies."""
from __future__ import annotations

import logging
from typing import Annotated

from fastapi import Depends, HTTPException, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.user import User
from app.security.tokens import decode_access_token

logger = logging.getLogger(__name__)
bearer_scheme = HTTPBearer(auto_error=False)

ROLE_HIERARCHY = {"viewer": 0, "analyst": 1, "admin": 2}


def _get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Security(bearer_scheme)],
    db: Session = Depends(get_db),
) -> User:
    if credentials is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    payload = decode_access_token(credentials.credentials)
    if payload is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")
    username: str = payload.get("sub", "")
    user = db.query(User).filter(User.username == username, User.is_active == True).first()
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    return user


def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Security(bearer_scheme)],
    db: Session = Depends(get_db),
) -> User:
    return _get_current_user(credentials, db)


def require_role(minimum_role: str):
    """FastAPI dependency factory — enforces minimum role."""
    def dependency(current_user: User = Depends(get_current_user)) -> User:
        if ROLE_HIERARCHY.get(current_user.role, -1) < ROLE_HIERARCHY.get(minimum_role, 99):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires '{minimum_role}' role or above",
            )
        return current_user
    return dependency


require_viewer = require_role("viewer")
require_analyst = require_role("analyst")
require_admin = require_role("admin")
