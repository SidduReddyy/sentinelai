"""Authentication endpoints — login, logout, token refresh."""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.user import User
from app.schemas.auth import LoginRequest, TokenResponse, UserCreate, UserOut
from app.security.passwords import hash_password, verify_password
from app.security.permissions import get_current_user, require_admin
from app.security.tokens import create_access_token
from app.services import audit

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/login", response_model=TokenResponse)
def login(
    body: LoginRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    ip = request.client.host if request.client else None
    user = db.query(User).filter(User.username == body.username, User.is_active == True).first()
    if user is None or not verify_password(body.password, user.hashed_password):
        audit.record(db, "login_failure", actor=body.username, ip_address=ip, result="failure")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    user.last_login = datetime.now(timezone.utc)
    db.commit()
    audit.record(db, "login_success", actor=user.username, ip_address=ip)
    token = create_access_token({"sub": user.username, "role": user.role})
    return TokenResponse(access_token=token, role=user.role, username=user.username)


@router.post("/users", response_model=UserOut, status_code=201)
def create_user(
    body: UserCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    """Admin-only: create a new user."""
    if db.query(User).filter(User.username == body.username).first():
        raise HTTPException(status_code=409, detail="Username already exists")
    if db.query(User).filter(User.email == body.email).first():
        raise HTTPException(status_code=409, detail="Email already exists")
    new_user = User(
        username=body.username,
        email=body.email,
        hashed_password=hash_password(body.password),
        role=body.role,
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    audit.record(db, "user_created", actor=current_user.username, resource_type="user", resource_id=new_user.id)
    return new_user


@router.get("/users", response_model=list[UserOut])
def list_users(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    return db.query(User).all()


@router.get("/me", response_model=UserOut)
def me(current_user: User = Depends(get_current_user)):
    return current_user
