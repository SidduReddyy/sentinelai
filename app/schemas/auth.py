"""Pydantic schemas for authentication."""
from __future__ import annotations

from pydantic import BaseModel, EmailStr, Field


class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=64)
    password: str = Field(..., min_length=1, max_length=256)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str
    username: str


class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=64, pattern=r"^[a-zA-Z0-9_\-]+$")
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=256)
    role: str = Field("viewer", pattern=r"^(admin|analyst|viewer)$")


class UserOut(BaseModel):
    id: str
    username: str
    email: str
    role: str
    is_active: bool

    model_config = {"from_attributes": True}
