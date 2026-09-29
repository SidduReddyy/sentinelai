"""Secure password hashing using native bcrypt."""
from __future__ import annotations

import bcrypt


def hash_password(plain: str) -> str:
    """Return a bcrypt hash of the plain-text password."""
    # Bcrypt maximum password length is 72 bytes
    pwd_bytes = plain.encode("utf-8")[:72]
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(pwd_bytes, salt).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    """Return True if plain matches the stored hash."""
    try:
        pwd_bytes = plain.encode("utf-8")[:72]
        return bcrypt.checkpw(pwd_bytes, hashed.encode("utf-8"))
    except Exception:
        return False

