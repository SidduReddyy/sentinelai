"""
Input redaction — strip sensitive fields before any external transmission.
"""
from __future__ import annotations

import re
from typing import Any, Dict

_SENSITIVE_KEYS = frozenset({
    "password", "secret", "token", "api_key", "apikey", "auth", "credential",
    "private_key", "access_token", "refresh_token",
})

_REDACTED = "[REDACTED]"


def redact_dict(data: Dict[str, Any], depth: int = 0) -> Dict[str, Any]:
    """Recursively redact sensitive keys from a dict."""
    if depth > 5:
        return data
    result: Dict[str, Any] = {}
    for k, v in data.items():
        if any(s in k.lower() for s in _SENSITIVE_KEYS):
            result[k] = _REDACTED
        elif isinstance(v, dict):
            result[k] = redact_dict(v, depth + 1)
        else:
            result[k] = v
    return result


def redact_string(text: str, max_length: int = 2000) -> str:
    """Truncate and strip obvious secret patterns from a string."""
    text = text[:max_length]
    # Redact key=value patterns where key looks sensitive
    text = re.sub(
        r'(?i)(password|secret|token|api_key|apikey)\s*[=:]\s*\S+',
        r'\1=[REDACTED]',
        text,
    )
    return text
