"""
Event normalization — convert raw ingestion data to a canonical form.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from app.schemas.event import EventCreate

logger = logging.getLogger(__name__)


def normalize_timestamp(ts: Any) -> datetime:
    """Return a timezone-aware UTC datetime from various input types."""
    if isinstance(ts, datetime):
        if ts.tzinfo is None:
            return ts.replace(tzinfo=timezone.utc)
        return ts.astimezone(timezone.utc)
    if isinstance(ts, (int, float)):
        return datetime.fromtimestamp(ts, tz=timezone.utc)
    if isinstance(ts, str):
        for fmt in (
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d",
        ):
            try:
                dt = datetime.strptime(ts, fmt)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt.astimezone(timezone.utc)
            except ValueError:
                continue
    raise ValueError(f"Cannot parse timestamp: {ts!r}")


def normalize_event(raw: Dict[str, Any]) -> EventCreate:
    """Validate and normalize a raw event dict into an EventCreate schema."""
    if "timestamp" in raw:
        raw["timestamp"] = normalize_timestamp(raw["timestamp"])

    # Sanitize extra_data — must not contain code or executable strings
    extra = raw.pop("extra_data", None) or raw.pop("metadata", None)
    if isinstance(extra, str):
        try:
            extra = json.loads(extra)
        except json.JSONDecodeError:
            extra = {"raw_extra": extra[:512]}
    if isinstance(extra, dict):
        raw["extra_data"] = extra

    return EventCreate(**raw)
