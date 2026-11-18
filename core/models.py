"""Typed, label-free event and alert models shared across detector modules."""

from dataclasses import dataclass
from datetime import datetime
from typing import Any


@dataclass(frozen=True)
class Event:
    """Represent one synthetic API event without exposing its ground-truth label."""

    event_id: int
    ts: datetime
    token_id: str
    token_type: str
    principal: str
    tenant_id: str
    source_ip: str
    geo_lat: float
    geo_lon: float
    geo_city: str
    object_type: str
    action: str
    records_returned: int
    granted_scopes: tuple[str, ...]


@dataclass(frozen=True)
class Alert:
    """Describe a detector finding using only observed event information."""

    detector: str
    subtype: str
    event_id: int
    token_id: str
    ts: datetime
    score: float
    reason: str
    details: dict[str, Any]
