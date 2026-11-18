"""Detect implausible geographic jumps using each token's baseline activity."""

import math
from collections import Counter

from config import MAX_SPEED_KMH, MIN_DIST_KM
from core.models import Alert, Event


def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Return great-circle distance in kilometers for two coordinate pairs."""
    radius = 6371.0
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    delta_phi = math.radians(lat2 - lat1)
    delta_lambda = math.radians(lon2 - lon1)
    value = (
        math.sin(delta_phi / 2) ** 2
        + math.cos(phi1) * math.cos(phi2) * math.sin(delta_lambda / 2) ** 2
    )
    return radius * 2 * math.atan2(math.sqrt(value), math.sqrt(max(0.0, 1 - value)))


class ImpossibleTravelDetector:
    """Compare consecutive token locations and alert only on unknown-IP jumps."""

    name = "impossible_travel"

    def __init__(self) -> None:
        """Initialize learned profiles and explicit cold-start accounting."""
        self.baseline_ips: dict[str, set[str]] = {}
        self.last_event: dict[str, Event] = {}
        self.skipped: Counter[str] = Counter()

    def fit(self, events: list[Event]) -> None:
        """Store each token's baseline IP set and final training event."""
        self.baseline_ips.clear()
        self.last_event.clear()
        self.skipped.clear()
        for event in sorted(events, key=lambda item: (item.ts, item.event_id)):
            self.baseline_ips.setdefault(event.token_id, set()).add(event.source_ip)
            self.last_event[event.token_id] = event

    def detect(self, events: list[Event]) -> list[Alert]:
        """Alert on later events whose location jump exceeds plausible travel speed."""
        alerts: list[Alert] = []
        previous = dict(self.last_event)
        current_tokens = {event.token_id for event in events}
        self.skipped = Counter({
            "no baseline": sum(token_id not in self.baseline_ips for token_id in current_tokens)
        })
        for event in sorted(events, key=lambda item: (item.ts, item.event_id)):
            prior = previous.get(event.token_id)
            if prior is not None:
                distance = haversine_km(prior.geo_lat, prior.geo_lon, event.geo_lat, event.geo_lon)
                hours = max((event.ts - prior.ts).total_seconds() / 3600.0, 1.0 / 3600.0)
                speed = distance / hours
                if (
                    distance >= MIN_DIST_KM
                    and speed > MAX_SPEED_KMH
                    and event.source_ip not in self.baseline_ips.get(event.token_id, set())
                ):
                    alerts.append(
                        Alert(
                            self.name, "impossible_travel", event.event_id, event.token_id,
                            event.ts, min(1.0, speed / (4 * MAX_SPEED_KMH)),
                            f"Location changed {distance:.0f} km at {speed:.0f} km/h.",
                            {"distance_km": round(distance, 2), "speed_kmh": round(speed, 2)},
                        )
                    )
            previous[event.token_id] = event
        return alerts