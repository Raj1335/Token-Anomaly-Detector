"""Detect activity at UTC hours absent from an individual's baseline profile."""

from collections import Counter, defaultdict

from config import MIN_BASELINE_EVENTS, TEMPORAL_MIN_SHARE
from core.models import Alert, Event


class TemporalAnomalyDetector:
    """Fit smoothed UTC-hour distributions and alert on unusually quiet hours."""

    name = "temporal_anomaly"

    def __init__(self) -> None:
        """Initialize per-token hour profiles and cold-start counters."""
        self.hour_share: dict[str, tuple[float, ...]] = {}
        self.baseline_counts: Counter[str] = Counter()
        self.skipped: Counter[str] = Counter()

    def fit(self, events: list[Event]) -> None:
        """Build normalized circularly smoothed 24-hour baseline histograms."""
        histograms: dict[str, list[int]] = defaultdict(lambda: [0] * 24)
        self.baseline_counts.clear()
        self.skipped.clear()
        for event in events:
            histograms[event.token_id][event.ts.hour] += 1
            self.baseline_counts[event.token_id] += 1
        self.hour_share.clear()
        for token_id, histogram in histograms.items():
            smoothed = [
                0.25 * histogram[(hour - 1) % 24]
                + 0.5 * histogram[hour]
                + 0.25 * histogram[(hour + 1) % 24]
                for hour in range(24)
            ]
            total = sum(smoothed)
            self.hour_share[token_id] = tuple(value / total for value in smoothed)

    def detect(self, events: list[Event]) -> list[Alert]:
        """Alert on evaluation events whose smoothed UTC-hour share is too low."""
        alerts: list[Alert] = []
        self.skipped = Counter()
        for event in events:
            if self.baseline_counts.get(event.token_id, 0) < MIN_BASELINE_EVENTS:
                self.skipped["fewer than minimum baseline events"] += 1
                continue
            share = self.hour_share[event.token_id][event.ts.hour]
            if share < TEMPORAL_MIN_SHARE:
                alerts.append(
                    Alert(
                        self.name, "temporal", event.event_id, event.token_id, event.ts,
                        min(1.0, 1.0 - share),
                        f"UTC hour {event.ts.hour:02d} has baseline share {share:.4f}.",
                        {"utc_hour": event.ts.hour, "baseline_share": share},
                    )
                )
        return alerts