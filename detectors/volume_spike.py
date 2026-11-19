"""Detect token-level volume bursts and causal tenant fan-out from new IPs."""

from collections import Counter, defaultdict, deque
from datetime import datetime, timedelta
from statistics import median

from config import (
    FANOUT_MIN_TENANTS,
    FANOUT_WINDOW_MIN,
    MIN_ABS_EVENTS,
    MIN_ABS_RECORDS,
    MIN_ACTIVE_WINDOWS,
    VOLUME_HEADROOM,
    VOLUME_K,
)
from core.models import Alert, Event


class VolumeSpikeDetector:
    """Learn robust active-window limits and evaluate rate and fan-out signals."""

    name = "volume_spike"

    def __init__(self) -> None:
        """Initialize token thresholds, known IPs, and skip accounting."""
        self.thresholds: dict[str, dict[str, float]] = {}
        self.baseline_ips: dict[str, set[str]] = {}
        self.skipped: Counter[str] = Counter()
        self._eligible: set[str] = set()

    def fit(self, events: list[Event]) -> None:
        """Learn per-token active-window thresholds from baseline traffic."""
        windows: dict[str, dict[int, list[int]]] = defaultdict(dict)
        ips: dict[str, set[str]] = defaultdict(set)
        for event in events:
            bucket = int(event.ts.timestamp()) // 300
            totals = windows[event.token_id].setdefault(bucket, [0, 0])
            totals[0] += 1
            totals[1] += event.records_returned
            ips[event.token_id].add(event.source_ip)
        self.thresholds.clear()
        self.baseline_ips = dict(ips)
        self.skipped.clear()
        self._eligible.clear()
        token_ids = {event.token_id for event in events}
        for token_id in token_ids:
            values = list(windows[token_id].values())
            if len(values) < MIN_ACTIVE_WINDOWS:
                self.skipped["fewer than minimum active windows"] += 1
                continue
            count_values = [value[0] for value in values]
            record_values = [value[1] for value in values]
            self.thresholds[token_id] = {
                "count": self._threshold(count_values),
                "records": self._threshold(record_values),
            }
            self._eligible.add(token_id)

    @staticmethod
    def _threshold(values: list[int]) -> float:
        """Calculate a robust limit above both spread and the baseline maximum."""
        middle = median(values)
        mad = median([abs(value - middle) for value in values])
        robust = middle + VOLUME_K * max(1.4826 * mad, 1.0)
        return max(robust, VOLUME_HEADROOM * max(values))

    def detect(self, events: list[Event]) -> list[Alert]:
        """Emit rate alerts on threshold crossings and causal new-IP fan-out alerts."""
        ordered = sorted(events, key=lambda item: (item.ts, item.event_id))
        evaluation_tokens = {event.token_id for event in ordered}
        self.skipped["no baseline"] = sum(
            token_id not in self.baseline_ips for token_id in evaluation_tokens
        )
        alerts = self._rate_alerts(ordered)
        alerts.extend(self._fanout_alerts(ordered))
        return alerts

    def _rate_alerts(self, events: list[Event]) -> list[Alert]:
        """Track evaluation bucket totals and emit at most one alert per metric."""
        totals: dict[tuple[str, int], list[int]] = defaultdict(lambda: [0, 0])
        emitted: set[tuple[str, int, str]] = set()
        alerts: list[Alert] = []
        for event in events:
            if event.token_id not in self._eligible:
                continue
            bucket = int(event.ts.timestamp()) // 300
            current = totals[(event.token_id, bucket)]
            current[0] += 1
            current[1] += event.records_returned
            for metric, position, absolute in (
                ("count", 0, MIN_ABS_EVENTS),
                ("records", 1, MIN_ABS_RECORDS),
            ):
                key = (event.token_id, bucket, metric)
                observed = current[position]
                threshold = self.thresholds[event.token_id][metric]
                if key not in emitted and observed > threshold and observed >= absolute:
                    emitted.add(key)
                    alerts.append(
                        Alert(
                            self.name, "per_token_rate", event.event_id, event.token_id,
                            event.ts, min(1.0, observed / max(threshold * 2, 1)),
                            f"{metric} reached {observed}, above threshold {threshold:.1f}.",
                            {
                                "subtype": "per_token_rate", "metric": metric,
                                "observed": observed, "threshold": threshold,
                            },
                        )
                    )
        return alerts

    def _fanout_alerts(self, events: list[Event]) -> list[Alert]:
        """Alert only on new tenants arriving after a new-IP fan-out threshold."""
        active: dict[str, deque[tuple[datetime, str]]] = defaultdict(deque)
        alerted: dict[str, set[str]] = defaultdict(set)
        alerts: list[Alert] = []
        for event in events:
            if event.token_id not in self.baseline_ips:
                continue
            if event.source_ip in self.baseline_ips[event.token_id]:
                continue
            queue = active[event.source_ip]
            cutoff = event.ts - timedelta(minutes=FANOUT_WINDOW_MIN)
            while queue and queue[0][0] < cutoff:
                queue.popleft()
            if len({tenant for _, tenant in queue}) < FANOUT_MIN_TENANTS:
                alerted[event.source_ip].clear()
            queue.append((event.ts, event.tenant_id))
            tenants = {tenant for _, tenant in queue}
            if len(tenants) < FANOUT_MIN_TENANTS:
                continue
            if event.tenant_id in alerted[event.source_ip]:
                continue
            alerted[event.source_ip].add(event.tenant_id)
            alerts.append(
                Alert(
                    self.name, "new_ip_fanout", event.event_id, event.token_id,
                    event.ts, min(1.0, len(tenants) / (2 * FANOUT_MIN_TENANTS)),
                    f"New source IP reached {len(tenants)} tenants in "
                    f"{FANOUT_WINDOW_MIN} minutes.",
                    {"source_ip": event.source_ip, "tenant_count": len(tenants)},
                )
            )
        return alerts