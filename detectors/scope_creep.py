def scope_creep(event):
    token = event.get("token")
    object_type, action = event.get("request_query")
    new_event = f"{object_type}:{action}"
    normal_scope = token.get("scope")

    if new_event not in normal_scope:
        return True
    return False


    

    
"""Detect rare object-action behavior independently of granted permissions."""

from collections import Counter, defaultdict

from config import MIN_BASELINE_EVENTS, SCOPE_MIN_RELEVANCY
from core.models import Alert, Event


class ScopeCreepDetector:
    """Flag low-relevancy activity while separately enforcing granted scopes."""

    name = "scope_creep"

    def __init__(self) -> None:
        """Initialize per-token profile state and cold-start counters."""
        self.relevancy: dict[str, dict[str, float]] = {}
        self.baseline_counts: Counter[str] = Counter()
        self.skipped: Counter[str] = Counter()

    def fit(self, events: list[Event]) -> None:
        """Learn each token's object-action frequencies from training events."""
        counts: dict[str, Counter[str]] = defaultdict(Counter)
        self.baseline_counts.clear()
        self.skipped.clear()
        for event in events:
            counts[event.token_id][f"{event.object_type}:{event.action}"] += 1
            self.baseline_counts[event.token_id] += 1
        self.relevancy = {
            token_id: {
                pair: count / self.baseline_counts[token_id]
                for pair, count in pairs.items()
            }
            for token_id, pairs in counts.items()
        }

    def detect(self, events: list[Event]) -> list[Alert]:
        """Emit deviation and out-of-grant alerts for tokens with enough history."""
        alerts: list[Alert] = []
        self.skipped = Counter()
        for event in sorted(events, key=lambda item: (item.ts, item.event_id)):
            total = self.baseline_counts.get(event.token_id, 0)
            if total < MIN_BASELINE_EVENTS:
                self.skipped["fewer than minimum baseline events"] += 1
                continue
            pair = f"{event.object_type}:{event.action}"
            if pair not in event.granted_scopes:
                alerts.append(
                    Alert(
                        self.name, "scope_violation", event.event_id, event.token_id,
                        event.ts, 1.0, f"{pair} is outside the token's granted scopes.",
                        {"scope": pair},
                    )
                )
            relevancy = self.relevancy.get(event.token_id, {}).get(pair, 0.0)
            if relevancy < SCOPE_MIN_RELEVANCY:
                alerts.append(
                    Alert(
                        self.name, "scope_deviation", event.event_id, event.token_id,
                        event.ts, min(1.0, 1.0 - relevancy),
                        f"{pair} is rare in this token's baseline activity.",
                        {"scope": pair, "relevancy": relevancy},
                    )
                )
        return alerts