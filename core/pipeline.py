"""Shared detector fitting, detection, and correlation pipeline."""

import json
import sqlite3

from core.correlate import correlate
from core.models import Alert, Event
from core.timeutil import parse_ts
from detectors.impossible_travel import ImpossibleTravelDetector
from detectors.scope_creep import ScopeCreepDetector
from detectors.temporal_anomaly import TemporalAnomalyDetector
from detectors.volume_spike import VolumeSpikeDetector


def load_events(connection: sqlite3.Connection) -> tuple[list[Event], list[Event]]:
    """Load baseline and evaluation events without label fields."""
    values = dict(connection.execute("SELECT key, value FROM metadata"))
    baseline_end = parse_ts(values["baseline_end_utc"])
    eval_end = parse_ts(values["eval_end_utc"])
    baseline: list[Event] = []
    evaluation: list[Event] = []
    for row in connection.execute("SELECT * FROM events ORDER BY ts, event_id"):
        event = Event(
            row[0], parse_ts(row[1]), row[2], row[3], row[4], row[5],
            row[6], row[7], row[8], row[9], row[10], row[11], row[12],
            tuple(json.loads(row[13])),
        )
        if event.ts < baseline_end:
            baseline.append(event)
        elif event.ts < eval_end:
            evaluation.append(event)
    return baseline, evaluation


def run_detection(db_path: str, disabled_detectors: set[str] | None = None) -> list[Alert]:
    """Reset derived tables, fit on baseline, detect evaluation, and correlate."""
    connection = sqlite3.connect(db_path)
    connection.execute("PRAGMA foreign_keys = ON")
    try:
        baseline, evaluation = load_events(connection)
        all_detectors = [
            ImpossibleTravelDetector(),
            ScopeCreepDetector(),
            TemporalAnomalyDetector(),
            VolumeSpikeDetector(),
        ]
        disabled = disabled_detectors or set()
        detectors = [detector for detector in all_detectors if detector.name not in disabled]
        skipped: dict[str, dict[str, int]] = {}
        with connection:
            connection.execute(
                "DELETE FROM alerts"
            )
            connection.execute("DELETE FROM incidents")
            connection.execute("DELETE FROM token_status")
            connection.execute("DELETE FROM notifications")
            connection.execute(
                "DELETE FROM sqlite_sequence WHERE name IN ('alerts', 'incidents', 'notifications')"
            )
            for detector in detectors:
                detector.fit(baseline)
                skipped[detector.name] = dict(detector.skipped)
        alerts: list[Alert] = []
        for detector in detectors:
            alerts.extend(detector.detect(evaluation))
            skipped[detector.name] = dict(detector.skipped)
        correlate(connection, alerts)
        with connection:
            connection.executemany(
                "INSERT OR REPLACE INTO metadata(key, value) VALUES(?, ?)",
                [
                    ("disabled_detectors_json", json.dumps(sorted(disabled))),
                    ("detection_skips_json", json.dumps(skipped, sort_keys=True)),
                ],
            )
        return alerts
    finally:
        connection.close()
