"""SQLite schema and bulk persistence helpers for generated and detected data."""

import json
import sqlite3
from pathlib import Path
from typing import Iterable

from core.models import Alert, Event
from core.timeutil import format_ts

SCHEMA_VERSION = "1"


def connect(path: str | Path) -> sqlite3.Connection:
    """Open a database connection with foreign-key checks enabled."""
    connection = sqlite3.connect(str(path))
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def create_schema(connection: sqlite3.Connection) -> None:
    """Create all project tables and indexes if they do not already exist."""
    connection.executescript(
        """
        CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS events (
            event_id INTEGER PRIMARY KEY, ts TEXT NOT NULL, token_id TEXT NOT NULL,
            token_type TEXT NOT NULL, principal TEXT NOT NULL, tenant_id TEXT NOT NULL,
            source_ip TEXT NOT NULL, geo_lat REAL, geo_lon REAL,
            geo_city TEXT NOT NULL, object_type TEXT NOT NULL, action TEXT NOT NULL,
            records_returned INTEGER NOT NULL, granted_scopes_json TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_events_token_ts ON events(token_id, ts);
        CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
        CREATE TABLE IF NOT EXISTS labels (
            event_id INTEGER PRIMARY KEY REFERENCES events(event_id),
            is_attack INTEGER NOT NULL CHECK(is_attack IN (0, 1)),
            scenario TEXT NOT NULL, campaign_id TEXT
        );
        CREATE TABLE IF NOT EXISTS alerts (
            alert_id INTEGER PRIMARY KEY AUTOINCREMENT, detector TEXT NOT NULL,
            subtype TEXT NOT NULL, event_id INTEGER NOT NULL REFERENCES events(event_id),
            token_id TEXT NOT NULL, ts TEXT NOT NULL, score REAL NOT NULL,
            reason TEXT NOT NULL, details_json TEXT NOT NULL, incident_id INTEGER
        );
        CREATE INDEX IF NOT EXISTS idx_alerts_token_ts ON alerts(token_id, ts);
        CREATE TABLE IF NOT EXISTS incidents (
            incident_id INTEGER PRIMARY KEY AUTOINCREMENT, token_id TEXT NOT NULL,
            start_ts TEXT NOT NULL, end_ts TEXT NOT NULL, detectors_json TEXT NOT NULL,
            severity TEXT NOT NULL, action TEXT NOT NULL, alert_count INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS token_status (
            token_id TEXT PRIMARY KEY, revoked_at TEXT
        );
        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL,
            token_id TEXT NOT NULL, severity TEXT NOT NULL, message TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS eval_report (
            id INTEGER PRIMARY KEY CHECK(id = 1), seed INTEGER NOT NULL,
            created_at TEXT NOT NULL, report_json TEXT NOT NULL
        );
        """
    )


def insert_dataset(
    connection: sqlite3.Connection,
    events: Iterable[Event],
    labels: Iterable[tuple[int, int, str, str | None]],
    metadata: dict[str, str],
) -> None:
    """Persist metadata, events, and labels together in one transaction."""
    event_rows = [
        (
            event.event_id, format_ts(event.ts), event.token_id, event.token_type,
            event.principal, event.tenant_id, event.source_ip, event.geo_lat,
            event.geo_lon, event.geo_city, event.object_type, event.action,
            event.records_returned, json.dumps(event.granted_scopes),
        )
        for event in events
    ]
    with connection:
        connection.executemany(
            "INSERT INTO metadata(key, value) VALUES(?, ?)", metadata.items()
        )
        connection.executemany(
            """INSERT INTO events VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            event_rows,
        )
        connection.executemany(
            "INSERT INTO labels(event_id, is_attack, scenario, campaign_id) VALUES(?, ?, ?, ?)",
            labels,
        )


def insert_alerts(connection: sqlite3.Connection, alerts: Iterable[Alert]) -> None:
    """Bulk insert alerts using parameterized SQL in the caller's transaction."""
    connection.executemany(
        """INSERT INTO alerts(detector, subtype, event_id, token_id, ts, score, reason, details_json)
           VALUES(?, ?, ?, ?, ?, ?, ?, ?)""",
        [
            (
                alert.detector, alert.subtype, alert.event_id, alert.token_id,
                format_ts(alert.ts), alert.score, alert.reason,
                json.dumps(alert.details, sort_keys=True),
            )
            for alert in alerts
        ],
    )
