"""Group alerts into token incidents and apply the simplified response policy."""

import sqlite3
from collections import defaultdict
from datetime import timedelta

from config import INCIDENT_GAP_MIN, RESPONSE_POLICY
from core.db import insert_alerts
from core.models import Alert


def correlate(connection: sqlite3.Connection, alerts: list[Alert]) -> list[int]:
    """Build incidents, assign alert incident IDs, and write simulated responses."""
    groups: dict[str, list[Alert]] = defaultdict(list)
    for alert in alerts:
        groups[alert.token_id].append(alert)

    incident_ids: list[int] = []
    with connection:
        insert_alerts(connection, alerts)
        alert_rows = connection.execute(
            "SELECT alert_id, detector, token_id, ts FROM alerts"
        ).fetchall()
        alert_lookup = {
            (row[2], row[3], row[1]): row[0] for row in alert_rows
        }
        for token_id, token_alerts in groups.items():
            ordered = sorted(token_alerts, key=lambda item: (item.ts, item.event_id))
            episodes: list[list[Alert]] = []
            for alert in ordered:
                if not episodes or (
                    alert.ts - episodes[-1][-1].ts
                ) > timedelta(minutes=INCIDENT_GAP_MIN):
                    episodes.append([alert])
                else:
                    episodes[-1].append(alert)
            for episode in episodes:
                detectors = {alert.detector for alert in episode}
                severity = "LOW"
                action = "log"
                if len(detectors) >= 2:
                    severity = "HIGH"
                    action = "revoke"
                elif len(detectors) == 1:
                    severity, action = RESPONSE_POLICY[detectors.copy().pop()]
                cursor = connection.execute(
                    """INSERT INTO incidents(token_id, start_ts, end_ts, detectors_json,
                       severity, action, alert_count)
                       VALUES(?, ?, ?, ?, ?, ?, ?)""",
                    (
                        token_id, episode[0].ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
                        episode[-1].ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
                        __import__("json").dumps(sorted(detectors)),
                        severity, action, len(episode),
                    ),
                )
                incident_id = int(cursor.lastrowid)
                incident_ids.append(incident_id)
                seen: set[str] = set()
                revoke_ts: str | None = None
                for alert in episode:
                    if len(seen) < 1:
                        seen.add(alert.detector)
                    else:
                        seen.add(alert.detector)
                        if len(seen) >= 2 and revoke_ts is None:
                            revoke_ts = alert.ts.strftime("%Y-%m-%dT%H:%M:%SZ")
                    ts_text = alert.ts.strftime("%Y-%m-%dT%H:%M:%SZ")
                    matching = alert_lookup.get((token_id, ts_text, alert.detector))
                    if matching is not None:
                        connection.execute(
                            "UPDATE alerts SET incident_id = ? WHERE alert_id = ?",
                            (incident_id, matching),
                        )
                if severity == "HIGH" and revoke_ts is not None:
                    connection.execute(
                        "INSERT OR REPLACE INTO token_status(token_id, revoked_at) VALUES(?, ?)",
                        (token_id, revoke_ts),
                    )
                    connection.execute(
                        "INSERT INTO notifications(ts, token_id, severity, message) VALUES(?, ?, ?, ?)",
                        (revoke_ts, token_id, "HIGH", "Multiple detector families indicated token abuse."),
                    )
                elif action == "notify":
                    ts_text = episode[-1].ts.strftime("%Y-%m-%dT%H:%M:%SZ")
                    connection.execute(
                        "INSERT INTO notifications(ts, token_id, severity, message) VALUES(?, ?, ?, ?)",
                        (ts_text, token_id, severity, "Anomaly detector requested notification."),
                    )
    return incident_ids
