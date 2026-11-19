"""Read-only local Flask dashboard for incidents and evaluation results."""

import json
import re
import sqlite3
from collections import defaultdict
from pathlib import Path
from typing import Any

from flask import Flask, abort, render_template, request

from core.timeutil import parse_ts

SEVERITIES = ("HIGH", "MEDIUM", "LOW")
DETECTOR_LABELS = {
    "impossible_travel": "Impossible travel",
    "scope_creep": "Scope deviation",
    "temporal_anomaly": "Temporal anomaly",
    "volume_spike": "Volume spike",
}
CAMPAIGN_DESCRIPTIONS = {
    "camp_travel": "A session token appears in Frankfurt shortly after normal activity.",
    "camp_scope": "An integration begins querying objects rare in its baseline.",
    "camp_temporal": "A session token becomes active during an unusual UTC hour.",
    "camp_drift": "A shared integration replay spans many tenants in a short window.",
}


def readonly_uri(db_path: str | Path) -> str:
    """Build a read-only SQLite URI that handles spaces and Windows drive letters."""
    return Path(db_path).resolve().as_uri() + "?mode=ro"


def _connect(db_path: str | Path) -> sqlite3.Connection:
    """Open SQLite in read-only mode for all dashboard queries."""
    connection = sqlite3.connect(readonly_uri(db_path), uri=True)
    connection.row_factory = sqlite3.Row
    return connection


def _display_ts(value: str | None) -> str:
    """Format stored UTC timestamps consistently for human-readable pages."""
    if not value:
        return "—"
    return parse_ts(value).strftime("%Y-%m-%d %H:%M:%S UTC")


def _duration(start: str, end: str) -> str:
    """Format the elapsed incident period as hours and minutes."""
    seconds = max(0, int((parse_ts(end) - parse_ts(start)).total_seconds()))
    hours, remainder = divmod(seconds, 3600)
    minutes = remainder // 60
    return f"{hours}h {minutes}m" if hours else f"{minutes}m"


def _number(value: int | float | None) -> str:
    """Render counts consistently with thousands separators."""
    return f"{value or 0:,}"


def create_app(db_path: str | Path) -> Flask:
    """Create the read-only dashboard application for the requested database."""
    app = Flask(__name__)
    app.config["DATABASE"] = str(db_path)
    app.jinja_env.filters["display_ts"] = _display_ts
    app.jinja_env.filters["number"] = _number
    app.jinja_env.filters["duration"] = _duration

    @app.after_request
    def security_headers(response):
        """Add the required browser security headers to every response."""
        response.headers["Content-Security-Policy"] = "default-src 'self'"
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response

    @app.errorhandler(404)
    def not_found(_error):
        """Render a consistent styled not-found page."""
        missing_database = not Path(app.config["DATABASE"]).exists()
        return render_template(
            "error.html",
            title="Database unavailable" if missing_database else "Page not found",
            message=(
                "The dataset database is missing. Run the demo pipeline to create it."
                if missing_database else "The requested page could not be found."
            ),
        ), 404

    @app.context_processor
    def common_template_data() -> dict[str, Any]:
        """Provide dataset metadata to the shared page footer when available."""
        path = Path(app.config["DATABASE"])
        if not path.exists():
            return {"footer_metadata": None}
        connection: sqlite3.Connection | None = None
        try:
            connection = _connect(path)
            metadata = dict(connection.execute(
                "SELECT key, value FROM metadata WHERE key IN "
                "('seed', 'dataset_start_utc', 'eval_end_utc', 'source', "
                "'source_filename', 'analyzed_at')"
            ))
            return {"footer_metadata": metadata}
        except sqlite3.Error:
            return {"footer_metadata": None}
        finally:
            if connection is not None:
                connection.close()

    def db_or_missing() -> sqlite3.Connection:
        """Open the configured database or show a friendly missing-database page."""
        if not Path(app.config["DATABASE"]).exists():
            abort(404)
        try:
            return _connect(app.config["DATABASE"])
        except sqlite3.Error:
            abort(404)

    @app.route("/healthz")
    def healthz():
        """Expose a process health check without touching SQLite."""
        return "ok\n", 200, {"Content-Type": "text/plain; charset=utf-8"}

    @app.route("/")
    def index():
        """Show dataset KPIs, alert distributions, severity, and evaluation results."""
        connection = db_or_missing()
        try:
            counts = {
                "events": connection.execute("SELECT COUNT(*) FROM events").fetchone()[0],
                "alerts": connection.execute("SELECT COUNT(*) FROM alerts").fetchone()[0],
                "incidents": connection.execute("SELECT COUNT(*) FROM incidents").fetchone()[0],
                "revoked": connection.execute(
                    "SELECT COUNT(*) FROM token_status WHERE revoked_at IS NOT NULL"
                ).fetchone()[0],
            }
            severity_counts = {
                row["severity"]: row["count"]
                for row in connection.execute(
                    "SELECT severity, COUNT(*) AS count FROM incidents GROUP BY severity"
                )
            }
            severity_total = sum(severity_counts.values()) or 1
            severities = [
                {
                    "name": severity,
                    "count": severity_counts.get(severity, 0),
                    "percent": round(100 * severity_counts.get(severity, 0) / severity_total),
                }
                for severity in SEVERITIES
            ]
            alert_rows = connection.execute(
                """SELECT detector, subtype, COUNT(*) AS count
                   FROM alerts GROUP BY detector, subtype
                   ORDER BY detector, subtype LIMIT 200"""
            ).fetchall()
            maximum = max((row["count"] for row in alert_rows), default=1)
            alert_types = [
                {
                    "detector": DETECTOR_LABELS.get(row["detector"], row["detector"]),
                    "subtype": row["subtype"],
                    "count": row["count"],
                    "width": max(1, round(180 * row["count"] / maximum)),
                }
                for row in alert_rows
            ]
            report_row = connection.execute(
                "SELECT report_json FROM eval_report WHERE id=1"
            ).fetchone()
            report = json.loads(report_row["report_json"]) if report_row else None
            campaigns = []
            if report:
                for campaign, passed in report.get("campaign_pass", {}).items():
                    campaigns.append({
                        "name": campaign,
                        "passed": bool(passed),
                        "description": CAMPAIGN_DESCRIPTIONS.get(
                            campaign, "Synthetic evaluation scenario."
                        ),
                    })
            benign = report.get("false_positive_benign_events", 0) if report else 0
            benign_alerted = (
                report.get("false_positive_benign_alerted_events", 0) if report else 0
            )
            return render_template(
                "index.html", counts=counts, severities=severities,
                alert_types=alert_types, report=report, campaigns=campaigns,
                benign=benign, benign_alerted=benign_alerted,
            )
        except (json.JSONDecodeError, TypeError, ValueError):
            return render_template(
                "index.html", counts={"events": 0, "alerts": 0, "incidents": 0, "revoked": 0},
                severities=[], alert_types=[], report=None, campaigns=[],
                benign=0, benign_alerted=0, report_malformed=True,
            )
        finally:
            connection.close()

    @app.route("/incidents")
    def incidents():
        """List incidents with a validated severity filter."""
        requested = request.args.get("severity", "ALL").upper()
        severity = requested if requested in SEVERITIES else "ALL"
        connection = db_or_missing()
        try:
            if severity == "ALL":
                rows = connection.execute(
                    "SELECT * FROM incidents ORDER BY start_ts DESC, incident_id DESC LIMIT 200"
                ).fetchall()
            else:
                rows = connection.execute(
                    "SELECT * FROM incidents WHERE severity=? "
                    "ORDER BY start_ts DESC, incident_id DESC LIMIT 200",
                    (severity,),
                ).fetchall()
            incidents_with_details = []
            for row in rows:
                try:
                    detectors = json.loads(row["detectors_json"])
                except json.JSONDecodeError:
                    detectors = []
                incidents_with_details.append({
                    "row": row,
                    "detectors": detectors,
                    "duration": _duration(row["start_ts"], row["end_ts"]),
                })
            return render_template(
                "incidents.html", incidents=incidents_with_details, severity=severity
            )
        finally:
            connection.close()

    @app.route("/incident/<int:incident_id>")
    def incident_detail(incident_id: int):
        """Show incident summary, grouped alerts, and its alert-linked timeline."""
        connection = db_or_missing()
        try:
            incident = connection.execute(
                "SELECT * FROM incidents WHERE incident_id=?", (incident_id,)
            ).fetchone()
            if incident is None:
                abort(404)
            alerts = connection.execute(
                "SELECT * FROM alerts WHERE incident_id=? "
                "ORDER BY detector, ts, alert_id LIMIT 200",
                (incident_id,),
            ).fetchall()
            grouped: dict[str, list[sqlite3.Row]] = defaultdict(list)
            event_detectors: dict[int, list[str]] = defaultdict(list)
            for alert in alerts:
                grouped[alert["detector"]].append(alert)
                event_detectors[alert["event_id"]].append(
                    DETECTOR_LABELS.get(alert["detector"], alert["detector"])
                )
            timeline = connection.execute(
                """SELECT * FROM events
                   WHERE token_id=? AND ts>=? AND ts<=?
                   ORDER BY ts, event_id LIMIT 200""",
                (incident["token_id"], incident["start_ts"], incident["end_ts"]),
            ).fetchall()
            token_status = connection.execute(
                "SELECT revoked_at FROM token_status WHERE token_id=?",
                (incident["token_id"],),
            ).fetchone()
            profile = connection.execute(
                "SELECT token_type, principal, tenant_id, geo_city FROM events "
                "WHERE token_id=? ORDER BY ts DESC LIMIT 1",
                (incident["token_id"],),
            ).fetchone()
            return render_template(
                "incident.html", incident=incident, grouped_alerts=grouped,
                timeline=timeline, event_detectors=event_detectors,
                token_status=token_status, profile=profile,
            )
        finally:
            connection.close()

    @app.route("/token/<token_id>")
    def token_detail(token_id: str):
        """Show token profile, response state, alerts, and the latest 200 events."""
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", token_id):
            abort(404)
        connection = db_or_missing()
        try:
            events = connection.execute(
                "SELECT * FROM events WHERE token_id=? ORDER BY ts DESC LIMIT 200",
                (token_id,),
            ).fetchall()
            alerts = connection.execute(
                "SELECT * FROM alerts WHERE token_id=? ORDER BY ts DESC LIMIT 200",
                (token_id,),
            ).fetchall()
            status = connection.execute(
                "SELECT revoked_at FROM token_status WHERE token_id=?", (token_id,)
            ).fetchone()
            profile = connection.execute(
                """SELECT token_type, principal, tenant_id
                   FROM events WHERE token_id=? ORDER BY ts DESC LIMIT 1""",
                (token_id,),
            ).fetchone()
            home_city = connection.execute(
                """SELECT geo_city FROM events
                   WHERE token_id=? AND ts < (
                       SELECT value FROM metadata WHERE key='baseline_end_utc'
                   )
                   GROUP BY geo_city ORDER BY COUNT(*) DESC, geo_city LIMIT 1""",
                (token_id,),
            ).fetchone()
            return render_template(
                "token.html", token_id=token_id, events=events,
                alerts=alerts, status=status, profile=profile,
                home_city=home_city["geo_city"] if home_city else None,
            )
        finally:
            connection.close()

    return app
