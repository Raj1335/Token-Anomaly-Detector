"""Read-only local Flask dashboard for incidents and evaluation results."""

import json
import re
import sqlite3
from pathlib import Path

from flask import Flask, abort, request, render_template


def readonly_uri(db_path: str | Path) -> str:
    """Build a read-only SQLite URI that handles spaces and Windows drive letters."""
    return Path(db_path).resolve().as_uri() + "?mode=ro"


def _connect(db_path: str | Path) -> sqlite3.Connection:
    """Open SQLite read-only and keep every dashboard route side-effect free."""
    connection = sqlite3.connect(readonly_uri(db_path), uri=True)
    connection.row_factory = sqlite3.Row
    return connection


def create_app(db_path: str | Path) -> Flask:
    """Create a safe localhost dashboard app for the requested database."""
    app = Flask(__name__)
    app.config["DATABASE"] = str(db_path)

    @app.after_request
    def security_headers(response):
        """Add browser security headers to every response."""
        response.headers["Content-Security-Policy"] = "default-src 'self'"
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response

    def db_or_404() -> sqlite3.Connection:
        """Return a read-only connection or abort with a friendly missing-DB page."""
        if not Path(app.config["DATABASE"]).exists():
            abort(404)
        return _connect(app.config["DATABASE"])

    @app.route("/")
    def index():
        """Show counts, incident severity, and evaluation status."""
        connection = db_or_404()
        try:
            counts = {
                "events": connection.execute("SELECT COUNT(*) FROM events").fetchone()[0],
                "alerts": connection.execute("SELECT COUNT(*) FROM alerts").fetchone()[0],
                "incidents": connection.execute("SELECT COUNT(*) FROM incidents").fetchone()[0],
            }
            severities = connection.execute(
                "SELECT severity, COUNT(*) AS count FROM incidents GROUP BY severity"
            ).fetchall()
            report_row = connection.execute(
                "SELECT report_json FROM eval_report WHERE id=1"
            ).fetchone()
            report = json.loads(report_row[0]) if report_row else None
            return render_template(
                "index.html", counts=counts, severities=severities, report=report
            )
        except json.JSONDecodeError:
            return render_template("missing.html", message="Evaluation report is malformed.")
        finally:
            connection.close()

    @app.route("/incidents")
    def incidents():
        """List incidents, optionally filtered by severity."""
        connection = db_or_404()
        try:
            severity = request.args.get("severity")
            if severity:
                rows = connection.execute(
                    "SELECT * FROM incidents WHERE severity=? ORDER BY incident_id",
                    (severity,),
                ).fetchall()
            else:
                rows = connection.execute(
                    "SELECT * FROM incidents ORDER BY incident_id"
                ).fetchall()
            return render_template("incidents.html", incidents=rows)
        finally:
            connection.close()

    @app.route("/incident/<int:incident_id>")
    def incident_detail(incident_id: int):
        """Show an incident's alerts and token event timeline."""
        connection = db_or_404()
        try:
            incident = connection.execute(
                "SELECT * FROM incidents WHERE incident_id=?", (incident_id,)
            ).fetchone()
            if incident is None:
                abort(404)
            alerts = connection.execute(
                "SELECT * FROM alerts WHERE incident_id=? ORDER BY ts, alert_id",
                (incident_id,),
            ).fetchall()
            timeline = connection.execute(
                "SELECT * FROM events WHERE token_id=? ORDER BY ts DESC LIMIT 200",
                (incident["token_id"],),
            ).fetchall()
            return render_template(
                "incident.html", incident=incident, alerts=alerts, timeline=timeline
            )
        finally:
            connection.close()

    @app.route("/token/<token_id>")
    def token_detail(token_id: str):
        """Show a token's last 200 events and associated alerts."""
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", token_id):
            abort(404)
        connection = db_or_404()
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
                "SELECT * FROM token_status WHERE token_id=?", (token_id,)
            ).fetchone()
            return render_template(
                "token.html", token_id=token_id, events=events,
                alerts=alerts, status=status,
            )
        finally:
            connection.close()

    return app