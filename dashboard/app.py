"""Read-only local Flask dashboard for incidents and evaluation results."""

import hmac
import json
import os
import re
import secrets
import shutil
import sqlite3
import tempfile
import uuid
from collections import defaultdict
from pathlib import Path
from typing import Any

from flask import Flask, Response, abort, redirect, render_template, request, send_file, session, url_for

from core.timeutil import parse_ts
from data.analyze import analyze_input
from data.log_input import InputFileError

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
MAX_UPLOAD_BYTES = 100 * 1024 * 1024
UPLOAD_OUTPUTS = {
    "alerts.csv", "analysis.db", "incidents.csv", "report.html", "summary.json",
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
    app.config["SECRET_KEY"] = os.environ.get("UPLOAD_SECRET_KEY")
    app.secret_key = app.config["SECRET_KEY"]
    app.config["UPLOAD_USERNAME"] = os.environ.get("UPLOAD_USERNAME", "")
    app.config["UPLOAD_PASSWORD"] = os.environ.get("UPLOAD_PASSWORD", "")
    app.config["UPLOADS_ENABLED"] = (
        bool(app.config["UPLOAD_USERNAME"])
        and len(app.config["UPLOAD_PASSWORD"]) >= 16
        and bool(app.config["SECRET_KEY"])
        and len(app.config["SECRET_KEY"]) >= 32
    )
    app.config["ANALYSIS_DATA_DIR"] = Path(
        os.environ.get(
            "ANALYSIS_DATA_DIR",
            str(Path(tempfile.gettempdir()) / "token-anomaly-detector-uploads"),
        )
    )
    app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_BYTES
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.config["SESSION_COOKIE_SECURE"] = os.environ.get(
        "UPLOAD_COOKIE_SECURE", "1"
    ).strip().lower() not in ("0", "false", "no")
    app.jinja_env.filters["display_ts"] = _display_ts
    app.jinja_env.filters["number"] = _number
    app.jinja_env.filters["duration"] = _duration

    @app.after_request
    def security_headers(response):
        """Add the required browser security headers to every response."""
        response.headers["Content-Security-Policy"] = "default-src 'self'"
        response.headers["X-Content-Type-Options"] = "nosniff"
        if request.path == "/upload" or request.path.startswith("/uploads/"):
            response.headers["Cache-Control"] = "no-store"
            response.headers["Pragma"] = "no-cache"
        if re.fullmatch(r"/uploads/[a-f0-9]{32}/report\.html", request.path):
            response.headers["Content-Security-Policy"] = (
                "default-src 'none'; style-src 'unsafe-inline'; "
                "base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
            )
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

    @app.errorhandler(413)
    def upload_too_large(_error):
        """Explain the configured request-size limit without reflecting input."""
        return Response(
            "The upload exceeds the 100 MiB request-size limit.\n",
            status=413,
            content_type="text/plain; charset=utf-8",
        )

    @app.context_processor
    def common_template_data() -> dict[str, Any]:
        """Provide dataset metadata to the shared page footer when available."""
        path = Path(app.config["DATABASE"])
        if not path.exists():
            return {
                "footer_metadata": None,
                "uploads_enabled": app.config["UPLOADS_ENABLED"],
            }
        connection: sqlite3.Connection | None = None
        try:
            connection = _connect(path)
            metadata = dict(connection.execute(
                "SELECT key, value FROM metadata WHERE key IN "
                "('seed', 'dataset_start_utc', 'eval_end_utc', 'source', "
                "'source_filename', 'analyzed_at')"
            ))
            return {
                "footer_metadata": metadata,
                "uploads_enabled": app.config["UPLOADS_ENABLED"],
            }
        except sqlite3.Error:
            return {
                "footer_metadata": None,
                "uploads_enabled": app.config["UPLOADS_ENABLED"],
            }
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

    def upload_auth_error() -> Response | None:
        """Require configured shared credentials for private upload endpoints."""
        if not app.config["UPLOADS_ENABLED"]:
            return Response(
                "Log uploads are disabled: configure strong upload credentials and a secret key.\n",
                status=503,
                content_type="text/plain; charset=utf-8",
            )
        credentials = request.authorization
        valid = credentials is not None
        if credentials is not None:
            username_ok = hmac.compare_digest(
                (credentials.username or "").encode("utf-8"),
                app.config["UPLOAD_USERNAME"].encode("utf-8"),
            )
            password_ok = hmac.compare_digest(
                (credentials.password or "").encode("utf-8"),
                app.config["UPLOAD_PASSWORD"].encode("utf-8"),
            )
            valid = username_ok and password_ok
        if not valid:
            return Response(
                "Authentication required.\n",
                status=401,
                headers={"WWW-Authenticate": 'Basic realm="Token log analysis"'},
                content_type="text/plain; charset=utf-8",
            )
        return None

    def upload_csrf_token() -> str:
        """Get or create the per-session CSRF token for upload forms."""
        token = session.get("upload_csrf")
        if not isinstance(token, str):
            token = secrets.token_urlsafe(32)
            session["upload_csrf"] = token
        return token

    def csrf_is_valid() -> bool:
        """Validate a state-changing form submission against the session token."""
        supplied = request.form.get("csrf_token", "")
        expected = session.get("upload_csrf", "")
        return (
            isinstance(expected, str)
            and bool(supplied)
            and hmac.compare_digest(supplied, expected)
        )

    def upload_directory(upload_id: str) -> Path:
        """Resolve an opaque upload ID to its stored analysis directory."""
        if not re.fullmatch(r"[a-f0-9]{32}", upload_id):
            abort(404)
        return Path(app.config["ANALYSIS_DATA_DIR"]) / upload_id

    @app.route("/upload", methods=["GET", "POST"])
    def upload_logs():
        """Accept, analyze, and report one authenticated CSV or JSONL upload."""
        auth_error = upload_auth_error()
        if auth_error is not None:
            return auth_error
        if request.method == "GET":
            return render_template(
                "upload.html", csrf_token=upload_csrf_token(),
                hide_dataset_metadata=True,
            )
        if not csrf_is_valid():
            return render_template(
                "upload.html", csrf_token=upload_csrf_token(),
                error="The form expired or was invalid. Please try again.",
                hide_dataset_metadata=True,
            ), 400

        log_file = request.files.get("log_file")
        if log_file is None or not log_file.filename:
            return render_template(
                "upload.html", csrf_token=upload_csrf_token(),
                error="Choose a CSV or JSONL log file.",
                hide_dataset_metadata=True,
            ), 400
        original_filename = log_file.filename.replace("\\", "/").rsplit("/", 1)[-1]
        if (
            not original_filename
            or len(original_filename) > 256
            or any(ord(character) < 32 or ord(character) == 127 for character in original_filename)
        ):
            return render_template(
                "upload.html", csrf_token=upload_csrf_token(),
                error="The uploaded filename is invalid or longer than 256 characters.",
                hide_dataset_metadata=True,
            ), 400
        suffix = Path(original_filename).suffix.lower()
        if suffix not in (".csv", ".jsonl"):
            return render_template(
                "upload.html", csrf_token=upload_csrf_token(),
                error="Upload a .csv or .jsonl file.",
                hide_dataset_metadata=True,
            ), 400

        geo_file = request.files.get("geo_table")
        if geo_file is not None and geo_file.filename:
            geo_name = geo_file.filename.replace("\\", "/").rsplit("/", 1)[-1]
            if Path(geo_name).suffix.lower() != ".csv":
                return render_template(
                    "upload.html", csrf_token=upload_csrf_token(),
                    error="The geo table must be a .csv file.",
                    hide_dataset_metadata=True,
                ), 400
        else:
            geo_file = None

        baseline_days_text = request.form.get("baseline_days", "").strip()
        baseline_until = request.form.get("baseline_until", "").strip() or None
        try:
            baseline_days = int(baseline_days_text) if baseline_days_text else None
        except ValueError:
            return render_template(
                "upload.html", csrf_token=upload_csrf_token(),
                error="Baseline days must be a positive integer.",
                hide_dataset_metadata=True,
            ), 400
        if baseline_days is not None and baseline_until is not None:
            return render_template(
                "upload.html", csrf_token=upload_csrf_token(),
                error="Choose either baseline days or a baseline-until timestamp.",
                hide_dataset_metadata=True,
            ), 400

        upload_id = uuid.uuid4().hex
        upload_dir = upload_directory(upload_id)
        source_path = upload_dir / f"input{suffix}"
        geo_path = upload_dir / "geo-table.csv" if geo_file is not None else None
        output_dir = upload_dir / "analysis"
        upload_directory_created = False
        try:
            upload_dir.mkdir(parents=True, mode=0o700)
            upload_directory_created = True
            log_file.save(source_path)
            if geo_file is not None and geo_path is not None:
                geo_file.save(geo_path)
            report = analyze_input(
                source_path,
                output_dir,
                source_filename=original_filename,
                baseline_days=baseline_days,
                baseline_until=baseline_until,
                geo_table=geo_path,
                column_map=request.form.get("column_map", "").strip() or None,
                assume_utc=request.form.get("assume_utc") == "on",
                skip_bad_rows=request.form.get("skip_bad_rows") == "on",
                max_rows=500_000,
            )
        except (InputFileError, OSError, sqlite3.Error, ValueError) as error:
            if upload_directory_created:
                shutil.rmtree(upload_dir)
            return render_template(
                "upload.html", csrf_token=upload_csrf_token(),
                error=str(error), hide_dataset_metadata=True,
            ), 400

        for staged_file in (source_path, geo_path):
            if staged_file is not None:
                try:
                    staged_file.unlink(missing_ok=True)
                except OSError:
                    app.logger.warning("Could not remove staged upload file %s", staged_file)
        return render_template(
            "upload_result.html",
            upload_id=upload_id,
            source_filename=original_filename,
            report=report,
            csrf_token=upload_csrf_token(),
            hide_dataset_metadata=True,
        )

    @app.route("/uploads/<upload_id>")
    def uploaded_result(upload_id: str):
        """Show the summary for an authenticated analysis."""
        auth_error = upload_auth_error()
        if auth_error is not None:
            return auth_error
        directory = upload_directory(upload_id) / "analysis"
        summary_path = directory / "summary.json"
        if not summary_path.is_file():
            abort(404)
        try:
            report = json.loads(summary_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            abort(404)
        return render_template(
            "upload_result.html",
            upload_id=upload_id,
            source_filename=report["run_parameters"]["input_file"],
            report=report,
            csrf_token=upload_csrf_token(),
            hide_dataset_metadata=True,
        )

    @app.route("/uploads/<upload_id>/<filename>")
    def uploaded_output(upload_id: str, filename: str):
        """Serve only generated report artifacts to the authenticated uploader."""
        auth_error = upload_auth_error()
        if auth_error is not None:
            return auth_error
        if filename not in UPLOAD_OUTPUTS:
            abort(404)
        path = upload_directory(upload_id) / "analysis" / filename
        if not path.is_file():
            abort(404)
        return send_file(
            path,
            as_attachment=filename != "report.html",
            download_name=filename,
            max_age=0,
        )

    @app.route("/uploads/<upload_id>/delete", methods=["POST"])
    def delete_uploaded_analysis(upload_id: str):
        """Delete a stored analysis after an authenticated CSRF-checked request."""
        auth_error = upload_auth_error()
        if auth_error is not None:
            return auth_error
        if not csrf_is_valid():
            abort(400)
        directory = upload_directory(upload_id)
        if not directory.is_dir():
            abort(404)
        shutil.rmtree(directory)
        session.pop("upload_csrf", None)
        return redirect(url_for("upload_logs"))

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
