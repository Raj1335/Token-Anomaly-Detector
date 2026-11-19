"""Tests for safe user-supplied log ingestion, analysis, and report exports."""

import csv
import base64
import contextlib
import io
import json
import os
import re
import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from core.timeutil import format_ts
from data.analyze import analyze_input, export_sample_csv
from data.log_input import (
    InputFileError,
    calculate_baseline_boundary,
    parse_log_file,
)
from dashboard.app import create_app


def write_csv(path: Path, headers: list[str], rows: list[dict[str, object]]) -> None:
    """Write a small UTF-8 test CSV with a canonical header."""
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=headers)
        writer.writeheader()
        writer.writerows(rows)


def simple_row(timestamp: str, **updates: object) -> dict[str, object]:
    """Create one valid canonical log row for focused parser tests."""
    row: dict[str, object] = {
        "timestamp": timestamp,
        "token_id": "token_1",
        "source_ip": "203.0.113.10",
        "token_type": "integration",
        "principal": "service",
        "tenant_id": "tenant_1",
        "object_type": "Account",
        "action": "query",
        "records_returned": 5,
        "granted_scopes": "Account:query",
        "geo_lat": "",
        "geo_lon": "",
        "geo_city": "",
    }
    row.update(updates)
    return row


class LogInputTests(unittest.TestCase):
    """Verify schema mapping, strict row validation, geolocation, and split logic."""

    def setUp(self) -> None:
        """Create an isolated temporary directory for each parser case."""
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)

    def tearDown(self) -> None:
        """Remove temporary test files."""
        self.tempdir.cleanup()

    def test_valid_csv_jsonl_and_case_insensitive_mapping(self) -> None:
        """Parse CSV and JSONL while normalizing header case and mapped names."""
        csv_path = self.root / "events.csv"
        write_csv(
            csv_path, ["WHEN", "Token", "IP", "OBJECT"],
            [{"WHEN": "2026-01-01T10:00:00+00:00", "Token": "t1",
              "IP": "2001:db8::1", "OBJECT": "Case"}],
        )
        mapped = parse_log_file(
            csv_path, column_map="when=timestamp,token=token_id,ip=source_ip,object=object_type"
        )
        self.assertEqual(len(mapped.events), 1)
        self.assertEqual(mapped.events[0].token_id, "t1")
        self.assertEqual(mapped.events[0].source_ip, "2001:db8::1")
        self.assertEqual(mapped.events[0].object_type, "Case")

        jsonl_path = self.root / "events.jsonl"
        jsonl_path.write_text(
            json.dumps({
                "timestamp": "2026-01-01T12:00:00Z",
                "token_id": "t2",
                "source_ip": "192.0.2.4",
                "granted_scopes": ["Account:query", "Case:read"],
            }) + "\n",
            encoding="utf-8",
        )
        result = parse_log_file(jsonl_path)
        self.assertEqual(result.events[0].granted_scopes, ("Account:query", "Case:read"))
        self.assertEqual(result.events[0].token_type, "unknown")
        self.assertEqual(result.events[0].principal, "t2")

    def test_missing_required_column_names_it(self) -> None:
        """Reject a schema that omits a required field and name the field."""
        path = self.root / "missing.csv"
        write_csv(path, ["timestamp", "token_id"], [{
            "timestamp": "2026-01-01T00:00:00Z", "token_id": "t1",
        }])
        with self.assertRaisesRegex(InputFileError, "source_ip"):
            parse_log_file(path)

    def test_row_validation_reports_line_numbers_and_skip_count(self) -> None:
        """Report bad timestamp, IP, and record count on source line numbers."""
        path = self.root / "bad.csv"
        write_csv(path, ["timestamp", "token_id", "source_ip", "records_returned"], [
            {"timestamp": "not-a-time", "token_id": "t1", "source_ip": "192.0.2.1",
             "records_returned": "1"},
            {"timestamp": "2026-01-01T00:00:00Z", "token_id": "t2",
             "source_ip": "999.1.1.1", "records_returned": "1"},
            {"timestamp": "2026-01-01T00:00:01Z", "token_id": "t3",
             "source_ip": "192.0.2.3", "records_returned": "-4"},
            {"timestamp": "2026-01-01T00:00:02Z", "token_id": "t4",
             "source_ip": "192.0.2.4", "records_returned": "1"},
        ])
        with self.assertRaises(InputFileError) as caught:
            parse_log_file(path)
        message = str(caught.exception)
        self.assertIn("line 2", message)
        self.assertIn("line 3", message)
        self.assertIn("line 4", message)
        result = parse_log_file(path, skip_bad_rows=True)
        self.assertEqual(result.skipped_rows, 3)
        self.assertEqual(len(result.events), 1)
        self.assertEqual(len(result.errors), 3)

    def test_naive_timestamp_and_assume_utc(self) -> None:
        """Reject naive timestamps by default and accept them only when requested."""
        path = self.root / "naive.csv"
        write_csv(path, ["timestamp", "token_id", "source_ip"], [
            {"timestamp": "2026-01-01T10:00:00", "token_id": "t1",
             "source_ip": "192.0.2.1"},
        ])
        with self.assertRaisesRegex(InputFileError, "--assume-utc"):
            parse_log_file(path)
        result = parse_log_file(path, assume_utc=True)
        self.assertEqual(result.events[0].ts.utcoffset(), timedelta(0))

    def test_row_cap_is_enforced(self) -> None:
        """Stop when the input contains more rows than the configured cap."""
        path = self.root / "many.csv"
        write_csv(path, ["timestamp", "token_id", "source_ip"], [
            {"timestamp": f"2026-01-01T00:00:0{index}Z", "token_id": "t",
             "source_ip": "192.0.2.1"}
            for index in range(2)
        ])
        with self.assertRaisesRegex(InputFileError, "row cap exceeded"):
            parse_log_file(path, max_rows=1)

    def test_geo_coordinates_and_specific_cidr(self) -> None:
        """Use direct coordinates or the most-specific matching CIDR."""
        direct = self.root / "direct.csv"
        write_csv(direct, ["timestamp", "token_id", "source_ip", "geo_lat", "geo_lon", "geo_city"], [
            {"timestamp": "2026-01-01T00:00:00Z", "token_id": "t1",
             "source_ip": "10.1.2.3", "geo_lat": "12.5", "geo_lon": "30.5",
             "geo_city": "Direct"},
        ])
        direct_result = parse_log_file(direct)
        self.assertEqual((direct_result.events[0].geo_lat, direct_result.events[0].geo_lon), (12.5, 30.5))
        self.assertTrue(direct_result.has_geo_data)

        no_coordinates = self.root / "cidr.csv"
        write_csv(no_coordinates, ["timestamp", "token_id", "source_ip"], [
            {"timestamp": "2026-01-01T00:00:00Z", "token_id": "t1",
             "source_ip": "10.1.2.3"},
        ])
        geo_table = self.root / "geo.csv"
        write_csv(geo_table, ["cidr", "lat", "lon", "city"], [
            {"cidr": "10.0.0.0/8", "lat": "1", "lon": "2", "city": "Broad"},
            {"cidr": "10.1.0.0/16", "lat": "3", "lon": "4", "city": "Specific"},
        ])
        mapped = parse_log_file(no_coordinates, geo_table=geo_table)
        self.assertEqual(mapped.events[0].geo_lat, 3.0)
        self.assertEqual(mapped.events[0].geo_city, "Specific")

    def test_baseline_splits_and_short_baseline_warning(self) -> None:
        """Use requested days, exact boundary timestamps, and default 70 percent."""
        path = self.root / "time.csv"
        rows = [
            simple_row(format_ts(datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(days=day)))
            for day in (0, 5, 10)
        ]
        write_csv(path, list(rows[0]), rows)
        parsed = parse_log_file(path)
        start = parsed.events[0].ts
        self.assertEqual(
            calculate_baseline_boundary(parsed.events, baseline_days=3),
            start + timedelta(days=3),
        )
        self.assertEqual(
            calculate_baseline_boundary(parsed.events),
            start + timedelta(days=7),
        )
        self.assertEqual(
            calculate_baseline_boundary(parsed.events, baseline_until="2026-01-04T00:00:00Z"),
            start + timedelta(days=3),
        )
        summary = analyze_input(path, self.root / "out", baseline_days=1)
        self.assertIn("baseline spans fewer than 3 days", summary["warnings"])
        self.assertIn("baseline has fewer than 1,000 events", summary["warnings"])

    def test_no_geo_disables_travel_and_is_reported(self) -> None:
        """Disable impossible-travel detection rather than inventing coordinates."""
        path = self.root / "no_geo.csv"
        write_csv(path, ["timestamp", "token_id", "source_ip"], [
            {"timestamp": "2026-01-01T00:00:00Z", "token_id": "t1",
             "source_ip": "192.0.2.1"},
            {"timestamp": "2026-01-05T00:00:00Z", "token_id": "t1",
             "source_ip": "192.0.2.2"},
        ])
        console = io.StringIO()
        with contextlib.redirect_stdout(console):
            result = analyze_input(path, self.root / "out")
        self.assertEqual(result["disabled_detectors"]["impossible_travel"], "no geo data")
        self.assertIn("impossible_travel disabled: no geo data", console.getvalue())
        report_html = (self.root / "out" / "report.html").read_text(encoding="utf-8")
        self.assertIn("impossible_travel disabled: no geo data", report_html)
        database = sqlite3.connect(self.root / "out" / "analysis.db")
        values = dict(database.execute("SELECT key, value FROM metadata"))
        database.close()
        self.assertEqual(values["impossible_travel_disabled_reason"], "no geo data")

    def test_partial_geo_columns_are_rejected(self) -> None:
        """Require latitude and longitude columns as a pair."""
        path = self.root / "partial_geo.csv"
        write_csv(path, ["timestamp", "token_id", "source_ip", "geo_lat"], [
            {"timestamp": "2026-01-01T00:00:00Z", "token_id": "t1",
             "source_ip": "192.0.2.1", "geo_lat": "1"},
        ])
        with self.assertRaisesRegex(InputFileError, "geo_lat and geo_lon"):
            parse_log_file(path)

    def test_formula_safe_csv_and_escaped_html_report(self) -> None:
        """Escape a hostile principal in HTML and prefix formula cells in CSV."""
        for folder, principal in (
            ("formula_out", '=HYPERLINK("https://example.invalid","x")'),
            ("html_out", "<script>alert(1)</script>"),
        ):
            path = self.root / f"{folder}.csv"
            baseline = [
                simple_row(
                    format_ts(datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(hours=index)),
                    principal="regular",
                )
                for index in range(80)
            ]
            baseline.append(simple_row(
                format_ts(datetime(2026, 1, 4, 8, tzinfo=timezone.utc)),
                object_type="User", principal=principal,
            ))
            write_csv(path, list(baseline[0]), baseline)
            output = self.root / folder
            analyze_input(path, output)
            with (output / "alerts.csv").open("r", encoding="utf-8", newline="") as stream:
                exported = list(csv.DictReader(stream))
            self.assertTrue(any(row["principal"].startswith("'=") for row in exported)) if folder == "formula_out" else None
            report_html = (output / "report.html").read_text(encoding="utf-8")
            if folder == "html_out":
                self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", report_html)
                self.assertNotIn("<script>alert(1)</script>", report_html)

    def test_output_overwrite_requires_force(self) -> None:
        """Refuse an existing output directory unless force is explicit."""
        path = self.root / "once.csv"
        write_csv(path, ["timestamp", "token_id", "source_ip"], [
            {"timestamp": "2026-01-01T00:00:00Z", "token_id": "t",
             "source_ip": "192.0.2.1"},
        ])
        output = self.root / "out"
        analyze_input(path, output)
        with self.assertRaisesRegex(InputFileError, "pass --force"):
            analyze_input(path, output)
        analyze_input(path, output, force=True)


class SampleRoundTripTests(unittest.TestCase):
    """Verify the shipped synthetic sample drives the complete import workflow."""

    @classmethod
    def setUpClass(cls) -> None:
        """Create the 2,000-row sample once for end-to-end testing."""
        cls.tempdir = tempfile.TemporaryDirectory()
        cls.root = Path(cls.tempdir.name)
        cls.sample = cls.root / "sample_logs.csv"
        cls.sample_rows = export_sample_csv(cls.sample)
        cls.output = cls.root / "analysis"
        cls.summary = analyze_input(cls.sample, cls.output)

    @classmethod
    def tearDownClass(cls) -> None:
        """Remove generated sample and analysis files."""
        cls.tempdir.cleanup()

    def test_export_size_and_high_incidents_for_replay_tokens(self) -> None:
        """Retain the Drift replay and derive HIGH incidents without ground truth."""
        self.assertEqual(self.sample_rows, 2000)
        connection = sqlite3.connect(self.output / "analysis.db")
        tokens = {
            row[0] for row in connection.execute(
                "SELECT token_id FROM incidents WHERE severity='HIGH'"
            )
        }
        label_count = connection.execute("SELECT COUNT(*) FROM labels").fetchone()[0]
        connection.close()
        expected = {f"int_{number:03d}" for number in range(5, 17)}
        self.assertTrue(expected.issubset(tokens))
        self.assertEqual(label_count, 0)

    def test_import_dashboard_routes_and_banner(self) -> None:
        """Render all imported-data routes without a synthetic evaluation panel."""
        client = create_app(self.output / "analysis.db").test_client()
        connection = sqlite3.connect(self.output / "analysis.db")
        incident_id = connection.execute(
            "SELECT incident_id FROM incidents ORDER BY incident_id LIMIT 1"
        ).fetchone()[0]
        connection.close()
        paths = [
            "/", "/incidents", f"/incident/{incident_id}", "/token/int_005", "/healthz",
        ]
        for route in paths:
            response = client.get(route)
            self.assertEqual(response.status_code, 200, route)
            if route != "/healthz":
                self.assertIn(b"Imported data: sample_logs.csv", response.data)
                self.assertNotIn(b"Demo using synthetic data", response.data)
        overview = client.get("/")
        self.assertIn(b"No ground truth for imported data", overview.data)
        self.assertNotIn(b"Evaluation results", overview.data)


class WebUploadTests(unittest.TestCase):
    """Verify authenticated, CSRF-protected web uploads and stored results."""

    def setUp(self) -> None:
        """Create isolated upload storage and enable local HTTP test cookies."""
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.environment = patch.dict(os.environ, {
            "UPLOAD_USERNAME": "test-analyst",
            "UPLOAD_PASSWORD": "test-password-at-least-16",
            "UPLOAD_SECRET_KEY": "test-secret-key-with-at-least-32-characters",
            "UPLOAD_COOKIE_SECURE": "0",
            "ANALYSIS_DATA_DIR": str(self.root / "uploads"),
        })
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.addCleanup(self.tempdir.cleanup)
        self.client = create_app(self.root / "synthetic.db").test_client()
        credential = base64.b64encode(
            b"test-analyst:test-password-at-least-16"
        ).decode("ascii")
        self.auth = {"Authorization": f"Basic {credential}"}

    def test_authenticated_upload_report_download_and_delete(self) -> None:
        """Analyze a posted CSV, guard results, and delete them with a CSRF token."""
        unauthorized = self.client.get("/upload")
        self.assertEqual(unauthorized.status_code, 401)
        self.assertIn("WWW-Authenticate", unauthorized.headers)
        wrong_credential = base64.b64encode(
            b"test-analyst:incorrect-password"
        ).decode("ascii")
        self.assertEqual(
            self.client.get(
                "/upload", headers={"Authorization": f"Basic {wrong_credential}"}
            ).status_code,
            401,
        )
        form = self.client.get("/upload", headers=self.auth)
        self.assertEqual(form.status_code, 200)
        self.assertIn(b"Analyze a log file", form.data)
        self.assertEqual(
            form.headers.get("Content-Security-Policy"), "default-src 'self'"
        )
        self.assertEqual(form.headers.get("Cache-Control"), "no-store")
        self.assertIn(b">Analyze logs</a>", form.data)
        token_match = re.search(rb'name="csrf_token" value="([^"]+)"', form.data)
        self.assertIsNotNone(token_match)
        assert token_match is not None
        csrf_token = token_match.group(1).decode("ascii")

        csv_content = (
            "timestamp,token_id,source_ip\n"
            "2026-01-01T00:00:00Z,web_token,192.0.2.1\n"
            "2026-01-01T01:00:00Z,web_token,192.0.2.1\n"
            "2026-01-01T02:00:00Z,web_token,192.0.2.1\n"
            "2026-01-01T03:00:00Z,web_token,192.0.2.1\n"
        ).encode("utf-8")
        response = self.client.post(
            "/upload",
            headers=self.auth,
            data={
                "csrf_token": csrf_token,
                "log_file": (io.BytesIO(csv_content), "customer-events.csv"),
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"customer-events.csv", response.data)
        self.assertIn(b"Analysis complete", response.data)
        upload_match = re.search(
            rb'/uploads/([a-f0-9]{32})/report\.html', response.data
        )
        self.assertIsNotNone(upload_match)
        assert upload_match is not None
        upload_id = upload_match.group(1).decode("ascii")
        upload_dir = self.root / "uploads" / upload_id
        self.assertFalse((upload_dir / "input.csv").exists())
        self.assertTrue((upload_dir / "analysis" / "analysis.db").is_file())

        self.assertEqual(self.client.get(f"/uploads/{upload_id}").status_code, 401)
        report_response = self.client.get(
            f"/uploads/{upload_id}/report.html", headers=self.auth
        )
        self.assertEqual(report_response.status_code, 200)
        self.assertIn(b"Token Anomaly Analysis Report", report_response.data)
        self.assertEqual(report_response.headers.get("Cache-Control"), "no-store")
        self.assertEqual(
            report_response.headers.get("Content-Security-Policy"),
            "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; "
            "form-action 'none'; frame-ancestors 'none'",
        )
        self.assertNotIn(b"<script", report_response.data.lower())
        report_response.close()
        self.assertEqual(
            self.client.get(
                f"/uploads/{upload_id}/unexpected.txt", headers=self.auth
            ).status_code,
            404,
        )
        self.assertEqual(
            self.client.post(
                f"/uploads/{upload_id}/delete",
                headers=self.auth,
                data={"csrf_token": "invalid"},
            ).status_code,
            400,
        )
        deleted = self.client.post(
            f"/uploads/{upload_id}/delete",
            headers=self.auth,
            data={"csrf_token": csrf_token},
        )
        self.assertEqual(deleted.status_code, 302)
        self.assertFalse(upload_dir.exists())

    def test_upload_endpoint_fails_closed_on_partial_auth_configuration(self) -> None:
        """Do not accidentally expose uploads when auth variables are incomplete."""
        with patch.dict(os.environ, {
            "UPLOAD_USERNAME": "configured-user",
            "UPLOAD_PASSWORD": "",
            "UPLOAD_SECRET_KEY": "",
        }):
            client = create_app(self.root / "synthetic.db").test_client()
            response = client.get("/upload")
        self.assertEqual(response.status_code, 503)
        self.assertIn(b"Log uploads are disabled", response.data)

    def test_public_upload_works_without_render_configuration(self) -> None:
        """Allow demo uploads without credentials when auth is not configured."""
        with patch.dict(os.environ, {
            "UPLOAD_USERNAME": "",
            "UPLOAD_PASSWORD": "",
            "UPLOAD_SECRET_KEY": "",
        }):
            client = create_app(self.root / "synthetic.db").test_client()
            form = client.get("/upload")
            self.assertEqual(form.status_code, 200)
            self.assertIn(b"sanitized", form.data)
            response = client.post(
                "/upload",
                data={
                    "log_file": (
                        io.BytesIO(
                            b"timestamp,token_id,source_ip\n"
                            b"2026-01-01T00:00:00Z,public_token,192.0.2.1\n"
                            b"2026-01-01T01:00:00Z,public_token,192.0.2.1\n"
                        ),
                        "demo.csv",
                    ),
                },
                content_type="multipart/form-data",
            )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Analysis complete", response.data)
        self.assertIn(b"demo.csv", response.data)

    def test_upload_size_limit_returns_a_clear_413(self) -> None:
        """Return a clear error when the configured request cap is exceeded."""
        self.client.application.config["MAX_CONTENT_LENGTH"] = 64
        response = self.client.post(
            "/upload",
            headers=self.auth,
            data={
                "csrf_token": "oversized",
                "log_file": (io.BytesIO(b"x" * 256), "large.csv"),
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 413)
        self.assertIn(b"100 MiB request-size limit", response.data)


if __name__ == "__main__":
    unittest.main()
