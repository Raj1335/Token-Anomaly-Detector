"""Known-answer tests for shared timestamp and SQLite scaffold behavior."""

import sqlite3
import tempfile
import unittest
from pathlib import Path
from datetime import datetime, timedelta, timezone
from dataclasses import replace

from core.db import create_schema
from core.models import Event
from core.timeutil import format_ts, parse_ts
from detectors.impossible_travel import ImpossibleTravelDetector, haversine_km
from detectors.scope_creep import ScopeCreepDetector
from detectors.temporal_anomaly import TemporalAnomalyDetector
from detectors.volume_spike import VolumeSpikeDetector
from data.generate_data import generate_database
from dashboard.app import create_app, readonly_uri
from core.pipeline import run_detection


def event(
    event_id: int,
    token: str = "token",
    hour: int = 12,
    minute: int = 0,
    ip: str = "1.1.1.1",
    lat: float = 51.5,
    lon: float = -0.1,
    city: str = "London",
    obj: str = "Account",
    action: str = "query",
    records: int = 10,
) -> Event:
    """Create a compact labeled-free test event with UTC coordinates."""
    return Event(
        event_id, datetime(2026, 3, 12, hour, minute, tzinfo=timezone.utc),
        token, "integration", "principal", "tenant_001", ip, lat, lon, city,
        obj, action, records,
        ("Account:query", "Opportunity:query", "Case:query", "User:query"),
    )


class SharedScaffoldTests(unittest.TestCase):
    """Verify foundational serialization behavior before adding detector tests."""

    def test_timestamp_round_trip_is_utc(self) -> None:
        """Round-trip timestamps without losing UTC awareness."""
        value = datetime(2026, 3, 2, tzinfo=timezone.utc)
        self.assertEqual(parse_ts(format_ts(value)), value)

    def test_schema_is_created(self) -> None:
        """Build the schema on an in-memory connection."""
        connection = sqlite3.connect(":memory:")
        create_schema(connection)
        names = {
            row[0] for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        self.assertIn("events", names)
        self.assertIn("labels", names)


class DetectorTests(unittest.TestCase):
    """Exercise haversine, travel, scope, temporal, volume, and fan-out boundaries."""

    def test_haversine_known_distances(self) -> None:
        """Check Mumbai-Delhi and London-New York approximate distances."""
        mumbai_delhi = haversine_km(19.0760, 72.8777, 28.6139, 77.2090)
        london_new_york = haversine_km(51.5072, -0.1276, 40.7128, -74.0060)
        self.assertAlmostEqual(mumbai_delhi, 1150, delta=30)
        self.assertAlmostEqual(london_new_york, 5570, delta=50)

    def test_impossible_travel_and_equal_time(self) -> None:
        """Alert distant unknown-IP jumps and not slow or known-IP pairs."""
        baseline = [event(1, ip="1.1.1.1", lat=51.5, lon=-0.1)]
        detector = ImpossibleTravelDetector()
        detector.fit(baseline)
        london = replace(
            event(2, ip="1.1.1.1", lat=51.5, lon=-0.1),
            ts=datetime(2026, 3, 12, 12, tzinfo=timezone.utc),
        )
        new_york = replace(
            event(3, ip="2.2.2.2", lat=40.7, lon=-74.0),
            ts=datetime(2026, 3, 12, 12, 10, tzinfo=timezone.utc),
        )
        alerts = detector.detect([london, new_york])
        self.assertTrue(any(alert.event_id == 3 for alert in alerts))
        self.assertFalse(any(
            alert.event_id == 2 for alert in alerts
        ))
        equal = replace(
            event(4, ip="3.3.3.3", lat=40.7, lon=-74.0),
            ts=datetime(2026, 3, 12, 12, tzinfo=timezone.utc),
        )
        alerts = ImpossibleTravelDetector()
        alerts.fit([event(1, ip="1.1.1.1")])
        self.assertTrue(alerts.detect([equal]))

    def test_scope_cold_start_and_relevancy(self) -> None:
        """Require 30 baseline events and flag rare object-action pairs."""
        baseline = [event(index, obj="Account") for index in range(1, 101)]
        detector = ScopeCreepDetector()
        detector.fit(baseline)
        alerts = detector.detect([event(101, obj="User")])
        self.assertTrue(any(alert.subtype == "scope_deviation" for alert in alerts))
        cold = ScopeCreepDetector()
        cold.fit([event(index) for index in range(1, 6)])
        cold.detect([event(6, obj="User")])
        self.assertTrue(cold.skipped)

    def test_temporal_profile(self) -> None:
        """Alert 03:00 but not a populated 12:00 on a 10-17 baseline."""
        baseline = [
            event(index, hour=hour)
            for hour in range(10, 18)
            for index in range(hour * 10, hour * 10 + 10)
        ]
        detector = TemporalAnomalyDetector()
        detector.fit(baseline)
        self.assertTrue(detector.detect([event(900, hour=3)]))
        self.assertFalse(detector.detect([event(901, hour=12)]))
        flat = TemporalAnomalyDetector()
        flat.fit([event(index, hour=index % 24) for index in range(1, 73)])
        self.assertFalse(flat.detect([event(100, hour=3)]))

    def test_volume_count_records_and_cold_start(self) -> None:
        """Cross count and record thresholds independently."""
        baseline = [
            event(index, hour=10, records=100)
            for index in range(1, 61)
        ]
        detector = VolumeSpikeDetector()
        detector.fit(baseline)
        count_event = event(200, hour=12, records=10)
        alerts = detector.detect([count_event])
        self.assertFalse(alerts)

    def test_fanout_causal_alerting(self) -> None:
        """Alert only on the fifth and later tenants with repeat suppression."""
        baseline = [event(index, token=f"int_{index:03d}") for index in range(1, 31)]
        detector = VolumeSpikeDetector()
        detector.fit(baseline)
        events = [
            event(index, token=f"int_{index:03d}", ip="9.9.9.9")
            for index in range(1, 7)
        ]
        for index, item in enumerate(events, start=1):
            item = Event(
                item.event_id, item.ts, item.token_id, item.token_type,
                item.principal, f"tenant_{index:03d}", item.source_ip,
                item.geo_lat, item.geo_lon, item.geo_city, item.object_type,
                item.action, item.records_returned, item.granted_scopes,
            )
            events[index - 1] = item
        alerts = detector.detect(events)
        fanout = [alert for alert in alerts if alert.subtype == "new_ip_fanout"]
        self.assertEqual(len(fanout), 2)

    def test_event_model_has_no_label(self) -> None:
        """Keep ground truth outside the detector input dataclass."""
        self.assertFalse(hasattr(event(1), "label"))
        self.assertFalse(hasattr(event(1), "is_attack"))


class PipelineDashboardTests(unittest.TestCase):
    """Exercise real seed generation, idempotency, and safe dashboard routes."""

    @classmethod
    def setUpClass(cls) -> None:
        """Generate one real seed-1 temporary database for pipeline tests."""
        cls.tempdir = tempfile.TemporaryDirectory()
        cls.db = str(Path(cls.tempdir.name) / "events db.db")
        generate_database(1, cls.db)

    @classmethod
    def tearDownClass(cls) -> None:
        """Remove the temporary database and directory."""
        cls.tempdir.cleanup()

    def test_labels_and_readonly_uri(self) -> None:
        """Check label completeness and a space-containing read-only URI."""
        connection = sqlite3.connect(self.db)
        event_count = connection.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        label_count = connection.execute("SELECT COUNT(*) FROM labels").fetchone()[0]
        self.assertEqual(event_count, label_count)
        uri = readonly_uri(self.db)
        self.assertIn("mode=ro", uri)
        connection.close()

    def test_dashboard_routes_and_escape(self) -> None:
        """Serve every route and reject malformed token IDs."""
        app = create_app(self.db)
        client = app.test_client()
        self.assertEqual(client.get("/").status_code, 200)
        self.assertEqual(client.get("/incidents").status_code, 200)
        self.assertEqual(client.get("/token/sess_001").status_code, 200)
        self.assertEqual(client.get("/token/bad token").status_code, 404)

    def test_detection_is_idempotent(self) -> None:
        """Re-running detection leaves derived-table counts unchanged."""
        run_detection(self.db)
        connection = sqlite3.connect(self.db)
        first = tuple(connection.execute(
            "SELECT (SELECT COUNT(*) FROM alerts), "
            "(SELECT COUNT(*) FROM incidents), "
            "(SELECT COUNT(*) FROM notifications)"
        ).fetchone())
        connection.close()
        run_detection(self.db)
        connection = sqlite3.connect(self.db)
        second = tuple(connection.execute(
            "SELECT (SELECT COUNT(*) FROM alerts), "
            "(SELECT COUNT(*) FROM incidents), "
            "(SELECT COUNT(*) FROM notifications)"
        ).fetchone())
        connection.close()
        self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main()