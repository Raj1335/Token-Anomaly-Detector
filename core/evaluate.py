"""Evaluate campaign, event, false-positive, and exposure outcomes from labels."""

import json
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path

from core.timeutil import format_ts, parse_ts

EXPECTED = (
    ("camp_travel", "impossible_travel", "impossible_travel", "sess_005", 1),
    ("camp_scope", "scope_creep", "scope_deviation", "int_003", 1),
    ("camp_temporal", "temporal_anomaly", "temporal", "sess_012", 1),
)


def evaluate_database(db_path: str) -> dict:
    """Join detected alerts to ground truth and replace the evaluation report."""
    connection = sqlite3.connect(db_path)
    connection.row_factory = sqlite3.Row
    try:
        metadata = dict(connection.execute("SELECT key, value FROM metadata"))
        seed = int(metadata["seed"])
        start = parse_ts(metadata["dataset_start_utc"])
        eval_start = parse_ts(metadata["baseline_end_utc"])
        eval_end = parse_ts(metadata["eval_end_utc"])
        label_count = connection.execute("SELECT COUNT(*) FROM labels").fetchone()[0]
        event_count = connection.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        orphan_count = connection.execute(
            "SELECT COUNT(*) FROM labels l LEFT JOIN events e "
            "ON e.event_id=l.event_id WHERE e.event_id IS NULL"
        ).fetchone()[0]
        missing_count = event_count - label_count
        if label_count != event_count or orphan_count or missing_count:
            raise ValueError("labels must exactly cover events with no duplicates or orphans")

        eval_events = connection.execute(
            "SELECT * FROM events WHERE ts >= ? AND ts < ?",
            (format_ts(eval_start), format_ts(eval_end)),
        ).fetchall()
        campaign_rows = [
            ["camp_travel", "impossible_travel", "impossible_travel", "sess_005", 1],
            ["camp_scope", "scope_creep", "scope_deviation", "int_003", 1],
            ["camp_temporal", "temporal_anomaly", "temporal", "sess_012", 1],
        ]
        for token_number in range(5, 17):
            campaign_rows.append([
                "camp_drift", "volume_spike", "per_token_rate",
                f"int_{token_number:03d}", 1,
            ])
            campaign_rows.append([
                "camp_drift", "scope_creep", "scope_deviation",
                f"int_{token_number:03d}", 1,
            ])
            campaign_rows.append([
                "camp_drift", "impossible_travel", "impossible_travel",
                f"int_{token_number:03d}", 1,
            ])
        for tenant_number in range(5, 13):
            campaign_rows.append([
                "camp_drift", "volume_spike", "new_ip_fanout",
                f"tenant_{tenant_number:03d}", 1,
            ])

        campaign_results = {}
        for campaign, detector, subtype, target, minimum in campaign_rows:
            key = (campaign, detector, subtype, target)
            if key not in campaign_results:
                campaign_results[key] = {"required": minimum, "found": 0}
            if target.startswith("tenant_"):
                query = (
                    "SELECT COUNT(*) FROM alerts a JOIN events e ON e.event_id=a.event_id "
                    "JOIN labels l ON l.event_id=e.event_id "
                    "WHERE l.campaign_id=? AND a.detector=? AND a.subtype=? "
                    "AND e.tenant_id=?"
                )
                count = connection.execute(
                    query, (campaign, detector, subtype, target)
                ).fetchone()[0]
            else:
                query = (
                    "SELECT COUNT(*) FROM alerts a JOIN events e ON e.event_id=a.event_id "
                    "JOIN labels l ON l.event_id=e.event_id "
                    "WHERE l.campaign_id=? AND a.detector=? AND a.subtype=? "
                    "AND e.token_id=?"
                )
                count = connection.execute(
                    query, (campaign, detector, subtype, target)
                ).fetchone()[0]
            if campaign == "camp_drift" and subtype == "new_ip_fanout":
                count = connection.execute(
                    "SELECT COUNT(DISTINCT e.tenant_id) FROM alerts a "
                    "JOIN events e ON e.event_id=a.event_id "
                    "JOIN labels l ON l.event_id=e.event_id "
                    "WHERE l.campaign_id=? AND a.detector=? AND a.subtype=?",
                    (campaign, detector, subtype),
                ).fetchone()[0]
            campaign_results[key]["found"] = max(campaign_results[key]["found"], count)

        campaign_pass = {}
        for campaign in ("camp_travel", "camp_scope", "camp_temporal", "camp_drift"):
            campaign_pass[campaign] = all(
                result["found"] >= result["required"]
                for key, result in campaign_results.items() if key[0] == campaign
            )

        benign = connection.execute(
            "SELECT COUNT(*) FROM events e JOIN labels l ON l.event_id=e.event_id "
            "WHERE l.is_attack=0 AND e.ts>=? AND e.ts<?",
            (format_ts(eval_start), format_ts(eval_end)),
        ).fetchone()[0]
        benign_alerted = connection.execute(
            "SELECT COUNT(DISTINCT a.event_id) FROM alerts a "
            "JOIN events e ON e.event_id=a.event_id "
            "JOIN labels l ON l.event_id=e.event_id "
            "WHERE l.is_attack=0 AND e.ts>=? AND e.ts<?",
            (format_ts(eval_start), format_ts(eval_end)),
        ).fetchone()[0]
        benign_fraction = benign_alerted / benign if benign else 0.0

        hard_negative = {}
        for scenario in ("hn_ip_churn", "hn_legit_trip", "hn_nightly_batch"):
            subtype = "impossible_travel" if "trip" in scenario or "churn" in scenario else "per_token_rate"
            detector = "impossible_travel" if subtype == "impossible_travel" else "volume_spike"
            count = connection.execute(
                "SELECT COUNT(*) FROM alerts a JOIN events e ON e.event_id=a.event_id "
                "JOIN labels l ON l.event_id=e.event_id "
                "WHERE l.scenario=? AND a.detector=? AND a.subtype=?",
                (scenario, detector, subtype),
            ).fetchone()[0]
            hard_negative[scenario] = count

        report = {
            "seed": seed,
            "created_at": format_ts(datetime.now().astimezone()),
            "campaign_pass": campaign_pass,
            "campaign_results": {
                f"{key[0]}|{key[1]}|{key[2]}|{key[3]}": value
                for key, value in campaign_results.items()
            },
            "false_positive_benign_fraction": benign_fraction,
            "false_positive_benign_alerted_events": benign_alerted,
            "false_positive_benign_events": benign,
            "hard_negative_alert_counts": hard_negative,
        }
        report_path = Path("reports") / f"eval_seed{seed}.json"
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(
            json.dumps(report, indent=2, sort_keys=True), encoding="utf-8"
        )
        with connection:
            connection.execute(
                "INSERT OR REPLACE INTO eval_report(id, seed, created_at, report_json) "
                "VALUES(1, ?, ?, ?)",
                (seed, report["created_at"], json.dumps(report, sort_keys=True)),
            )
        print("Campaign evaluation:")
        print("campaign              result")
        for campaign, passed in campaign_pass.items():
            print(f"{campaign:<22}{'PASS' if passed else 'FAIL'}")
        print(
            f"Benign false positives: {benign_alerted}/{benign} "
            f"({benign_fraction:.2%})"
        )
        print(f"Report: {report_path}")
        return report
    finally:
        connection.close()
