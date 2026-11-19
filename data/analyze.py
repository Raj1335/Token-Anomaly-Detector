"""Persist imported logs, run detection, and write portable analysis outputs."""

import csv
import html
import json
import random
import sqlite3
from collections import Counter
from datetime import timedelta
from pathlib import Path
from typing import Any

from core.db import connect, create_schema, insert_dataset
from core.pipeline import run_detection
from core.timeutil import format_ts
from data.log_input import (
    InputFileError,
    ParseResult,
    calculate_baseline_boundary,
    imported_metadata,
    parse_log_file,
)

DETECTOR_NAMES = (
    "impossible_travel", "scope_creep", "temporal_anomaly", "volume_spike",
)


def _spreadsheet_safe(value: Any) -> str:
    """Prefix spreadsheet formula-like cells to prevent formula execution."""
    text = "" if value is None else str(value)
    if text.startswith(("=", "+", "-", "@", "\t", "\r")):
        return "'" + text
    return text


def _write_csv(path: Path, fieldnames: list[str], rows: list[dict[str, Any]]) -> None:
    """Write UTF-8 CSV output with spreadsheet-safe cells."""
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({key: _spreadsheet_safe(row.get(key)) for key in fieldnames})


def _write_html_report(path: Path, report: dict[str, Any]) -> None:
    """Create a self-contained HTML report with every untrusted value escaped."""
    esc = lambda value: html.escape(str(value), quote=True)
    severity_rows = "".join(
        f"<tr><th scope='row'>{esc(severity)}</th><td>{report['severity_counts'].get(severity, 0):,}</td></tr>"
        for severity in ("HIGH", "MEDIUM", "LOW")
    )
    detector_rows = "".join(
        f"<tr><th scope='row'>{esc(name)}</th><td>{count:,}</td></tr>"
        for name, count in sorted(report["alert_counts"].items())
    ) or "<tr><td colspan='2'>No alerts</td></tr>"
    incident_rows = []
    for incident in report["top_incidents"]:
        reasons = "<br>".join(esc(reason) for reason in incident["reasons"])
        incident_rows.append(
            "<tr>"
            f"<td>{esc(incident['token_id'])}</td><td>{esc(incident['principal'])}</td>"
            f"<td>{esc(incident['severity'])}</td>"
            f"<td>{esc(', '.join(incident['detectors']))}</td>"
            f"<td>{esc(incident['first_alert'])}</td><td>{esc(incident['last_alert'])}</td>"
            f"<td>{reasons}</td></tr>"
        )
    incident_body = "".join(incident_rows) or "<tr><td colspan='7'>No incidents</td></tr>"
    skip_rows = []
    for detector in DETECTOR_NAMES:
        reasons = report["skipped_detectors"].get(detector, {})
        detail = ", ".join(f"{esc(reason)}: {count}" for reason, count in reasons.items())
        if detector in report["disabled_detectors"]:
            detail = f"{esc(detector)} disabled: {esc(report['disabled_detectors'][detector])}"
        skip_rows.append(f"<tr><th scope='row'>{esc(detector)}</th><td>{detail or 'None'}</td></tr>")
    metadata_rows = "".join(
        f"<tr><th scope='row'>{esc(key)}</th><td>{esc(value)}</td></tr>"
        for key, value in report["run_parameters"].items()
    )
    quality_rows = "".join(
        f"<tr><th scope='row'>{esc(key.replace('_', ' ').title())}</th><td>{esc(value)}</td></tr>"
        for key, value in report["data_quality"].items()
    )
    warning_list = "".join(f"<li>{esc(warning)}</li>" for warning in report["warnings"])
    document = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Token Anomaly Analysis Report</title><style>
body{{font:15px system-ui,Segoe UI,sans-serif;line-height:1.55;max-width:1100px;margin:32px auto;padding:0 20px;color:#17212b;background:#f4f6f8}}
h1,h2{{line-height:1.2}}h1{{font-size:30px}}section{{background:#fff;border:1px solid #d7dfe5;border-radius:8px;padding:20px;margin:16px 0}}
table{{width:100%;border-collapse:collapse;display:block;overflow-x:auto}}th,td{{text-align:left;padding:9px;border-bottom:1px solid #d7dfe5;vertical-align:top}}
th{{font-size:12px;color:#435568}}code{{font-family:Consolas,monospace;overflow-wrap:anywhere}}.note{{color:#526170}}
@media(prefers-color-scheme:dark){{body{{background:#101820;color:#edf3f7}}section{{background:#18232d;border-color:#354550}}th{{color:#bdc9d2}}td{{border-color:#354550}}.note{{color:#bdc9d2}}}}
</style></head><body>
<header><h1>Token Anomaly Analysis Report</h1><p class="note">Generated from user-supplied log data. All timestamps are UTC.</p></header>
<section><h2>Run parameters</h2><table><tbody>{metadata_rows}</tbody></table></section>
<section><h2>Data quality</h2><table><tbody>{quality_rows}</tbody></table></section>
<section><h2>Incidents by severity</h2><table><tbody>{severity_rows}</tbody></table></section>
<section><h2>Top incidents</h2><table><thead><tr><th scope="col">Token</th><th scope="col">Principal</th><th scope="col">Severity</th><th scope="col">Detectors</th><th scope="col">First alert</th><th scope="col">Last alert</th><th scope="col">Reasons</th></tr></thead><tbody>{incident_body}</tbody></table></section>
<section><h2>Alerts by detector</h2><table><tbody>{detector_rows}</tbody></table></section>
<section><h2>Skipped and disabled detectors</h2><table><tbody>{''.join(skip_rows)}</tbody></table></section>
<section><h2>Warnings</h2>{'<ul>' + warning_list + '</ul>' if warning_list else '<p>None</p>'}</section>
<section><h2>Limitations</h2><p>Detectors were tuned on synthetic data and require an appropriate, clean historical baseline. Results are rule-based signals, not proof of compromise. Geographic conclusions are only as accurate as the supplied coordinates or CIDR mapping.</p></section>
</body></html>"""
    path.write_text(document, encoding="utf-8")


def validate_input(
    input_path: str | Path,
    column_map: str | None = None,
    assume_utc: bool = False,
    max_rows: int = 500_000,
) -> ParseResult:
    """Run schema and row validation without writing a database."""
    result = parse_log_file(
        input_path, column_map=column_map, assume_utc=assume_utc,
        max_rows=max_rows,
    )
    print(
        f"Valid input: {result.rows_read} rows read, "
        f"{len(result.events)} valid, {result.skipped_rows} skipped"
    )
    if not result.events:
        raise InputFileError("input contains no valid events")
    print(f"Timestamp range: {format_ts(min(event.ts for event in result.events))} to "
          f"{format_ts(max(event.ts for event in result.events))}")
    print("Geo data: available" if result.has_geo_data else
          "impossible_travel disabled: no geo data")
    return result


def export_sample_csv(output_path: str | Path, seed: int = 1, row_limit: int = 2000) -> int:
    """Export a compact synthetic sample retaining replay baselines and attacks."""
    from data.generate_data import DATASET_START, _make_rows

    events, labels, _ = _make_rows(seed)
    attacks_by_id = {event_id for event_id, is_attack, scenario, _ in labels
                     if is_attack and scenario == "drift_replay"}
    replay_tokens = {f"int_{number:03d}" for number in range(5, 17)}
    by_token: dict[str, list[Any]] = {}
    baseline_cutoff = DATASET_START + timedelta(days=7)
    for event in events:
        if (
            event.token_id.startswith("int_")
            and event.token_id in replay_tokens
            and event.ts < baseline_cutoff
        ):
            by_token.setdefault(event.token_id, []).append(event)
    selected: dict[int, Any] = {}
    for token_id in sorted(by_token):
        baseline = by_token[token_id]
        if len(baseline) < 30:
            raise InputFileError(f"cannot build sample: insufficient baseline for {token_id}")
        for index in range(30):
            position = round(index * (len(baseline) - 1) / 29)
            chosen = baseline[position]
            selected[chosen.event_id] = chosen
    for event in events:
        if event.event_id in attacks_by_id:
            selected[event.event_id] = event
    if len(selected) > row_limit:
        raise InputFileError("sample row limit is too small to retain replay data")
    pool = [
        event for event in events
        if event.ts < baseline_cutoff and event.event_id not in selected
    ]
    rng = random.Random(seed)
    needed = row_limit - len(selected)
    if needed > len(pool):
        raise InputFileError("not enough synthetic rows to fill requested sample")
    for event in rng.sample(pool, needed):
        selected[event.event_id] = event

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = [
        "timestamp", "token_id", "source_ip", "token_type", "principal",
        "tenant_id", "object_type", "action", "records_returned",
        "granted_scopes", "geo_lat", "geo_lon", "geo_city",
    ]
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        for event in sorted(selected.values(), key=lambda item: (item.ts, item.event_id)):
            writer.writerow({
                "timestamp": format_ts(event.ts),
                "token_id": event.token_id,
                "source_ip": event.source_ip,
                "token_type": event.token_type,
                "principal": event.principal,
                "tenant_id": event.tenant_id,
                "object_type": event.object_type,
                "action": event.action,
                "records_returned": event.records_returned,
                "granted_scopes": ";".join(event.granted_scopes),
                "geo_lat": event.geo_lat,
                "geo_lon": event.geo_lon,
                "geo_city": event.geo_city,
            })
    print(f"Exported {len(selected)} synthetic sample rows to {path}")
    return len(selected)


def analyze_input(
    input_path: str | Path,
    out_dir: str | Path,
    *,
    baseline_days: int | None = None,
    baseline_until: str | None = None,
    geo_table: str | Path | None = None,
    column_map: str | None = None,
    assume_utc: bool = False,
    skip_bad_rows: bool = False,
    max_rows: int = 500_000,
    force: bool = False,
) -> dict[str, Any]:
    """Analyze an input log and write a database, CSV exports, summary, and report."""
    result = parse_log_file(
        input_path, column_map=column_map, assume_utc=assume_utc,
        skip_bad_rows=skip_bad_rows, max_rows=max_rows, geo_table=geo_table,
    )
    if not result.events:
        raise InputFileError("input contains no valid events")
    boundary = calculate_baseline_boundary(
        result.events, baseline_days, baseline_until, assume_utc
    )
    start = min(event.ts for event in result.events)
    end = max(event.ts for event in result.events)
    baseline_events = [event for event in result.events if event.ts < boundary]
    eval_events = [event for event in result.events if event.ts >= boundary]
    warnings: list[str] = []
    if boundary - start < timedelta(days=3):
        warnings.append("baseline spans fewer than 3 days")
    if len(baseline_events) < 1000:
        warnings.append("baseline has fewer than 1,000 events")

    output = Path(out_dir)
    if output.exists() and not force:
        raise InputFileError(f"output directory already exists: {output}; pass --force to overwrite")
    output.mkdir(parents=True, exist_ok=True)
    db_path = output / "analysis.db"
    if db_path.exists():
        db_path.unlink()
    metadata = imported_metadata(
        str(input_path), result.events, boundary, result.rows_read,
        result.skipped_rows, result.has_geo_data,
    )
    metadata.update({
        "input_baseline_days": str(baseline_days or ""),
        "input_baseline_until": baseline_until or "",
        "skip_bad_rows": skip_bad_rows,
        "input_geo_table": Path(geo_table).name if geo_table else "",
        "input_column_map": column_map or "",
        "input_assume_utc": "1" if assume_utc else "0",
        "input_max_rows": str(max_rows),
        "input_skip_bad_rows": "1" if skip_bad_rows else "0",
    })
    connection = connect(db_path)
    try:
        create_schema(connection)
        insert_dataset(connection, result.events, [], metadata)
    finally:
        connection.close()

    disabled = set()
    disabled_reasons: dict[str, str] = {}
    if not result.has_geo_data:
        disabled.add("impossible_travel")
        disabled_reasons["impossible_travel"] = "no geo data"
    alerts = run_detection(str(db_path), disabled_detectors=disabled)
    connection = sqlite3.connect(db_path)
    connection.row_factory = sqlite3.Row
    try:
        incidents = connection.execute(
            "SELECT * FROM incidents ORDER BY alert_count DESC, start_ts LIMIT 200"
        ).fetchall()
        severity_counts = Counter(
            row[0] for row in connection.execute(
                "SELECT severity FROM incidents"
            ).fetchall()
        )
        severity_counts = Counter({
            severity: severity_counts.get(severity, 0)
            for severity in ("HIGH", "MEDIUM", "LOW")
        })
        alert_counts = Counter(alert.detector for alert in alerts)
        subtype_counts = Counter(f"{alert.detector}/{alert.subtype}" for alert in alerts)
        raw_skips = dict(connection.execute(
            "SELECT key, value FROM metadata WHERE key IN "
            "('detection_skips_json', 'disabled_detectors_json')"
        ))
        try:
            skipped_detectors = json.loads(raw_skips.get("detection_skips_json", "{}"))
        except json.JSONDecodeError:
            skipped_detectors = {}
        top_incidents: list[dict[str, Any]] = []
        for incident in incidents[:20]:
            alert_rows = connection.execute(
                "SELECT detector, ts, reason FROM alerts WHERE incident_id=? "
                "ORDER BY ts, alert_id LIMIT 100",
                (incident["incident_id"],),
            ).fetchall()
            detectors = json.loads(incident["detectors_json"])
            top_incidents.append({
                "token_id": incident["token_id"],
                "principal": connection.execute(
                    """SELECT e.principal FROM alerts a
                       JOIN events e ON e.event_id=a.event_id
                       WHERE a.incident_id=? ORDER BY a.ts, a.alert_id LIMIT 1""",
                    (incident["incident_id"],),
                ).fetchone()[0],
                "severity": incident["severity"],
                "detectors": detectors,
                "first_alert": alert_rows[0]["ts"] if alert_rows else incident["start_ts"],
                "last_alert": alert_rows[-1]["ts"] if alert_rows else incident["end_ts"],
                "reasons": list(dict.fromkeys(row["reason"] for row in alert_rows))[:5],
            })
        alert_rows = connection.execute(
            """SELECT a.alert_id, a.detector, a.subtype, a.event_id, a.token_id,
                      e.principal, a.ts, a.score, a.reason, a.details_json, a.incident_id
               FROM alerts a JOIN events e ON e.event_id=a.event_id
               ORDER BY a.ts, a.alert_id"""
        ).fetchall()
        incident_rows = connection.execute(
            "SELECT incident_id, token_id, start_ts, end_ts, detectors_json, severity, "
            "action, alert_count FROM incidents ORDER BY start_ts, incident_id"
        ).fetchall()
    finally:
        connection.close()

    _write_csv(
        output / "alerts.csv",
        ["alert_id", "detector", "subtype", "event_id", "token_id", "principal", "ts",
         "score", "reason", "details_json", "incident_id"],
        [dict(row) for row in alert_rows],
    )
    _write_csv(
        output / "incidents.csv",
        ["incident_id", "token_id", "start_ts", "end_ts", "detectors",
         "severity", "action", "alert_count"],
        [
            {
                "incident_id": row["incident_id"], "token_id": row["token_id"],
                "start_ts": row["start_ts"], "end_ts": row["end_ts"],
                "detectors": row["detectors_json"], "severity": row["severity"],
                "action": row["action"], "alert_count": row["alert_count"],
            }
            for row in incident_rows
        ],
    )
    data_quality = {
        "rows_read": result.rows_read,
        "valid_events": len(result.events),
        "skipped_rows": result.skipped_rows,
        "baseline_events": len(baseline_events),
        "evaluation_events": len(eval_events),
        "baseline_start": format_ts(start),
        "baseline_end_exclusive": format_ts(boundary),
        "evaluation_start_inclusive": format_ts(boundary),
        "evaluation_end_exclusive": format_ts(end + timedelta(seconds=1)),
        "input_end": format_ts(end),
        "baseline_days": round((boundary - start).total_seconds() / 86400, 3),
    }
    report = {
        "run_parameters": {
            "input_file": Path(input_path).name,
            "baseline_mode": (
                f"{baseline_days} days" if baseline_days is not None
                else f"until {baseline_until}" if baseline_until
                else "first 70% of time span"
            ),
            "geo_table": Path(geo_table).name if geo_table else "not used",
            "column_map": column_map or "not used",
            "assume_utc": assume_utc,
            "max_rows": max_rows,
        },
        "data_quality": data_quality,
        "severity_counts": dict(severity_counts),
        "alert_counts": {name: alert_counts.get(name, 0) for name in DETECTOR_NAMES},
        "alert_subtype_counts": dict(subtype_counts),
        "skipped_detectors": skipped_detectors,
        "disabled_detectors": disabled_reasons,
        "warnings": warnings,
        "row_errors": list(result.errors),
        "top_incidents": top_incidents,
    }
    (output / "summary.json").write_text(
        json.dumps(report, indent=2, sort_keys=True), encoding="utf-8"
    )
    _write_html_report(output / "report.html", report)
    print(f"Rows read: {result.rows_read}; skipped: {result.skipped_rows}")
    print(
        f"Baseline: {format_ts(start)} to {format_ts(boundary)} "
        f"({len(baseline_events)} events); analysed: {len(eval_events)}"
    )
    print(f"Alerts: {len(alerts)}; incidents: {sum(severity_counts.values())}")
    print(
        "Incidents by severity: "
        + ", ".join(f"{key}={severity_counts.get(key, 0)}" for key in ("HIGH", "MEDIUM", "LOW"))
    )
    if disabled_reasons:
        for detector, reason in disabled_reasons.items():
            print(f"{detector} disabled: {reason}")
    for detector, reasons in skipped_detectors.items():
        skip_total = sum(reasons.values())
        print(f"Detector skipped tokens: {detector}={skip_total}")
    for warning in warnings:
        print(f"Warning: {warning}")
    print(f"Output: {output.resolve()}")
    return report
