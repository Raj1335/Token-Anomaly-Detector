"""Command-line interface for synthetic demos and user-supplied log analysis."""

import argparse
import sqlite3
import sys
from pathlib import Path

from data.generate_data import generate_database
from data.analyze import analyze_input, export_sample_csv, validate_input


def main() -> int:
    """Parse commands and dispatch project operations."""
    parser = argparse.ArgumentParser(description="Token anomaly detector")
    subparsers = parser.add_subparsers(dest="command", required=True)
    generate = subparsers.add_parser("generate")
    generate.add_argument("--seed", type=int, required=True)
    generate.add_argument("--db", default="data/events.db")
    detect = subparsers.add_parser("detect")
    detect.add_argument("--db", default="data/events.db")
    evaluate = subparsers.add_parser("evaluate")
    evaluate.add_argument("--db", default="data/events.db")
    run_all = subparsers.add_parser("run-all")
    run_all.add_argument("--seed", type=int, required=True)
    run_all.add_argument("--db", default="data/events.db")
    dashboard = subparsers.add_parser("dashboard")
    dashboard.add_argument("--db", default="data/events.db")
    dashboard.add_argument("--port", type=int, default=5000)
    validate = subparsers.add_parser("validate", help="Validate a CSV or JSONL input file")
    validate.add_argument("--input", required=True)
    validate.add_argument("--map")
    validate.add_argument("--assume-utc", action="store_true")
    validate.add_argument("--max-rows", type=int, default=500_000)
    analyze = subparsers.add_parser("analyze", help="Analyze a user-supplied log file")
    analyze.add_argument("--input", required=True)
    analyze.add_argument("--out", required=True)
    baseline = analyze.add_mutually_exclusive_group()
    baseline.add_argument("--baseline-days", type=int)
    baseline.add_argument("--baseline-until")
    analyze.add_argument("--geo-table")
    analyze.add_argument("--map")
    analyze.add_argument("--assume-utc", action="store_true")
    analyze.add_argument("--skip-bad-rows", action="store_true")
    analyze.add_argument("--max-rows", type=int, default=500_000)
    analyze.add_argument("--force", action="store_true")
    export_sample = subparsers.add_parser(
        "export-sample", help="Write a compact synthetic CSV sample"
    )
    export_sample.add_argument("--out", default="data/sample_logs.csv")
    args = parser.parse_args()
    try:
        if args.command in ("validate", "analyze"):
            if args.command == "validate":
                validate_input(
                    args.input, column_map=args.map, assume_utc=args.assume_utc,
                    max_rows=args.max_rows,
                )
            else:
                analyze_input(
                    args.input, args.out, baseline_days=args.baseline_days,
                    baseline_until=args.baseline_until, geo_table=args.geo_table,
                    column_map=args.map, assume_utc=args.assume_utc,
                    skip_bad_rows=args.skip_bad_rows, max_rows=args.max_rows,
                    force=args.force,
                )
        elif args.command == "export-sample":
            export_sample_csv(args.out)
        elif args.command != "generate" and args.command != "run-all":
            if not Path(args.db).exists():
                raise FileNotFoundError(
                    f"database not found; run `python main.py run-all --seed 1` first"
                )
        if args.command == "generate":
            generate_database(args.seed, args.db)
        elif args.command in ("detect", "evaluate", "run-all", "dashboard"):
            if args.command == "run-all":
                generate_database(args.seed, args.db)
            if args.command in ("detect", "run-all"):
                from core.pipeline import run_detection
                run_detection(args.db)
            if args.command in ("evaluate", "run-all"):
                from core.evaluate import evaluate_database
                evaluate_database(args.db)
            if args.command == "dashboard":
                from dashboard.app import create_app
                create_app(args.db).run(
                    host="127.0.0.1", port=args.port, debug=False
                )
    except (OSError, sqlite3.Error, ValueError, AssertionError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())