"""Command-line entry point for generating, detecting, evaluating, and serving."""

import argparse
import sqlite3
import sys
from pathlib import Path

from data.generate_data import generate_database


def main() -> int:
    """Parse commands and dispatch project operations."""
    parser = argparse.ArgumentParser(description="Token anomaly detector MVP")
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
    args = parser.parse_args()
    try:
        if args.command != "generate" and args.command != "run-all":
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
    except (FileNotFoundError, sqlite3.Error, ValueError, AssertionError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())