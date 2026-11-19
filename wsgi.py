"""Gunicorn entry point for the synthetic dashboard and optional log uploads."""

from pathlib import Path

from dashboard.app import create_app

DATABASE = Path("data") / "events.db"

if not DATABASE.exists():
    from core.evaluate import evaluate_database
    from core.pipeline import run_detection
    from data.generate_data import generate_database

    generate_database(1, DATABASE)
    run_detection(str(DATABASE))
    evaluate_database(str(DATABASE))

app = create_app(DATABASE)
