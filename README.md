# Token Anomaly Detector

A local CLI tool for analyzing token-authenticated API request logs. It profiles a historical baseline, detects unusual travel, scope behavior, timing, and request volume, then writes a SQLite database, CSV exports, JSON summary, and standalone HTML report. A synthetic generator remains available for demos and repeatable tests.

## What it does

- Accepts user-supplied CSV and JSONL logs; it does not upload data or make network requests.
- Learns detector profiles from an early baseline window and analyzes later events.
- Produces token-level incidents and simulated response labels; it does not revoke real credentials or contact anyone.
- Provides a local, read-only Flask dashboard for imported and synthetic databases.

## Quickstart with your own CSV (PowerShell)

```powershell
python -m venv venv
.\venv\Scripts\python.exe -m pip install -r requirements.txt
.\venv\Scripts\python.exe main.py validate --input data\sample_logs.csv
.\venv\Scripts\python.exe main.py analyze --input data\sample_logs.csv --out out\sample-analysis
Start-Process .\out\sample-analysis\report.html
.\venv\Scripts\python.exe main.py dashboard --db out\sample-analysis\analysis.db
```

The dashboard opens at `http://127.0.0.1:5000`. The included [data/sample_logs.csv](data/sample_logs.csv) contains 2,000 **synthetic** rows; it is a format example, not real customer data. Use `--force` to replace an existing analysis output directory.

## Input format

See [docs/INPUT_FORMAT.md](docs/INPUT_FORMAT.md) for the CSV/JSONL schema, validation rules, column mapping, and examples.

## Geo options

Impossible-travel detection requires coordinates. Provide both `geo_lat` and `geo_lon` columns in your logs, or pass `--geo-table path.csv` with `cidr,lat,lon,city` columns. CIDR matches use the most-specific network. Without usable coordinates, travel detection is disabled and noted in the summary. Coordinates are never guessed and there are no geo-IP lookups.

## How the baseline works

Events are sorted by timestamp before event IDs are assigned. By default, the baseline is the first 70% of the input time span; the remaining events are the evaluation window. Override this with `--baseline-days N` (from the earliest event) or `--baseline-until "YYYY-MM-DDTHH:MM:SSZ"`. Baselines shorter than three days or 1,000 events produce warnings, not errors. Check that the selected baseline represents clean, normal activity.

## Limitations

- A clean historical baseline is needed; an unrepresentative baseline can hide anomalies or create false positives.
- You must map your log columns to this input schema. There are no built-in Okta, Entra ID, or Salesforce adapters yet.
- Geographic accuracy depends on your event coordinates or CIDR table.
- The dashboard has no authentication; bind it to localhost and do not expose it publicly.
- Detector thresholds were tuned on synthetic data only. Results are not evidence of production effectiveness.
- Low-and-slow behavior that resembles the baseline may evade these rules.
- The tool only analyzes the fields provided; it does not inspect response payloads for exposed credentials.

## Synthetic demo mode

To generate, detect, and evaluate the built-in synthetic scenarios:

```powershell
.\venv\Scripts\python.exe main.py run-all --seed 1
.\venv\Scripts\python.exe main.py dashboard --db data\events.db
.\venv\Scripts\python.exe -m unittest tests.known_answer_cases -v
```

The generator is deterministic by seed and writes only synthetic events and ground-truth labels.

## Live demo

Live demo: **[Render demo URL](https://your-render-demo-url.onrender.com)** (replace this placeholder after deployment).

To deploy, create a Render web service from this repository and use the included `render.yaml` settings. The build command installs requirements and runs the seed-1 synthetic pipeline. The service runs through Gunicorn and exposes `/healthz`.

The configured Render commands are `pip install -r requirements.txt && python main.py run-all --seed 1` and `gunicorn wsgi:app --bind 0.0.0.0:$PORT`. On Windows, run Flask with `python main.py dashboard --db data\events.db`; Gunicorn does not run on Windows.

Render's free tier sleeps when idle, so the first page load after a quiet period can take up to about a minute. The demo has no authentication because it serves only synthetic data. Do not deploy real logs or credentials to it.

## Tested environment

- Python: 3.14.7
- Faker: 37.6.0
- Flask: 3.1.2
- Gunicorn: 23.0.0 (Render/Linux only)
