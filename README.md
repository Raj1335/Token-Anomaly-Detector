# Token Anomaly Detector MVP

This project is a synthetic OAuth/session-token anomaly detector. It combines statistical baselines with explainable rules and a small Flask dashboard.

## Quickstart (PowerShell)

```powershell
python -m venv venv
.\venv\Scripts\python.exe -m pip install -r requirements.txt
.\venv\Scripts\python.exe main.py run-all --seed 1
.\venv\Scripts\python.exe main.py dashboard --db data/events.db --port 5000
```

Open `http://127.0.0.1:5000`. Dashboard routes include `/`, `/incidents`, `/incident/<id>`, and `/token/<token_id>`.

## Live demo

Live demo: **[Render demo URL](https://your-render-demo-url.onrender.com)** (replace this placeholder after deployment).

To deploy, create a Render web service from this repository and use the included `render.yaml` settings. The build command installs the requirements and generates, detects, and evaluates the seed-1 synthetic dataset. The service runs through Gunicorn and exposes `/healthz`.

The configured Render commands are `pip install -r requirements.txt && python main.py run-all --seed 1` and `gunicorn wsgi:app --bind 0.0.0.0:$PORT`. On Windows, run the Flask dashboard locally with `python main.py dashboard --db data/events.db`; Gunicorn does not run on Windows.

Render's free tier sleeps when idle, so the first page load after a quiet period can take up to about a minute. The demo has no authentication because it serves only synthetic data. Do not deploy real logs or credentials to this demo.

## Architecture

```text
main.py
  -> data/generate_data.py -> SQLite events + labels
  -> core/pipeline.py -> baseline fit -> detectors -> alerts
  -> core/correlate.py -> incidents + simulated response
  -> core/evaluate.py -> campaign report
  -> dashboard/app.py -> read-only local view
```

All detection logic uses timezone-aware UTC datetimes and in-memory dataclasses. Ground-truth labels are read only by evaluation code.

## Tested environment

- Python: 3.14.7
- Faker: 37.6.0
- Flask: 3.1.2
- Gunicorn: 23.0.0 (Render/Linux only)

The brief targets Python 3.11+; Python 3.14.7 is the tested environment.

## Seed 2 held-out results

| Campaign | Result |
|---|---|
| camp_travel | PASS |
| camp_scope | PASS |
| camp_temporal | PASS |
| camp_drift | PASS |

Benign false-positive fraction: 6 of 17,382 evaluation benign events (0.03%). Seed 1 was used for threshold tuning; seed 2 is held out and untuned.

## Commands

```powershell
.\venv\Scripts\python.exe main.py generate --seed 1
.\venv\Scripts\python.exe main.py detect --db data/events.db
.\venv\Scripts\python.exe main.py evaluate --db data/events.db
.\venv\Scripts\python.exe main.py run-all --seed 2
.\venv\Scripts\python.exe -m unittest tests.known_answer_cases -v
```

## Honest limitations

- Results use synthetic data authored alongside the detector rules, so they demonstrate catching modelled attacks, not production effectiveness.
- Thresholds are tuned on seed 1 and reported on seed 2.
- Detectors need baseline history and have cold-start skip policies.
- Temporal detection is blind for 24/7 integrations.
- Geographic coordinates and city offsets are simulated.
- VPN and mobile users can produce real-world false positives.
- A low-and-slow attacker that mimics baseline behavior can evade these rules.
- Revocation and notification are simulated SQLite actions.
- The dashboard has no authentication and must not be exposed publicly as-is.

## MITRE ATT&CK

- T1528 - Steal Application Access Token: verify at attack.mitre.org
- T1550.001 - Application Access Token: verify at attack.mitre.org
