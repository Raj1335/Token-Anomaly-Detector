# Walkthrough

## Modules

`core/models.py` contains frozen Event and Alert dataclasses. `core/timeutil.py` formats UTC timestamps. `core/db.py` owns the schema and parameterized persistence. `data/generate_data.py` creates token profiles and events. Detectors fit baseline events and inspect evaluation events.

`core/pipeline.py` loads dataclass events and runs detection. `core/correlate.py` creates incidents and simulated actions. `core/evaluate.py` is the only module that reads labels.

## Worked impossible-travel example

A session is seen in London at 12:00, then Frankfurt at 12:12. The distance and elapsed time exceed 900 km/h and the Frankfurt IP is new, so the later event alerts.

## Worked replay example

Each integration starts 60 requests in a 5-minute bucket. Count and record thresholds stay above legitimate nightly batches. The replay crosses both gates and emits per-token-rate alerts.

## 10-question rehearsal

1. Why synthetic data? It demonstrates the incident without real logs or credential exposure.
2. Why does scope detection ignore granted scope? The attacker stayed within broad grants; low baseline relevancy is more meaningful.
3. How are vendor IPs handled? They are known baseline IPs and do not trigger impossible-travel alerts.
4. Why tie volume to baseline maximum? It prevents nightly 12-request batches from becoming replay alerts.
5. What defeats this? Low-and-slow activity that mimics baseline timing, city, objects, and volume.
6. Why one incident per token? Correlation is token-level and campaign mapping happens only in evaluation.
7. Why train/test intervals? Baseline fitting cannot leak evaluation labels.
8. How is revocation completed? The alert establishing the second detector family triggers the revoke timestamp.
9. Why sort before IDs? Attack events cannot be inferred from ID sequences.
10. Why is the dashboard read-only? It is presentation-only and cannot mutate security state.
