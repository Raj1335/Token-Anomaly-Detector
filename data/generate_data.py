"""Build reproducible synthetic API activity and ground-truth labels."""

import random
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from faker import Faker

from core.db import SCHEMA_VERSION, connect, create_schema, insert_dataset
from core.models import Event
from core.timeutil import format_ts

DATASET_START = datetime(2026, 3, 2, tzinfo=timezone.utc)
OBJECTS = ("Account", "Opportunity", "Case", "User", "Contact")
INTEGRATION_SCOPES = tuple(f"{name}:query" for name in OBJECTS)

# Fixed simulated UTC offsets; locations and addresses are entirely synthetic.
CITIES: dict[str, tuple[float, float, float, str]] = {
    "Mumbai": (19.0760, 72.8777, 5.5, "103.10"),
    "Delhi": (28.6139, 77.2090, 5.5, "103.20"),
    "Bengaluru": (12.9716, 77.5946, 5.5, "103.30"),
    "London": (51.5072, -0.1276, 0, "104.10"),
    "Frankfurt": (50.1109, 8.6821, 1, "104.20"),
    "New York": (40.7128, -74.0060, -5, "104.30"),
    "San Francisco": (37.7749, -122.4194, -8, "104.40"),
    "Singapore": (1.3521, 103.8198, 8.0, "104.50"),
    "Sydney": (-33.8688, 151.2093, 10.0, "104.60"),
    "Dubai": (25.2048, 55.2708, 4.0, "104.70"),
    "Sao Paulo": (-23.5505, -46.6333, -3.0, "104.80"),
    "Tokyo": (35.6762, 139.6503, 9.0, "104.90"),
}
HOME_CITIES = tuple(city for city in CITIES if city != "Frankfurt")
LabelledRow = tuple[int, Event, int, str, str | None]


@dataclass(frozen=True)
class TokenConfig:
    """Keep token behavior stable before event generation begins."""

    token_id: str
    token_type: str
    tenant_id: str
    principal: str
    home_city: str
    baseline_ip: str
    baseline_objects: tuple[str, ...]


def _ip(rng: random.Random, city: str) -> str:
    """Generate an address in a fake city-specific IPv4 prefix."""
    prefix = CITIES[city][3]
    return f"{prefix}.{rng.randint(1, 254)}.{rng.randint(1, 254)}"


def _build_tokens(rng: random.Random, fake: Faker) -> list[TokenConfig]:
    """Create all seeded token profiles before generating any activity."""
    tokens: list[TokenConfig] = []
    tenants = [f"tenant_{index:03d}" for index in range(1, 21)]
    for index in range(1, 41):
        city = "Mumbai" if index == 20 else ("London" if index == 12 else rng.choice(HOME_CITIES))
        tenant = tenants[(index - 1) % len(tenants)]
        tokens.append(
            TokenConfig(
                f"sess_{index:03d}", "session", tenant,
                f"{fake.first_name()} {fake.last_name()}",
                city, _ip(rng, city), tuple(rng.sample(OBJECTS, rng.randint(2, 3))),
            )
        )
    for index in range(1, 21):
        city = rng.choice(HOME_CITIES) if index <= 10 else "New York"
        objects = tuple(rng.sample(("Account", "Opportunity", "Contact"), 2))
        tokens.append(
            TokenConfig(
                f"int_{index:03d}", "integration", tenants[index - 1],
                f"service_{index:03d}", city, _ip(rng, city), objects,
            )
        )
    return tokens


def _add(
    rows: list[LabelledRow],
    token: TokenConfig,
    ts: datetime,
    city: str,
    ip: str,
    obj: str,
    action: str,
    records: int,
    label: tuple[int, str, str | None] = (0, "benign", None),
    rng: random.Random | None = None,
) -> None:
    """Append a provisional event and its private label before assigning IDs."""
    lat, lon, _, _ = CITIES[city]
    jitter_source = rng if rng is not None else random.Random(0)
    scopes = (
        INTEGRATION_SCOPES if token.token_type == "integration"
        else tuple(f"{name}:{verb}" for name in OBJECTS for verb in ("query", "read"))
    )
    rows.append(
        (
            len(rows),
            Event(
                0, ts, token.token_id, token.token_type, token.principal,
                token.tenant_id, ip, lat + jitter_source.uniform(-0.2, 0.2),
                lon + jitter_source.uniform(-0.2, 0.2), city, obj, action,
                records, scopes,
            ),
            label[0], label[1], label[2],
        )
    )


def _session_day(
    rows: list[LabelledRow], token: TokenConfig, day: datetime, rng: random.Random
) -> None:
    """Generate a weekday session workload within its simulated local shift."""
    offset = CITIES[token.home_city][2]
    count = rng.randint(20, 120)
    start = datetime(day.year, day.month, day.day, 9, tzinfo=timezone.utc) - timedelta(hours=offset)
    seconds = sorted(rng.randint(0, 8 * 60 * 60 - 1) for _ in range(count))
    for second in seconds:
        _add(
            rows, token, start + timedelta(seconds=second), token.home_city,
            token.baseline_ip, rng.choice(token.baseline_objects),
            rng.choice(("query", "read")), rng.randint(1, 100), rng=rng,
        )


def _integration_event(
    rows: list[LabelledRow], token: TokenConfig, ts: datetime, rng: random.Random
) -> None:
    """Generate one ordinary integration request."""
    _add(
        rows, token, ts, token.home_city, token.baseline_ip,
        rng.choice(token.baseline_objects), "query", rng.randint(1, 50), rng=rng,
    )


def _make_rows(
    seed: int,
) -> tuple[list[Event], list[tuple[int, int, str, str | None]], dict[str, str]]:
    """Generate, sort, and label the complete deterministic 14-day population."""
    rng = random.Random(seed)
    fake = Faker()
    fake.seed_instance(seed)
    tokens = _build_tokens(rng, fake)
    by_id = {token.token_id: token for token in tokens}
    rows: list[LabelledRow] = []
    eval_day = DATASET_START + timedelta(days=10)

    for token in tokens:
        if token.token_type == "session":
            for day_number in range(14):
                day = DATASET_START + timedelta(days=day_number)
                if day.weekday() >= 5:
                    continue
                if token.token_id == "sess_005" and day_number == 10:
                    for hour in (0, 2, 4, 5, 6):
                        _add(rows, token, day + timedelta(hours=hour), token.home_city,
                             token.baseline_ip, token.baseline_objects[0], "query", 10,
                             rng=rng)
                    for index in range(15):
                        ts = day + timedelta(minutes=12, seconds=20 * index)
                        _add(rows, token, ts, "Frankfurt", _ip(rng, "Frankfurt"),
                             token.baseline_objects[index % len(token.baseline_objects)],
                             "query", rng.randint(1, 100),
                             (1, "impossible_travel", "camp_travel"), rng)
                elif token.token_id == "sess_012" and day_number == 10:
                    offset = CITIES[token.home_city][2]
                    local_start = datetime(2026, 3, 12, 2, tzinfo=timezone.utc)
                    start = local_start - timedelta(hours=offset)
                    for index in range(20):
                        _add(
                            rows, token, start + timedelta(minutes=3 * index),
                            token.home_city, token.baseline_ip,
                            token.baseline_objects[index % len(token.baseline_objects)],
                            "query", rng.randint(1, 100),
                            (1, "temporal", "camp_temporal"), rng,
                        )
                elif token.token_id == "sess_020" and day_number == 10:
                    for city, start, count in (
                        ("Mumbai", day + timedelta(hours=8), 3),
                        ("Delhi", day + timedelta(hours=11, minutes=30), 8),
                    ):
                        ip = token.baseline_ip if city == "Mumbai" else _ip(rng, city)
                        for index in range(count):
                            _add(rows, token, start + timedelta(minutes=index * 15),
                                 city, ip, token.baseline_objects[0], "read", 20,
                                 (0, "hn_legit_trip", None), rng)
                else:
                    _session_day(rows, token, day, rng)
                    if token.token_id == "sess_021" and day_number == 10:
                        second_ip = _ip(rng, token.home_city)
                        for index in range(5):
                            _add(rows, token, day + timedelta(hours=9, minutes=index * 10),
                                 token.home_city, second_ip, token.baseline_objects[0],
                                 "read", 20, (0, "hn_ip_churn", None), rng)
        else:
            current = DATASET_START
            end = DATASET_START + timedelta(days=14)
            while current < end:
                _integration_event(rows, token, current, rng)
                current += timedelta(minutes=rng.randint(5, 15))

            for day_number in range(14):
                day = DATASET_START + timedelta(days=day_number)
                for index in range(12):
                    _add(rows, token, day + timedelta(hours=2, minutes=index * 10 // 12),
                         token.home_city, token.baseline_ip, token.baseline_objects[0],
                         "query", rng.randint(1, 50),
                         (0, "hn_nightly_batch", None) if day_number >= 10 else (0, "benign", None),
                         rng)

    token = by_id["int_003"]
    for index in range(30):
        ts = eval_day + timedelta(hours=14, minutes=2 * index)
        _add(rows, token, ts, token.home_city, token.baseline_ip,
             ("User", "Case")[index % 2], "query", rng.randint(1, 50),
             (1, "scope_creep", "camp_scope"), rng)

    drift_start = eval_day + timedelta(days=1, hours=10)
    attacker_ip = _ip(rng, "Frankfurt")
    for token_index in range(5, 17):
        token = by_id[f"int_{token_index:03d}"]
        start = drift_start + timedelta(seconds=210 * (token_index - 5))
        elapsed = 0.0
        for request_index in range(60):
            elapsed += rng.uniform(2.0, 3.0)
            ts = start + timedelta(seconds=elapsed)
            obj = ("Account", "Opportunity", "Case", "User")[request_index % 4]
            _add(rows, token, ts, "Frankfurt", attacker_ip, obj, "query",
                 rng.randint(500, 5000), (1, "drift_replay", "camp_drift"), rng)

    rows.sort(key=lambda row: (row[1].ts, row[0]))
    events: list[Event] = []
    labels: list[tuple[int, int, str, str | None]] = []
    for _, event, is_attack, scenario, campaign in rows:
        if event.ts < DATASET_START or event.ts >= DATASET_START + timedelta(days=14):
            continue
        event_id = len(events) + 1
        events.append(
            Event(len(events) + 1, event.ts, event.token_id, event.token_type, event.principal,
                  event.tenant_id, event.source_ip, event.geo_lat, event.geo_lon,
                  event.geo_city, event.object_type, event.action,
                  event.records_returned, event.granted_scopes)
        )
        labels.append((event_id, is_attack, scenario, campaign))

    baseline_end = DATASET_START + timedelta(days=10)
    if any(is_attack and event.ts < baseline_end
           for event, (_, is_attack, _, _) in zip(events, labels)):
        raise AssertionError("baseline contains attack events")
    metadata = {
        "seed": str(seed),
        "dataset_start_utc": format_ts(DATASET_START),
        "baseline_end_utc": format_ts(baseline_end),
        "eval_end_utc": format_ts(DATASET_START + timedelta(days=14)),
        "schema_version": SCHEMA_VERSION,
    }
    return events, labels, metadata


def generate_database(seed: int, db_path: str | Path = "data/events.db") -> dict[str, int]:
    """Rebuild the requested .db file and print compact population counts."""
    path = Path(db_path)
    if path.suffix.lower() != ".db":
        raise ValueError("database path must end in .db")
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        path.unlink()
    events, labels, metadata = _make_rows(seed)
    connection = connect(path)
    try:
        create_schema(connection)
        insert_dataset(connection, events, labels, metadata)
    finally:
        connection.close()

    counts = Counter(event.token_type for event in events)
    attacks = sum(label[1] for label in labels)
    baseline = sum(event.ts < datetime(2026, 3, 12, tzinfo=timezone.utc) for event in events)
    evaluation = len(events) - baseline
    print(
        f"Generated {len(events)} events: session={counts['session']}, "
        f"integration={counts['integration']}, baseline={baseline}, "
        f"evaluation={evaluation}, labelled_attack_events={attacks}"
    )
    return {"events": len(events), "attacks": attacks, "baseline": baseline, "evaluation": evaluation}