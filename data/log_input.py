"""Parse and validate untrusted CSV or JSONL API-request logs."""

import csv
import ipaddress
import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator

from core.models import Event
from core.timeutil import format_ts

CANONICAL_FIELDS = (
    "timestamp", "token_id", "source_ip", "token_type", "principal",
    "tenant_id", "object_type", "action", "records_returned",
    "granted_scopes", "geo_lat", "geo_lon", "geo_city",
)
REQUIRED_FIELDS = ("timestamp", "token_id", "source_ip")
DEFAULTS = {
    "token_type": "unknown",
    "principal": None,
    "tenant_id": "unknown",
    "object_type": "unknown",
    "action": "unknown",
    "records_returned": 0,
    "granted_scopes": "",
    "geo_city": "unknown",
}
MAX_ERRORS = 50


class InputFileError(ValueError):
    """Report a fatal file/schema/row validation problem to the CLI."""


@dataclass(frozen=True)
class ParseResult:
    """Hold normalized valid events and input quality statistics."""

    events: list[Event]
    rows_read: int
    skipped_rows: int
    errors: tuple[str, ...]
    has_geo_data: bool


def parse_column_map(specification: str | None) -> dict[str, str]:
    """Parse external-column=canonical-column mappings case-insensitively."""
    mapping: dict[str, str] = {}
    if not specification:
        return mapping
    for pair in specification.split(","):
        parts = pair.split("=", 1)
        if len(parts) != 2 or not parts[0].strip() or not parts[1].strip():
            raise InputFileError(f"invalid --map entry {pair!r}; expected their_col=our_col")
        source, target = parts[0].strip().lower(), parts[1].strip().lower()
        if target not in CANONICAL_FIELDS:
            raise InputFileError(f"unsupported mapped field {target!r}")
        if source in mapping:
            raise InputFileError(f"duplicate mapping for source column {source!r}")
        mapping[source] = target
    return mapping


def _column_index(headers: list[str], mapping: dict[str, str]) -> dict[str, str]:
    """Resolve actual header names to canonical schema field names."""
    resolved: dict[str, str] = {}
    for header in headers:
        key = header.strip().lower()
        canonical = mapping.get(key, key)
        if canonical in resolved:
            raise InputFileError(f"multiple columns map to {canonical!r}")
        resolved[canonical] = header
    missing = [field for field in REQUIRED_FIELDS if field not in resolved]
    if missing:
        raise InputFileError("missing required column(s): " + ", ".join(missing))
    return resolved


def _jsonl_rows(path: Path) -> tuple[list[str], Iterator[tuple[int, dict[str, Any]]]]:
    """Read JSON Lines objects while preserving source line numbers."""
    handle = path.open("r", encoding="utf-8-sig")

    def rows() -> Iterator[tuple[int, dict[str, Any]]]:
        try:
            for line_number, line in enumerate(handle, start=1):
                if not line.strip():
                    continue
                try:
                    value = json.loads(line)
                except json.JSONDecodeError as error:
                    yield line_number, {"__parse_error__": f"invalid JSON: {error.msg}"}
                    continue
                if not isinstance(value, dict):
                    yield line_number, {"__parse_error__": "JSONL row must be an object"}
                    continue
                yield line_number, value
        finally:
            handle.close()

    iterator = rows()
    prefix: list[tuple[int, dict[str, Any]]] = []
    headers: list[str] | None = None
    for row in iterator:
        prefix.append(row)
        if "__parse_error__" not in row[1]:
            headers = [str(key) for key in row[1]]
            break
    if headers is None:
        iterator.close()
        if prefix:
            line_number, row = prefix[0]
            raise InputFileError(f"line {line_number}: {row['__parse_error__']}")
        raise InputFileError("input file contains no JSONL rows")
    return headers, _prepend_many(prefix, iterator)


def _prepend_many(
    prefix: list[tuple[int, dict[str, Any]]],
    remaining: Iterator[tuple[int, dict[str, Any]]],
) -> Iterator[tuple[int, dict[str, Any]]]:
    """Yield prefetched JSONL rows before the remaining input stream."""
    yield from prefix
    yield from remaining


def _csv_rows(path: Path) -> tuple[list[str], Iterator[tuple[int, dict[str, Any]]]]:
    """Stream CSV dictionaries from a UTF-8 headered file."""
    with path.open("r", encoding="utf-8-sig", newline="") as header_stream:
        reader = csv.reader(header_stream)
        try:
            headers = next(reader)
        except StopIteration:
            headers = []
        except csv.Error as error:
            raise InputFileError(
                f"CSV header line {reader.line_num}: {error}"
            ) from error
    if not headers:
        raise InputFileError("CSV file is missing a header row")

    def rows() -> Iterator[tuple[int, dict[str, Any]]]:
        with path.open("r", encoding="utf-8-sig", newline="") as handle:
            reader = csv.DictReader(handle)
            try:
                for row in reader:
                    yield reader.line_num, row
            except csv.Error as error:
                yield reader.line_num, {"__parse_error__": f"invalid CSV: {error}"}

    return [str(item) for item in headers], rows()


def _string_value(value: Any, name: str) -> str:
    """Validate a text field's type, length, and NUL-byte safety."""
    if value is None:
        return ""
    if not isinstance(value, str):
        raise ValueError(f"{name} must be text")
    if "\x00" in value:
        raise ValueError(f"{name} contains a NUL byte")
    if len(value) > 256:
        raise ValueError(f"{name} exceeds 256 characters")
    return value.strip()


def _validate_untrusted_value(value: Any) -> None:
    """Reject NUL bytes and overlong text in every supplied field."""
    if isinstance(value, str):
        if "\x00" in value:
            raise ValueError("field contains a NUL byte")
        if len(value) > 256:
            raise ValueError("field exceeds 256 characters")
    elif isinstance(value, list):
        for item in value:
            _validate_untrusted_value(item)
    elif isinstance(value, dict):
        for key, item in value.items():
            _validate_untrusted_value(str(key))
            _validate_untrusted_value(item)


def _timestamp(value: str, assume_utc: bool) -> datetime:
    """Parse an ISO-8601 timestamp and require or explicitly assume UTC."""
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError("timestamp is not valid ISO-8601") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        if not assume_utc:
            raise ValueError("timestamp has no timezone; pass --assume-utc to assume UTC")
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).replace(microsecond=0)


def _record_count(value: Any) -> int:
    """Parse records_returned as a non-negative integer."""
    if value is None or value == "":
        return 0
    if isinstance(value, bool):
        raise ValueError("records_returned must be a non-negative integer")
    if isinstance(value, int):
        number = value
    elif isinstance(value, str) and value.strip().isdecimal():
        number = int(value.strip())
    else:
        raise ValueError("records_returned must be a non-negative integer")
    if number < 0:
        raise ValueError("records_returned must be a non-negative integer")
    return number


def _coordinate(value: Any, field: str, low: float, high: float) -> float | None:
    """Validate one optional geographic coordinate."""
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        raise ValueError(f"{field} must be numeric")
    try:
        number = float(value)
    except (TypeError, ValueError) as error:
        raise ValueError(f"{field} must be numeric") from error
    if not low <= number <= high:
        raise ValueError(f"{field} must be between {low:g} and {high:g}")
    return number


def load_geo_table(path: str | Path | None) -> list[tuple[Any, float, float, str]]:
    """Load and validate CIDR enrichment rows without making network calls."""
    if path is None:
        return []
    geo_path = Path(path)
    if geo_path.suffix.lower() != ".csv":
        raise InputFileError("geo table must be a .csv file")
    entries: list[tuple[Any, float, float, str]] = []
    try:
        with geo_path.open("r", encoding="utf-8-sig", newline="") as stream:
            reader = csv.DictReader(stream)
            headers = {name.strip().lower(): name for name in (reader.fieldnames or [])}
            missing = [name for name in ("cidr", "lat", "lon", "city") if name not in headers]
            if missing:
                raise InputFileError("geo table missing column(s): " + ", ".join(missing))
            for line_number, row in enumerate(reader, start=2):
                try:
                    network = ipaddress.ip_network(row[headers["cidr"]].strip(), strict=False)
                    latitude = _coordinate(row[headers["lat"]], "lat", -90, 90)
                    longitude = _coordinate(row[headers["lon"]], "lon", -180, 180)
                    city = _string_value(row[headers["city"]], "city")
                    if latitude is None or longitude is None:
                        raise ValueError("lat and lon are required")
                    entries.append((network, latitude, longitude, city or "unknown"))
                except (ValueError, AttributeError) as error:
                    raise InputFileError(f"geo table line {line_number}: {error}") from error
    except OSError as error:
        raise InputFileError(f"cannot read geo table: {error}") from error
    return entries


def _geo_lookup(
    source_ip: str, geo_entries: list[tuple[Any, float, float, str]]
) -> tuple[float | None, float | None, str]:
    """Return coordinates from the most-specific matching network."""
    address = ipaddress.ip_address(source_ip)
    matches = [
        entry for entry in geo_entries
        if address.version == entry[0].version and address in entry[0]
    ]
    if not matches:
        return None, None, "unknown"
    _, latitude, longitude, city = max(matches, key=lambda entry: entry[0].prefixlen)
    return latitude, longitude, city


def parse_log_file(
    input_path: str | Path,
    column_map: str | None = None,
    assume_utc: bool = False,
    skip_bad_rows: bool = False,
    max_rows: int = 500_000,
    geo_table: str | Path | None = None,
) -> ParseResult:
    """Validate a CSV or JSONL file and produce sorted, label-free Events."""
    path = Path(input_path)
    if path.suffix.lower() not in (".csv", ".jsonl"):
        raise InputFileError("input extension must be .csv or .jsonl")
    if max_rows < 1:
        raise InputFileError("--max-rows must be a positive integer")
    mapping = parse_column_map(column_map)
    geo_entries = load_geo_table(geo_table)
    try:
        headers, rows = _csv_rows(path) if path.suffix.lower() == ".csv" else _jsonl_rows(path)
    except OSError as error:
        raise InputFileError(f"cannot read input file: {error}") from error
    try:
        column_names = _column_index(headers, mapping)
    except InputFileError:
        rows.close()
        raise
    has_latitude = "geo_lat" in column_names
    has_longitude = "geo_lon" in column_names
    if has_latitude != has_longitude:
        rows.close()
        raise InputFileError("geo_lat and geo_lon columns must be provided together")
    geo_columns = has_latitude and has_longitude
    provisional: list[tuple[int, Event]] = []
    errors: list[str] = []
    rows_read = 0
    skipped = 0
    any_geo = False

    for line_number, raw in rows:
        rows_read += 1
        if rows_read > max_rows:
            raise InputFileError(
                f"row cap exceeded: input has more than --max-rows {max_rows} data rows"
            )
        try:
            if "__parse_error__" in raw:
                raise ValueError(str(raw["__parse_error__"]))
            _validate_untrusted_value(raw)
            normalized: dict[str, Any] = {}
            for key, value in raw.items():
                if key is None:
                    raise ValueError("row has more values than the header")
                canonical = mapping.get(str(key).strip().lower(), str(key).strip().lower())
                if canonical in normalized:
                    raise ValueError(f"duplicate value for column {canonical}")
                normalized[canonical] = value
            for required in REQUIRED_FIELDS:
                if required not in normalized:
                    raise ValueError(f"missing required column {required}")
            timestamp_text = _string_value(normalized.get("timestamp"), "timestamp")
            if not timestamp_text:
                raise ValueError("timestamp is required")
            timestamp = _timestamp(timestamp_text, assume_utc)
            token_id = _string_value(normalized.get("token_id"), "token_id")
            if not token_id:
                raise ValueError("token_id is required")
            ip_text = _string_value(normalized.get("source_ip"), "source_ip")
            try:
                source_ip = str(ipaddress.ip_address(ip_text))
            except ValueError as error:
                raise ValueError("source_ip must be a valid IPv4 or IPv6 address") from error

            values: dict[str, str] = {}
            for field in ("token_type", "principal", "tenant_id", "object_type", "action", "geo_city"):
                raw_value = normalized.get(field, DEFAULTS[field])
                value = _string_value(raw_value, field)
                if field == "principal" and not value:
                    value = token_id
                if field in ("token_type", "tenant_id", "object_type", "action", "geo_city") and not value:
                    value = str(DEFAULTS[field])
                values[field] = value

            records = _record_count(normalized.get("records_returned", 0))
            scopes_value = normalized.get("granted_scopes", "")
            if isinstance(scopes_value, list):
                scopes = []
                for scope in scopes_value:
                    scopes.append(_string_value(scope, "granted_scopes"))
            else:
                scope_text = _string_value(scopes_value, "granted_scopes")
                scopes = [item.strip() for item in scope_text.split(";") if item.strip()]
            if any(len(scope) > 256 for scope in scopes):
                raise ValueError("granted_scopes entry exceeds 256 characters")

            latitude: float | None = None
            longitude: float | None = None
            city = values["geo_city"]
            if geo_columns:
                latitude = _coordinate(normalized.get("geo_lat"), "geo_lat", -90, 90)
                longitude = _coordinate(normalized.get("geo_lon"), "geo_lon", -180, 180)
                if (latitude is None) != (longitude is None):
                    raise ValueError("geo_lat and geo_lon must be provided together")
                if latitude is not None:
                    any_geo = True
            elif geo_entries:
                latitude, longitude, mapped_city = _geo_lookup(source_ip, geo_entries)
                if latitude is not None:
                    city = mapped_city
                    any_geo = True

            event = Event(
                0, timestamp, token_id, values["token_type"], values["principal"],
                values["tenant_id"], source_ip, latitude, longitude, city,
                values["object_type"], values["action"], records, tuple(scopes),
            )
            provisional.append((rows_read, event))
        except (ValueError, TypeError) as error:
            errors.append(f"line {line_number}: {error}")
            skipped += 1
            if len(errors) >= MAX_ERRORS:
                errors.append(f"stopped after {MAX_ERRORS} row errors")
                break

    if errors and not skip_bad_rows:
        raise InputFileError("\n".join(errors))
    provisional.sort(key=lambda item: (item[1].ts, item[0]))
    events = [
        Event(
            event_id, item.ts, item.token_id, item.token_type, item.principal,
            item.tenant_id, item.source_ip, item.geo_lat, item.geo_lon,
            item.geo_city, item.object_type, item.action, item.records_returned,
            item.granted_scopes,
        )
        for event_id, (_, item) in enumerate(provisional, start=1)
    ]
    return ParseResult(events, rows_read, skipped, tuple(errors), any_geo)


def calculate_baseline_boundary(
    events: list[Event],
    baseline_days: int | None = None,
    baseline_until: str | None = None,
    assume_utc: bool = False,
) -> datetime:
    """Choose the explicit or first-70-percent baseline boundary."""
    if baseline_days is not None and baseline_days <= 0:
        raise InputFileError("--baseline-days must be a positive integer")
    if baseline_days is not None and baseline_until is not None:
        raise InputFileError("choose only one of --baseline-days or --baseline-until")
    if not events:
        raise InputFileError("input contains no valid events")
    if baseline_until is not None:
        return _timestamp(baseline_until, assume_utc)
    start = min(event.ts for event in events)
    if baseline_days is not None:
        return start + timedelta(days=baseline_days)
    end = max(event.ts for event in events)
    return start + (end - start) * 0.7


def imported_metadata(
    source_name: str,
    events: list[Event],
    boundary: datetime,
    rows_read: int,
    skipped_rows: int,
    has_geo_data: bool,
) -> dict[str, str]:
    """Create metadata for detection windows and imported source provenance."""
    if not events:
        raise InputFileError("input contains no valid events")
    start = min(event.ts for event in events)
    end = max(event.ts for event in events)
    eval_end = end + timedelta(seconds=1)
    return {
        "seed": "0",
        "dataset_start_utc": format_ts(start),
        "baseline_end_utc": format_ts(boundary),
        "eval_end_utc": format_ts(eval_end),
        "schema_version": "1",
        "source": "imported",
        "source_filename": Path(source_name).name,
        "analyzed_at": format_ts(datetime.now(timezone.utc)),
        "rows_read": str(rows_read),
        "skipped_rows": str(skipped_rows),
        "geo_data_available": "1" if has_geo_data else "0",
        "impossible_travel_disabled_reason": "" if has_geo_data else "no geo data",
    }
