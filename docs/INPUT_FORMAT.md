# Input log format

The CLI accepts UTF-8 CSV files with a header row (`.csv`) and JSON Lines files (`.jsonl`). Each row/object represents one API request authenticated by a token. Input is processed with Python's `csv`, `json`, and `ipaddress` standard-library modules; it is never evaluated or deserialized as executable data.

## Required fields

| Field | Meaning and validation |
|---|---|
| `timestamp` | ISO-8601 datetime with timezone, for example `2026-03-12T10:15:30Z` or `2026-03-12T15:45:30+05:30`. Naive timestamps are rejected unless `--assume-utc` is supplied. |
| `token_id` | Token identifier, non-empty text. |
| `source_ip` | A valid IPv4 or IPv6 address. |

Headers are case-insensitive. Use `--map "their_time=timestamp,the_token=token_id,client_ip=source_ip"` to map external names to canonical names. Mapping is comma-separated; the left side is the input header and the right side is a supported canonical field.

## Optional fields

| Field | Default |
|---|---|
| `token_type` | `unknown` |
| `principal` | `token_id` |
| `tenant_id` | `unknown` |
| `object_type` | `unknown` |
| `action` | `unknown` |
| `records_returned` | `0`; otherwise a non-negative integer |
| `granted_scopes` | Empty; CSV uses semicolon-separated values such as `Account:query;Case:read`. JSONL accepts either this string form or an array of strings. |
| `geo_lat`, `geo_lon` | No coordinate. Supply both to enable travel checks. Latitude must be -90..90; longitude -180..180. |
| `geo_city` | `unknown` |

Text fields are limited to 256 characters and NUL bytes are rejected. Bad rows report the source line and reason. By default, any bad row fails analysis; `--skip-bad-rows` skips invalid rows and reports the count. Processing stops after 50 row errors. `--max-rows` defaults to 500,000 and prevents larger files from being processed.

## Geo table

When coordinates are absent from the log schema, `--geo-table networks.csv` accepts UTF-8 CSV with these headers:

```csv
cidr,lat,lon,city
192.0.2.0/24,40.7,-74.0,Example City
```

IP addresses use the most-specific matching CIDR. No match means coordinates remain unknown. No external geo service is consulted.

## Commands

```powershell
python main.py validate --input logs.csv
python main.py validate --input logs.jsonl --assume-utc
python main.py validate --input vendor.csv --map "time=timestamp,token=token_id,ip=source_ip"
python main.py analyze --input logs.csv --out out\analysis --baseline-days 14
python main.py analyze --input logs.csv --out out\analysis --geo-table networks.csv --skip-bad-rows
```

The default baseline is the first 70% of the file's timestamp span. `--baseline-days N` starts at the earliest event; `--baseline-until` takes an ISO-8601 timestamp. The two options are mutually exclusive.

The same input format is accepted at the web upload page (`/upload`). Uploads are public by default for convenience; use only synthetic or sanitized data unless all three optional authentication variables (`UPLOAD_USERNAME`, `UPLOAD_PASSWORD`, and `UPLOAD_SECRET_KEY`) are set. Uploads are limited to 100 MiB and 500,000 rows. Uploaded source files are removed after analysis, but generated results remain until deleted or temporary storage is cleared. See the README's [web upload instructions](../README.md#web-uploads-on-render).
