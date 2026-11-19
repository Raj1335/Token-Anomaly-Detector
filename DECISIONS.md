Decided to use synthetic Faker-backed event distributions instead of real logs, because no safe or authorized log source is available.
Decided not to integrate Splunk or another SIEM, because the MVP is zero-cost and local-first.
Decided to fix scope relevancy so low shares flag deviation instead of high shares, because high-frequency drift is normal for integrations.
Decided to protect volume detection with a baseline maximum headroom, because nightly batches must not alert.
Decided to track new-IP fan-out by distinct tenant rather than token count, because the tenant is the incident boundary.
Decided to make fan-out alerts causal, because prior tenants must not receive retroactive alerts.
Decided to keep campaign IDs separate from incident IDs, because campaign is ground truth and incident is detected state.
Decided to use fixed simulated UTC city offsets, because Windows may lack an IANA database.
Decided to enforce train/test windows in metadata, because fitting cannot leak evaluation labels.
Decided to simulate revocation and notification in SQLite, because there are no external communications or credential hooks.
Decided to use only the stdlib plus Faker and Flask, because ML and heavy packages are prohibited.
Decided to use local read-only SQLite for the dashboard, because it is not an authenticated hosted application.
Decided to accept a documented canonical CSV/JSONL schema plus explicit column mapping instead of provider-specific parsers, because vendor adapters need separate formats and samples.
Decided to split imported data by timestamp span rather than row order, because log exports may arrive unsorted.
Decided to preserve unknown geography as null and disable travel detection when no location data exists, because fabricated coordinates would create misleading alerts.
Decided to leave imported labels empty and skip evaluation, because user-provided data has no ground truth.
Decided to prefix spreadsheet-formula-like CSV cells with a quote and HTML-escape report values, because log fields are untrusted.
Decided to make the upload page public by default for the simple demo while retaining optional shared HTTP Basic authentication and CSRF tokens, because users requested low-friction uploads but private logs still need a protected mode.