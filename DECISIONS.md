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