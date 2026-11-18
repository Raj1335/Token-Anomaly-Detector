# Detection Specification

## Impossible travel

Signal: an unknown-IP event follows a distant prior event at implausible speed.
Simulation: Frankfurt travel and replay scenarios introduce distant or unfamiliar source IPs.
Detection: haversine distance divided by elapsed hours, with a 900 km/h threshold and baseline-IP check.
Proof: camp_travel and camp_drift emit impossible_travel alerts.

## Scope creep

Signal: an object-action pair has baseline relevancy below 0.02.
Simulation: int_003 queries User and Case and replay adds those objects.
Detection: fit per-token pair shares, emit scope_deviation for low relevancy and scope_violation outside grants.
Proof: campaign scope and all replay tokens emit scope_deviation alerts.

## Temporal anomaly

Signal: an event hour has smoothed UTC baseline share below 0.01.
Simulation: sess_012 activity occurs at an unusual hour.
Detection: circular 24-bin histogram with 0.25/0.50/0.25 smoothing.
Proof: the temporal campaign emits subtype temporal.

## Volume spike

Signal: running count or records in a 5-minute epoch bucket exceeds robust baseline limits.
Simulation: replay tokens produce 60 events and 500-5000 records per event.
Detection: median/MAD/headroom threshold with absolute minimum count and record gates.
Proof: each camp_drift token emits per_token_rate.

## New-IP fan-out

Signal: an unknown source IP reaches at least five tenants within 15 minutes.
Simulation: replay traffic uses a shared Frankfurt source across integration tenants.
Detection: sliding tenant set, with causal alerts after the threshold.
Proof: campaign evaluation reports tenant fan-out and incident mappings.
