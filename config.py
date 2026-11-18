"""Shared thresholds and response policy for the token anomaly detector."""

MIN_DIST_KM = 100.0  # Ignore travel between nearby locations.
MAX_SPEED_KMH = 900.0  # Flag implausible travel only above this speed.
SCOPE_MIN_RELEVANCY = 0.02  # Flag object-action pairs rarer than this baseline share.
MIN_BASELINE_EVENTS = 30  # Require this many events for scope and temporal profiles.
TEMPORAL_MIN_SHARE = 0.01  # Flag UTC hours below this smoothed baseline share.
VOLUME_K = 6.0  # Robust spread multiplier for active-window thresholds.
VOLUME_HEADROOM = 1.5  # Keep thresholds above the largest baseline bucket.
MIN_ABS_EVENTS = 10  # Require this many events before a count alert can fire.
MIN_ABS_RECORDS = 1000  # Require this many records before a record alert can fire.
MIN_ACTIVE_WINDOWS = 20  # Require this many populated baseline windows for volume.
FANOUT_WINDOW_MIN = 15  # Bound new-IP tenant fan-out to this many minutes.
FANOUT_MIN_TENANTS = 5  # Require this many distinct tenants for a fan-out alert.
INCIDENT_GAP_MIN = 30  # Start a new token incident after this quiet period.
RESPONSE_POLICY = {  # Map a single detector family to its simulated response.
    "impossible_travel": ("MEDIUM", "notify"),
    "volume_spike": ("MEDIUM", "notify"),
    "scope_creep": ("LOW", "log"),
    "temporal_anomaly": ("LOW", "log"),
}
