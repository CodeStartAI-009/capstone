"""SQLite schema for scan history (schema version 2).

Stored per scan: the URL (with secrets redacted, see services/history_service.py),
the model's result, the model version, the processing time and the
feature-based risk indicators that were shown to the user. Never stored: IP
addresses, user agents, request headers, cookies or page contents.
"""

SCHEMA_VERSION = 2

PREDICTIONS = ("Safe", "Suspicious", "Phishing")
RISK_LEVELS = ("Low", "Medium", "High")
SOURCES = ("web", "extension", "api")

# Version 1 (first release) had the columns up to `source`. The v2 table below is
# what a fresh database gets; MIGRATIONS upgrade an existing v1 file in place.
SCHEMA = """
CREATE TABLE IF NOT EXISTS scan_history (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    scanned_at           TEXT    NOT NULL,              -- ISO-8601 UTC
    url                  TEXT    NOT NULL,              -- as submitted (trimmed, secrets redacted)
    normalized_url       TEXT    NOT NULL,              -- normalised form (secrets redacted)
    prediction           TEXT    NOT NULL CHECK (prediction IN ('Safe', 'Suspicious', 'Phishing')),
    risk_level           TEXT    NOT NULL CHECK (risk_level IN ('Low', 'Medium', 'High')),
    confidence           REAL,                          -- NULL when the model has no probabilities
    source               TEXT    NOT NULL DEFAULT 'api' CHECK (source IN ('web', 'extension', 'api')),
    host                 TEXT,
    phishing_probability REAL,
    model_version        TEXT,
    processing_ms        REAL,
    features             TEXT,                          -- JSON object: the 17 model inputs
    indicators           TEXT                           -- JSON list: explanation items shown to the user
);
CREATE INDEX IF NOT EXISTS idx_scan_history_scanned_at ON scan_history (scanned_at);
CREATE INDEX IF NOT EXISTS idx_scan_history_prediction ON scan_history (prediction);
"""

MIGRATIONS = {
    2: [
        "ALTER TABLE scan_history ADD COLUMN host TEXT",
        "ALTER TABLE scan_history ADD COLUMN phishing_probability REAL",
        "ALTER TABLE scan_history ADD COLUMN model_version TEXT",
        "ALTER TABLE scan_history ADD COLUMN processing_ms REAL",
        "ALTER TABLE scan_history ADD COLUMN features TEXT",
        "ALTER TABLE scan_history ADD COLUMN indicators TEXT",
    ],
}

SUMMARY_COLUMNS = ("id", "scanned_at", "url", "normalized_url", "host", "prediction", "risk_level", "confidence",
                   "phishing_probability", "model_version", "processing_ms", "source")
DETAIL_COLUMNS = SUMMARY_COLUMNS + ("features", "indicators")
JSON_COLUMNS = ("features", "indicators")
