"""SQLite schema for scan history.

Only what is needed to show history and dashboard counts is stored: the URL as
submitted, its normalised form, the verdict and the time. No IP addresses,
user agents or other client information are recorded.
"""

SCHEMA = """
CREATE TABLE IF NOT EXISTS scan_history (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    scanned_at      TEXT    NOT NULL,              -- ISO-8601 UTC
    url             TEXT    NOT NULL,              -- as submitted (trimmed)
    normalized_url  TEXT    NOT NULL,
    prediction      TEXT    NOT NULL CHECK (prediction IN ('Safe', 'Suspicious', 'Phishing')),
    risk_level      TEXT    NOT NULL CHECK (risk_level IN ('Low', 'Medium', 'High')),
    confidence      REAL,                          -- NULL when the model has no probabilities
    source          TEXT    NOT NULL DEFAULT 'api' CHECK (source IN ('web', 'extension', 'api'))
);
CREATE INDEX IF NOT EXISTS idx_scan_history_scanned_at ON scan_history (scanned_at);
CREATE INDEX IF NOT EXISTS idx_scan_history_prediction ON scan_history (prediction);
"""

COLUMNS = ("id", "scanned_at", "url", "normalized_url", "prediction", "risk_level", "confidence", "source")
