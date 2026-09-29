"""SQLite access for scan history (standard library only)."""
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

from database.models import COLUMNS, SCHEMA

MAX_STORED_URL_LENGTH = 2048


class HistoryStore:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with closing(self._connect()) as conn, conn:
            conn.executescript(SCHEMA)

    def _connect(self):
        conn = sqlite3.connect(self.path, timeout=5)
        conn.row_factory = sqlite3.Row
        return conn

    def add(self, url, normalized_url, prediction, risk_level, confidence, source="api"):
        scanned_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
        with closing(self._connect()) as conn, conn:
            cursor = conn.execute(
                "INSERT INTO scan_history (scanned_at, url, normalized_url, prediction, risk_level, confidence, source)"
                " VALUES (?, ?, ?, ?, ?, ?, ?)",
                (scanned_at, url[:MAX_STORED_URL_LENGTH], normalized_url[:MAX_STORED_URL_LENGTH],
                 prediction, risk_level, confidence, source),
            )
            return {"id": cursor.lastrowid, "scanned_at": scanned_at}

    def recent(self, limit=20):
        with closing(self._connect()) as conn:
            rows = conn.execute(
                f"SELECT {', '.join(COLUMNS)} FROM scan_history ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(row) for row in rows]

    def stats(self):
        with closing(self._connect()) as conn:
            total = conn.execute("SELECT COUNT(*) FROM scan_history").fetchone()[0]
            by_prediction = dict(conn.execute(
                "SELECT prediction, COUNT(*) FROM scan_history GROUP BY prediction").fetchall())
            by_risk = dict(conn.execute(
                "SELECT risk_level, COUNT(*) FROM scan_history GROUP BY risk_level").fetchall())
            by_source = dict(conn.execute(
                "SELECT source, COUNT(*) FROM scan_history GROUP BY source").fetchall())
            first_last = conn.execute("SELECT MIN(scanned_at), MAX(scanned_at) FROM scan_history").fetchone()
        return {
            "total": total,
            "by_prediction": {k: by_prediction.get(k, 0) for k in ("Safe", "Suspicious", "Phishing")},
            "by_risk_level": {k: by_risk.get(k, 0) for k in ("Low", "Medium", "High")},
            "by_source": {k: by_source.get(k, 0) for k in ("web", "extension", "api")},
            "first_scan_at": first_last[0],
            "last_scan_at": first_last[1],
        }

    def clear(self):
        with closing(self._connect()) as conn, conn:
            return conn.execute("DELETE FROM scan_history").rowcount
