"""All SQL for scan history. Every value is passed as a query parameter."""
import json

from database.models import DETAIL_COLUMNS, JSON_COLUMNS, PREDICTIONS, RISK_LEVELS, SOURCES, SUMMARY_COLUMNS

MAX_STORED_URL_LENGTH = 2048


def _escape_like(text):
    return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _row(row, columns):
    out = {c: row[c] for c in columns}
    for c in JSON_COLUMNS:
        if c in out:
            out[c] = json.loads(out[c]) if out[c] else None
    return out


class ScanRepository:
    def __init__(self, database):
        self.db = database

    def add(self, scan):
        """Insert one scan (dict with the column names) and return its id."""
        values = {
            "scanned_at": scan["scanned_at"],
            "url": scan["url"][:MAX_STORED_URL_LENGTH],
            "normalized_url": scan["normalized_url"][:MAX_STORED_URL_LENGTH],
            "host": (scan.get("host") or "")[:255],
            "prediction": scan["prediction"],
            "risk_level": scan["risk_level"],
            "confidence": scan.get("confidence"),
            "phishing_probability": scan.get("phishing_probability"),
            "model_version": scan.get("model_version"),
            "processing_ms": scan.get("processing_ms"),
            "source": scan.get("source", "api"),
            "features": json.dumps(scan["features"]) if scan.get("features") is not None else None,
            "indicators": json.dumps(scan["indicators"]) if scan.get("indicators") is not None else None,
        }
        columns = ", ".join(values)
        placeholders = ", ".join(f":{c}" for c in values)
        return self.db.run(lambda conn: conn.execute(
            f"INSERT INTO scan_history ({columns}) VALUES ({placeholders})", values).lastrowid)

    def get(self, scan_id):
        row = self.db.run(lambda conn: conn.execute(
            f"SELECT {', '.join(DETAIL_COLUMNS)} FROM scan_history WHERE id = ?", (scan_id,)).fetchone())
        return _row(row, DETAIL_COLUMNS) if row else None

    def list(self, page=1, limit=20, prediction=None, search=None):
        """(items, total) for one page, newest first, optionally filtered."""
        where, params = [], []
        if prediction:
            where.append("prediction = ?")
            params.append(prediction)
        if search:
            where.append("(url LIKE ? ESCAPE '\\' OR host LIKE ? ESCAPE '\\')")
            params += [f"%{_escape_like(search)}%"] * 2
        clause = f"WHERE {' AND '.join(where)}" if where else ""

        def query(conn):
            total = conn.execute(f"SELECT COUNT(*) FROM scan_history {clause}", params).fetchone()[0]
            rows = conn.execute(
                f"SELECT {', '.join(SUMMARY_COLUMNS)} FROM scan_history {clause} ORDER BY id DESC LIMIT ? OFFSET ?",
                params + [limit, (page - 1) * limit]).fetchall()
            return [_row(r, SUMMARY_COLUMNS) for r in rows], total
        return self.db.run(query)

    def delete(self, scan_id):
        return self.db.run(lambda conn: conn.execute("DELETE FROM scan_history WHERE id = ?", (scan_id,)).rowcount) > 0

    def clear(self):
        return self.db.run(lambda conn: conn.execute("DELETE FROM scan_history").rowcount)

    def stats(self, days=30):
        def query(conn):
            total = conn.execute("SELECT COUNT(*) FROM scan_history").fetchone()[0]
            by_prediction = dict(conn.execute(
                "SELECT prediction, COUNT(*) FROM scan_history GROUP BY prediction").fetchall())
            by_risk = dict(conn.execute("SELECT risk_level, COUNT(*) FROM scan_history GROUP BY risk_level").fetchall())
            by_source = dict(conn.execute("SELECT source, COUNT(*) FROM scan_history GROUP BY source").fetchall())
            first, last = conn.execute("SELECT MIN(scanned_at), MAX(scanned_at) FROM scan_history").fetchone()
            daily = conn.execute(
                "SELECT substr(scanned_at, 1, 10) AS day, prediction, COUNT(*) FROM scan_history "
                "WHERE scanned_at >= date('now', ?) GROUP BY day, prediction ORDER BY day",
                (f"-{int(days) - 1} days",)).fetchall()
            return total, by_prediction, by_risk, by_source, first, last, daily
        total, by_prediction, by_risk, by_source, first, last, daily = self.db.run(query)
        per_day = {}
        for day, prediction, count in daily:
            per_day.setdefault(day, {p: 0 for p in PREDICTIONS})[prediction] = count
        return {
            "total": total,
            "by_prediction": {k: by_prediction.get(k, 0) for k in PREDICTIONS},
            "by_risk_level": {k: by_risk.get(k, 0) for k in RISK_LEVELS},
            "by_source": {k: by_source.get(k, 0) for k in SOURCES},
            "first_scan_at": first,
            "last_scan_at": last,
            "daily": [{"date": day, **counts} for day, counts in sorted(per_day.items())],
            "daily_window_days": int(days),
        }
