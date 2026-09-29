"""Scan history: database layer, service, API endpoints and failure handling."""
import sqlite3
from contextlib import closing

import pytest

from database import Database, DatabaseError, ScanRepository
from database.models import DETAIL_COLUMNS, SCHEMA_VERSION
from services.history_service import HistoryService, redact_url


def scan(**overrides):
    base = {"scanned_at": "2026-09-29T10:00:00+00:00", "url": "https://a.example/x",
            "normalized_url": "https://a.example/x", "host": "a.example", "prediction": "Safe", "risk_level": "Low",
            "confidence": 0.7, "phishing_probability": 0.3, "model_version": "1.2.0", "processing_ms": 4.2,
            "source": "web", "features": {"URLLength": 20}, "indicators": [{"severity": "info", "message": "m"}]}
    return {**base, **overrides}


@pytest.fixture
def repo(tmp_path):
    return ScanRepository(Database(tmp_path / "h.db"))


# --- database layer ----------------------------------------------------------------
def test_initialisation_creates_schema_version_and_indexes(tmp_path):
    db = Database(tmp_path / "sub" / "h.db")
    db.initialize()
    db.initialize()  # idempotent
    with closing(sqlite3.connect(db.path)) as conn:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION
        columns = [r[1] for r in conn.execute("PRAGMA table_info(scan_history)")]
        indexes = {r[1] for r in conn.execute("PRAGMA index_list(scan_history)")}
    assert set(DETAIL_COLUMNS) <= set(columns)
    assert {"idx_scan_history_scanned_at", "idx_scan_history_prediction"} <= indexes


def test_v1_database_is_migrated_in_place(tmp_path):
    path = tmp_path / "old.db"
    with closing(sqlite3.connect(path)) as conn, conn:
        conn.execute("CREATE TABLE scan_history (id INTEGER PRIMARY KEY AUTOINCREMENT, scanned_at TEXT NOT NULL, "
                     "url TEXT NOT NULL, normalized_url TEXT NOT NULL, prediction TEXT NOT NULL, "
                     "risk_level TEXT NOT NULL, confidence REAL, source TEXT NOT NULL DEFAULT 'api')")
        conn.execute("INSERT INTO scan_history (scanned_at, url, normalized_url, prediction, risk_level, confidence) "
                     "VALUES ('2026-01-01T00:00:00+00:00', 'https://old.example', 'https://old.example', 'Safe', "
                     "'Low', 0.9)")
    repo = ScanRepository(Database(path))
    old = repo.get(1)
    assert old["url"] == "https://old.example" and old["model_version"] is None and old["features"] is None
    new_id = repo.add(scan())
    assert repo.get(new_id)["model_version"] == "1.2.0"


def test_create_retrieve_delete_clear(repo):
    first = repo.add(scan())
    second = repo.add(scan(prediction="Phishing", risk_level="High", url="https://b.example"))
    item = repo.get(first)
    assert item["id"] == first and item["features"] == {"URLLength": 20}
    assert item["indicators"] == [{"severity": "info", "message": "m"}]
    assert repo.get(999) is None
    assert repo.delete(first) is True and repo.delete(first) is False
    assert repo.list()[1] == 1
    assert repo.clear() == 1 and repo.list() == ([], 0)
    assert second  # ids are not reused after delete
    assert repo.add(scan()) > second


def test_pagination_newest_first(repo):
    ids = [repo.add(scan(url=f"https://s{i}.example")) for i in range(25)]
    items, total = repo.list(page=1, limit=10)
    assert total == 25 and [i["id"] for i in items] == ids[::-1][:10]
    items, _ = repo.list(page=3, limit=10)
    assert [i["id"] for i in items] == ids[::-1][20:]
    assert repo.list(page=4, limit=10) == ([], 25)


def test_filter_and_search_are_parameterised(repo):
    repo.add(scan(url="https://shop.example/100%_off", host="shop.example"))
    repo.add(scan(url="https://evil.test/", host="evil.test", prediction="Phishing", risk_level="High"))
    assert repo.list(prediction="Phishing")[1] == 1
    assert repo.list(search="100%_")[1] == 1           # LIKE wildcards are matched literally
    assert repo.list(search="%")[1] == 1
    assert repo.list(search="' OR 1=1 --")[1] == 0     # SQL injection text is just a search string
    assert repo.list(search="evil")[1] == 1


def test_duplicate_and_long_urls(repo):
    a, b = repo.add(scan()), repo.add(scan())
    assert a != b and repo.list()[1] == 2               # every scan is its own record
    long_id = repo.add(scan(url="https://a.example/" + "x" * 5000))
    assert len(repo.get(long_id)["url"]) == 2048


def test_constraints_reject_invalid_values(repo):
    with pytest.raises(DatabaseError):
        repo.add(scan(prediction="Definitely safe"))


def test_stats_counts_and_daily_series(repo):
    from datetime import datetime, timezone
    today = datetime.now(timezone.utc).isoformat(timespec="seconds")
    repo.add(scan(scanned_at=today))
    repo.add(scan(scanned_at=today, prediction="Phishing", risk_level="High", source="extension"))
    repo.add(scan(scanned_at="2000-01-01T00:00:00+00:00"))  # outside the 30-day chart window
    s = repo.stats()
    assert s["total"] == 3 and s["by_prediction"] == {"Safe": 2, "Suspicious": 0, "Phishing": 1}
    assert s["by_source"]["extension"] == 1
    assert s["daily"] == [{"date": today[:10], "Safe": 1, "Suspicious": 0, "Phishing": 1}]


def test_unwritable_database_raises_database_error(tmp_path):
    blocker = tmp_path / "file"
    blocker.write_text("not a directory")
    with pytest.raises(DatabaseError):
        Database(blocker / "h.db").initialize()


# --- privacy -------------------------------------------------------------------------
@pytest.mark.parametrize("url,stored", [
    ("https://a.example/reset?token=abc123&email=v%40x.com#frag",
     "https://a.example/reset?token=[redacted]&email=[redacted]"),
    ("https://user:hunter2@a.example/", "https://user@a.example/"),
    ("https://a.example/path", "https://a.example/path"),
    ("https://a.example/?flag", "https://a.example/?flag=[redacted]"),
])
def test_urls_are_redacted_before_storage(url, stored):
    assert redact_url(url) == stored


def test_secrets_in_scanned_url_never_reach_the_database(client, tmp_path):
    client.post("/api/predict", json={"url": "https://user:hunter2@shop.example/login?session=SECRET-TOKEN-1#x"})
    db_file = client.application.config["DATABASE_PATH"]
    raw = b"".join(p.read_bytes() for p in db_file.parent.glob(db_file.name + "*"))
    assert b"SECRET-TOKEN-1" not in raw and b"hunter2" not in raw


# --- API -----------------------------------------------------------------------------
def test_predict_is_recorded_and_retrievable(client):
    body = client.post("/api/predict", json={"url": "https://www.example.com", "source": "web"}).get_json()
    assert body["history"]["saved"] is True
    item = client.get(f"/api/history/{body['history']['id']}").get_json()["item"]
    assert item["url"] == "https://www.example.com" and item["source"] == "web"
    assert item["prediction"] == body["prediction"] and item["confidence"] == body["confidence"]
    assert item["model_version"] == body["model_version"] and item["features"] == body["features"]
    assert [i["message"] for i in item["indicators"]] == [e["message"] for e in body["explanations"]]
    assert item["scanned_at"] == body["scanned_at"]


def test_history_list_shape_and_pagination(client):
    for i in range(3):
        client.post("/api/predict", json={"url": f"https://site{i}.example.com"})
    body = client.get("/api/history?page=1&limit=2").get_json()
    assert {k: body[k] for k in ("success", "page", "limit", "total", "pages")} == \
        {"success": True, "page": 1, "limit": 2, "total": 3, "pages": 2}
    assert [i["url"] for i in body["items"]] == ["https://site2.example.com", "https://site1.example.com"]
    assert "features" not in body["items"][0]  # list view is a summary
    assert len(client.get("/api/history?page=2&limit=2").get_json()["items"]) == 1


def test_history_filter_and_search(client):
    client.post("/api/predict", json={"url": "https://www.wikipedia.org"})
    client.post("/api/predict", json={"url": "https://jhjhgfg-3176c.firebaseapp.com/"})
    assert client.get("/api/history?prediction=Phishing").get_json()["total"] == 1
    assert client.get("/api/history?q=wikipedia").get_json()["total"] == 1


def test_record_false_is_not_stored(client):
    body = client.post("/api/predict", json={"url": "https://www.example.com", "record": False}).get_json()
    assert body["history"] == {"saved": False, "reason": "not requested"}
    assert client.get("/api/history").get_json()["total"] == 0


def test_unknown_source_is_rejected_and_not_stored(client):
    r = client.post("/api/predict", json={"url": "https://www.example.com", "source": "<script>"})
    assert r.status_code == 400 and r.get_json()["error"]["code"] == "INVALID_FIELD"
    assert client.get("/api/history").get_json()["total"] == 0


@pytest.mark.parametrize("query", ["limit=abc", "limit=0", "limit=101", "page=0", "page=-1", "prediction=Safe%27",
                                   "q=" + "x" * 201, "days=0"])
def test_invalid_history_parameters(client, query):
    path = "/api/stats?" + query if query.startswith("days") else "/api/history?" + query
    r = client.get(path)
    assert r.status_code == 400 and r.get_json()["error"]["code"] == "INVALID_PARAMETER"


@pytest.mark.parametrize("raw_id", ["abc", "0", "-1", "1.5", "1%20OR%201=1", "99999999999999999999"])
def test_invalid_ids(client, raw_id):
    for method in (client.get, client.delete):
        r = method(f"/api/history/{raw_id}")
        assert r.status_code == 400 and r.get_json()["error"]["code"] == "INVALID_ID"


def test_missing_id_is_404(client):
    for method in (client.get, client.delete):
        r = method("/api/history/12345")
        assert r.status_code == 404 and r.get_json()["error"]["code"] == "SCAN_NOT_FOUND"


def test_delete_one_and_clear(client):
    ids = [client.post("/api/predict", json={"url": u}).get_json()["history"]["id"]
           for u in ("https://www.example.com", "https://www.example.org", "https://www.example.net")]
    assert client.delete(f"/api/history/{ids[0]}").get_json() == {"success": True, "deleted": 1}
    assert client.get(f"/api/history/{ids[0]}").status_code == 404
    assert client.delete("/api/history").get_json() == {"success": True, "deleted": 2}
    assert client.get("/api/history").get_json()["total"] == 0


def test_stats_endpoint(client):
    client.post("/api/predict", json={"url": "https://www.example.com", "source": "web"})
    client.post("/api/predict", json={"url": "https://jhjhgfg-3176c.firebaseapp.com/", "source": "extension"})
    s = client.get("/api/stats").get_json()
    assert s["total"] == 2 and s["by_prediction"]["Phishing"] == 1 and s["by_source"]["extension"] == 1
    assert sum(sum(d[p] for p in ("Safe", "Suspicious", "Phishing")) for d in s["daily"]) == 2


# --- failure handling ------------------------------------------------------------------
class BrokenRepository:
    def __getattr__(self, name):
        def fail(*args, **kwargs):
            raise DatabaseError("disk I/O error at /secret/path/history.db")
        return fail


def test_database_failure_keeps_prediction_and_hides_internals(make_app):
    app = make_app()
    app.extensions["history"] = HistoryService(BrokenRepository())
    client = app.test_client()
    r = client.post("/api/predict", json={"url": "https://www.example.com"})
    body = r.get_json()
    assert r.status_code == 200 and body["success"] and body["prediction"] in {"Safe", "Suspicious", "Phishing"}
    assert body["history"] == {"saved": False}
    for path, method in (("/api/history", client.get), ("/api/history/1", client.get), ("/api/stats", client.get),
                         ("/api/history", client.delete), ("/api/history/1", client.delete)):
        r = method(path)
        assert r.status_code == 503 and r.get_json()["error"]["code"] == "HISTORY_UNAVAILABLE"
        assert b"/secret/path" not in r.data and b"disk I/O" not in r.data


def test_app_starts_when_database_path_is_unusable(make_app, tmp_path):
    blocker = tmp_path / "file"
    blocker.write_text("x")
    client = make_app(DATABASE_PATH=blocker / "h.db").test_client()
    assert client.get("/api/health").status_code == 200
    r = client.post("/api/predict", json={"url": "https://www.example.com"})
    assert r.status_code == 200 and r.get_json()["history"] == {"saved": False}
    assert client.get("/api/history").status_code == 503
