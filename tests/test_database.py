"""Scan history storage and the history/stats endpoints."""
import sqlite3

from database import HistoryStore


def test_store_add_recent_stats_clear(tmp_path):
    store = HistoryStore(tmp_path / "h.db")
    store.add("a.com", "https://a.com", "Safe", "Low", 0.9, "web")
    store.add("b.com", "https://b.com", "Phishing", "High", 0.99, "extension")
    store.add("c.com", "https://c.com", "Suspicious", "Medium", None, "api")
    recent = store.recent(10)
    assert [r["url"] for r in recent] == ["c.com", "b.com", "a.com"]
    assert recent[0]["confidence"] is None and recent[1]["normalized_url"] == "https://b.com"
    stats = store.stats()
    assert stats["total"] == 3
    assert stats["by_prediction"] == {"Safe": 1, "Suspicious": 1, "Phishing": 1}
    assert stats["by_risk_level"] == {"Low": 1, "Medium": 1, "High": 1}
    assert store.clear() == 3 and store.stats()["total"] == 0


def test_schema_has_indexes_and_constraints(tmp_path):
    HistoryStore(tmp_path / "h.db")
    conn = sqlite3.connect(tmp_path / "h.db")
    indexes = {row[1] for row in conn.execute("PRAGMA index_list('scan_history')")}
    assert {"idx_scan_history_scanned_at", "idx_scan_history_prediction"} <= indexes
    columns = [row[1] for row in conn.execute("PRAGMA table_info('scan_history')")]
    assert columns == ["id", "scanned_at", "url", "normalized_url", "prediction", "risk_level", "confidence", "source"]
    try:
        conn.execute("INSERT INTO scan_history (scanned_at, url, normalized_url, prediction, risk_level)"
                     " VALUES ('t', 'u', 'u', 'Maybe', 'Low')")
        raise AssertionError("CHECK constraint not enforced")
    except sqlite3.IntegrityError:
        pass


def test_predict_is_recorded_and_listed(client):
    client.post("/api/predict", json={"url": "https://www.example.com", "source": "web"})
    body = client.get("/api/history").get_json()
    assert body["success"] and len(body["scans"]) == 1
    scan = body["scans"][0]
    assert scan["url"] == "https://www.example.com" and scan["source"] == "web"
    assert set(scan) == {"id", "scanned_at", "url", "normalized_url", "prediction", "risk_level", "confidence",
                         "source"}


def test_background_scans_are_not_recorded(client):
    client.post("/api/predict", json={"url": "https://www.example.com", "source": "extension", "record": False})
    assert client.get("/api/history").get_json()["scans"] == []


def test_unknown_source_is_stored_as_api(client):
    client.post("/api/predict", json={"url": "https://www.example.com", "source": "<script>"})
    assert client.get("/api/history").get_json()["scans"][0]["source"] == "api"


def test_history_limit_validation(client):
    assert client.get("/api/history?limit=abc").status_code == 400
    for i in range(3):
        client.post("/api/predict", json={"url": f"https://www.site{i}.com"})
    assert len(client.get("/api/history?limit=2").get_json()["scans"]) == 2
    assert len(client.get("/api/history?limit=-5").get_json()["scans"]) == 1


def test_delete_history_and_stats(client):
    client.post("/api/predict", json={"url": "https://www.example.com"})
    client.post("/api/predict", json={"url": "http://192.168.1.20:8080/login.php"})
    stats = client.get("/api/stats").get_json()
    assert stats["total"] == 2 and sum(stats["by_prediction"].values()) == 2
    assert client.delete("/api/history").get_json() == {"success": True, "deleted": 2}
    assert client.get("/api/stats").get_json()["total"] == 0
