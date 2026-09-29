"""Phase 6 end-to-end tests: web UI + extension + API + ML + SQLite, against live servers.

Numbering follows the integration test plan (docs/testing.md).
"""
import json
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.request import Request, urlopen
from urllib.error import HTTPError

import pytest

from tests.browser.conftest import LiveServer
from tests.browser.test_extension_browser import extension_for, scan_via_popup  # noqa: F401 (fixture)
from tests.browser.test_frontend_browser import submit, text, visible, wait_outcome


def post(url, payload, raw=None, content_type="application/json"):
    data = raw if raw is not None else json.dumps(payload).encode()
    req = Request(url + "/api/predict", data=data, headers={"Content-Type": content_type}, method="POST")
    try:
        with urlopen(req, timeout=30) as r:
            return r.status, json.loads(r.read())
    except HTTPError as e:
        return e.code, json.loads(e.read())


@pytest.fixture
def fresh_server(tmp_path):
    server = LiveServer(tmp_path)
    yield server
    server.stop()


# TEST 1 + 3: frontend -> API -> ML -> database -> dashboard
def test_1_3_frontend_scan_is_stored_and_shown_on_dashboard(page, fresh_server):
    url = "https://jhjhgfg-3176c.firebaseapp.com/login?user=victim%40example.com"
    page.goto(fresh_server.url + "/inspect")
    submit(page, url)
    wait_outcome(page)
    shown = {k: text(page, k) for k in ("prediction", "risk-level", "confidence")}
    item = fresh_server.client().get("/api/history").get_json()["items"][0]
    assert item["source"] == "web" and item["prediction"] == shown["prediction"] == "Phishing"
    assert item["url"] == "https://jhjhgfg-3176c.firebaseapp.com/login?user=[redacted]"   # stored redacted
    assert text(page, "result-url") == url                                                  # user sees the original
    page.goto(fresh_server.url + "/dashboard")
    page.wait_for("document.querySelectorAll('#history-rows .pill').length === 1")
    assert page.js("document.querySelector('#history-rows code').textContent") == item["url"]
    assert page.js("document.querySelector('#history-rows .pill').textContent") == "Phishing"
    assert text(page, "stat-total") == "1" and text(page, "stat-risk") == "1"


# TEST 2 + acceptance step 13: extension -> API -> same predictor as the web app
def test_2_extension_and_web_app_agree(chrome, page, fresh_server, extension_for):
    target = "https://www.python.org/"
    page.goto(fresh_server.url + "/inspect")
    submit(page, target)
    wait_outcome(page)
    tab, popup = scan_via_popup(chrome, extension_for(fresh_server.url), target)
    for web_id, ext_id in (("prediction", "prediction"), ("risk-level", "risk"), ("confidence", "confidence"),
                           ("verdict-text", "verdict")):
        assert text(page, web_id) == popup.js(f"document.getElementById('{ext_id}').textContent")
    items = fresh_server.client().get("/api/history").get_json()["items"]
    assert [i["source"] for i in items] == ["extension", "web"]
    assert items[0]["phishing_probability"] == items[1]["phishing_probability"]


# TEST 4: multiple consecutive scans through the UI
def test_4_consecutive_scans(page, fresh_server):
    urls = [f"https://www.shop{i}.example.com" for i in range(8)] + ["https://www.wikipedia.org"]
    page.goto(fresh_server.url + "/")
    for url in urls:
        submit(page, url)
        page.wait_for(f"document.getElementById('result-url').textContent === {json.dumps(url)} && "
                      "!document.getElementById('scan-button').disabled")
    items = fresh_server.client().get("/api/history?limit=20").get_json()["items"]
    assert [i["url"] for i in items] == urls[::-1]
    page.wait_for("document.querySelectorAll('#recent-rows tr').length === 5")


# TEST 5, 10, 11: invalid, very long and unsupported URLs are rejected server-side (even bypassing the UI)
@pytest.mark.parametrize("url,code", [("http://exa mple.com", "INVALID_URL"),
                                      ("https://example.com/" + "a" * 5000, "URL_TOO_LONG"),
                                      ("file:///etc/passwd", "UNSUPPORTED_SCHEME"),
                                      ("javascript:alert(document.cookie)", "UNSUPPORTED_SCHEME"),
                                      ("data:text/html,<script>alert(1)</script>", "UNSUPPORTED_SCHEME"),
                                      ("http://169.254.169.254/latest/meta-data/", "UNSUPPORTED_HOST")])
def test_5_10_11_bad_urls_rejected_by_live_api(live_server, url, code):
    status, body = post(live_server.url, {"url": url})
    assert status == 400 and body["error"]["code"] == code


def test_10_long_url_in_ui(page, live_server):
    page.goto(live_server.url + "/inspect")
    submit(page, "https://example.com/" + "a" * 3000)  # programmatic value bypasses maxlength
    wait_outcome(page)
    assert "longer than 2048" in text(page, "url-error")


# TEST 6: malformed requests to the live server
@pytest.mark.parametrize("raw,ctype,status,code", [
    (b"{broken", "application/json", 400, "INVALID_JSON"),
    (b"[1,2]", "application/json", 400, "INVALID_JSON"),
    (b'{"url": 5}', "application/json", 400, "INVALID_TYPE"),
    (b'{"url": "https://a.com", "features": [0.1]}', "application/json", 400, "UNEXPECTED_FIELD"),
    (b"url=https://a.com", "application/x-www-form-urlencoded", 415, "UNSUPPORTED_MEDIA_TYPE"),
    (b'{"url": "' + b"a" * 20000 + b'"}', "application/json", 413, "PAYLOAD_TOO_LARGE"),
])
def test_6_malformed_requests(live_server, raw, ctype, status, code):
    got_status, body = post(live_server.url, None, raw=raw, content_type=ctype)
    assert got_status == status and body["error"]["code"] == code


# TEST 7: API really unavailable (server stopped while the page is open)
def test_7_api_down(page, tmp_path):
    server = LiveServer(tmp_path)
    page.goto(server.url + "/inspect")
    server.stop()
    submit(page, "https://www.example.com")
    wait_outcome(page)
    assert text(page, "error-title") == "Service unavailable" and visible(page, "offline-banner")


# TEST 8: database failure (unusable database path) -> predictions still work, history reports unavailable
def test_8_database_failure(page, tmp_path):
    blocker = tmp_path / "not-a-dir"
    blocker.write_text("x")
    server = LiveServer(tmp_path, DATABASE_PATH=blocker / "history.db")
    try:
        page.goto(server.url + "/inspect")
        submit(page, "https://www.wikipedia.org")
        wait_outcome(page)
        assert visible(page, "state-result") and text(page, "prediction") == "Safe"
        assert text(page, "history-note") == "This result could not be saved to the scan history."
        page.goto(server.url + "/dashboard")
        page.wait_for("!document.getElementById('history-message').hidden")
        assert text(page, "history-message") == "Scan history is temporarily unavailable."
    finally:
        server.stop()


# TEST 9: model loading failure
def test_9_model_loading_failure(page, tmp_path):
    server = LiveServer(tmp_path, MODEL_PATH=tmp_path / "missing.pkl")
    try:
        assert server.client().get("/api/health").get_json() == {"status": "ok", "model_loaded": False}
        page.goto(server.url + "/inspect")
        page.wait_for("!document.getElementById('offline-banner').hidden")
        assert "model is not loaded" in text(page, "offline-message")
        submit(page, "https://www.example.com")
        wait_outcome(page)
        assert text(page, "error-title") == "Model not available"
        status, body = post(server.url, {"url": "https://www.example.com"})
        assert status == 503 and body["error"]["code"] == "MODEL_UNAVAILABLE"
        assert b"missing.pkl" not in json.dumps(body).encode()
    finally:
        server.stop()


# TEST 12: concurrent requests (threaded server, SQLite WAL)
def test_12_concurrent_requests(fresh_server):
    urls = [f"https://www.concurrent{i}.example.com" for i in range(60)]
    with ThreadPoolExecutor(max_workers=12) as pool:
        results = list(pool.map(lambda u: post(fresh_server.url, {"url": u}), urls))
        reads = list(pool.map(lambda _: urlopen(fresh_server.url + "/api/stats", timeout=30).status, range(20)))
    assert all(status == 200 and body["history"]["saved"] for status, body in results)
    assert reads == [200] * 20
    ids = [body["history"]["id"] for _, body in results]
    assert len(set(ids)) == 60
    assert fresh_server.client().get("/api/stats").get_json()["total"] == 60


def test_12_rate_limit_on_live_server(tmp_path):
    server = LiveServer(tmp_path, RATE_LIMIT_PER_MINUTE=5)
    try:
        statuses = [post(server.url, {"url": "https://www.example.com", "record": False})[0] for _ in range(7)]
        assert statuses == [200] * 5 + [429] * 2
    finally:
        server.stop()
