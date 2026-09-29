"""Web frontend in real headless Chrome against a live Flask server (Phase 4).

Every scan goes through the real /api/predict -> predictor -> model path, except
where a test deliberately intercepts the request to simulate a failure.
"""
import json
import time

import pytest

from tests.browser.cdp import Interceptor, fail, fulfill

PHISHING_URL = "https://jhjhgfg-3176c.firebaseapp.com/"  # held-out test split, label phishing
XSS_URL = 'https://example.com/"><svg/onload=window.__xss=1><img/src/onerror=window.__xss=2>'


def visible(page, element_id):
    return page.js(f"(() => {{ const n = document.getElementById({json.dumps(element_id)});"
                   f" return !!n && getComputedStyle(n).display !== 'none' && n.getClientRects().length > 0; }})()")


def text(page, element_id):
    return page.js(f"document.getElementById({json.dumps(element_id)}).textContent")


def submit(page, url):
    page.js(f"document.getElementById('url-input').value = {json.dumps(url)};"
            "document.getElementById('scan-form').requestSubmit();")


def wait_outcome(page, timeout=20):
    page.wait_for("['state-result','state-error'].some(id => !document.getElementById(id).hidden) || "
                  "!document.getElementById('url-error').hidden", timeout)


def real_errors(page):
    """Console errors other than the network failures a test injected on purpose."""
    return [e for e in page.console_errors if "Failed to load resource" not in e]


def history_total(live_server):
    return live_server.client().get("/api/history").get_json()["total"]


# --- scanning ----------------------------------------------------------------------------
def test_low_risk_scan_matches_api(page, live_server):
    page.goto(live_server.url + "/inspect")
    submit(page, "https://www.wikipedia.org")
    wait_outcome(page)
    assert visible(page, "state-result")
    api = live_server.client().post("/api/predict", json={"url": "https://www.wikipedia.org", "record": False}).get_json()
    assert text(page, "verdict-text") == "Low-risk prediction" == api["verdict"]
    assert text(page, "prediction") == "Safe" and text(page, "risk-level") == "Low"
    assert text(page, "confidence") == f"{api['confidence'] * 100:.1f}%"
    assert text(page, "result-url") == "https://www.wikipedia.org"
    assert "not a guarantee" in text(page, "result-disclaimer") or "does not mean a site is safe" in \
        text(page, "result-disclaimer")
    assert page.js("document.querySelectorAll('#feature-rows tr').length") == 17
    assert page.js("document.querySelectorAll('#explanations li').length") >= 1
    assert text(page, "history-note") == "Saved to scan history."
    assert "safe" not in text(page, "verdict-summary").lower()
    assert real_errors(page) == []


def test_phishing_risk_scan(page, live_server):
    page.goto(live_server.url + "/")
    submit(page, PHISHING_URL)
    wait_outcome(page)
    assert text(page, "verdict-text") == "Phishing-risk prediction (high)"
    assert page.js("document.getElementById('verdict').className") == "verdict phishing"
    assert text(page, "risk-level") == "High"
    assert page.js("document.querySelectorAll('#explanations li.risk, #explanations li.caution').length") >= 1
    link = page.js("document.getElementById('details-link').getAttribute('href')")
    assert link.startswith("/inspect?id=") and visible(page, "details-link")
    # the saved scan opens on /inspect with the same prediction
    page.goto(live_server.url + link)
    page.wait_for("!document.getElementById('state-result').hidden")
    assert text(page, "prediction") == "Phishing" and "saved scan" in text(page, "result-origin")
    assert page.js("document.querySelectorAll('#feature-rows tr').length") == 17
    assert real_errors(page) == []


def test_empty_input_is_rejected_without_a_request(page, live_server):
    page.goto(live_server.url + "/inspect")
    before = history_total(live_server)
    submit(page, "   ")
    wait_outcome(page)
    assert visible(page, "url-error") and text(page, "url-error") == "Please enter a URL to scan."
    assert not visible(page, "state-result")
    assert history_total(live_server) == before


@pytest.mark.parametrize("url,expected", [
    ("https://exa mple.com", "invalid"),
    ("javascript:alert(1)", "Only http:// and https://"),
    ("http://localhost:8000/", "cannot be scanned"),
])
def test_invalid_urls_show_server_message(page, live_server, url, expected):
    page.goto(live_server.url + "/inspect")
    submit(page, url)
    wait_outcome(page)
    assert visible(page, "url-error") and expected in text(page, "url-error")
    assert page.js("document.getElementById('url-input').getAttribute('aria-invalid')") == "true"
    assert not visible(page, "state-result")


def test_duplicate_submissions_are_ignored(page, live_server):
    page.goto(live_server.url + "/inspect")
    before = history_total(live_server)
    page.js("{ const i = document.getElementById('url-input'); i.value = 'https://www.python.org';"
            "const f = document.getElementById('scan-form'); f.requestSubmit(); f.requestSubmit(); f.requestSubmit(); }")
    wait_outcome(page)
    time.sleep(0.5)
    assert history_total(live_server) == before + 1


def test_scanned_url_cannot_inject_markup_or_script(page, live_server):
    page.goto(live_server.url + "/inspect")
    submit(page, XSS_URL)
    wait_outcome(page)
    assert visible(page, "state-result")
    assert text(page, "result-url") == XSS_URL
    assert page.js("typeof window.__xss") == "undefined"
    assert page.js("document.querySelectorAll('#state-result svg, #state-result img').length") == 0
    page.goto(live_server.url + "/dashboard")
    page.wait_for("document.querySelectorAll('#history-rows code').length > 0")
    assert page.js("typeof window.__xss") == "undefined"
    assert page.js("document.querySelectorAll('#history-rows svg, #history-rows img').length") == 0


# --- failure states ------------------------------------------------------------------------
def test_api_unavailable(page, live_server):
    page.goto(live_server.url + "/inspect")
    icpt = Interceptor(page, "*/api/predict*", lambda p, params: fail(p, params))
    try:
        submit(page, "https://www.example.com")
        wait_outcome(page)
    finally:
        icpt.stop()
    assert text(page, "error-title") == "Service unavailable"
    assert "Flask server is running" in text(page, "error-message")
    assert visible(page, "offline-banner")
    assert page.js("document.getElementById('scan-button').disabled") is False


def test_malformed_api_response(page, live_server):
    page.goto(live_server.url + "/inspect")
    icpt = Interceptor(page, "*/api/predict*",
                       lambda p, params: fulfill(p, params, 200, "<html>proxy error</html>", "text/html"))
    try:
        submit(page, "https://www.example.com")
        wait_outcome(page)
    finally:
        icpt.stop()
    assert text(page, "error-title") == "Unexpected response"


def test_server_error_shows_friendly_message(page, live_server):
    page.goto(live_server.url + "/inspect")
    body = json.dumps({"success": False, "error": {"code": "PREDICTION_FAILED",
                                                   "message": "The URL could not be analysed because of an internal error."}})
    icpt = Interceptor(page, "*/api/predict*", lambda p, params: fulfill(p, params, 500, body))
    try:
        submit(page, "https://www.example.com")
        wait_outcome(page)
    finally:
        icpt.stop()
    assert text(page, "error-title") == "Scan failed"
    assert text(page, "error-message") == "The URL could not be analysed because of an internal error."


def test_request_timeout(page, live_server):
    page.goto(live_server.url + "/inspect")
    icpt = Interceptor(page, "*/api/predict*", lambda p, params: None)  # never answered
    try:
        start = time.time()
        submit(page, "https://www.example.com")
        wait_outcome(page, timeout=25)
    finally:
        icpt.stop()
    assert text(page, "error-title") == "Request timed out"
    assert 14 <= time.time() - start <= 22  # 15 s client timeout


# --- dashboard -----------------------------------------------------------------------------
def test_dashboard_statistics_and_table_match_api(page, live_server):
    client = live_server.client()
    client.delete("/api/history")
    for url in ("https://www.wikipedia.org", "https://www.python.org", PHISHING_URL):
        client.post("/api/predict", json={"url": url, "source": "web"})
    page.goto(live_server.url + "/dashboard")
    page.wait_for("document.getElementById('stat-total').textContent !== '–' && "
                  "document.querySelectorAll('#history-rows tr .pill').length === 3")
    stats = client.get("/api/stats").get_json()
    assert text(page, "stat-total") == str(stats["total"]) == "3"
    p = stats["by_prediction"]
    assert text(page, "stat-risk") == str(p["Suspicious"] + p["Phishing"])
    assert text(page, "stat-low") == str(p["Safe"])
    assert page.js("document.querySelectorAll('#chart-distribution .dist-row').length") == 3
    assert page.js("Array.from(document.querySelectorAll('#chart-distribution .dist-value')).map(n => n.textContent)") \
        == [f"{p['Safe']} (67%)", f"{p['Suspicious']} (0%)", f"{p['Phishing']} (33%)"]
    assert page.js("document.querySelectorAll('#chart-activity rect').length") >= 1
    # search and filter
    page.js("{ const s = document.getElementById('history-search'); s.value = 'wikipedia';"
            "s.dispatchEvent(new Event('input')); }")
    page.wait_for("document.querySelectorAll('#history-rows tr .pill').length === 1")
    page.js("{ const s = document.getElementById('history-search'); s.value = ''; s.dispatchEvent(new Event('input'));"
            "const f = document.getElementById('history-filter'); f.value = 'Phishing'; f.dispatchEvent(new Event('change')); }")
    page.wait_for("document.querySelectorAll('#history-rows tr .pill').length === 1 && "
                  "document.querySelector('#history-rows .pill').textContent === 'Phishing'")
    assert real_errors(page) == []


def test_dashboard_pagination(page, live_server):
    client = live_server.client()
    client.delete("/api/history")
    for i in range(12):
        client.post("/api/predict", json={"url": f"https://www.site{i}.example.com"})
    page.goto(live_server.url + "/dashboard")
    page.wait_for("document.querySelectorAll('#history-rows tr .pill').length === 10")
    assert "Page 1 of 2" in text(page, "page-info")
    assert page.js("document.getElementById('prev-page').disabled") is True
    page.js("document.getElementById('next-page').click()")
    page.wait_for("document.querySelectorAll('#history-rows tr .pill').length === 2")
    assert "Page 2 of 2" in text(page, "page-info")


def test_dashboard_delete_and_clear(page, live_server):
    client = live_server.client()
    client.delete("/api/history")
    for url in ("https://www.wikipedia.org", "https://www.python.org"):
        client.post("/api/predict", json={"url": url})
    page.goto(live_server.url + "/dashboard")
    page.wait_for("document.querySelectorAll('#history-rows button').length === 2")
    page.js("document.querySelector('#history-rows button').click()")
    page.wait_for("document.querySelectorAll('#history-rows button').length === 1")
    assert page.dialogs[-1] == "Delete this scan from the history?"
    assert client.get("/api/history").get_json()["total"] == 1
    page.wait_for("document.getElementById('stat-total').textContent === '1'")
    page.accept_dialogs = False  # cancelling must not delete
    page.js("document.getElementById('clear-button').click()")
    time.sleep(0.5)
    assert client.get("/api/history").get_json()["total"] == 1
    page.accept_dialogs = True
    page.js("document.getElementById('clear-button').click()")
    page.wait_for("document.getElementById('stat-total').textContent === '0'")
    assert client.get("/api/history").get_json()["total"] == 0
    assert "No scans yet." in page.js("document.getElementById('history-rows').textContent")


def test_dashboard_history_failure(page, live_server):
    body = json.dumps({"success": False, "error": {"code": "HISTORY_UNAVAILABLE",
                                                   "message": "Scan history is temporarily unavailable."}})
    icpt = Interceptor(page, "*/api/*", lambda p, params: fulfill(p, params, 503, body)
                       if "/api/history" in params["request"]["url"] or "/api/stats" in params["request"]["url"]
                       else p.send("Fetch.continueRequest", {"requestId": params["requestId"]}))
    try:
        page.goto(live_server.url + "/dashboard")
        page.wait_for("!document.getElementById('history-message').hidden && !document.getElementById('stats-error').hidden")
    finally:
        icpt.stop()
    assert text(page, "history-message") == "Scan history is temporarily unavailable."
    assert "database cannot be read" in text(page, "stats-error")


# --- existing pages and layout ---------------------------------------------------------------
HIDDEN_BUT_RENDERED = ("Array.from(document.querySelectorAll('[hidden]'))"
                       ".filter(n => getComputedStyle(n).display !== 'none').map(n => n.id || n.className)")


def test_hidden_elements_are_not_rendered(page, live_server):
    """Regression: component display rules once overrode the hidden attribute (all states showed at once)."""
    for path in ("/", "/inspect", "/dashboard"):
        page.goto(live_server.url + path)
        time.sleep(0.6)
        assert page.js(HIDDEN_BUT_RENDERED) == [], path
    page.goto(live_server.url + "/")
    submit(page, "https://www.wikipedia.org")
    wait_outcome(page)
    assert page.js(HIDDEN_BUT_RENDERED) == []
    assert [page.js(f"getComputedStyle(document.getElementById('state-{s}')).display")
            for s in ("idle", "loading", "error")] == ["none"] * 3


def test_pages_load_without_console_or_csp_errors(page, live_server):
    for path in ("/", "/inspect", "/dashboard"):
        page.console_errors.clear()
        page.goto(live_server.url + path)
        time.sleep(0.6)
        assert page.js("document.querySelectorAll('script').length") >= 2
        assert real_errors(page) == [], (path, page.console_errors)
    page.goto(live_server.url + "/")
    page.wait_for("document.querySelector('[data-metric=recall]').textContent.endsWith('%')")
    recall = live_server.client().get("/api/model-info").get_json()["evaluation"]["recall"]
    assert page.js("document.querySelector('[data-metric=recall]').textContent") == f"{recall * 100:.1f}%"


@pytest.mark.parametrize("width,height,label", [(375, 812, "mobile"), (768, 1024, "tablet"), (1280, 900, "desktop")])
def test_responsive_layout_has_no_horizontal_overflow(page, live_server, artifacts, width, height, label):
    page.viewport(width, height, mobile=width < 500)
    long_url = "https://www.example.com/" + "segment/" * 40
    page.goto(live_server.url + "/")
    submit(page, long_url)
    wait_outcome(page)
    for path in ("/", "/inspect", "/dashboard"):
        if path != "/":
            page.goto(live_server.url + path)
            time.sleep(0.8)
        overflow = page.js("document.documentElement.scrollWidth - document.documentElement.clientWidth")
        assert overflow <= 0, (label, path, overflow)
        if artifacts:
            page.screenshot(artifacts / f"{label}{path.replace('/', '_') or '_home'}.png")
    page.send("Emulation.clearDeviceMetricsOverride")
