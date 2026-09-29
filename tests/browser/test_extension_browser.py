"""Chrome extension in real headless Chrome (Phase 5).

The unpacked extension is loaded with Extensions.loadUnpacked and the popup is opened with
Extensions.triggerAction, which simulates the user clicking the toolbar icon, so Chrome grants
the real `activeTab` permission. The copy under test differs from extension/ only in the API
origin (config.js API_BASE and the matching manifest host_permissions), which points at a
test server.
"""
import json
import shutil
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from tests.browser.cdp import Interceptor, Page, fulfill

EXTENSION_DIR = Path(__file__).resolve().parents[2] / "extension"
POPUP_STATE = ("!document.getElementById('result').hidden || !document.getElementById('error').hidden")


def build_extension(tmp_path, api_base):
    target = tmp_path / f"ext-{abs(hash(api_base))}"
    shutil.copytree(EXTENSION_DIR, target)
    config = (target / "config.js").read_text()
    assert config.count('"http://127.0.0.1:5000"') == 1
    (target / "config.js").write_text(config.replace('"http://127.0.0.1:5000"', json.dumps(api_base)))
    manifest = json.loads((target / "manifest.json").read_text())
    manifest["host_permissions"] = [api_base + "/*"]
    (target / "manifest.json").write_text(json.dumps(manifest))
    return target


class MockApi:
    """Stand-in API for failure modes: 'slow' (never answers in time), 'error' (500 JSON), 'html' (non-JSON)."""

    def __init__(self, mode):
        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                self.rfile.read(int(self.headers.get("Content-Length", 0)))
                if mode == "slow":
                    time.sleep(12)
                    body, status, ctype = b"{}", 200, "application/json"
                elif mode == "error":
                    body = json.dumps({"success": False, "error": {"code": "PREDICTION_FAILED",
                                       "message": "The URL could not be analysed because of an internal error."}}).encode()
                    status, ctype = 500, "application/json"
                else:
                    body, status, ctype = b"<html>Bad gateway</html>", 502, "text/html"
                try:
                    self.send_response(status)
                    self.send_header("Content-Type", ctype)
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                except (BrokenPipeError, ConnectionResetError):
                    pass

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.url = f"http://127.0.0.1:{self.server.server_port}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def stop(self):
        self.server.shutdown()


def closed_port_url():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    return f"http://127.0.0.1:{port}"


@pytest.fixture(scope="module")
def extension_for(chrome, tmp_path_factory):
    cache = {}

    def load(api_base):
        if api_base not in cache:
            cache[api_base] = chrome.load_extension(build_extension(tmp_path_factory.mktemp("ext"), api_base))
        return cache[api_base]
    return load


def open_tab(chrome, url, body="<h1>Test page</h1>"):
    """Open a tab at `url`. http(s) pages are served by request interception, so no real network is used."""
    tab = chrome.new_page()
    if url.startswith("http"):
        Interceptor(tab, url.split("?")[0] + "*", lambda p, params: fulfill(p, params, 200, body, "text/html"))
    tab.goto(url)
    return tab


def click_action(chrome, ext_id, tab):
    """Simulate the toolbar click on `tab` and return the opened popup page."""
    existing = {t["targetId"] for t in chrome.targets()}
    tab_target = next(t for t in chrome.send("Target.getTargets", {"filter": [{"type": "tab"}]})["targetInfos"]
                      if t["url"] == tab.js("location.href"))
    chrome.send("Extensions.triggerAction", {"id": ext_id, "targetId": tab_target["targetId"]})
    info = chrome.wait_for_target(lambda t: t["targetId"] not in existing and t["url"].endswith(f"{ext_id}/popup.html"))
    popup = Page(chrome, info["targetId"], chrome.attach(info["targetId"]))
    popup.wait_for("document.readyState === 'complete'")
    return popup


def popup_text(popup, element_id):
    return popup.js(f"document.getElementById('{element_id}').textContent")


def scan_via_popup(chrome, ext_id, url, body="<h1>Test page</h1>", timeout=15):
    tab = open_tab(chrome, url, body)
    popup = click_action(chrome, ext_id, tab)
    popup.wait_for(POPUP_STATE, timeout)
    return tab, popup


def history(live_server):
    return live_server.client().get("/api/history").get_json()


# --- scanning through the real API -------------------------------------------------------------
def test_https_page_matches_web_app_prediction(chrome, live_server, extension_for):
    ext_id = extension_for(live_server.url)
    before = history(live_server)["total"]
    tab, popup = scan_via_popup(chrome, ext_id, "https://www.wikipedia.org/")
    assert popup_text(popup, "url") == "https://www.wikipedia.org/"
    assert not popup.js("document.getElementById('result').hidden")
    web = live_server.client().post("/api/predict", json={"url": "https://www.wikipedia.org/", "record": False}).get_json()
    assert popup_text(popup, "verdict") == web["verdict"] == "Low-risk prediction"
    assert popup_text(popup, "prediction") == web["prediction"] and popup_text(popup, "risk") == web["risk_level"]
    assert popup_text(popup, "confidence") == f"{web['confidence'] * 100:.1f}%"
    assert popup.js("Array.from(document.querySelectorAll('#reasons li')).map(l => l.textContent)") == web["explanation"][:4]
    assert "does not mean a site is safe" in popup_text(popup, "disclaimer")
    items = history(live_server)
    assert items["total"] == before + 1 and items["items"][0]["source"] == "extension"
    assert popup.console_errors == []


def test_suspicious_http_page(chrome, live_server, extension_for):
    ext_id = extension_for(live_server.url)
    url = "http://paypal-login-secure-verify.account-update.xyz/signin"
    tab, popup = scan_via_popup(chrome, ext_id, url)
    assert popup_text(popup, "url") == url
    assert popup_text(popup, "verdict").startswith("Phishing-risk prediction")
    assert popup.js("document.getElementById('verdict').className") in ("verdict suspicious", "verdict phishing")
    assert popup.js("document.querySelectorAll('#reasons li').length") >= 1


def test_details_and_dashboard_buttons_open_the_web_app(chrome, live_server, extension_for):
    ext_id = extension_for(live_server.url)
    tab, popup = scan_via_popup(chrome, ext_id, "https://www.python.org/")
    scan_id = history(live_server)["items"][0]["id"]
    before = {t["targetId"] for t in chrome.targets()}
    popup.js("document.getElementById('details').click()")
    expected = f"{live_server.url}/inspect?id={scan_id}"
    chrome.wait_for_target(lambda t: t["targetId"] not in before and t["type"] == "page" and t["url"] == expected)
    tab2, popup2 = scan_via_popup(chrome, ext_id, "https://www.python.org/")
    before = {t["targetId"] for t in chrome.targets()}
    popup2.js("document.getElementById('dashboard').click()")
    chrome.wait_for_target(lambda t: t["targetId"] not in before and t["type"] == "page"
                           and t["url"] == f"{live_server.url}/dashboard")


# --- unsupported pages: rejected in the popup, nothing sent to the API ------------------------------
# Chrome does not expose these pages' URLs to activeTab at all, so the popup cannot even see them.
@pytest.mark.parametrize("url", ["chrome://version/", "about:blank", "data:text/html,<h1>x</h1>"])
def test_unsupported_schemes_are_not_sent(chrome, live_server, extension_for, url):
    ext_id = extension_for(live_server.url)
    before = history(live_server)["total"]
    tab, popup = scan_via_popup(chrome, ext_id, url)
    assert popup_text(popup, "error").startswith("This page cannot be scanned. Only http:// and https://")
    assert popup.js("document.getElementById('result').hidden") is True
    time.sleep(0.3)
    assert history(live_server)["total"] == before


def test_file_page_is_not_sent(chrome, live_server, extension_for, tmp_path):
    ext_id = extension_for(live_server.url)
    page_file = tmp_path / "local.html"
    page_file.write_text("<h1>local</h1>")
    before = history(live_server)["total"]
    tab, popup = scan_via_popup(chrome, ext_id, page_file.as_uri())
    assert "local files" in popup_text(popup, "error")
    assert history(live_server)["total"] == before


@pytest.mark.parametrize("url,expected", [
    ("http://-bad-.example/", "The supplied URL is invalid"),   # malformed host: rejected by the API
    ("http://localhost:1/", "cannot be scanned"),                # internal host: rejected by the API
])
def test_api_validation_errors_are_shown(chrome, live_server, extension_for, url, expected):
    ext_id = extension_for(live_server.url)
    tab, popup = scan_via_popup(chrome, ext_id, url)
    assert expected in popup_text(popup, "error")


# --- API failure modes -------------------------------------------------------------------------------
def test_api_unavailable(chrome, extension_for):
    api = closed_port_url()
    tab, popup = scan_via_popup(chrome, extension_for(api), "https://www.wikipedia.org/")
    assert popup_text(popup, "error") == (f"Cannot reach the scanner API at {api}. Start the Flask server "
                                          "(python app.py) and try again.")
    assert popup.js("document.getElementById('scan').disabled") is False


def test_api_timeout(chrome, extension_for):
    mock = MockApi("slow")
    try:
        start = time.time()
        tab, popup = scan_via_popup(chrome, extension_for(mock.url), "https://www.wikipedia.org/", timeout=20)
        elapsed = time.time() - start
    finally:
        mock.stop()
    assert "did not respond within 8 seconds" in popup_text(popup, "error")
    assert 7 <= elapsed <= 14


@pytest.mark.parametrize("mode,expected", [
    ("error", "The URL could not be analysed because of an internal error."),
    ("html", "unexpected response (HTTP 502)"),
])
def test_api_error_responses(chrome, extension_for, mode, expected):
    mock = MockApi(mode)
    try:
        tab, popup = scan_via_popup(chrome, extension_for(mock.url), "https://www.wikipedia.org/")
    finally:
        mock.stop()
    assert expected in popup_text(popup, "error")


# --- rendering ------------------------------------------------------------------------------------
def test_popup_rendering_and_safe_dom(chrome, live_server, extension_for, artifacts):
    ext_id = extension_for(live_server.url)
    url = 'https://www.example.com/"><img/src/onerror=window.__xss=1>'
    tab, popup = scan_via_popup(chrome, ext_id, url)
    assert popup.js("typeof window.__xss") == "undefined"
    assert popup.js("document.querySelectorAll('#url img, #reasons img').length") == 0
    # Chrome percent-encodes "<> in tab URLs; the popup shows exactly what the tab reports, as text.
    assert popup_text(popup, "url") == tab.js("location.href") == \
        "https://www.example.com/%22%3E%3Cimg/src/onerror=window.__xss=1%3E"
    assert popup.js("Array.from(document.querySelectorAll('[hidden]')).filter(n => getComputedStyle(n).display !== "
                    "'none').length") == 0
    assert popup.js("getComputedStyle(document.body).width") == "360px"
    assert popup.js("document.documentElement.scrollWidth <= document.documentElement.clientWidth") is True
    assert popup.console_errors == []
    if artifacts:
        popup.screenshot(artifacts / "extension_popup.png")
