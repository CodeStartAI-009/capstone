"""Automatic checks, warning page, Go Back to Safety and Continue Anyway in REAL headless Chrome.

Setup:
- A separate Chrome instance (so the popup tests' extensions cannot act on these tabs) loads a copy of
  extension/ in which only config.js differs: API_BASE points at RecordingApi and REQUEST_TIMEOUT_MS is 2 s.
- RecordingApi records every request body and normally forwards it over HTTP to a live Flask server
  running the real model (tests/browser/conftest.py LiveServer), so the scores are the deployed model's.
  It can also simulate failures (down, slow, non-JSON, invalid JSON).
- Web pages are served by request interception (Fetch domain): no request reaches the internet, and the
  "high-risk" sites are synthetic names under the reserved .example TLD.
- Badges and storage are read through an extension page (chrome-extension://<id>/safe.html), which has the
  same chrome.action / chrome.tabs / chrome.storage APIs as the worker.
"""
import base64
import itertools
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

from tests.browser.cdp import CDPError, Chrome, Interceptor
from tests.browser.test_extension_browser import build_extension, click_action

LOW = "https://www.wikipedia.org/"                                # real model: Safe / Low (0.09)
MEDIUM = "https://shop.example/"                                  # real model: Suspicious / Medium (0.55)
HIGH = "https://secure-login-verify-account.example/"             # real model: Phishing / High (0.84)
HIGH2 = "https://my-account-security-check-2024.example/"         # real model: Phishing / High (0.92)
TIMEOUT_MS = 2000
_tags = itertools.count(1)


class RecordingApi:
    def __init__(self, upstream):
        api = self
        self.upstream, self.bodies, self.mode, self.delays = upstream, [], "forward", {}
        self.lock = threading.Lock()

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
                with api.lock:
                    api.bodies.append(body)
                time.sleep(api.delays.get(body.get("url"), 0))
                if api.mode == "down":
                    self.close_connection = True        # no response at all: fetch() fails like a dead server
                    return
                if api.mode == "slow":
                    time.sleep(TIMEOUT_MS / 1000 + 1.5)
                if api.mode == "html":
                    return self.reply(502, b"<html>Bad gateway</html>", "text/html")
                if api.mode == "invalid":
                    return self.reply(200, json.dumps({"success": True, "prediction": "Benign"}).encode())
                req = Request(api.upstream + "/api/predict", data=json.dumps(body).encode(),
                              headers={"Content-Type": "application/json"}, method="POST")
                try:
                    with urlopen(req, timeout=10) as r:
                        self.reply(r.status, r.read())
                except HTTPError as e:
                    self.reply(e.code, e.read())

            def reply(self, status, data, ctype="application/json"):
                try:
                    self.send_response(status)
                    self.send_header("Content-Type", ctype)
                    self.send_header("Content-Length", str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)
                except (BrokenPipeError, ConnectionResetError):
                    pass

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.url = f"http://127.0.0.1:{self.server.server_port}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def sent_urls(self):
        with self.lock:
            return [b.get("url") for b in self.bodies]

    def reset(self):
        with self.lock:
            self.bodies.clear()
        self.mode, self.delays = "forward", {}

    def stop(self):
        self.server.shutdown()


def serve(page, params):
    """Synthetic web pages. /redirect-to/<base64url> answers with a 302 to the decoded URL."""
    url = params["request"]["url"]
    if "/redirect-to/" in url:
        target = base64.urlsafe_b64decode(url.split("/redirect-to/", 1)[1].split("?")[0] + "==").decode()
        headers, status, body = [{"name": "Location", "value": target}], 302, ""
    else:
        headers, status = [{"name": "Content-Type", "value": "text/html"}], 200
        body = "<title>Test site</title><h1>Synthetic test page</h1><form><input type=password name=pw></form>"
    page.send("Fetch.fulfillRequest", {"requestId": params["requestId"], "responseCode": status,
                                       "responseHeaders": headers, "body": base64.b64encode(body.encode()).decode()})


@pytest.fixture(scope="module")
def env(live_server, tmp_path_factory):
    api = RecordingApi(live_server.url)
    browser = Chrome()
    ext_id = browser.load_extension(build_extension(tmp_path_factory.mktemp("auto"), api.url, auto_scan=True,
                                                    overrides={"REQUEST_TIMEOUT_MS": TIMEOUT_MS}))
    control = browser.new_page(f"chrome-extension://{ext_id}/safe.html")
    yield {"chrome": browser, "ext": ext_id, "api": api, "control": control, "server": live_server}
    browser.close()
    api.stop()


@pytest.fixture
def ctx(env):
    """Fresh extension state for each test: settings to defaults, session state and cache cleared."""
    control = env["control"]
    control.js("Promise.all([chrome.storage.local.clear(), chrome.storage.session.clear()]).then(() => true)")
    env["api"].reset()
    tabs = []
    env["tabs"] = tabs
    yield env
    for tab in tabs:
        try:
            tab.close()
        except CDPError:
            pass


class Tab:
    """A browser tab plus its chrome.tabs id (found through a unique about:blank#tag URL)."""

    def __init__(self, env):
        self.env, self.control = env, env["control"]
        self.page = env["chrome"].new_page()
        tag = f"about:blank#tab-{next(_tags)}"
        self.page.send("Page.navigate", {"url": tag})
        self.id = self.wait(lambda: self.control.js(
            f"chrome.tabs.query({{}}).then(ts => (ts.find(t => t.url === {json.dumps(tag)}) || {{}}).id || null)"))
        Interceptor(self.page, "http*", serve)
        env["tabs"].append(self.page)

    def go(self, url):
        self.page.send("Page.navigate", {"url": url})

    def href(self):
        return self.control.js(f"chrome.tabs.get({self.id}).then(t => t.url)")

    def badge(self):
        return self.control.js(f"chrome.action.getBadgeText({{tabId: {self.id}}})")

    def title(self):
        return self.control.js(f"chrome.action.getTitle({{tabId: {self.id}}})")

    def js(self, expression):
        return self.page.js(expression)

    def on_warning(self):
        return (self.href() or "").startswith(f"chrome-extension://{self.env['ext']}/warning.html")

    def wait_warning_ready(self):
        self.wait(lambda: self.on_warning())
        self.page.wait_for("document.body && document.body.dataset.ready === 'true'", 10)

    @staticmethod
    def wait(predicate, timeout=10, interval=0.05):
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                value = predicate()
            except CDPError:
                value = None
            if value:
                return value
            time.sleep(interval)
        raise AssertionError("condition not met within %ss" % timeout)


def settings(env, **values):
    env["control"].js(f"chrome.storage.local.set({json.dumps(values)}).then(() => true)")


def stop_worker(env, tab):
    tab.page.send("ServiceWorker.enable")
    tab.page.send("ServiceWorker.stopAllWorkers")
    Tab.wait(lambda: not [t for t in env["chrome"].targets()
                          if t["type"] == "service_worker" and env["ext"] in t["url"]], 10)


# --- automatic scanning and risk levels --------------------------------------------------------------------
def test_low_risk_page_is_checked_automatically_sending_only_the_origin(ctx):
    tab = Tab(ctx)
    tab.go(LOW + "wiki/Phishing?session=SECRET123#History")
    Tab.wait(lambda: tab.badge() == "LOW")
    assert ctx["api"].bodies == [{"url": LOW, "source": "extension", "record": False}]
    assert "SECRET123" not in json.dumps(ctx["api"].bodies)
    assert tab.href() == LOW + "wiki/Phishing?session=SECRET123#History"     # no redirect, no interference
    assert "not a guarantee" in tab.title()
    assert ctx["server"].client().get("/api/history").get_json()["total"] == 0  # record: false -> nothing stored


def test_medium_risk_shows_a_caution_badge_without_a_warning_page(ctx):
    tab = Tab(ctx)
    tab.go(MEDIUM + "products")
    Tab.wait(lambda: tab.badge() == "MED")
    time.sleep(0.5)
    assert tab.href() == MEDIUM + "products"
    assert tab.title().startswith("Caution")


def test_high_risk_page_is_replaced_by_the_warning_page(ctx, artifacts):
    tab = Tab(ctx)
    tab.go(HIGH + "signin?next=%2Faccount")
    tab.wait_warning_ready()
    assert tab.badge() == "HIGH"
    text = lambda element_id: tab.js(f"document.getElementById('{element_id}').textContent")
    assert tab.js("document.title") == "Potential Phishing Risk"
    assert text("host") == "secure-login-verify-account.example"
    assert text("url") == HIGH + "signin?next=%2Faccount"
    assert text("verdict") == "Phishing-risk prediction (high)" and text("risk") == "High"
    expected = ctx["server"].client().post("/api/predict", json={"url": HIGH, "record": False}).get_json()
    assert text("score").startswith(f"{expected['phishing_probability']:.2f} ")
    assert text("model-input") == expected["model_input"] and text("model-version") == expected["model_version"]
    assert tab.js("document.querySelectorAll('#reasons li').length") >= 1
    assert "may be wrong" in tab.js("document.querySelector('.limits').innerText")
    assert "Legitimate sites can be flagged, and phishing sites can be missed" in tab.js(
        "document.querySelector('.limits').innerText")
    for button, label in (("back", "Go Back to Safety"), ("proceed", "Continue Anyway")):
        assert tab.js(f"getComputedStyle(document.getElementById('{button}')).display") != "none"
        assert text(button) == label
    assert "100%" not in tab.js("document.body.innerText")
    assert tab.page.console_errors == []
    if artifacts:
        tab.page.screenshot(artifacts / "extension_warning_page.png")


def test_warning_page_renders_the_url_as_inert_text(ctx):
    tab = Tab(ctx)
    tab.go(HIGH + '"><img/src/onerror=window.__xss=1>')
    tab.wait_warning_ready()
    assert tab.js("typeof window.__xss") == "undefined"
    assert tab.js("document.querySelectorAll('main img, main script').length") == 0
    assert "onerror=window.__xss=1" in tab.js("document.getElementById('url').textContent")


def test_server_redirect_to_a_high_risk_site_is_warned_about(ctx):
    tab = Tab(ctx)
    target = HIGH2 + "landing"
    tab.go(LOW + "redirect-to/" + base64.urlsafe_b64encode(target.encode()).decode().rstrip("="))
    tab.wait_warning_ready()
    assert tab.js("document.getElementById('url').textContent") == target


# --- Go Back to Safety -----------------------------------------------------------------------------------------------
def test_go_back_to_safety_returns_to_the_previous_checked_page(ctx):
    tab = Tab(ctx)
    tab.go(LOW + "wiki/Main_Page")
    Tab.wait(lambda: tab.badge() == "LOW")
    tab.go(HIGH)
    tab.wait_warning_ready()
    tab.js("document.getElementById('back').click()")
    Tab.wait(lambda: tab.href() == LOW + "wiki/Main_Page")
    Tab.wait(lambda: tab.badge() == "LOW")


def test_go_back_to_safety_without_a_previous_page_opens_the_local_safe_page(ctx):
    tab = Tab(ctx)
    tab.go(HIGH)
    tab.wait_warning_ready()
    tab.js("document.getElementById('back').click()")
    Tab.wait(lambda: tab.href() == f"chrome-extension://{ctx['ext']}/safe.html")
    time.sleep(0.5)
    assert tab.href() == f"chrome-extension://{ctx['ext']}/safe.html"     # no redirect loop
    assert ctx["api"].sent_urls() == [HIGH]


# --- Continue Anyway --------------------------------------------------------------------------------------------
def test_continue_anyway_allows_the_site_once_in_this_tab_only(ctx):
    tab = Tab(ctx)
    tab.go(HIGH + "login")
    tab.wait_warning_ready()
    tab.js("document.getElementById('proceed').click()")
    Tab.wait(lambda: tab.href() == HIGH + "login")
    time.sleep(1.0)
    assert tab.href() == HIGH + "login"                                  # the warning does not come back
    assert tab.badge() == "HIGH" and "Continue Anyway" in tab.title()    # still shown as high risk
    tab.page.send("Page.reload")                                          # reload: still allowed
    time.sleep(1.0)
    assert tab.href() == HIGH + "login"
    tab.js("history.pushState({}, '', '/step-2')")                       # SPA URL change on the same site
    time.sleep(0.8)
    assert tab.href() == HIGH + "step-2"
    assert ctx["api"].sent_urls() == [HIGH]                              # one request; score reused, not lowered

    other = Tab(ctx)                                                     # another tab: warned again
    other.go(HIGH + "login")
    other.wait_warning_ready()

    tab.go(LOW)                                                          # leaving the site ends the bypass
    Tab.wait(lambda: tab.badge() == "LOW")
    tab.go(HIGH + "login")
    tab.wait_warning_ready()


# --- pages that are not checked ---------------------------------------------------------------------------------
@pytest.mark.parametrize("url", ["chrome://version/", "about:blank", "data:text/html,<h1>x</h1>", "file:///"])
def test_unsupported_pages_are_never_sent(ctx, url):
    tab = Tab(ctx)
    tab.go(url)
    time.sleep(0.8)
    assert ctx["api"].bodies == []
    assert tab.badge() == ""


def test_tab_switch_checks_a_tab_that_was_not_checked_yet(ctx):
    settings(ctx, autoScan=False)
    first, second = Tab(ctx), Tab(ctx)
    first.go(LOW)
    second.go(MEDIUM)
    Tab.wait(lambda: first.badge() == "OFF" and second.badge() == "OFF")
    assert ctx["api"].bodies == []
    ctx["chrome"].send("Target.activateTarget", {"targetId": second.page.target_id})
    settings(ctx, autoScan=True)                         # turning checks on checks the active tab only
    Tab.wait(lambda: second.badge() == "MED")
    assert ctx["api"].sent_urls() == [MEDIUM]
    ctx["chrome"].send("Target.activateTarget", {"targetId": first.page.target_id})
    Tab.wait(lambda: first.badge() == "LOW")             # tabs.onActivated
    ctx["chrome"].send("Target.activateTarget", {"targetId": second.page.target_id})
    time.sleep(0.5)
    assert sorted(ctx["api"].sent_urls()) == sorted([MEDIUM, LOW])   # switching back does not rescan


def test_repeated_navigation_to_one_site_is_scanned_once(ctx):
    tab = Tab(ctx)
    for path in ("a", "b", "b#frag", "c?x=1"):
        tab.go(MEDIUM + path)
        time.sleep(0.3)
    tab.js("history.pushState({}, '', '/spa-route')")
    time.sleep(0.5)
    assert ctx["api"].sent_urls() == [MEDIUM]
    assert tab.badge() == "MED"


# --- failures are never "safe" -----------------------------------------------------------------------------------
@pytest.mark.parametrize("mode,reason", [("down", "Cannot reach the scanner API"),
                                         ("slow", "did not respond within 2 seconds"),
                                         ("html", "unexpected response (HTTP 502)"),
                                         ("invalid", "unexpected response")])
def test_api_failure_is_reported_as_not_checked(ctx, mode, reason):
    ctx["api"].mode = mode
    tab = Tab(ctx)
    tab.go(HIGH)
    Tab.wait(lambda: tab.badge() == "?", timeout=TIMEOUT_MS / 1000 + 6)
    assert "could NOT be checked" in tab.title() and reason in tab.title()
    assert tab.href() == HIGH                     # unchecked: no warning, but also never labelled low risk
    ctx["api"].mode = "forward"                   # failures are not cached: the next load retries
    tab.page.send("Page.reload")
    tab.wait_warning_ready()


def test_stale_response_does_not_redirect_a_tab_that_moved_on(ctx):
    ctx["api"].delays = {HIGH: 1.5}
    tab = Tab(ctx)
    tab.go(HIGH)
    Tab.wait(lambda: tab.badge() == "…")
    tab.go(LOW)
    Tab.wait(lambda: tab.badge() == "LOW")
    time.sleep(2.0)                               # the slow high-risk answer arrives now
    assert tab.href() == LOW
    assert tab.badge() == "LOW"


def test_disabled_extension_sends_nothing_and_shows_off(ctx):
    settings(ctx, autoScan=False)
    tab = Tab(ctx)
    tab.go(HIGH)
    Tab.wait(lambda: tab.badge() == "OFF")
    time.sleep(0.8)
    assert tab.href() == HIGH and ctx["api"].bodies == []


def test_record_setting_saves_only_the_origin_to_history(ctx):
    settings(ctx, recordAutoScans=True)
    before = ctx["server"].client().get("/api/history").get_json()["total"]
    tab = Tab(ctx)
    tab.go(MEDIUM + "account?email=victim%40example.com")
    Tab.wait(lambda: tab.badge() == "MED")
    items = ctx["server"].client().get("/api/history").get_json()
    assert items["total"] == before + 1
    assert items["items"][0]["url"] == MEDIUM and items["items"][0]["source"] == "extension"


# --- service-worker restart --------------------------------------------------------------------------------------
def test_warning_and_continue_anyway_survive_a_service_worker_restart(ctx):
    tab = Tab(ctx)
    tab.go(HIGH)
    tab.wait_warning_ready()
    stop_worker(ctx, tab)                                         # Chrome stops idle workers the same way
    tab.js("document.getElementById('proceed').click()")          # the message restarts the worker
    Tab.wait(lambda: tab.href() == HIGH)
    stop_worker(ctx, tab)
    tab.page.send("Page.reload")                                  # tabs.onUpdated restarts the worker
    Tab.wait(lambda: tab.badge() == "HIGH")
    time.sleep(0.8)
    assert tab.href() == HIGH                                     # bypass kept in chrome.storage.session
    assert ctx["api"].sent_urls() == [HIGH]                       # cached result kept as well


def test_popup_shows_the_automatic_check_and_the_settings(ctx):
    tab = Tab(ctx)
    tab.go(MEDIUM)
    Tab.wait(lambda: tab.badge() == "MED")
    ctx["chrome"].send("Target.activateTarget", {"targetId": tab.page.target_id})
    popup = click_action(ctx["chrome"], ctx["ext"], tab.page)
    popup.wait_for("document.getElementById('auto-status').textContent.length > 0")
    assert popup.js("document.getElementById('auto-status').textContent").startswith(
        "Automatic check: moderate phishing-risk prediction")
    assert popup.js("document.getElementById('auto-scan').checked") is True
    assert popup.js("document.getElementById('record-auto').checked") is False
    popup.js("document.getElementById('auto-scan').click()")
    Tab.wait(lambda: ctx["control"].js("chrome.storage.local.get('autoScan').then(v => v.autoScan === false)"))
    assert popup.console_errors == []
