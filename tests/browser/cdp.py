"""Minimal Chrome DevTools Protocol client over --remote-debugging-pipe (standard library only).

Used by the browser tests to drive a real headless Chrome: load pages, run JS,
intercept network requests, emulate devices, take screenshots and load the
unpacked extension (Extensions.loadUnpacked; Chrome no longer honours
--load-extension in branded builds).
"""
import base64
import json
import os
import queue
import shutil
import subprocess
import tempfile
import threading
import time
from pathlib import Path

CHROME_CANDIDATES = [
    os.environ.get("CHROME_PATH", ""),
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
    shutil.which("google-chrome") or "", shutil.which("chromium") or "", shutil.which("chromium-browser") or "",
]


def find_chrome():
    for path in CHROME_CANDIDATES:
        if path and Path(path).exists():
            return path
    return None


class CDPError(RuntimeError):
    pass


class Chrome:
    def __init__(self, headless=True, extra_args=()):
        chrome = find_chrome()
        if not chrome:
            raise CDPError("Chrome not found")
        self.profile = tempfile.mkdtemp(prefix="cdp-profile-")
        cmd_r, cmd_w = os.pipe()   # we write commands -> Chrome reads fd 3
        res_r, res_w = os.pipe()   # Chrome writes responses on fd 4 -> we read

        def child_fds():
            a, b = os.dup(cmd_r), os.dup(res_w)  # move out of the way before dup2 onto 3/4
            os.dup2(a, 3)
            os.dup2(b, 4)
            os.set_inheritable(3, True)
            os.set_inheritable(4, True)

        args = [chrome, "--remote-debugging-pipe", "--enable-unsafe-extension-debugging",
                f"--user-data-dir={self.profile}", "--no-first-run", "--no-default-browser-check",
                "--disable-background-networking", "--disable-sync", "--disable-component-update",
                "--disable-features=Translate,MediaRouter", "--password-store=basic", "--use-mock-keychain",
                "--window-size=1280,900", *extra_args]
        if headless:
            args.insert(1, "--headless=new")
        self.proc = subprocess.Popen(args, preexec_fn=child_fds, close_fds=False,
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        os.close(cmd_r)
        os.close(res_w)
        self._out = os.fdopen(cmd_w, "wb", buffering=0)
        self._in = os.fdopen(res_r, "rb", buffering=0)
        self._next_id = 0
        self._pending = {}
        self._events = queue.Queue()
        self._lock = threading.Lock()
        self._listeners = []
        threading.Thread(target=self._reader, daemon=True).start()
        self.send("Target.setDiscoverTargets", {"discover": True})

    # -- transport -------------------------------------------------------------------
    def _reader(self):
        buf = b""
        while True:
            chunk = self._in.read(65536)
            if not chunk:
                break
            buf += chunk
            while b"\0" in buf:
                raw, buf = buf.split(b"\0", 1)
                msg = json.loads(raw)
                if "id" in msg:
                    slot = self._pending.pop(msg["id"], None)
                    if slot:
                        slot.put(msg)
                else:
                    for listener in list(self._listeners):
                        listener(msg)
                    self._events.put(msg)

    def send(self, method, params=None, session=None, timeout=15):
        with self._lock:
            self._next_id += 1
            mid = self._next_id
            slot = queue.Queue()
            self._pending[mid] = slot
            msg = {"id": mid, "method": method, "params": params or {}}
            if session:
                msg["sessionId"] = session
            self._out.write(json.dumps(msg).encode() + b"\0")
        try:
            reply = slot.get(timeout=timeout)
        except queue.Empty:
            raise CDPError(f"timeout waiting for {method}") from None
        if "error" in reply:
            raise CDPError(f"{method}: {reply['error']}")
        return reply.get("result", {})

    def on(self, listener):
        self._listeners.append(listener)

    def off(self, listener):
        self._listeners.remove(listener)

    # -- targets ---------------------------------------------------------------------
    def attach(self, target_id):
        session = self.send("Target.attachToTarget", {"targetId": target_id, "flatten": True})["sessionId"]
        for domain in ("Page", "Runtime", "Log"):
            try:
                self.send(f"{domain}.enable", session=session)
            except CDPError:
                pass  # service workers have no Page domain
        return session

    def new_page(self, url="about:blank"):
        target = self.send("Target.createTarget", {"url": "about:blank"})["targetId"]
        page = Page(self, target, self.attach(target))
        if url != "about:blank":
            page.goto(url)
        return page

    def targets(self):
        return self.send("Target.getTargets")["targetInfos"]

    def wait_for_target(self, predicate, timeout=10):
        deadline = time.time() + timeout
        while time.time() < deadline:
            for t in self.targets():
                if predicate(t):
                    return t
            time.sleep(0.1)
        raise CDPError("target not found")

    def load_extension(self, path):
        return self.send("Extensions.loadUnpacked", {"path": str(path)})["id"]

    def close(self):
        try:
            self.send("Browser.close", timeout=5)
        except Exception:
            pass
        try:
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.proc.kill()
        shutil.rmtree(self.profile, ignore_errors=True)


class Page:
    def __init__(self, browser, target_id, session):
        self.browser, self.target_id, self.session = browser, target_id, session
        self.console_errors = []
        self.dialogs = []
        browser.on(self._listen)

    def _listen(self, msg):
        if msg.get("sessionId") != self.session:
            return
        method, params = msg.get("method"), msg.get("params", {})
        if method == "Runtime.exceptionThrown":
            self.console_errors.append(params["exceptionDetails"].get("text", "exception"))
        elif method == "Log.entryAdded" and params["entry"]["level"] == "error":
            self.console_errors.append(params["entry"].get("text", ""))
        elif method == "Runtime.consoleAPICalled" and params.get("type") == "error":
            self.console_errors.append(" ".join(str(a.get("value", "")) for a in params.get("args", [])))
        elif method == "Page.javascriptDialogOpening":
            self.dialogs.append(params.get("message"))
            accept = getattr(self, "accept_dialogs", True)
            threading.Thread(target=lambda: self.send("Page.handleJavaScriptDialog", {"accept": accept}),
                             daemon=True).start()

    def send(self, method, params=None, timeout=15):
        return self.browser.send(method, params, session=self.session, timeout=timeout)

    def goto(self, url, timeout=15):
        self.send("Page.navigate", {"url": url})
        self.wait_for("document.readyState === 'complete'", timeout)

    def js(self, expression, await_promise=True):
        result = self.send("Runtime.evaluate", {"expression": expression, "returnByValue": True,
                                                "awaitPromise": await_promise})
        if "exceptionDetails" in result:
            raise CDPError(f"JS error: {result['exceptionDetails'].get('exception', {}).get('description')}")
        return result["result"].get("value")

    def wait_for(self, condition, timeout=15, interval=0.05):
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                if self.js(f"Boolean({condition})"):
                    return True
            except CDPError:
                pass
            time.sleep(interval)
        raise CDPError(f"condition not met within {timeout}s: {condition}")

    def screenshot(self, path, full_page=True):
        params = {"format": "png", "captureBeyondViewport": full_page}
        Path(path).write_bytes(base64.b64decode(self.send("Page.captureScreenshot", params)["data"]))

    def viewport(self, width, height, mobile=False):
        self.send("Emulation.setDeviceMetricsOverride", {"width": width, "height": height,
                                                        "deviceScaleFactor": 1, "mobile": mobile})

    def close(self):
        self.browser.off(self._listen)
        self.browser.send("Target.closeTarget", {"targetId": self.target_id})


class Interceptor:
    """Answer matching requests of one page from Python (Fetch domain)."""

    def __init__(self, page, pattern, handler):
        self.page, self.handler = page, handler
        page.send("Fetch.enable", {"patterns": [{"urlPattern": pattern}]})
        page.browser.on(self._listen)

    def _listen(self, msg):
        if msg.get("sessionId") != self.page.session or msg.get("method") != "Fetch.requestPaused":
            return
        params = msg["params"]
        threading.Thread(target=self.handler, args=(self.page, params), daemon=True).start()

    def stop(self):
        self.page.browser.off(self._listen)
        self.page.send("Fetch.disable")


def fulfill(page, params, status, body, content_type="application/json"):
    page.send("Fetch.fulfillRequest", {
        "requestId": params["requestId"], "responseCode": status,
        "responseHeaders": [{"name": "Content-Type", "value": content_type}],
        "body": base64.b64encode(body.encode()).decode()})


def fail(page, params, reason="ConnectionRefused"):
    page.send("Fetch.failRequest", {"requestId": params["requestId"], "errorReason": reason})
