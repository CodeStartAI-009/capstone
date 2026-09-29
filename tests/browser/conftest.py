"""Fixtures for real-browser tests: a live Flask server (temporary database) and headless Chrome.

Skipped automatically when Chrome is not installed. Screenshots are written to
$BROWSER_ARTIFACTS (if set) for manual review.
"""
import os
import threading
from pathlib import Path

import pytest
from werkzeug.serving import make_server

from backend import create_app
from config import Config
from tests.browser.cdp import Chrome, find_chrome

pytestmark = pytest.mark.browser


def pytest_collection_modifyitems(items):
    if find_chrome() is None:
        skip = pytest.mark.skip(reason="Chrome/Chromium not installed")
        for item in items:
            if "tests/browser" in str(item.fspath):
                item.add_marker(skip)


class LiveServer:
    def __init__(self, tmp_dir, **overrides):
        attrs = {"TESTING": True, "DATABASE_PATH": Path(tmp_dir) / "history.db", "RATE_LIMIT_PER_MINUTE": 0,
                 **overrides}
        self.app = create_app(type("BrowserTestConfig", (Config,), attrs))
        self.server = make_server("127.0.0.1", 0, self.app, threaded=True)
        self.port = self.server.server_port
        self.url = f"http://127.0.0.1:{self.port}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def client(self):
        return self.app.test_client()

    def stop(self):
        self.server.shutdown()


@pytest.fixture(scope="session")
def chrome():
    browser = Chrome()
    yield browser
    browser.close()


@pytest.fixture(scope="module")
def live_server(tmp_path_factory):
    server = LiveServer(tmp_path_factory.mktemp("live"))
    yield server
    server.stop()


@pytest.fixture
def page(chrome):
    p = chrome.new_page()
    yield p
    p.close()


@pytest.fixture(scope="session")
def artifacts():
    target = os.environ.get("BROWSER_ARTIFACTS")
    if not target:
        return None
    path = Path(target)
    path.mkdir(parents=True, exist_ok=True)
    return path
