"""Static checks on the web frontend and extension code (no browser needed)."""
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EXT = ROOT / "extension"
WEB_JS = sorted((ROOT / "static" / "js").glob("*.js"))
EXT_JS = sorted(EXT.glob("*.js"))
UNSAFE_DOM = re.compile(r"\binnerHTML\b|\bouterHTML\b|insertAdjacentHTML|document\.write|\beval\s*\(|new Function\s*\("
                        r"|setTimeout\s*\(\s*['\"]")


def manifest():
    return json.loads((EXT / "manifest.json").read_text())


def test_manifest_is_mv3_with_minimal_permissions():
    m = manifest()
    assert m["manifest_version"] == 3
    # tabs: read tab URLs for automatic checks; storage: settings + per-tab state (no page access at all)
    assert m["permissions"] == ["tabs", "storage"]
    assert m["host_permissions"] == ["http://127.0.0.1:5000/*"]
    for broad in ("history", "webRequest", "webRequestBlocking", "declarativeNetRequest", "cookies", "scripting",
                  "webNavigation", "clipboardRead", "<all_urls>"):
        assert broad not in m["permissions"] and broad not in json.dumps(m["host_permissions"])
    assert m["background"] == {"service_worker": "background.js"}
    # No content scripts, no pages exposed to websites, no messaging from websites or other extensions.
    for key in ("content_scripts", "web_accessible_resources", "externally_connectable", "optional_permissions",
                "optional_host_permissions"):
        assert key not in m, key
    assert "unsafe" not in m["content_security_policy"]["extension_pages"]


def test_background_worker_sends_only_the_origin_and_never_page_data():
    code = code_without_comments(EXT / "background.js")
    assert 'importScripts("config.js", "scan-core.js")' in code
    assert re.findall(r"callApi\(([^,]+),", code) == ['origin + "/"']
    for forbidden in ("chrome.scripting", "executeScript", "chrome.cookies", "chrome.history", "document.",
                      "localStorage", "chrome.webRequest"):
        assert forbidden not in code, forbidden
    core = code_without_comments(EXT / "scan-core.js")
    assert 'credentials: "omit"' in core
    assert "JSON.stringify({ url: url, source: \"extension\", record: record })" in core


def test_manifest_files_exist():
    m = manifest()
    paths = [m["action"]["default_popup"], m["background"]["service_worker"], *m["action"]["default_icon"].values(),
             *m["icons"].values(), "warning.html", "safe.html"]
    for rel in paths:
        assert (EXT / rel).is_file(), rel
    for page in EXT.glob("*.html"):
        for src in re.findall(r'(?:src|href)="([^"]+)"', page.read_text()):
            assert (EXT / src).is_file(), f"{page.name}: {src}"
    for name in re.findall(r'importScripts\(([^)]*)\)', (EXT / "background.js").read_text())[0].split(","):
        assert (EXT / name.strip().strip('"')).is_file(), name


def test_api_base_is_configured_in_one_place_and_matches_host_permissions():
    config = (EXT / "config.js").read_text()
    bases = re.findall(r'const API_BASE = "([^"]+)";', config)
    assert bases == ["http://127.0.0.1:5000"]
    assert manifest()["host_permissions"] == [bases[0] + "/*"]
    for path in EXT_JS:
        if path.name != "config.js":
            assert "127.0.0.1" not in path.read_text() and "localhost" not in path.read_text(), path.name


def code_without_comments(path):
    text = re.sub(r"/\*.*?\*/", "", path.read_text(), flags=re.S)
    return re.sub(r"(^|\s)//[^\n]*", r"\1", text)


def test_no_unsafe_dom_apis_in_client_code():
    for path in WEB_JS + EXT_JS:
        assert not UNSAFE_DOM.search(code_without_comments(path)), path


def test_no_inline_scripts_or_handlers_in_templates_and_popup():
    for path in [*(ROOT / "templates").glob("*.html"), *EXT.glob("*.html")]:
        text = path.read_text()
        assert not re.search(r"<script(?![^>]*\bsrc=)[^>]*>", text), path.name
        assert not re.search(r"\son[a-z]+\s*=", text), path.name
        assert "style=" not in text, path.name


def test_no_prediction_logic_or_secrets_in_client_code():
    for path in WEB_JS + EXT_JS:
        text = path.read_text()
        assert "predict_proba" not in text and "FEATURE_NAMES" not in text
        assert not re.search(r"(api[_-]?key|secret|token)\s*[:=]\s*['\"][^'\"]+['\"]", text, re.I), path.name
