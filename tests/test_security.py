"""Security controls: rate limiting, headers, CORS, no fetching, threat-intel isolation."""
import io
import json
import socket

import pytest

from backend.utils.rate_limit import RateLimiter
from services.threat_intelligence import DisabledThreatIntelligence, GoogleSafeBrowsing, from_environment


def test_rate_limit_returns_429_with_retry_after(make_app):
    client = make_app(RATE_LIMIT_PER_MINUTE=2).test_client()
    for _ in range(2):
        assert client.post("/api/predict", json={"url": "https://www.example.com"}).status_code == 200
    r = client.post("/api/predict", json={"url": "https://www.example.com"})
    assert r.status_code == 429 and int(r.headers["Retry-After"]) >= 1
    assert r.get_json() == {"success": False, "error": {"code": "RATE_LIMITED",
                                                         "message": "Too many requests. Please wait and try again."}}


def test_rate_limiter_window_expires():
    now = [0.0]
    limiter = RateLimiter(2, 60, clock=lambda: now[0])
    assert limiter.check("a")[0] and limiter.check("a")[0]
    assert not limiter.check("a")[0]
    assert limiter.check("b")[0]  # per-client
    now[0] = 61
    assert limiter.check("a")[0]


def test_security_headers(client):
    for path in ("/", "/api/health"):
        r = client.get(path)
        assert r.headers["X-Content-Type-Options"] == "nosniff"
        assert r.headers["X-Frame-Options"] == "DENY"
        assert "default-src 'self'" in r.headers["Content-Security-Policy"]
    assert client.get("/api/health").headers["Cache-Control"] == "no-store"


def test_cors_only_for_allow_listed_origins(make_app):
    client = make_app(CORS_ORIGINS="http://localhost:3000").test_client()
    ok = client.get("/api/health", headers={"Origin": "http://localhost:3000"})
    assert ok.headers.get("Access-Control-Allow-Origin") == "http://localhost:3000"
    bad = client.get("/api/health", headers={"Origin": "https://evil.example"})
    assert "Access-Control-Allow-Origin" not in bad.headers
    pre = client.open("/api/predict", method="OPTIONS", headers={"Origin": "http://localhost:3000"})
    assert pre.status_code == 204 and pre.headers.get("Access-Control-Allow-Origin") == "http://localhost:3000"


def test_client_origin_setting_and_wildcard_refused(make_app):
    client = make_app(CLIENT_ORIGIN="https://ui.example.org, *", CORS_ORIGINS="").test_client()
    ok = client.get("/api/health", headers={"Origin": "https://ui.example.org"})
    assert ok.headers.get("Access-Control-Allow-Origin") == "https://ui.example.org"
    assert "Access-Control-Allow-Credentials" not in ok.headers
    other = client.get("/api/health", headers={"Origin": "https://evil.example"})
    assert "Access-Control-Allow-Origin" not in other.headers  # "*" was ignored, not honoured


def test_default_config_allows_no_cross_origin(client):
    r = client.get("/api/health", headers={"Origin": "https://evil.example"})
    assert "Access-Control-Allow-Origin" not in r.headers


def test_scanning_never_opens_network_connections(client, monkeypatch):
    """The detector is URL-string only: no DNS lookup or HTTP request (no SSRF surface)."""
    def forbidden(*args, **kwargs):
        raise AssertionError("network access attempted")
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    for url in ("http://169.254.169.254/latest/meta-data/", "http://127.0.0.1:22/", "http://10.0.0.1/admin"):
        assert client.post("/api/predict", json={"url": url}).status_code == 400
    for url in ("https://www.example.com", "http://45.77.10.3/login"):
        assert client.post("/api/predict", json={"url": url}).status_code == 200


@pytest.mark.parametrize("url", [
    "http://localhost/", "http://LOCALHOST:5000/x", "http://app.localhost/", "http://127.0.0.1/",
    "http://127.1/", "http://2130706433/", "http://0x7f.0.0.1/", "http://10.0.0.1/", "http://192.168.1.1/",
    "http://172.16.0.5/", "http://169.254.169.254/", "http://100.64.0.1/", "http://0.0.0.0/", "http://[::1]/",
    "http://[fd00::1]/", "http://[::ffff:127.0.0.1]/", "http://printer/", "http://nas.local/", "http://db.internal/",
])
def test_internal_targets_rejected_by_default(client, url):
    r = client.post("/api/predict", json={"url": url})
    assert r.status_code == 400 and r.get_json()["error"]["code"] == "UNSUPPORTED_HOST"


@pytest.mark.parametrize("url", ["https://www.example.com", "http://8.8.8.8/", "https://sub.example.co.uk/a",
                                 "https://xn--bcher-kva.de/"])
def test_public_targets_accepted(client, url):
    assert client.post("/api/predict", json={"url": url}).status_code == 200


def test_private_hosts_can_be_enabled_and_are_flagged_out_of_scope(make_app):
    client = make_app(ALLOW_PRIVATE_HOSTS=True).test_client()
    body = client.post("/api/predict", json={"url": "http://10.0.0.1/admin"}).get_json()
    assert body["success"] and any(e.get("check") == "local" for e in body["explanations"])


def test_error_responses_do_not_leak_stack_traces(client):
    r = client.post("/api/predict", data=b"\xff\xfe", content_type="application/json")
    assert r.status_code == 400 and b"Traceback" not in r.data


def test_threat_intel_disabled_by_default():
    ti = from_environment({})
    assert isinstance(ti, DisabledThreatIntelligence) and not ti.enabled
    assert isinstance(from_environment({"THREAT_INTEL_PROVIDER": "google_safe_browsing"}), DisabledThreatIntelligence)


def test_threat_intel_only_contacts_fixed_endpoint_and_is_separate_from_model(make_app):
    seen = {}

    def fake_open(request, timeout):
        seen["url"] = request.full_url
        seen["body"] = json.loads(request.data)
        return io.BytesIO(json.dumps({"matches": [{"threatType": "SOCIAL_ENGINEERING"}]}).encode())

    ti = GoogleSafeBrowsing("test-key", opener=fake_open)
    app = make_app()
    app.extensions["prediction_service"].threat_intel = ti
    body = app.test_client().post("/api/predict", json={"url": "https://www.example.com"}).get_json()
    assert seen["url"].startswith(GoogleSafeBrowsing.ENDPOINT)
    assert seen["body"]["threatInfo"]["threatEntries"] == [{"url": "https://www.example.com"}]
    assert body["threat_intelligence"] == {"provider": "google_safe_browsing", "status": "ok", "listed": True,
                                           "threat_types": ["SOCIAL_ENGINEERING"]}
    assert body["prediction"] in {"Safe", "Suspicious", "Phishing"}  # model verdict unchanged by the lookup


def test_threat_intel_failure_is_contained():
    def failing_open(request, timeout):
        raise TimeoutError()
    assert GoogleSafeBrowsing("k", opener=failing_open).lookup("https://a.com")["status"] == "error"


# --- Phase 6 security checks --------------------------------------------------------------------
SQLI = ["' OR '1'='1", "'; DROP TABLE scan_history; --", "\" OR 1=1 --", "%' UNION SELECT sqlite_version() --"]


@pytest.mark.parametrize("payload", SQLI)
def test_sql_injection_in_search_is_inert(client, payload):
    client.post("/api/predict", json={"url": "https://www.example.com"})
    r = client.get("/api/history", query_string={"q": payload})
    assert r.status_code == 200 and r.get_json()["total"] == 0
    assert client.get("/api/history").get_json()["total"] == 1  # table intact


@pytest.mark.parametrize("payload", SQLI)
def test_sql_injection_in_url_and_id_is_inert(client, payload):
    r = client.post("/api/predict", json={"url": "https://www.example.com/" + payload.replace(" ", "%20")})
    assert r.status_code == 200
    stored = client.get(f"/api/history/{r.get_json()['history']['id']}").get_json()["item"]["url"]
    assert stored == "https://www.example.com/" + payload.replace(" ", "%20")  # stored verbatim as data
    from urllib.parse import quote
    assert client.get("/api/history/" + quote(payload, safe="")).status_code in (400, 404)
    assert client.delete("/api/history/" + quote(payload, safe="")).status_code in (400, 404)
    assert client.get("/api/history").get_json()["total"] == 1


@pytest.mark.parametrize("path", ["/static/../config.py", "/static/..%2fconfig.py", "/static/%2e%2e/app.py",
                                  "/static/../../etc/passwd", "/static/..%5c..%5cconfig.py",
                                  "/api/history/..%2f..%2fetc%2fpasswd", "/../.env"])
def test_path_traversal_is_refused(client, path):
    r = client.get(path)
    assert r.status_code in (400, 404)
    assert b"SECRET" not in r.data and b"class Config" not in r.data and b"root:" not in r.data


def test_query_parameters_are_not_reflected_into_html(client):
    marker = '<script>alert("x")</script>'
    for path in ("/", "/inspect", "/dashboard"):
        r = client.get(path, query_string={"id": marker, "url": marker})
        assert marker.encode() not in r.data


def test_json_responses_cannot_be_sniffed_as_html(client):
    r = client.post("/api/predict", json={"url": "https://example.com/<script>alert(1)</script>"})
    assert r.status_code == 400 or r.mimetype == "application/json"
    r = client.post("/api/predict", json={"url": "https://example.com/%3Cscript%3E"})
    assert r.mimetype == "application/json" and r.headers["X-Content-Type-Options"] == "nosniff"


def test_hardening_headers_and_no_version_disclosure(client):
    for path in ("/", "/api/health", "/api/nope", "/static/css/style.css"):
        h = client.get(path).headers
        assert h["Server"] == "phishing-detector"
        assert "object-src 'none'" in h["Content-Security-Policy"] and "frame-ancestors 'none'" in h["Content-Security-Policy"]
        assert "camera=()" in h["Permissions-Policy"]
        assert h["Cross-Origin-Opener-Policy"] == "same-origin"
        assert "Strict-Transport-Security" not in h  # plain HTTP locally
    assert "Strict-Transport-Security" in client.get("/api/health", base_url="https://localhost").headers


def test_debug_mode_off_by_default():
    from config import Config
    from backend import create_app
    app = create_app(Config)
    assert app.debug is False and Config.DEBUG is False


def test_cors_preflight_from_unlisted_origin_gets_no_grant(make_app):
    client = make_app(CLIENT_ORIGIN="https://ui.example.org").test_client()
    pre = client.open("/api/history", method="OPTIONS", headers={
        "Origin": "https://evil.example", "Access-Control-Request-Method": "DELETE"})
    assert "Access-Control-Allow-Origin" not in pre.headers and "Access-Control-Allow-Methods" not in pre.headers
    ok = client.open("/api/history", method="OPTIONS", headers={
        "Origin": "https://ui.example.org", "Access-Control-Request-Method": "DELETE"})
    assert ok.headers["Access-Control-Allow-Origin"] == "https://ui.example.org"
    assert "Access-Control-Allow-Credentials" not in ok.headers


@pytest.mark.parametrize("path,method", [("/api/nope", "get"), ("/api/predict", "put"), ("/api/history/1", "post")])
def test_errors_never_reveal_internals(client, path, method):
    r = getattr(client, method)(path)
    assert r.is_json and r.get_json()["success"] is False
    for marker in (b"Traceback", b"werkzeug", b"/Users/", b".py", b"sqlite"):
        assert marker not in r.data
