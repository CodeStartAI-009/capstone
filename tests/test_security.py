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
    assert r.get_json() == {"success": False, "error": "Too many requests. Please wait and try again."}


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


def test_default_config_allows_no_cross_origin(client):
    r = client.get("/api/health", headers={"Origin": "https://evil.example"})
    assert "Access-Control-Allow-Origin" not in r.headers


def test_scanning_never_opens_network_connections(client, monkeypatch):
    """The detector is URL-string only: no DNS lookup or HTTP request (no SSRF surface)."""
    def forbidden(*args, **kwargs):
        raise AssertionError("network access attempted")
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    for url in ("http://169.254.169.254/latest/meta-data/", "http://127.0.0.1:22/", "http://10.0.0.1/admin",
                "https://www.example.com"):
        assert client.post("/api/predict", json={"url": url}).status_code == 200


def test_private_address_is_flagged_as_out_of_scope(client):
    body = client.post("/api/predict", json={"url": "http://10.0.0.1/admin"}).get_json()
    assert any(e.get("check") == "local" for e in body["explanations"])


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
    app.extensions["threat_intel"] = ti
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
