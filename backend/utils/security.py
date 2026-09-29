"""HTTP security headers and a strict CORS allow-list."""
import logging
from urllib.parse import urlsplit

from flask import request

logger = logging.getLogger(__name__)

CONTENT_SECURITY_POLICY = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
)
PERMISSIONS_POLICY = "camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()"
SERVER_HEADER = "phishing-detector"  # replaces "Werkzeug/x Python/y" (no version disclosure)


def parse_origins(*values):
    """Exact origins from comma-separated strings. Wildcards and non-origins are ignored with a warning."""
    origins = set()
    for value in values:
        for item in (value or "").split(","):
            origin = item.strip().rstrip("/")
            if not origin:
                continue
            parts = urlsplit(origin)
            if "*" in origin or parts.scheme not in ("http", "https") or not parts.netloc or parts.path:
                logger.warning("Ignoring invalid CORS origin %r (use exact scheme://host[:port])", origin)
                continue
            origins.add(origin)
    return origins


def apply_security_headers(response, allowed_origins):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Content-Security-Policy", CONTENT_SECURITY_POLICY)
    response.headers.setdefault("Permissions-Policy", PERMISSIONS_POLICY)
    response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
    response.headers.setdefault("Cross-Origin-Resource-Policy", "same-origin")
    response.headers["Server"] = SERVER_HEADER
    if request.is_secure:  # only meaningful (and only honoured) over HTTPS
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    if request.path.startswith("/api/"):
        response.headers.setdefault("Cache-Control", "no-store")
        origin = request.headers.get("Origin", "").rstrip("/")
        if origin and origin in allowed_origins:
            response.headers["Access-Control-Allow-Origin"] = origin
            response.headers["Vary"] = "Origin"
            response.headers["Access-Control-Allow-Methods"] = "GET, POST, DELETE, OPTIONS"
            response.headers["Access-Control-Allow-Headers"] = "Content-Type"
            response.headers["Access-Control-Max-Age"] = "600"
    return response
