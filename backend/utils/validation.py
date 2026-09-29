"""Validation of /api/predict requests and of the submitted URL.

The URL is untrusted input. Nothing in this project fetches it or resolves it in
DNS (the model works on the URL string only), so there is no SSRF surface. The
host policy below exists because the model was trained on public web URLs: a
score for localhost, a private address or an internal single-label name would
be meaningless, so such targets are rejected unless ALLOW_PRIVATE_HOSTS is set.
"""
import ipaddress
import socket
from urllib.parse import urlsplit

from backend.utils.errors import ApiError
from ml.url_utils import InvalidURLError, UnsupportedSchemeError, normalize_url

ALLOWED_FIELDS = {"url", "source", "record"}
ALLOWED_SOURCES = ("web", "extension", "api")
INTERNAL_SUFFIXES = (".localhost", ".local", ".internal", ".lan", ".home.arpa")


def parse_predict_payload(request):
    """Return (url, source, record) from a JSON request or raise ApiError."""
    if not request.is_json:
        raise ApiError("UNSUPPORTED_MEDIA_TYPE",
                       "The request body must be JSON (Content-Type: application/json).", 415)
    payload = request.get_json(silent=True)
    if payload is None:
        raise ApiError("INVALID_JSON", "The request body is not valid JSON.")
    if not isinstance(payload, dict):
        raise ApiError("INVALID_JSON", "The request body must be a JSON object.")
    unexpected = sorted(set(payload) - ALLOWED_FIELDS)
    if unexpected:
        raise ApiError("UNEXPECTED_FIELD", f"Unexpected field(s): {', '.join(unexpected)[:200]}. "
                                           f"Allowed: {', '.join(sorted(ALLOWED_FIELDS))}.")

    url = payload.get("url")
    if url is None:
        raise ApiError("MISSING_URL", "Please provide a URL to scan in the 'url' field.")
    if not isinstance(url, str):
        raise ApiError("INVALID_TYPE", "The 'url' field must be a string.")
    if not url.strip():
        raise ApiError("MISSING_URL", "Please provide a URL to scan in the 'url' field.")

    source = payload.get("source", "api")
    if source not in ALLOWED_SOURCES:
        raise ApiError("INVALID_FIELD", f"'source' must be one of: {', '.join(ALLOWED_SOURCES)}.")
    record = payload.get("record", True)
    if not isinstance(record, bool):
        raise ApiError("INVALID_TYPE", "The 'record' field must be true or false.")
    return url, source, record


def _as_ip(host):
    """The IP address a host denotes, including shorthand forms browsers accept (e.g. 2130706433, 0x7f.1)."""
    host = host.strip("[]")
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        pass
    if host and all(ch in "0123456789abcdefx." for ch in host.lower()) and any(ch.isdigit() for ch in host):
        try:
            return ipaddress.IPv4Address(socket.inet_aton(host))  # parsing only; no network access
        except (OSError, ValueError):
            return None
    return None


def is_internal_host(host):
    """True for localhost, private/loopback/link-local/reserved addresses and internal-only names."""
    host = host.lower().rstrip(".")
    ip = _as_ip(host)
    if ip is not None:
        if getattr(ip, "ipv4_mapped", None):
            ip = ip.ipv4_mapped
        return not ip.is_global or ip.is_multicast
    return host == "localhost" or "." not in host or host.endswith(INTERNAL_SUFFIXES)


def validate_url(raw, max_length, allow_private_hosts=False):
    """Normalise ``raw`` (see ml.url_utils.normalize_url) and apply the API's URL policy.

    Returns the normalised URL or raises ApiError.
    """
    if len(raw) > max_length:
        raise ApiError("URL_TOO_LONG", f"The URL is longer than {max_length} characters.")
    try:
        url = normalize_url(raw, max_length=max_length)
    except UnsupportedSchemeError:
        raise ApiError("UNSUPPORTED_SCHEME", "Only http:// and https:// URLs can be scanned.") from None
    except InvalidURLError as exc:
        raise ApiError("INVALID_URL", f"The supplied URL is invalid: {exc}.") from None
    if not allow_private_hosts and is_internal_host(urlsplit(url).hostname or ""):
        raise ApiError("UNSUPPORTED_HOST", "Local, private-network and internal host names cannot be scanned; "
                                           "the model only assesses public web URLs.")
    return url
