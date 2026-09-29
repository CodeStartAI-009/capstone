"""URL validation and normalisation.

Works on the URL *string* only. Nothing in this project fetches the URL, so
there is no server-side request forgery (SSRF) surface.
"""
import ipaddress
import re
from functools import lru_cache
from importlib.metadata import version as _pkg_version
from urllib.parse import urlsplit, urlunsplit

import tldextract

MAX_URL_LENGTH = 2048
ALLOWED_SCHEMES = ("http", "https")
DEFAULT_SCHEME = "https"

_NON_WEB_SCHEME_RE = re.compile(
    r"^(javascript|data|vbscript|file|ftp|mailto|about|chrome|chrome-extension|blob|tel):", re.IGNORECASE
)
_LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")


# Public Suffix List (PSL): which parts of a host name are a registry suffix (".com", ".co.uk",
# and shared-hosting suffixes such as "firebaseapp.com" or "web.app" from the PSL private section).
# The bundled snapshot of the pinned tldextract release is used, never a network download, so the
# result is reproducible. The PSL describes domain *registration structure*; it says nothing about
# whether a site is trustworthy, and it is not a safe-list.
_PSL = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None, include_psl_private_domains=True)
PSL_SOURCE = (f"Public Suffix List snapshot bundled with tldextract {_pkg_version('tldextract')} "
              "(offline, private domains included)")


@lru_cache(maxsize=65536)
def split_registrable(host):
    """(subdomain, registrable_domain) of a lower-case host name, using the PSL.

    IP addresses, single-label names and hosts without a known suffix have no
    registrable domain; they are returned unchanged as ("", host).
    """
    host = host.strip("[]").rstrip(".")
    if not host or _is_ip_literal(host):
        return "", host
    parts = _PSL(host)
    if not parts.suffix or not parts.domain:
        return "", host
    return parts.subdomain, f"{parts.domain}.{parts.suffix}"


def registrable_domain(host):
    """The PSL registrable domain of `host`, or "" if it has none (IP address, unknown suffix, single label)."""
    host = host.strip("[]").rstrip(".").lower()
    if not host or _is_ip_literal(host):
        return ""
    parts = _PSL(host)
    return f"{parts.domain}.{parts.suffix}" if parts.suffix and parts.domain else ""


class InvalidURLError(ValueError):
    """Input cannot be interpreted as an http(s) URL."""


class UnsupportedSchemeError(InvalidURLError):
    """Input is a URL, but not an http(s) one (javascript:, data:, file:, ftp:, ...)."""


def _is_ip_literal(host):
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def _to_ascii_host(host):
    """Validate a host name and return it lower-cased in IDNA (punycode) form."""
    if not host:
        raise InvalidURLError("URL has no host name")
    if _is_ip_literal(host) or host == "localhost":
        return host
    try:
        ascii_host = host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise InvalidURLError("URL host name is not a valid domain") from exc
    labels = ascii_host.rstrip(".").split(".")
    if len(ascii_host) > 253 or not all(_LABEL_RE.match(label) for label in labels):
        raise InvalidURLError("URL host name is not a valid domain")
    return ascii_host


def has_explicit_scheme(raw):
    return isinstance(raw, str) and "://" in raw


def normalize_url(raw, max_length=MAX_URL_LENGTH):
    """Validate ``raw`` and return a normalised ``http(s)://`` URL.

    Normalisation is deliberately minimal so the features describe what the
    user submitted:
      * surrounding whitespace is trimmed;
      * a missing scheme defaults to https:// (as HTTPS-first browsers do);
        callers can detect this with has_explicit_scheme();
      * scheme and host are lower-cased; a Unicode host is converted to its
        IDNA/punycode form, which is also what Chrome reports for tab URLs;
      * path, query and fragment are left untouched.
    """
    if raw is None:
        raise InvalidURLError("URL is required")
    if not isinstance(raw, str):
        raise InvalidURLError("URL must be a string")
    url = raw.strip()
    if not url:
        raise InvalidURLError("URL is required")
    if len(url) > max_length:
        raise InvalidURLError(f"URL is longer than {max_length} characters")
    if any(ch.isspace() or ord(ch) < 32 or ord(ch) == 127 for ch in url):
        raise InvalidURLError("URL must not contain spaces or control characters")

    if "://" not in url:
        if _NON_WEB_SCHEME_RE.match(url):
            raise UnsupportedSchemeError("Only http and https URLs can be scanned")
        url = f"{DEFAULT_SCHEME}://{url.lstrip('/')}"

    try:
        parts = urlsplit(url)
        port = parts.port  # raises ValueError for a non-numeric or out-of-range port
    except ValueError as exc:
        raise InvalidURLError("URL is malformed") from exc

    scheme = parts.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        raise UnsupportedSchemeError("Only http and https URLs can be scanned")

    host = _to_ascii_host((parts.hostname or "").lower())
    netloc = f"[{host}]" if ":" in host else host
    if port is not None:
        netloc = f"{netloc}:{port}"
    if "@" in parts.netloc:
        netloc = parts.netloc.rpartition("@")[0] + "@" + netloc

    normalized = urlunsplit((scheme, netloc, parts.path, parts.query, parts.fragment))
    if len(normalized) > max_length:
        raise InvalidURLError(f"URL is longer than {max_length} characters")
    return normalized


def describe_url(url):
    """Structural facts about a normalised URL that are not model features.

    Used by the explanation engine; none of these values are fed to the model.
    """
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    registrable_labels = host.split(".")
    subdomain, registrable = split_registrable(host)
    return {
        "scheme": parts.scheme,
        "host": host,
        "registrable_domain": registrable,
        "subdomain": subdomain,
        "port": parts.port,
        "non_standard_port": parts.port is not None and parts.port not in (80, 443),
        "has_userinfo": "@" in parts.netloc,
        "is_ip_literal": _is_ip_literal(host),
        "is_private_or_local": host == "localhost" or (
            _is_ip_literal(host) and not ipaddress.ip_address(host.strip("[]")).is_global
        ),
        "is_punycode": any(label.startswith("xn--") for label in registrable_labels),
        "hyphen_in_host": "-" in host,
        "has_www": host.startswith("www."),
        "has_path": parts.path not in ("", "/"),
        "has_query": bool(parts.query),
        "has_fragment": bool(parts.fragment),
    }
