"""Scan-history service used by /api/predict and /api/history.

Routes depend on this interface only; SQL lives in database/repository.py.

Privacy: a scanned URL can carry secrets (password-reset tokens, session ids,
a victim's e-mail address in a phishing link). Before anything is stored, the
URL is redacted by redact_url(): a userinfo password is removed, query values
are replaced by "[redacted]" (the keys are kept), and the fragment is dropped.
The API response itself still shows the URL the user submitted. Paths are
stored as-is (they are needed to recognise a scan) and are documented as a
residual risk in docs/database.md.
"""
import logging
from datetime import datetime, timezone
from urllib.parse import parse_qsl, quote, urlsplit, urlunsplit

from database import DatabaseError
from database.models import PREDICTIONS

logger = logging.getLogger(__name__)
REDACTED = "[redacted]"


class HistoryUnavailableError(RuntimeError):
    """The history store could not be read or written."""


def redact_url(url):
    try:
        parts = urlsplit(url)
    except ValueError:
        return url.split("?", 1)[0].split("#", 1)[0]
    netloc = parts.netloc
    if "@" in netloc:
        userinfo, _, hostport = netloc.rpartition("@")
        netloc = f"{userinfo.split(':', 1)[0]}@{hostport}"
    query = "&".join(f"{quote(k, safe='')}={REDACTED}" for k, _ in parse_qsl(parts.query, keep_blank_values=True))
    if parts.query and not query:  # unparseable query string: drop it entirely
        query = REDACTED
    return urlunsplit((parts.scheme, netloc, parts.path, query, ""))


def _indicators(result):
    return [{"severity": item.get("severity"), "source": item.get("source"),
             "key": item.get("feature") or item.get("check"), "message": item.get("message")}
            for item in result.get("explanations", [])]


class HistoryService:
    def __init__(self, repository):
        self.repo = repository

    def _call(self, fn, *args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except DatabaseError:
            logger.exception("History store failure")
            raise HistoryUnavailableError("history store unavailable") from None

    def record(self, raw_url, result, source):
        """Save a scan. Returns {"saved": True, "id": n} or {"saved": False} (never raises)."""
        scan = {
            "scanned_at": result.get("scanned_at") or datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "url": redact_url(raw_url.strip()),
            "normalized_url": redact_url(result["url"]),
            "host": (result.get("url_facts") or {}).get("host"),
            "prediction": result["prediction"],
            "risk_level": result["risk_level"],
            "confidence": result.get("confidence"),
            "phishing_probability": result.get("phishing_probability"),
            "model_version": result.get("model_version"),
            "processing_ms": (result.get("timing_ms") or {}).get("total"),
            "source": source,
            "features": result.get("features"),
            "indicators": _indicators(result),
        }
        try:
            return {"saved": True, "id": self._call(self.repo.add, scan)}
        except HistoryUnavailableError:
            return {"saved": False}

    def page(self, page, limit, prediction=None, search=None):
        if prediction is not None and prediction not in PREDICTIONS:
            raise ValueError("unknown prediction filter")
        items, total = self._call(self.repo.list, page, limit, prediction, search)
        return {"items": items, "page": page, "limit": limit, "total": total,
                "pages": (total + limit - 1) // limit}

    def get(self, scan_id):
        return self._call(self.repo.get, scan_id)

    def delete(self, scan_id):
        return self._call(self.repo.delete, scan_id)

    def clear(self):
        return self._call(self.repo.clear)

    def stats(self, days=30):
        return self._call(self.repo.stats, days)
