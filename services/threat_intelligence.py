"""Optional external threat intelligence (disabled unless configured).

The ML detector never depends on this. When enabled, the lookup result is
returned alongside the model's prediction as a separate field; it does not
change the model's score or risk level.

Only a fixed provider endpoint is contacted, and the scanned URL is sent as
data. The server never requests the scanned URL itself, so this adds no SSRF
exposure. Enabling a provider sends scanned URLs to that third party; see
docs/api.md ("Security considerations").

Configuration (environment variables):
    THREAT_INTEL_PROVIDER=google_safe_browsing
    GOOGLE_SAFE_BROWSING_API_KEY=<key>
"""
import json
import logging
import os
import urllib.error
import urllib.request

logger = logging.getLogger(__name__)


class ThreatIntelligence:
    """Interface. Subclasses implement lookup(url) -> dict."""
    name = "none"
    enabled = False

    def lookup(self, url):
        return {"provider": self.name, "status": "disabled"}


class DisabledThreatIntelligence(ThreatIntelligence):
    pass


class GoogleSafeBrowsing(ThreatIntelligence):
    name = "google_safe_browsing"
    enabled = True
    ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

    def __init__(self, api_key, timeout=3.0, opener=urllib.request.urlopen):
        self.api_key = api_key
        self.timeout = timeout
        self._open = opener

    def lookup(self, url):
        body = {
            "client": {"clientId": "capstone-phishing-detector", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            },
        }
        request = urllib.request.Request(
            f"{self.ENDPOINT}?key={self.api_key}", data=json.dumps(body).encode(),
            headers={"Content-Type": "application/json"}, method="POST",
        )
        try:
            with self._open(request, timeout=self.timeout) as response:
                data = json.loads(response.read().decode() or "{}")
        except (urllib.error.URLError, TimeoutError, ValueError) as exc:
            logger.warning("Safe Browsing lookup failed: %s", exc)
            return {"provider": self.name, "status": "error", "error": "lookup failed"}
        matches = data.get("matches", [])
        return {"provider": self.name, "status": "ok", "listed": bool(matches),
                "threat_types": sorted({m.get("threatType") for m in matches if m.get("threatType")})}


def from_environment(env=os.environ):
    provider = env.get("THREAT_INTEL_PROVIDER", "").strip().lower()
    if provider == "google_safe_browsing":
        key = env.get("GOOGLE_SAFE_BROWSING_API_KEY", "").strip()
        if key:
            return GoogleSafeBrowsing(key)
        logger.warning("THREAT_INTEL_PROVIDER is set but GOOGLE_SAFE_BROWSING_API_KEY is missing; disabled")
    return DisabledThreatIntelligence()
