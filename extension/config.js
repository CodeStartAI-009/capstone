/* The ONLY place the extension's API location and scanning settings are configured.
 *
 * Development (default): the Flask app started with `python app.py`.
 * Production: replace with your deployed HTTPS origin, e.g. "https://YOUR-PRODUCTION-API",
 * AND change "host_permissions" in manifest.json to the same origin followed by "/*".
 * No production URL exists yet, so none is configured here.
 */
const API_BASE = "http://127.0.0.1:5000";
const REQUEST_TIMEOUT_MS = 8000;

// Automatic checks (background.js). The two booleans are only the defaults; the user changes
// them in the popup and the choice is kept in chrome.storage.local.
const AUTO_SCAN_DEFAULT = true;            // check every http(s) page the user opens
const RECORD_AUTO_SCANS_DEFAULT = false;   // do not store automatic checks in the scan history
const SCAN_CACHE_TTL_MS = 5 * 60 * 1000;   // reuse a site's result for 5 minutes (no repeated API calls)
const BYPASS_TTL_MS = 30 * 60 * 1000;      // "Continue Anyway" lasts at most 30 minutes, in one tab, on one site
