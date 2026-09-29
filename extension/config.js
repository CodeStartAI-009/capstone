/* The ONLY place the extension's API location is configured.
 *
 * Development (default): the Flask app started with `python app.py`.
 * Production: replace with your deployed HTTPS origin, e.g. "https://YOUR-PRODUCTION-API",
 * AND change "host_permissions" in manifest.json to the same origin followed by "/*".
 * No production URL exists yet, so none is configured here.
 */
const API_BASE = "http://127.0.0.1:5000";
const REQUEST_TIMEOUT_MS = 8000;
