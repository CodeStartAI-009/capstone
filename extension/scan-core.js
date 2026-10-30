/* Shared by the popup (popup.html) and the background service worker (importScripts):
 * which URLs can be scanned, the call to POST {API_BASE}/api/predict and the checks on its
 * response. There is no model or prediction logic here; the Flask API is the single source of
 * truth. Requires config.js (API_BASE, REQUEST_TIMEOUT_MS) to be loaded first.
 */
"use strict";

const UNSUPPORTED_SCHEMES = {
  "chrome:": "Chrome's internal pages",
  "chrome-extension:": "extension pages",
  "chrome-search:": "Chrome's internal pages",
  "chrome-untrusted:": "Chrome's internal pages",
  "devtools:": "developer tools",
  "edge:": "browser internal pages",
  "about:": "about: pages",
  "file:": "local files",
  "data:": "data: URLs",
  "javascript:": "javascript: URLs",
  "blob:": "blob: URLs",
  "view-source:": "view-source pages",
  "ftp:": "FTP addresses",
};
const VERDICT_CLASSES = { Safe: "safe", Suspicious: "suspicious", Phishing: "phishing" };
// The API's fixed prediction -> risk level mapping (GET /api/model-info "risk_levels").
const RISK_LEVEL_OF = { Safe: "Low", Suspicious: "Medium", Phishing: "High" };

/* An error from callApi. `code` is the API's error code (e.g. "UNSUPPORTED_HOST") or one of
 * NETWORK, TIMEOUT, BAD_RESPONSE for failures before a valid API answer was received. */
class ScanError extends Error {
  constructor(message, code) {
    super(message);
    this.code = code;
  }
}

function apiUrl(path) {
  return API_BASE.replace(/\/+$/, "") + path;
}

/* Returns null if the URL can be scanned, otherwise a user-facing reason. */
function unsupportedReason(url) {
  if (typeof url !== "string" || !url) {
    // Chrome does not reveal the address of some of its own pages (chrome://, about:, data: ...).
    return "This page cannot be scanned. Only http:// and https:// web pages can be checked; browser pages, " +
      "local files and data: URLs are not supported.";
  }
  let parsed;
  try {
    parsed = new URL(url);
  } catch (err) {
    return "This page's address is not a valid URL.";
  }
  if (parsed.protocol === "http:" || parsed.protocol === "https:") return null;
  const kind = UNSUPPORTED_SCHEMES[parsed.protocol] || parsed.protocol + " addresses";
  return "Only http:// and https:// web pages can be scanned. This tab shows " + kind + ".";
}

/* POST the URL to the API and return its JSON body, or throw a ScanError. A response is accepted
 * only if it is a successful prediction with a known prediction label and the matching risk level. */
async function callApi(url, record) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  let response;
  try {
    response = await fetch(apiUrl("/api/predict"), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: url, source: "extension", record: record }),
      signal: controller.signal,
      credentials: "omit",
    });
  } catch (err) {
    if (controller.signal.aborted) {
      throw new ScanError("The scanner API did not respond within " + REQUEST_TIMEOUT_MS / 1000 + " seconds. " +
        "Try again.", "TIMEOUT");
    }
    throw new ScanError("Cannot reach the scanner API at " + API_BASE + ". Start the Flask server (python app.py) " +
      "and try again.", "NETWORK");
  } finally {
    clearTimeout(timer);
  }
  let body;
  try {
    body = await response.json();
  } catch (err) {
    throw new ScanError("The scanner API returned an unexpected response (HTTP " + response.status + ").",
      "BAD_RESPONSE");
  }
  if (!body || typeof body !== "object") {
    throw new ScanError("The scanner API returned an unexpected response.", "BAD_RESPONSE");
  }
  if (!response.ok || body.success !== true) {
    const err = body.error;
    const valid = err && typeof err.message === "string";
    throw new ScanError(valid ? err.message : "The scanner API returned an error (HTTP " + response.status + ").",
      valid && typeof err.code === "string" ? err.code : "BAD_RESPONSE");
  }
  if (typeof body.prediction !== "string" || !Object.prototype.hasOwnProperty.call(VERDICT_CLASSES, body.prediction) ||
      body.risk_level !== RISK_LEVEL_OF[body.prediction]) {
    throw new ScanError("The scanner API returned an unexpected response.", "BAD_RESPONSE");
  }
  return body;
}
