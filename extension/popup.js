/* Popup: read the active tab's URL (activeTab permission, granted when the user clicks the
 * toolbar icon), send it to the project API and show the API's result. There is no model
 * or prediction logic here; the Flask API is the single source of truth.
 * All text is written with textContent (no innerHTML).
 */
"use strict";

const $ = (id) => document.getElementById(id);
const MAX_REASONS = 4;
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

let currentUrl = null;
let busy = false;

function show(section) {
  $("loading").hidden = section !== "loading";
  $("error").hidden = section !== "error";
  $("result").hidden = section !== "result";
}

function showError(message) {
  $("error").textContent = message;
  show("error");
}

function percent(value) {
  return typeof value === "number" && isFinite(value) ? (value * 100).toFixed(1) + "%" : "not available";
}

/* Returns null if the URL can be scanned, otherwise a user-facing reason. */
function unsupportedReason(url) {
  if (typeof url !== "string" || !url) {
    // Chrome does not reveal the address of its own pages (chrome://, about:, data: ...) to activeTab.
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

async function callApi(url) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  let response;
  try {
    response = await fetch(API_BASE.replace(/\/+$/, "") + "/api/predict", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: url, source: "extension", record: true }),
      signal: controller.signal,
      credentials: "omit",
    });
  } catch (err) {
    if (controller.signal.aborted) {
      throw new Error("The scanner API did not respond within " + REQUEST_TIMEOUT_MS / 1000 + " seconds. Try again.");
    }
    throw new Error("Cannot reach the scanner API at " + API_BASE + ". Start the Flask server (python app.py) and try again.");
  } finally {
    clearTimeout(timer);
  }
  let body;
  try {
    body = await response.json();
  } catch (err) {
    throw new Error("The scanner API returned an unexpected response (HTTP " + response.status + ").");
  }
  if (!body || typeof body !== "object") {
    throw new Error("The scanner API returned an unexpected response.");
  }
  if (!response.ok || body.success !== true) {
    const err = body.error;
    throw new Error(err && typeof err.message === "string" ? err.message
      : "The scanner API returned an error (HTTP " + response.status + ").");
  }
  if (typeof body.prediction !== "string" || !(body.prediction in VERDICT_CLASSES)) {
    throw new Error("The scanner API returned an unexpected response.");
  }
  return body;
}

function render(result) {
  const verdict = $("verdict");
  verdict.textContent = result.verdict || result.prediction;
  verdict.className = "verdict " + VERDICT_CLASSES[result.prediction];
  $("prediction").textContent = result.prediction;
  $("risk").textContent = result.risk_level;
  $("confidence").textContent = percent(result.confidence);
  const reasons = $("reasons");
  reasons.replaceChildren();
  (Array.isArray(result.explanation) ? result.explanation : []).slice(0, MAX_REASONS).forEach((message) => {
    const li = document.createElement("li");
    li.textContent = String(message);
    reasons.appendChild(li);
  });
  $("disclaimer").textContent = result.disclaimer ||
    "This result is an automated machine-learning risk assessment and is not a guarantee that a website is safe.";
  const details = $("details");
  const id = result.history && result.history.saved ? result.history.id : null;
  details.hidden = !Number.isInteger(id);
  details.dataset.scanId = Number.isInteger(id) ? String(id) : "";
  show("result");
}

async function scan() {
  if (busy) return;
  const reason = unsupportedReason(currentUrl);
  if (reason) {
    showError(reason);
    return;
  }
  busy = true;
  $("scan").disabled = true;
  $("details").hidden = true;
  show("loading");
  try {
    render(await callApi(currentUrl));
    $("scan").textContent = "Scan again";
  } catch (err) {
    showError(err.message);
  } finally {
    busy = false;
    $("scan").disabled = false;
  }
}

function openPage(path) {
  chrome.tabs.create({ url: API_BASE.replace(/\/+$/, "") + path });
}

document.addEventListener("DOMContentLoaded", async () => {
  $("api-base").textContent = API_BASE;
  $("scan").addEventListener("click", scan);
  $("dashboard").addEventListener("click", () => openPage("/dashboard"));
  $("details").addEventListener("click", () => {
    const id = $("details").dataset.scanId;
    if (/^[1-9][0-9]*$/.test(id)) openPage("/inspect?id=" + id);
  });
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    currentUrl = tab ? tab.url : null;
  } catch (err) {
    currentUrl = null;
  }
  $("url").textContent = currentUrl || "(address not available)";
  scan();
});
