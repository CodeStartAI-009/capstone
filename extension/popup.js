/* Popup: read the active tab's URL, send it to the project API (scan-core.js) and show the API's
 * result. A popup scan is a manual scan: it sends the full URL and is saved to the scan history.
 * The popup also shows the background worker's automatic check for the tab (background.js) and
 * the two settings stored in chrome.storage.local.
 * There is no model or prediction logic here; the Flask API is the single source of truth.
 * All text is written with textContent (no innerHTML).
 */
"use strict";

const $ = (id) => document.getElementById(id);
const MAX_REASONS = 4;
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
    render(await callApi(currentUrl, true));
    $("scan").textContent = "Scan again";
  } catch (err) {
    showError(err.message);
  } finally {
    busy = false;
    $("scan").disabled = false;
  }
}

function openPage(path) {
  chrome.tabs.create({ url: apiUrl(path) });
}

/* The automatic-scanning settings. The background worker reacts to changes (storage.onChanged). */
async function loadSettings() {
  const defaults = { autoScan: AUTO_SCAN_DEFAULT, recordAutoScans: RECORD_AUTO_SCANS_DEFAULT };
  let settings = defaults;
  try {
    settings = { ...defaults, ...(await chrome.storage.local.get(defaults)) };
  } catch (err) {
    // storage unavailable: show the defaults
  }
  [["auto-scan", "autoScan"], ["record-auto", "recordAutoScans"]].forEach(([id, key]) => {
    const box = $(id);
    box.checked = settings[key] === true;
    box.addEventListener("change", () => {
      chrome.storage.local.set({ [key]: box.checked }).catch(() => {});
      if (key === "autoScan") $("auto-status").textContent = box.checked ? "Automatic checks are on." :
        "Automatic checks are off. Pages are checked only when you open this popup.";
    });
  });
}

/* One line describing the background worker's automatic check of this tab. */
async function loadAutoStatus(tabId) {
  let status = null;
  try {
    status = await chrome.runtime.sendMessage({ type: "status:get", tabId: tabId });
  } catch (err) {
    status = null;
  }
  $("auto-status").textContent = status && typeof status.text === "string" ? status.text
    : "Automatic check status is not available.";
}

document.addEventListener("DOMContentLoaded", async () => {
  $("api-base").textContent = API_BASE;
  $("scan").addEventListener("click", scan);
  $("dashboard").addEventListener("click", () => openPage("/dashboard"));
  $("details").addEventListener("click", () => {
    const id = $("details").dataset.scanId;
    if (/^[1-9][0-9]*$/.test(id)) openPage("/inspect?id=" + id);
  });
  let tab = null;
  try {
    [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    currentUrl = tab ? tab.url : null;
  } catch (err) {
    currentUrl = null;
  }
  $("url").textContent = currentUrl || "(address not available)";
  loadSettings();
  if (tab && Number.isInteger(tab.id)) loadAutoStatus(tab.id);
  scan();
});
