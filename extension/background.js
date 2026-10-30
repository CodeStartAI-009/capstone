/* Background service worker: automatic checks of the pages the user opens.
 *
 *   tab navigation (tabs.onUpdated / onActivated / onReplaced)
 *     -> origin of the tab URL (scheme://host[:port]); the path, query and fragment are NOT sent
 *     -> POST {API_BASE}/api/predict (scan-core.js), result cached per origin for SCAN_CACHE_TTL_MS
 *     -> toolbar badge: LOW / MED / HIGH, "…" while checking, "?" if the check failed, N/A if not checkable
 *     -> High: the tab is sent to warning.html ("Go Back to Safety" / "Continue Anyway")
 *
 * Sending only the origin loses nothing the model uses: the deployed model scores the site's
 * registrable domain (models/model_metadata.json "model_input_view": "registrable"), so the score is
 * the same as for the full URL, and paths or query strings (tokens, e-mail addresses) stay in the browser.
 *
 * State that must survive a service-worker restart is kept in chrome.storage.session (memory only,
 * cleared when the browser closes): per-tab state under "tab:<id>" and the result cache under
 * "scan-cache". Settings are in chrome.storage.local. Nothing here reads page contents; the extension
 * has no content scripts.
 *
 * Limitation: Chrome reports a navigation once it has started, so a high-risk page may begin to load
 * (and run its scripts) before the tab is moved to the warning page. This is a warning, not a guarantee
 * that the page is blocked before any of its content loads.
 */
"use strict";

importScripts("config.js", "scan-core.js");

const EXTENSION_ORIGIN = chrome.runtime.getURL("").replace(/\/$/, ""); // "chrome-extension://<id>"
const WARNING_PAGE = chrome.runtime.getURL("warning.html");
const SAFE_PAGE = chrome.runtime.getURL("safe.html");
const API_ORIGIN = new URL(API_BASE).origin;
const CACHE_KEY = "scan-cache";
const MAX_CACHE_ENTRIES = 200;
const MAX_EXPLANATIONS = 8;
// API error codes meaning "this address cannot be assessed" rather than "the scanner failed".
const NOT_CHECKABLE_CODES = new Set(["UNSUPPORTED_HOST", "UNSUPPORTED_SCHEME", "INVALID_URL", "URL_TOO_LONG"]);

const BADGES = {
  scanning: { text: "…", color: "#6b7280", title: "Checking this site's address…" },
  Low: { text: "LOW", color: "#15803d",
    title: "Low-risk prediction for this site. This is not a guarantee that it is safe." },
  Medium: { text: "MED", color: "#b45309",
    title: "Caution: moderate phishing-risk prediction for this site. Check the address before entering anything." },
  High: { text: "HIGH", color: "#b91c1c", title: "High phishing-risk prediction for this site." },
  bypassed: { text: "HIGH", color: "#b91c1c",
    title: "High phishing-risk prediction. You chose Continue Anyway for this site in this tab." },
  unavailable: { text: "?", color: "#6b7280", title: "This site could NOT be checked" },
  notChecked: { text: "N/A", color: "#9ca3af", title: "This page is not checked" },
  unsupported: { text: "", color: "#6b7280", title: "This page is not checked" },
  off: { text: "OFF", color: "#9ca3af", title: "Automatic checks are off. Click to check this page." },
};

// ------------------------------------------------------------------ helpers
const chains = new Map();

/* Run fn after every earlier call with the same key has finished (no lost read-modify-write updates). */
function serialized(key, fn) {
  const run = (chains.get(key) || Promise.resolve()).then(fn, fn);
  const tail = run.catch(() => {});
  chains.set(key, tail);
  tail.then(() => { if (chains.get(key) === tail) chains.delete(key); });
  return run;
}

function originOf(url) {
  try {
    return new URL(url).origin;
  } catch (err) {
    return null;
  }
}

function isHttpUrl(url) {
  return unsupportedReason(url) === null;
}

async function getSettings() {
  const defaults = { autoScan: AUTO_SCAN_DEFAULT, recordAutoScans: RECORD_AUTO_SCANS_DEFAULT };
  try {
    return { ...defaults, ...(await chrome.storage.local.get(defaults)) };
  } catch (err) {
    return defaults;
  }
}

const tabKey = (tabId) => "tab:" + tabId;

async function readTab(tabId) {
  const key = tabKey(tabId);
  return (await chrome.storage.session.get(key))[key] || {};
}

/* Change one tab's stored state; `mutate(state)` edits it in place and may return a value. */
function updateTab(tabId, mutate) {
  return serialized(tabKey(tabId), async () => {
    const state = await readTab(tabId);
    const value = mutate(state);
    await chrome.storage.session.set({ [tabKey(tabId)]: state });
    return value;
  });
}

async function currentUrlOf(tabId) {
  try {
    const tab = await chrome.tabs.get(tabId);
    return tab.pendingUrl || tab.url || null;
  } catch (err) {
    return null; // tab closed
  }
}

function score(result) {
  return typeof result.phishing_probability === "number" ? result.phishing_probability.toFixed(2) : "not available";
}

/* The sentence the popup shows for a tab's automatic check. */
function statusText(kind, result, detail) {
  switch (kind) {
    case "Low": return "Automatic check: low-risk prediction for this site (model phishing score " + score(result) +
      "). This is not a guarantee that it is safe.";
    case "Medium": return "Automatic check: moderate phishing-risk prediction (model phishing score " + score(result) +
      "). Be careful with this site.";
    case "High": return "Automatic check: high phishing-risk prediction (model phishing score " + score(result) +
      "). The warning page was shown.";
    case "bypassed": return "Automatic check: high phishing-risk prediction (model phishing score " + score(result) +
      "). You chose Continue Anyway for this site in this tab.";
    case "scanning": return "Automatic check in progress…";
    case "unavailable": return "Automatic check failed, so this page was NOT checked: " + detail;
    case "notChecked": return "This page is not checked automatically: " + detail;
    default: return "This page is not checked automatically.";
  }
}

async function setBadge(tabId, kind, detail) {
  const badge = BADGES[kind];
  try {
    await Promise.all([
      chrome.action.setBadgeText({ tabId: tabId, text: badge.text }),
      chrome.action.setBadgeBackgroundColor({ tabId: tabId, color: badge.color }),
      chrome.action.setTitle({ tabId: tabId, title: detail ? badge.title + ": " + detail : badge.title }),
    ]);
  } catch (err) {
    // the tab was closed meanwhile
  }
}

/* Only the latest navigation of a tab may change its badge or redirect it (in-memory; after a worker
 * restart the origin check in handleNavigation still drops responses for pages the tab has left). */
const latestNavigation = new Map();
let navigationCounter = 0;

// ------------------------------------------------------------------ scanning
function summarize(body) {
  const text = (value) => (typeof value === "string" ? value : "");
  const number = (value) => (typeof value === "number" && isFinite(value) ? value : null);
  return {
    prediction: body.prediction,
    risk_level: body.risk_level,
    verdict: text(body.verdict),
    summary: text(body.summary),
    disclaimer: text(body.disclaimer),
    phishing_probability: number(body.phishing_probability),
    confidence: number(body.confidence),
    model_input: text(body.model_input),
    model_version: text(body.model_version),
    explanations: (Array.isArray(body.explanations) ? body.explanations : [])
      .filter((item) => item && typeof item.message === "string")
      .slice(0, MAX_EXPLANATIONS)
      .map((item) => ({ source: text(item.source), severity: text(item.severity), message: item.message })),
  };
}

async function cachedResult(origin) {
  const cache = (await chrome.storage.session.get(CACHE_KEY))[CACHE_KEY] || {};
  const entry = cache[origin];
  return entry && Date.now() - entry.at < SCAN_CACHE_TTL_MS ? entry.result : null;
}

function storeResult(origin, result) {
  return serialized(CACHE_KEY, async () => {
    const now = Date.now();
    const cache = (await chrome.storage.session.get(CACHE_KEY))[CACHE_KEY] || {};
    cache[origin] = { at: now, result: result };
    const live = Object.entries(cache)
      .filter(([, entry]) => now - entry.at < SCAN_CACHE_TTL_MS)
      .sort((a, b) => b[1].at - a[1].at)
      .slice(0, MAX_CACHE_ENTRIES);
    await chrome.storage.session.set({ [CACHE_KEY]: Object.fromEntries(live) });
  });
}

const inflight = new Map(); // origin -> Promise<outcome>: one API request per origin at a time

/* {kind: "result", result} | {kind: "unavailable" | "notChecked", message}. Never rejects.
 * Failures are not cached, so the next navigation tries again. */
async function scanOrigin(origin) {
  const cached = await cachedResult(origin);
  if (cached) return { kind: "result", result: cached };
  if (!inflight.has(origin)) {
    const task = (async () => {
      try {
        const { recordAutoScans } = await getSettings();
        const result = summarize(await callApi(origin + "/", recordAutoScans === true));
        await storeResult(origin, result);
        return { kind: "result", result: result };
      } catch (err) {
        const message = err && typeof err.message === "string" ? err.message : "The scan failed.";
        return { kind: err && NOT_CHECKABLE_CODES.has(err.code) ? "notChecked" : "unavailable", message: message };
      }
    })();
    inflight.set(origin, task);
    task.then(() => inflight.delete(origin));
  }
  return inflight.get(origin);
}

async function showStatus(tabId, kind, result, detail) {
  await updateTab(tabId, (state) => {
    state.status = { kind: kind, text: statusText(kind, result, detail) };
  });
  await setBadge(tabId, kind, detail);
}

/* Act on a scan outcome for the page the tab is on now (`url`, already checked to be the scanned origin). */
async function applyOutcome(tabId, url, origin, outcome) {
  if (outcome.kind !== "result") {
    await showStatus(tabId, outcome.kind, null, outcome.message);
    return;
  }
  const result = outcome.result;
  if (result.risk_level !== "High") {
    await updateTab(tabId, (state) => {
      state.lastSafeUrl = url; // the "Go Back to Safety" target: the latest page here that was checked and not high-risk
      state.status = { kind: result.risk_level, text: statusText(result.risk_level, result) };
    });
    await setBadge(tabId, result.risk_level);
    return;
  }
  const kind = await updateTab(tabId, (state) => {
    const bypassed = state.bypass && state.bypass.origin === origin;
    if (!bypassed) state.warning = { url: url, origin: origin, result: result, at: Date.now() };
    state.status = { kind: bypassed ? "bypassed" : "High", text: statusText(bypassed ? "bypassed" : "High", result) };
    return bypassed ? "bypassed" : "High";
  });
  await setBadge(tabId, kind);
  if (kind === "High") {
    try {
      await chrome.tabs.update(tabId, { url: WARNING_PAGE });
    } catch (err) {
      // the tab was closed meanwhile
    }
  }
}

/* trigger: "navigation" (the tab loaded or changed its URL) or "activated" (tab switch, start-up). */
async function handleNavigation(tabId, url, trigger) {
  if (!Number.isInteger(tabId) || tabId < 0) return;
  const token = ++navigationCounter;
  latestNavigation.set(tabId, token);
  const isLatest = () => latestNavigation.get(tabId) === token;

  if (typeof url === "string" && url.startsWith(EXTENSION_ORIGIN + "/")) {
    if (url.startsWith(WARNING_PAGE)) await setBadge(tabId, "High");
    else await setBadge(tabId, "unsupported");
    return; // the extension's own pages: never scanned, and they do not end a bypass
  }
  const settings = await getSettings();
  if (!settings.autoScan) {
    await setBadge(tabId, "off");
    return;
  }
  const reason = unsupportedReason(url);
  const origin = reason ? null : originOf(url);
  const known = await updateTab(tabId, (state) => {
    // "Continue Anyway" ends when the tab leaves the site, or at the next page load after BYPASS_TTL_MS.
    if (state.bypass && (state.bypass.origin !== origin ||
        (trigger === "navigation" && Date.now() > state.bypass.expires))) delete state.bypass;
    if (state.warning && state.warning.origin !== origin) delete state.warning;
    const same = trigger === "activated" && state.origin === origin && state.status;
    state.origin = origin;
    return same ? state.status : null;
  });
  if (reason) {
    await showStatus(tabId, "unsupported", null, reason);
    return;
  }
  if (known && known.kind !== "scanning" && known.kind !== "unavailable") {
    await setBadge(tabId, BADGES[known.kind] ? known.kind : "unsupported"); // tab switch: no new scan, no redirect
    return;
  }
  if (origin === API_ORIGIN) {
    await showStatus(tabId, "notChecked", null, "the scanner's own web pages are not checked");
    return;
  }
  if (!(await cachedResult(origin)) && isLatest()) await showStatus(tabId, "scanning", null);
  const outcome = await scanOrigin(origin);
  const now = await currentUrlOf(tabId);
  if (!isLatest() || !now || !isHttpUrl(now) || originOf(now) !== origin) return; // stale: the tab moved on
  await applyOutcome(tabId, now, origin, outcome);
}

function onError(err) {
  console.warn("Phishing URL Scanner:", err && err.message ? err.message : err);
}

async function refreshAllTabs() {
  const { autoScan } = await getSettings();
  await chrome.action.setBadgeText({ text: autoScan ? "" : BADGES.off.text });
  await chrome.action.setBadgeBackgroundColor({ color: BADGES.off.color });
  for (const tab of await chrome.tabs.query({})) {
    if (!autoScan) await setBadge(tab.id, "off");
    else if (tab.active) handleNavigation(tab.id, tab.pendingUrl || tab.url, "activated").catch(onError);
  }
}

// ------------------------------------------------------------------ messages from the extension's own pages
async function warningInfo(message, sender) {
  const state = await readTab(sender.tab.id);
  if (!state.warning) return { ok: true, warning: null };
  const { url, result } = state.warning;
  return { ok: true, warning: { url: url, host: new URL(url).host, result: result } };
}

/* Go Back to Safety: the latest page in this tab that was checked and not high-risk, else safe.html.
 * The target never comes from the message or from the API response. */
async function goBack(message, sender) {
  const tabId = sender.tab.id;
  const target = await updateTab(tabId, (state) => {
    const blocked = state.warning ? state.warning.origin : null;
    const previous = state.lastSafeUrl;
    delete state.warning;
    return previous && isHttpUrl(previous) && originOf(previous) !== blocked ? previous : null;
  });
  await chrome.tabs.update(tabId, { url: target || SAFE_PAGE });
  return { ok: true, destination: target ? "previous" : "fallback" };
}

/* Continue Anyway: allow the flagged site once, in this tab only (see handleNavigation for when it ends).
 * The model score, the cache and the scan history are not changed. */
async function proceed(message, sender) {
  const tabId = sender.tab.id;
  const url = await updateTab(tabId, (state) => {
    if (!state.warning || !isHttpUrl(state.warning.url)) return null;
    state.bypass = { origin: state.warning.origin, expires: Date.now() + BYPASS_TTL_MS };
    const destination = state.warning.url;
    delete state.warning;
    return destination;
  });
  if (!url) return { ok: false };
  await chrome.tabs.update(tabId, { url: url });
  return { ok: true };
}

async function tabStatus(message) {
  if (!Number.isInteger(message.tabId)) return { ok: false };
  const { autoScan } = await getSettings();
  if (!autoScan) return { ok: true, kind: "off", text: "Automatic checks are off. Pages are checked only when you " +
    "open this popup." };
  const state = await readTab(message.tabId);
  if (!state.status) return { ok: true, kind: null, text: "This tab has not been checked automatically yet." };
  return { ok: true, kind: state.status.kind, text: state.status.text };
}

const HANDLERS = { "warning:get": warningInfo, "warning:back": goBack, "warning:proceed": proceed,
  "status:get": tabStatus };
const TAB_HANDLERS = new Set(["warning:get", "warning:back", "warning:proceed"]);

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  // Only the extension's own pages can send messages (no content scripts, no externally_connectable).
  if (sender.id !== chrome.runtime.id || typeof sender.url !== "string" ||
      !sender.url.startsWith(EXTENSION_ORIGIN + "/")) return false;
  const type = message && message.type;
  if (!Object.prototype.hasOwnProperty.call(HANDLERS, type)) return false;
  if (TAB_HANDLERS.has(type) && !(sender.tab && Number.isInteger(sender.tab.id))) return false;
  HANDLERS[type](message, sender).then(sendResponse, (err) => {
    onError(err);
    sendResponse({ ok: false });
  });
  return true; // the response is sent asynchronously
});

// ------------------------------------------------------------------ browser events (registered at top level,
// so they are delivered to a restarted service worker)
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.url || changeInfo.status === "loading") {
    handleNavigation(tabId, changeInfo.url || tab.url, "navigation").catch(onError);
  }
});

chrome.tabs.onActivated.addListener(({ tabId }) => {
  chrome.tabs.get(tabId)
    .then((tab) => handleNavigation(tabId, tab.pendingUrl || tab.url, "activated"))
    .catch(onError);
});

chrome.tabs.onReplaced.addListener((addedTabId, removedTabId) => {
  latestNavigation.delete(removedTabId);
  chrome.storage.session.remove(tabKey(removedTabId)).catch(onError);
  chrome.tabs.get(addedTabId)
    .then((tab) => handleNavigation(addedTabId, tab.pendingUrl || tab.url, "navigation"))
    .catch(onError);
});

chrome.tabs.onRemoved.addListener((tabId) => {
  latestNavigation.delete(tabId);
  chrome.storage.session.remove(tabKey(tabId)).catch(onError);
});

chrome.storage.onChanged.addListener((changes, area) => {
  if (area === "local" && changes.autoScan) refreshAllTabs().catch(onError);
});

chrome.runtime.onInstalled.addListener(() => refreshAllTabs().catch(onError));
chrome.runtime.onStartup.addListener(() => refreshAllTabs().catch(onError));
