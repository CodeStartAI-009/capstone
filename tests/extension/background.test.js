/* SIMULATED unit tests for extension/background.js (Node's built-in test runner, fake chrome API).
 * Run: node --test tests/extension/      (also run by tests/test_extension_logic.py under pytest)
 */
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { Browser, okBody, settle, EXT_ORIGIN, API } = require("./harness");

const WARNING = EXT_ORIGIN + "/warning.html";
const SAFE = EXT_ORIGIN + "/safe.html";

/* API stand-in: prediction chosen by the origin that was sent. */
function byOrigin(table, fallback = "Safe") {
  return (body) => {
    const origin = new URL(body.url).origin;
    const entry = table[origin] || fallback;
    return typeof entry === "string" ? { status: 200, body: okBody(entry) } : entry;
  };
}

function setup(table = {}, options = {}) {
  const browser = new Browser();
  browser.api = byOrigin(table);
  browser.startWorker(options);
  return browser;
}

// --- automatic scanning ------------------------------------------------------------------------------
test("navigation is scanned automatically and only the origin is sent", async () => {
  const b = setup();
  const tab = b.openTab("https://shop.example/account/reset?token=SECRET#top");
  await settle();
  assert.equal(b.requests.length, 1);
  const { url, body, init } = b.requests[0];
  assert.equal(url, API + "/api/predict");
  assert.deepEqual(body, { url: "https://shop.example/", source: "extension", record: false });
  assert.equal(init.credentials, "omit");
  assert.ok(!JSON.stringify(b.requests).includes("SECRET"));
  assert.equal(b.badge(tab), "LOW");
  assert.match(b.badges[tab].title, /not a guarantee/);
});

test("the 'save automatic checks' setting sends record: true", async () => {
  const b = new Browser();
  b.local.recordAutoScans = true;
  b.startWorker();
  b.openTab("https://shop.example/");
  await settle();
  assert.equal(b.requests[0].body.record, true);
});

test("same site, other paths, fragments and SPA pushState do not trigger new API calls", async () => {
  const b = setup();
  const tab = b.openTab("https://news.example/a");
  await settle();
  b.navigate(tab, "https://news.example/b?x=1");
  b.navigate(tab, "https://news.example/b?x=1#section");
  b.pushState(tab, "https://news.example/app/route/2");
  await settle();
  assert.equal(b.requests.length, 1);
  assert.equal(b.badge(tab), "LOW");
});

test("concurrent navigations to one site in two tabs share one API request", async () => {
  const b = setup();
  b.api = () => ({ status: 200, body: okBody("Safe"), delay: 30 });
  const t1 = b.openTab("https://blog.example/1");
  const t2 = b.openTab("https://blog.example/2");
  await new Promise((r) => setTimeout(r, 60));
  await settle();
  assert.equal(b.requests.length, 1);
  assert.equal(b.badge(t1), "LOW");
  assert.equal(b.badge(t2), "LOW");
});

test("the cache expires after SCAN_CACHE_TTL_MS", async () => {
  const b = new Browser();
  b.startWorker({ configOverrides: { SCAN_CACHE_TTL_MS: 20 } });
  const tab = b.openTab("https://shop.example/");
  await settle();
  await new Promise((r) => setTimeout(r, 40));
  b.navigate(tab, "https://shop.example/again");
  await settle();
  assert.equal(b.requests.length, 2);
});

test("a new tab that was never checked is scanned when it is activated", async () => {
  const b = new Browser();
  b.local.autoScan = false;
  b.startWorker();
  const t1 = b.openTab("https://one.example/");
  const t2 = b.openTab("https://two.example/", { active: false });
  await settle();
  assert.equal(b.requests.length, 0);
  assert.equal(b.badge(t1), "OFF");
  await b.worker.chrome.storage.local.set({ autoScan: true }); // user switches automatic checks on
  await settle();
  assert.deepEqual(b.requests.map((r) => r.body.url), ["https://one.example/"]); // only the active tab
  b.activate(t2);
  await settle();
  assert.deepEqual(b.requests.map((r) => r.body.url), ["https://one.example/", "https://two.example/"]);
  b.activate(t1);
  b.activate(t2);
  await settle();
  assert.equal(b.requests.length, 2); // switching back does not rescan
  assert.equal(b.badge(t2), "LOW");
});

// --- risk levels ---------------------------------------------------------------------------------------
test("low risk: badge only, no warning", async () => {
  const b = setup();
  const tab = b.openTab("https://shop.example/");
  await settle();
  assert.equal(b.url(tab), "https://shop.example/");
  assert.equal(b.badge(tab), "LOW");
});

test("medium risk: visible caution badge, no warning page", async () => {
  const b = setup({ "https://login.example": "Suspicious" });
  const tab = b.openTab("https://login.example/");
  await settle();
  assert.equal(b.url(tab), "https://login.example/");
  assert.equal(b.badge(tab), "MED");
  assert.match(b.badges[tab].title, /Caution/);
});

test("high risk: the tab is moved to the warning page with the result", async () => {
  const b = setup({ "https://bad.example": "Phishing" });
  const tab = b.openTab("https://bad.example/login?user=a");
  await settle();
  assert.equal(b.url(tab), WARNING);
  assert.equal(b.badge(tab), "HIGH");
  const reply = await b.message({ type: "warning:get" }, { tabId: tab });
  assert.equal(reply.ok, true);
  assert.equal(reply.warning.url, "https://bad.example/login?user=a");
  assert.equal(reply.warning.host, "bad.example");
  assert.equal(reply.warning.result.risk_level, "High");
  assert.equal(reply.warning.result.phishing_probability, 0.9);
});

// --- Go Back to Safety ------------------------------------------------------------------------------------
test("Go Back to Safety returns to the previous checked page", async () => {
  const b = setup({ "https://bad.example": "Phishing" });
  const tab = b.openTab("https://shop.example/cart");
  await settle();
  b.navigate(tab, "https://bad.example/");
  await settle();
  assert.equal(b.url(tab), WARNING);
  const reply = await b.message({ type: "warning:back" }, { tabId: tab });
  assert.deepEqual(reply, { ok: true, destination: "previous" });
  assert.equal(b.url(tab), "https://shop.example/cart");
  assert.equal(b.badge(tab), "LOW");
});

test("Go Back to Safety without a previous page goes to the local safe page", async () => {
  const b = setup({ "https://bad.example": "Phishing" });
  const tab = b.openTab("https://bad.example/");
  await settle();
  const reply = await b.message({ type: "warning:back" }, { tabId: tab });
  assert.equal(reply.destination, "fallback");
  assert.equal(b.url(tab), SAFE);
  assert.equal(b.requests.length, 1); // the extension page is not scanned
});

test("Go Back never returns to a page that was rated high-risk or not checked", async () => {
  const b = setup({ "https://bad.example": "Phishing", "https://bad2.example": "Phishing" });
  b.api = (body) => (body.url.startsWith("https://down.example") ? { reject: true }
    : byOrigin({ "https://bad.example": "Phishing", "https://bad2.example": "Phishing" })(body));
  const tab = b.openTab("https://down.example/");   // could not be checked -> not a safe target
  await settle();
  b.navigate(tab, "https://bad.example/");
  await settle();
  await b.message({ type: "warning:proceed" }, { tabId: tab });
  b.navigate(tab, "https://bad2.example/");          // the first flagged site is not a safe target either
  await settle();
  assert.equal(b.url(tab), WARNING);
  await b.message({ type: "warning:back" }, { tabId: tab });
  assert.equal(b.url(tab), SAFE);
});

// --- Continue Anyway -------------------------------------------------------------------------------------------
test("Continue Anyway opens the site once without a warning loop", async () => {
  const b = setup({ "https://bad.example": "Phishing" });
  const tab = b.openTab("https://bad.example/login");
  await settle();
  const reply = await b.message({ type: "warning:proceed" }, { tabId: tab });
  assert.deepEqual(reply, { ok: true });
  await settle();
  assert.equal(b.url(tab), "https://bad.example/login");
  assert.equal(b.badge(tab), "HIGH");                    // still shown as high risk
  assert.match(b.badges[tab].title, /Continue Anyway/);
  b.navigate(tab, "https://bad.example/login");          // reload
  b.pushState(tab, "https://bad.example/step2");          // SPA change on the same site
  await settle();
  assert.equal(b.url(tab), "https://bad.example/step2");
  assert.equal(b.requests.length, 1);                     // the score is reused, not lowered or re-requested
  const cache = b.session["scan-cache"]["https://bad.example"];
  assert.equal(cache.result.risk_level, "High");          // the decision did not change the stored result
});

test("Continue Anyway is revoked when the tab leaves the site", async () => {
  const b = setup({ "https://bad.example": "Phishing" });
  const tab = b.openTab("https://bad.example/");
  await settle();
  await b.message({ type: "warning:proceed" }, { tabId: tab });
  b.navigate(tab, "https://shop.example/");
  await settle();
  b.navigate(tab, "https://bad.example/");
  await settle();
  assert.equal(b.url(tab), WARNING);
});

test("Continue Anyway is tab-specific", async () => {
  const b = setup({ "https://bad.example": "Phishing" });
  const t1 = b.openTab("https://bad.example/");
  await settle();
  await b.message({ type: "warning:proceed" }, { tabId: t1 });
  const t2 = b.openTab("https://bad.example/");
  await settle();
  assert.equal(b.url(t1), "https://bad.example/");
  assert.equal(b.url(t2), WARNING);
});

test("Continue Anyway expires after BYPASS_TTL_MS at the next page load", async () => {
  const b = new Browser();
  b.api = byOrigin({ "https://bad.example": "Phishing" });
  b.startWorker({ configOverrides: { BYPASS_TTL_MS: 20 } });
  const tab = b.openTab("https://bad.example/");
  await settle();
  await b.message({ type: "warning:proceed" }, { tabId: tab });
  await new Promise((r) => setTimeout(r, 40));
  b.navigate(tab, "https://bad.example/");
  await settle();
  assert.equal(b.url(tab), WARNING);
});

test("Continue Anyway uses the stored URL, never one supplied in the message", async () => {
  const b = setup({ "https://bad.example": "Phishing" });
  const tab = b.openTab("https://bad.example/page");
  await settle();
  await b.message({ type: "warning:proceed", url: "https://attacker.example/" }, { tabId: tab });
  await settle();
  assert.equal(b.url(tab), "https://bad.example/page");
});

test("Continue Anyway without an active warning does nothing", async () => {
  const b = setup();
  const tab = b.openTab("https://shop.example/");
  await settle();
  const reply = await b.message({ type: "warning:proceed" }, { tabId: tab });
  assert.deepEqual(reply, { ok: false });
  assert.equal(b.url(tab), "https://shop.example/");
});

test("redirect chains: each new high-risk destination is warned about", async () => {
  const b = setup({ "https://bad.example": "Phishing", "https://bad2.example": "Phishing" });
  const tab = b.openTab("https://bad.example/");
  await settle();
  await b.message({ type: "warning:proceed" }, { tabId: tab });
  b.navigate(tab, "https://bad2.example/landing");   // the allowed site redirects elsewhere
  await settle();
  assert.equal(b.url(tab), WARNING);
  const reply = await b.message({ type: "warning:get" }, { tabId: tab });
  assert.equal(reply.warning.url, "https://bad2.example/landing");
});

// --- pages that are not checked ------------------------------------------------------------------------------
for (const url of ["chrome://settings/", "chrome-extension://otherextensionid/page.html", "file:///Users/me/a.html",
  "javascript:alert(1)", "data:text/html,<b>x</b>", "about:blank", "view-source:https://shop.example/",
  "ftp://files.example/", "", undefined]) {
  test(`unsupported page is not sent to the API: ${String(url)}`, async () => {
    const b = setup();
    const tab = b.openTab(null);
    b.navigate(tab, url);
    await settle();
    assert.equal(b.requests.length, 0);
    assert.notEqual(b.badge(tab), "LOW");
  });
}

test("the scanner's own web pages are not scanned", async () => {
  const b = setup();
  const tab = b.openTab(API + "/dashboard");
  await settle();
  assert.equal(b.requests.length, 0);
  assert.equal(b.badge(tab), "N/A");
});

test("hosts the API refuses (localhost, private) are shown as not checked, never as low risk", async () => {
  const b = setup();
  b.api = () => ({ status: 400, body: { success: false, error: { code: "UNSUPPORTED_HOST",
    message: "Local, private-network and internal host names cannot be scanned." } } });
  const tab = b.openTab("http://localhost:3000/");
  await settle();
  assert.equal(b.badge(tab), "N/A");
  const status = await b.message({ type: "status:get", tabId: tab }, { url: EXT_ORIGIN + "/popup.html" });
  assert.match(status.text, /not checked automatically/);
});

// --- failures: never "safe" ----------------------------------------------------------------------------------
const FAILURES = {
  "backend unavailable": { reject: true },
  "HTTP 500 JSON error": { status: 500, body: { success: false, error: { code: "PREDICTION_FAILED", message: "internal" } } },
  "non-JSON 502": { status: 502, raw: "<html>Bad gateway</html>" },
  "JSON array": { status: 200, raw: "[]" },
  "unknown prediction": { status: 200, body: { ...okBody("Safe"), prediction: "Benign" } },
  "risk level inconsistent with prediction": { status: 200, body: { ...okBody("Phishing"), risk_level: "Low" } },
  "success flag missing": { status: 200, body: { ...okBody("Safe"), success: undefined } },
  "prediction is not a string": { status: 200, body: { ...okBody("Safe"), prediction: ["Safe"] } },
};
for (const [name, reply] of Object.entries(FAILURES)) {
  test(`invalid or failed API response is "could not be checked": ${name}`, async () => {
    const b = setup();
    b.api = () => reply;
    const tab = b.openTab("https://shop.example/");
    await settle();
    assert.equal(b.badge(tab), "?");
    assert.match(b.badges[tab].title, /could NOT be checked/);
    assert.equal(b.url(tab), "https://shop.example/");                   // no redirect
    assert.equal(b.session["tab:" + tab].lastSafeUrl, undefined);       // not a safe target
    assert.equal((b.session["scan-cache"] || {})["https://shop.example"], undefined); // failures are not cached
    const status = await b.message({ type: "status:get", tabId: tab }, { url: EXT_ORIGIN + "/popup.html" });
    assert.match(status.text, /NOT checked/);
  });
}

test("timeout is reported as not checked, and the next navigation retries", async () => {
  const b = new Browser();
  b.api = () => ({ status: 200, body: okBody("Safe"), delay: 200 });
  b.startWorker({ configOverrides: { REQUEST_TIMEOUT_MS: 30 } });
  const tab = b.openTab("https://shop.example/");
  await new Promise((r) => setTimeout(r, 80));
  await settle();
  assert.equal(b.badge(tab), "?");
  assert.match(b.badges[tab].title, /did not respond/);
  b.api = () => ({ status: 200, body: okBody("Safe") });
  b.navigate(tab, "https://shop.example/");
  await settle();
  assert.equal(b.requests.length, 2);
  assert.equal(b.badge(tab), "LOW");
});

// --- stale responses and races ----------------------------------------------------------------------------------
test("a slow high-risk response for a page the tab already left is ignored", async () => {
  const b = setup();
  b.api = (body) => (body.url === "https://bad.example/" ? { status: 200, body: okBody("Phishing"), delay: 50 }
    : { status: 200, body: okBody("Safe") });
  const tab = b.openTab("https://bad.example/");
  await settle(5);
  b.navigate(tab, "https://shop.example/");
  await new Promise((r) => setTimeout(r, 100));
  await settle();
  assert.equal(b.url(tab), "https://shop.example/");   // not redirected to the warning page
  assert.equal(b.badge(tab), "LOW");                    // badge belongs to the current page
});

test("a slow response does not overwrite the badge of a newer page on the same tab", async () => {
  const b = setup();
  b.api = (body) => (body.url === "https://slow.example/" ? { status: 200, body: okBody("Suspicious"), delay: 50 }
    : { status: 200, body: okBody("Safe") });
  const tab = b.openTab("https://slow.example/");
  await settle(5);
  b.navigate(tab, "https://fast.example/");
  await new Promise((r) => setTimeout(r, 100));
  await settle();
  assert.equal(b.badge(tab), "LOW");
});

test("a closed tab is forgotten", async () => {
  const b = setup({ "https://bad.example": "Phishing" });
  const tab = b.openTab("https://bad.example/");
  await settle();
  b.closeTab(tab);
  await settle();
  assert.equal(b.session["tab:" + tab], undefined);
});

// --- service-worker restart -----------------------------------------------------------------------------------
test("warning, cache and Continue Anyway survive a service-worker restart", async () => {
  const b = setup({ "https://bad.example": "Phishing" });
  const tab = b.openTab("https://bad.example/x");
  await settle();
  b.startWorker({ onInstalled: false });            // Chrome stopped the idle worker and started a new one
  const reply = await b.message({ type: "warning:get" }, { tabId: tab });
  assert.equal(reply.warning.url, "https://bad.example/x");
  await b.message({ type: "warning:proceed" }, { tabId: tab });
  await settle();
  assert.equal(b.url(tab), "https://bad.example/x");
  b.startWorker({ onInstalled: false });
  b.navigate(tab, "https://bad.example/x");           // reload after another restart: still allowed once
  await settle();
  assert.equal(b.url(tab), "https://bad.example/x");
  assert.equal(b.requests.length, 1);                 // cached result reused across restarts
});

test("a response that arrives after a restart for a page the tab left is ignored", async () => {
  const b = setup();
  b.api = (body) => (body.url === "https://bad.example/" ? { status: 200, body: okBody("Phishing"), delay: 40 }
    : { status: 200, body: okBody("Safe") });
  const tab = b.openTab("https://bad.example/");
  await settle(5);
  const tabRecord = b.tabs.get(tab);
  tabRecord.url = "https://shop.example/";            // the tab moved on while the worker was being replaced
  await new Promise((r) => setTimeout(r, 80));
  await settle();
  assert.notEqual(b.url(tab), WARNING);
});

// --- enable / disable --------------------------------------------------------------------------------------
test("disabled: nothing is sent and the badge says OFF; the warning page still works", async () => {
  const b = setup({ "https://bad.example": "Phishing" });
  const tab = b.openTab("https://bad.example/");
  await settle();
  assert.equal(b.url(tab), WARNING);
  await b.worker.chrome.storage.local.set({ autoScan: false });
  await settle();
  assert.equal(b.globalBadge.text, "OFF");
  const other = b.openTab("https://bad2.example/");
  await settle();
  assert.equal(b.requests.length, 1);
  assert.equal(b.badge(other), "OFF");
  assert.equal(b.url(other), "https://bad2.example/");
  const reply = await b.message({ type: "warning:proceed" }, { tabId: tab }); // the user is never trapped
  assert.equal(reply.ok, true);
  await settle();
  assert.equal(b.url(tab), "https://bad.example/");
});

// --- message security ----------------------------------------------------------------------------------------
test("messages from other extensions or web pages are ignored", async () => {
  const b = setup({ "https://bad.example": "Phishing" });
  const tab = b.openTab("https://bad.example/");
  await settle();
  assert.equal(await b.message({ type: "warning:proceed" }, { tabId: tab, id: "otherextension" }), undefined);
  assert.equal(await b.message({ type: "warning:proceed" }, { tabId: tab, url: "https://bad.example/" }), undefined);
  assert.equal(await b.message({ type: "warning:unknown" }, { tabId: tab }), undefined);
  assert.equal(await b.message({ type: "warning:proceed" }, { tabId: undefined }), undefined);
  assert.equal(b.url(tab), WARNING);
});
