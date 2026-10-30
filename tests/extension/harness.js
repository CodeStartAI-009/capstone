/* SIMULATED test harness for extension/background.js (no browser).
 *
 * Loads the real extension/config.js, scan-core.js and background.js into a Node `vm` context with a
 * fake `chrome` API and a fake `fetch`. The fake follows the documented behaviour of the Chrome APIs the
 * worker uses (tabs, storage.local/session, action, runtime messaging), so it can test races, stale
 * responses and service-worker restarts deterministically. Real-browser behaviour is covered separately
 * by tests/browser/test_extension_autoscan.py.
 */
"use strict";

const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const EXT_DIR = path.resolve(__dirname, "..", "..", "extension");
const EXT_ID = "abcdefghijklmnopabcdefghijklmnop";
const EXT_ORIGIN = "chrome-extension://" + EXT_ID;
const API = "http://127.0.0.1:5000";

const tick = () => new Promise((resolve) => setImmediate(resolve));
async function settle(rounds = 30) {
  for (let i = 0; i < rounds; i++) await tick();
}

function event() {
  const listeners = [];
  return {
    listeners,
    addListener: (fn) => listeners.push(fn),
    fire: (...args) => listeners.map((fn) => fn(...args)),
  };
}

function storageArea(data, onChanged, areaName) {
  return {
    data,
    async get(keys) {
      if (keys === null || keys === undefined) return structuredClone(data);
      if (typeof keys === "string") return keys in data ? { [keys]: structuredClone(data[keys]) } : {};
      if (Array.isArray(keys)) return Object.fromEntries(keys.filter((k) => k in data).map((k) => [k, structuredClone(data[k])]));
      return Object.fromEntries(Object.entries(keys).map(([k, d]) => [k, k in data ? structuredClone(data[k]) : d]));
    },
    async set(items) {
      const changes = {};
      for (const [k, v] of Object.entries(items)) {
        changes[k] = { oldValue: data[k], newValue: structuredClone(v) };
        data[k] = structuredClone(v);
      }
      onChanged.fire(changes, areaName);
    },
    async remove(keys) {
      for (const k of [].concat(keys)) delete data[k];
    },
    async clear() {
      for (const k of Object.keys(data)) delete data[k];
    },
  };
}

/* The browser: tabs, storage and badges outlive a worker restart; the worker's memory does not. */
class Browser {
  constructor() {
    this.tabs = new Map();
    this.nextTabId = 1;
    this.local = {};
    this.session = {};
    this.badges = {};       // tabId -> {text, color, title}
    this.globalBadge = {};
    this.requests = [];     // fetch calls: {url, body, init}
    this.api = () => ({ status: 200, body: okBody("Safe") }); // (body) -> {status, body, delay, raw, reject}
    this.timeoutMs = null;
    this.worker = null;
  }

  openTab(url, { active = true } = {}) {
    const id = this.nextTabId++;
    if (active) for (const t of this.tabs.values()) t.active = false;
    this.tabs.set(id, { id, url: "about:blank", active, windowId: 1 });
    if (url) this.navigate(id, url);
    return id;
  }

  /* Simulate a committed navigation: Chrome updates tab.url and fires onUpdated (loading + url, then complete). */
  navigate(tabId, url) {
    const tab = this.tabs.get(tabId);
    if (!tab) return;
    tab.url = url;
    tab.pendingUrl = undefined;
    if (this.worker) {
      this.worker.chrome.tabs.onUpdated.fire(tabId, { status: "loading", url }, { ...tab });
      this.worker.chrome.tabs.onUpdated.fire(tabId, { status: "complete" }, { ...tab });
    }
  }

  /* history.pushState in a single-page app: only the URL changes. */
  pushState(tabId, url) {
    const tab = this.tabs.get(tabId);
    tab.url = url;
    this.worker.chrome.tabs.onUpdated.fire(tabId, { url }, { ...tab });
  }

  activate(tabId) {
    for (const t of this.tabs.values()) t.active = t.id === tabId;
    this.worker.chrome.tabs.onActivated.fire({ tabId, windowId: 1 });
  }

  closeTab(tabId) {
    this.tabs.delete(tabId);
    this.worker.chrome.tabs.onRemoved.fire(tabId, { windowId: 1, isWindowClosing: false });
  }

  url(tabId) {
    return this.tabs.get(tabId).url;
  }

  badge(tabId) {
    return (this.badges[tabId] || {}).text;
  }

  /* Start (or restart) the service worker: a fresh JS context over the same browser state. */
  startWorker({ onInstalled = true, configOverrides = {} } = {}) {
    const browser = this;
    const sessionChanged = event();
    const chrome = {
      runtime: {
        id: EXT_ID,
        getURL: (p) => EXT_ORIGIN + "/" + p,
        onMessage: event(),
        onInstalled: event(),
        onStartup: event(),
      },
      storage: {
        onChanged: sessionChanged,
      },
      tabs: {
        onUpdated: event(),
        onActivated: event(),
        onRemoved: event(),
        onReplaced: event(),
        async get(id) {
          const tab = browser.tabs.get(id);
          if (!tab) throw new Error("No tab with id: " + id + ".");
          return { ...tab };
        },
        async query() {
          return [...browser.tabs.values()].map((t) => ({ ...t }));
        },
        async update(id, props) {
          if (!browser.tabs.has(id)) throw new Error("No tab with id: " + id + ".");
          setImmediate(() => browser.navigate(id, props.url));
          return { ...browser.tabs.get(id) };
        },
      },
      action: {
        async setBadgeText({ tabId, text }) {
          if (tabId === undefined) browser.globalBadge.text = text;
          else (browser.badges[tabId] = browser.badges[tabId] || {}).text = text;
        },
        async setBadgeBackgroundColor({ tabId, color }) {
          if (tabId !== undefined) (browser.badges[tabId] = browser.badges[tabId] || {}).color = color;
        },
        async setTitle({ tabId, title }) {
          if (tabId !== undefined) (browser.badges[tabId] = browser.badges[tabId] || {}).title = title;
        },
      },
    };
    chrome.storage.local = storageArea(this.local, sessionChanged, "local");
    chrome.storage.session = storageArea(this.session, sessionChanged, "session");

    async function fetch(url, init) {
      const body = JSON.parse(init.body);
      browser.requests.push({ url, body, init });
      const reply = browser.api(body) || {};
      if (reply.delay) {
        await new Promise((resolve, reject) => {
          const timer = setTimeout(resolve, reply.delay);
          init.signal.addEventListener("abort", () => {
            clearTimeout(timer);
            reject(new DOMException("The operation was aborted.", "AbortError"));
          });
        });
      }
      if (reply.reject) throw new TypeError("Failed to fetch");
      const text = reply.raw !== undefined ? reply.raw : JSON.stringify(reply.body);
      return {
        ok: (reply.status || 200) < 400,
        status: reply.status || 200,
        json: async () => JSON.parse(text),
      };
    }

    const context = vm.createContext({
      chrome, fetch, console: { warn() {}, log() {}, error() {} },
      setTimeout, clearTimeout, AbortController, URL, DOMException, structuredClone,
    });
    context.self = context;
    context.importScripts = (...names) => {
      for (const name of names) {
        let code = fs.readFileSync(path.join(EXT_DIR, name), "utf8");
        if (name === "config.js") {
          for (const [key, value] of Object.entries(configOverrides)) {
            code = code.replace(new RegExp("const " + key + " = [^;]+;"), "const " + key + " = " + JSON.stringify(value) + ";");
          }
        }
        vm.runInContext(code, context, { filename: name });
      }
    };
    vm.runInContext(fs.readFileSync(path.join(EXT_DIR, "background.js"), "utf8"), context, { filename: "background.js" });
    this.worker = { chrome, context };
    if (onInstalled) chrome.runtime.onInstalled.fire({ reason: "install" });
    return this.worker;
  }

  /* Send a runtime message as the given extension page (default: the warning page in `tabId`). */
  async message(msg, { tabId, url = EXT_ORIGIN + "/warning.html", id = EXT_ID } = {}) {
    const sender = { id, url, tab: tabId === undefined ? undefined : { ...this.tabs.get(tabId) } };
    let response;
    let handled = false;
    const done = new Promise((resolve) => {
      const results = this.worker.chrome.runtime.onMessage.fire(msg, sender, (r) => {
        response = r === undefined ? r : JSON.parse(JSON.stringify(r)); // copy out of the worker's JS realm
        resolve();
      });
      handled = results.some((r) => r === true);
      if (!handled) resolve();
    });
    await done;
    await settle();
    return handled ? response : undefined;
  }
}

function okBody(prediction, extra = {}) {
  const risk = { Safe: "Low", Suspicious: "Medium", Phishing: "High" }[prediction];
  const p = { Safe: 0.1, Suspicious: 0.55, Phishing: 0.9 }[prediction];
  return {
    success: true, url: "https://x.example/", prediction, risk_level: risk, confidence: p >= 0.52 ? p : 1 - p,
    phishing_probability: p, model_input: "https://www.x.example", model_version: "2.0.0",
    verdict: { Safe: "Low-risk prediction", Suspicious: "Phishing-risk prediction (moderate)",
      Phishing: "Phishing-risk prediction (high)" }[prediction],
    summary: "summary", disclaimer: "disclaimer",
    explanations: [{ source: "model_feature", severity: "risk", feature: "DomainLength", message: "long domain" }],
    explanation: ["long domain"],
    ...extra,
  };
}

module.exports = { Browser, okBody, settle, EXT_ORIGIN, API };
