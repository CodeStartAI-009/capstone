/* Shared helpers for all pages: API client, safe DOM building, formatting.
 *
 * Security rules followed everywhere in the frontend:
 *  - API data and user input are only ever written with textContent / DOM APIs,
 *    never with innerHTML, so a scanned URL cannot inject markup or script.
 *  - A scanned URL is never used as a link target and is never opened.
 *  - All predictions come from POST /api/predict; no model logic runs here.
 */
(function () {
  "use strict";

  const DEFAULT_TIMEOUT_MS = 15000;
  const PREDICTIONS = ["Safe", "Suspicious", "Phishing"];

  class ApiError extends Error {
    constructor(message, code, status) {
      super(message);
      this.code = code;
      this.status = status;
    }
  }

  async function api(path, options) {
    const opts = options || {};
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), opts.timeoutMs || DEFAULT_TIMEOUT_MS);
    const init = { method: opts.method || "GET", signal: controller.signal, credentials: "same-origin", headers: {} };
    if (opts.body !== undefined) {
      init.headers["Content-Type"] = "application/json";
      init.body = JSON.stringify(opts.body);
    }
    let response;
    try {
      response = await fetch(path, init);
    } catch (err) {
      if (controller.signal.aborted) {
        throw new ApiError("The server took too long to respond. Please try again.", "TIMEOUT", 0);
      }
      showOffline(true, NETWORK_MESSAGE, "network");
      throw new ApiError("The detection service is unavailable. Check that the Flask server is running, then try again.",
        "NETWORK", 0);
    } finally {
      clearTimeout(timer);
    }
    clearOffline("network");  // the server answered, so a network banner is out of date
    let data;
    try {
      data = await response.json();
    } catch (err) {
      throw new ApiError("The server returned an unexpected response (HTTP " + response.status + ").", "BAD_RESPONSE",
        response.status);
    }
    if (data === null || typeof data !== "object" || Array.isArray(data)) {
      throw new ApiError("The server returned an unexpected response.", "BAD_RESPONSE", response.status);
    }
    if (!response.ok || data.success === false) {
      const err = data.error;
      const message = err && typeof err.message === "string" ? err.message
        : "The request failed (HTTP " + response.status + ").";
      const code = (err && typeof err.code === "string" && err.code) || "HTTP_" + response.status;
      if (code === "MODEL_UNAVAILABLE") showOffline(true, MODEL_MESSAGE, "model");
      throw new ApiError(message, code, response.status);
    }
    return data;
  }

  const NETWORK_MESSAGE = "The detection service is currently unavailable. Please try again later.";
  const MODEL_MESSAGE = "The phishing model is not loaded on the server, so URLs cannot be scanned right now.";

  /* The banner remembers why it is shown ("network" or "model") so that one cause
   * does not hide a banner raised by the other. */
  function showOffline(offline, message, reason) {
    const banner = document.getElementById("offline-banner");
    if (!banner) return;
    if (!offline) {
      banner.hidden = true;
      return;
    }
    document.getElementById("offline-message").textContent = message || NETWORK_MESSAGE;
    banner.dataset.reason = reason || "network";
    banner.hidden = false;
  }

  function clearOffline(reason) {
    const banner = document.getElementById("offline-banner");
    if (banner && !banner.hidden && banner.dataset.reason === reason) banner.hidden = true;
  }

  /* Create an element. `text` is always set with textContent. */
  function el(tag, text, className) {
    const node = document.createElement(tag);
    if (text !== undefined && text !== null) node.textContent = String(text);
    if (className) node.className = className;
    return node;
  }

  function predictionClass(prediction) {
    return PREDICTIONS.indexOf(prediction) >= 0 ? prediction.toLowerCase() : "unknown";
  }

  function formatPercent(value, digits) {
    return typeof value === "number" && isFinite(value) ? (value * 100).toFixed(digits === undefined ? 1 : digits) + "%"
      : "not available";
  }

  function formatDate(iso) {
    if (typeof iso !== "string") return "–";
    const date = new Date(iso);
    return isNaN(date.getTime()) ? iso : date.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
  }

  function formatNumber(value) {
    if (typeof value !== "number") return String(value);
    return Number.isInteger(value) ? String(value) : value.toFixed(4).replace(/0+$/, "").replace(/\.$/, "");
  }

  let modelInfoPromise = null;
  function modelInfo() {
    if (!modelInfoPromise) {
      modelInfoPromise = api("/api/model-info").catch((err) => {
        modelInfoPromise = null;
        throw err;
      });
    }
    return modelInfoPromise;
  }

  /* Fill every [data-metric="recall"] etc. with the real value from /api/model-info. */
  function fillModelFacts(info) {
    document.querySelectorAll("[data-metric]").forEach((node) => {
      const value = info.evaluation && info.evaluation[node.getAttribute("data-metric")];
      node.textContent = formatPercent(value);
    });
    document.querySelectorAll("[data-model]").forEach((node) => {
      const value = info[node.getAttribute("data-model")];
      node.textContent = value ? String(value) : "not available";
    });
  }

  async function checkHealth() {
    try {
      const health = await api("/api/health", { timeoutMs: 5000 });
      if (health.model_loaded === false) showOffline(true, MODEL_MESSAGE, "model");
    } catch (err) {
      /* api() already showed the banner for network errors */
    }
  }

  window.PhishApp = {
    api, ApiError, el, predictionClass, formatPercent, formatDate, formatNumber, modelInfo, fillModelFacts,
    showOffline, PREDICTIONS,
  };

  document.addEventListener("DOMContentLoaded", () => {
    checkHealth();
    if (document.querySelector("[data-metric], [data-model]")) {
      modelInfo().then(fillModelFacts).catch(() => {
        document.querySelectorAll("[data-metric], [data-model]").forEach((n) => { n.textContent = "not available"; });
      });
    }
  });
})();
