/* URL scanner (/ and /inspect): POST /api/predict and render the result.
 * /inspect?id=N shows a saved scan from GET /api/history/N instead.
 * All text is written with textContent (see main.js).
 */
(function () {
  "use strict";
  const A = window.PhishApp;
  const $ = (id) => document.getElementById(id);
  const FIELD_ERRORS = ["MISSING_URL", "INVALID_URL", "UNSUPPORTED_SCHEME", "UNSUPPORTED_HOST", "URL_TOO_LONG",
    "INVALID_TYPE"];
  const ERROR_TITLES = {
    NETWORK: "Service unavailable",
    TIMEOUT: "Request timed out",
    BAD_RESPONSE: "Unexpected response",
    RATE_LIMITED: "Too many requests",
    MODEL_UNAVAILABLE: "Model not available",
    FEATURE_EXTRACTION_FAILED: "URL could not be analysed",
    SCAN_NOT_FOUND: "Scan not found",
    INVALID_ID: "Invalid scan id",
    HISTORY_UNAVAILABLE: "History unavailable",
  };
  let inFlight = false;
  let featureSchema = null;

  function show(state) {
    ["idle", "loading", "error", "result"].forEach((name) => {
      const node = $("state-" + name);
      if (node) node.hidden = name !== state;
    });
  }

  function setFieldError(message) {
    const box = $("url-error");
    box.textContent = message || "";
    box.hidden = !message;
    $("url-input").setAttribute("aria-invalid", message ? "true" : "false");
  }

  function showError(err) {
    if (FIELD_ERRORS.indexOf(err.code) >= 0) {
      setFieldError(err.message);
      show("idle");
      return;
    }
    $("error-title").textContent = ERROR_TITLES[err.code] || "Scan failed";
    $("error-message").textContent = err.message || "Something went wrong. Please try again.";
    show("error");
  }

  function renderMeter(p, thresholds) {
    const meter = $("meter");
    if (typeof p !== "number" || !thresholds || typeof thresholds.flag !== "number") {
      meter.parentElement.hidden = true;
      return;
    }
    meter.parentElement.hidden = false;
    const flag = thresholds.flag;
    const high = typeof thresholds.high_confidence_phishing === "number" ? thresholds.high_confidence_phishing : 1;
    $("band-safe").style.width = (flag * 100) + "%";
    $("band-suspicious").style.width = ((high - flag) * 100) + "%";
    $("band-phishing").style.width = ((1 - high) * 100) + "%";
    $("meter-marker").style.left = (Math.min(Math.max(p, 0), 1) * 100) + "%";
    const caption = "Model phishing score " + p.toFixed(2) + " (decision threshold " + flag.toFixed(2) +
      ", high-confidence level " + high.toFixed(2) + ").";
    meter.setAttribute("aria-label", caption);
    $("meter-caption").textContent = caption;
  }

  function renderExplanations(items) {
    const list = $("explanations");
    list.replaceChildren();
    (items || []).forEach((item) => {
      const severity = ["risk", "caution", "info"].indexOf(item.severity) >= 0 ? item.severity : "info";
      const li = A.el("li", null, severity);
      li.appendChild(A.el("span", item.source === "observation" ? "observation" : "model feature", "tag"));
      li.appendChild(A.el("span", item.message));
      list.appendChild(li);
    });
    if (!list.children.length) list.appendChild(A.el("li", "No explanation items were produced.", "info"));
  }

  async function renderFeatures(features) {
    const body = $("feature-rows");
    if (!body) return;
    body.replaceChildren();
    if (!features) {
      body.appendChild(rowOf(["Feature values are not available for this scan."], 4));
      return;
    }
    if (!featureSchema) {
      try {
        featureSchema = (await A.api("/api/features")).features;
      } catch (err) {
        featureSchema = [];
      }
    }
    const meaning = {};
    featureSchema.forEach((f) => { meaning[f.name] = f.description; });
    Object.keys(features).forEach((name, i) => {
      const tr = document.createElement("tr");
      tr.appendChild(A.el("td", i + 1));
      tr.appendChild(A.el("td", name, "mono"));
      tr.appendChild(A.el("td", A.formatNumber(features[name]), "mono"));
      tr.appendChild(A.el("td", meaning[name] || ""));
      body.appendChild(tr);
    });
  }

  function rowOf(cells, colspan) {
    const tr = document.createElement("tr");
    cells.forEach((text) => {
      const td = A.el("td", text, "muted");
      if (colspan) td.colSpan = colspan;
      tr.appendChild(td);
    });
    return tr;
  }

  /* view: {url, prediction, risk_level, confidence, phishing_probability, scanned_at, model_version, verdict,
   *        summary, explanations, features, model_input, origin, history} */
  async function render(view) {
    let info = null;
    try {
      info = await A.modelInfo();
    } catch (err) {
      info = null;
    }
    const cls = A.predictionClass(view.prediction);
    $("verdict").className = "verdict " + cls;
    const verdicts = (info && info.verdicts) || {};
    $("verdict-text").textContent = view.verdict || verdicts[view.prediction] || view.prediction;
    $("prediction").textContent = view.prediction;
    $("risk-level").textContent = view.risk_level;
    $("confidence").textContent = A.formatPercent(view.confidence);
    $("scanned-at").textContent = A.formatDate(view.scanned_at);
    $("result-url").textContent = view.url;
    $("result-origin").textContent = view.origin || "";
    const summary = $("verdict-summary");
    summary.textContent = view.summary || "";
    summary.hidden = !view.summary;
    if (info && info.disclaimer) $("result-disclaimer").textContent = info.disclaimer;
    renderMeter(view.phishing_probability, info && info.thresholds);
    renderExplanations(view.explanations);

    const note = $("history-note");
    const link = $("details-link");
    if (link) link.hidden = true;
    note.hidden = true;
    if (view.history) {
      if (view.history.saved && Number.isInteger(view.history.id)) {
        note.textContent = "Saved to scan history.";
        note.hidden = false;
        if (link) {
          link.href = "/inspect?id=" + encodeURIComponent(view.history.id);
          link.hidden = false;
        }
      } else if (view.history.reason !== "not requested") {
        note.textContent = "This result could not be saved to the scan history.";
        note.hidden = false;
      }
    }
    if ($("model-input")) {
      $("model-input").textContent = view.model_input || "not available";
      $("model-version").textContent = view.model_version || "unknown";
    }
    await renderFeatures(view.features);
    show("result");
  }

  async function scan(event) {
    event.preventDefault();
    if (inFlight) return;
    const input = $("url-input");
    const url = input.value.trim();
    setFieldError("");
    if (!url) {
      setFieldError("Please enter a URL to scan.");
      input.focus();
      return;
    }
    inFlight = true;
    $("scan-button").disabled = true;
    input.readOnly = true;
    show("loading");
    try {
      const data = await A.api("/api/predict", { method: "POST", body: { url: url, source: "web" } });
      if (typeof data.prediction !== "string" || typeof data.url !== "string") {
        throw new A.ApiError("The server returned an unexpected response.", "BAD_RESPONSE", 200);
      }
      await render(Object.assign({}, data, { origin: "" }));
      loadRecent();
    } catch (err) {
      showError(err instanceof A.ApiError ? err : new A.ApiError("Something went wrong. Please try again.", "", 0));
    } finally {
      inFlight = false;
      $("scan-button").disabled = false;
      input.readOnly = false;
    }
  }

  async function loadSavedScan(rawId) {
    if (!/^[1-9][0-9]{0,17}$/.test(rawId)) {
      showError(new A.ApiError("The scan id in the address is not valid.", "INVALID_ID", 400));
      return;
    }
    show("loading");
    try {
      const item = (await A.api("/api/history/" + rawId)).item;
      await render({
        url: item.url, prediction: item.prediction, risk_level: item.risk_level, confidence: item.confidence,
        phishing_probability: item.phishing_probability, scanned_at: item.scanned_at,
        model_version: item.model_version, features: item.features,
        model_input: item.host ? "the registrable domain of " + item.host : null,
        explanations: (item.indicators || []).map((i) => ({ severity: i.severity, source: i.source, message: i.message })),
        origin: "(saved scan #" + item.id + ", " + item.source + ")",
      });
    } catch (err) {
      showError(err);
    }
  }

  async function loadRecent() {
    const body = $("recent-rows");
    if (!body) return;
    try {
      const data = await A.api("/api/history?page=1&limit=5");
      body.replaceChildren();
      if (!data.items.length) {
        body.appendChild(rowOf(["No scans yet."], 4));
        return;
      }
      data.items.forEach((item) => {
        const tr = document.createElement("tr");
        tr.appendChild(A.el("td", A.formatDate(item.scanned_at), "nowrap"));
        const urlCell = A.el("td", null, "url-cell");
        const code = A.el("code", item.url);
        code.title = item.url;
        urlCell.appendChild(code);
        tr.appendChild(urlCell);
        const pred = A.el("td");
        pred.appendChild(A.el("span", item.prediction, "pill " + A.predictionClass(item.prediction)));
        tr.appendChild(pred);
        tr.appendChild(A.el("td", A.formatPercent(item.confidence)));
        body.appendChild(tr);
      });
    } catch (err) {
      body.replaceChildren(rowOf([err.code === "HISTORY_UNAVAILABLE" ? "Scan history is temporarily unavailable."
        : "Recent scans could not be loaded."], 4));
    }
  }

  async function loadModelSection() {
    if (!$("eval-rows")) return;
    try {
      const info = await A.modelInfo();
      const ev = info.evaluation || {};
      $("eval-caption").textContent = info.model + " version " + info.version + ", evaluated once on " +
        (ev.rows || "?") + " held-out URLs at threshold " + (typeof ev.threshold === "number" ? ev.threshold.toFixed(4) : "?") +
        ". Phishing is the positive class.";
      const rows = [["Accuracy", ev.accuracy], ["Precision", ev.precision], ["Recall (phishing detected)", ev.recall],
        ["F1", ev.f1], ["ROC-AUC", ev.roc_auc], ["False-positive rate", ev.false_positive_rate]];
      const body = $("eval-rows");
      body.replaceChildren();
      rows.forEach(([label, value]) => {
        const tr = document.createElement("tr");
        tr.appendChild(A.el("th", label));
        tr.lastChild.scope = "row";
        tr.appendChild(A.el("td", typeof value === "number" ? value.toFixed(4) : "not available", "mono"));
        body.appendChild(tr);
      });
      const cm = ev.confusion_matrix || {};
      const cbody = $("confusion-rows");
      cbody.replaceChildren();
      [["Actually legitimate", cm.legitimate_correct_TN, cm.legitimate_flagged_FP],
        ["Actually phishing", cm.phishing_missed_FN, cm.phishing_caught_TP]].forEach(([label, a, b]) => {
        const tr = document.createElement("tr");
        const th = A.el("th", label);
        th.scope = "row";
        tr.appendChild(th);
        tr.appendChild(A.el("td", a === undefined ? "–" : a.toLocaleString(), "mono"));
        tr.appendChild(A.el("td", b === undefined ? "–" : b.toLocaleString(), "mono"));
        cbody.appendChild(tr);
      });
      const t = info.thresholds || {};
      if (typeof t.flag === "number" && typeof t.high_confidence_phishing === "number") {
        $("threshold-values").textContent = "Thresholds on the model's phishing score: decision " + t.flag.toFixed(4) +
          ", high-confidence " + t.high_confidence_phishing.toFixed(4) + " (both chosen on validation data only).";
      }
    } catch (err) {
      $("eval-caption").textContent = "Model information is not available: " + err.message;
      $("eval-rows").replaceChildren(rowOf(["not available"]));
      $("confusion-rows").replaceChildren(rowOf(["not available"], 3));
    }
    try {
      const schema = await A.api("/api/features");
      $("features-caption").textContent = schema.feature_count + " features (schema " + schema.schema_version +
        "), computed from the model input https://www.<registrable domain>, in this order:";
      const body = $("schema-rows");
      body.replaceChildren();
      schema.features.forEach((f, i) => {
        const tr = document.createElement("tr");
        tr.appendChild(A.el("td", i + 1));
        tr.appendChild(A.el("td", f.name, "mono"));
        tr.appendChild(A.el("td", f.type));
        tr.appendChild(A.el("td", f.description));
        body.appendChild(tr);
      });
    } catch (err) {
      $("features-caption").textContent = "The feature schema could not be loaded.";
      $("schema-rows").replaceChildren(rowOf(["not available"], 4));
    }
  }

  document.addEventListener("DOMContentLoaded", () => {
    $("scan-form").addEventListener("submit", scan);
    $("url-input").addEventListener("input", () => setFieldError(""));
    const id = new URLSearchParams(window.location.search).get("id");
    if (id !== null && $("feature-rows")) loadSavedScan(id);
    loadRecent();
    loadModelSection();
  });
})();
