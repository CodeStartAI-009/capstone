/* Dashboard: statistics, charts and scan history from GET /api/stats and GET /api/history.
 * Every number shown is taken from those responses; days without scans are shown as zero.
 */
(function () {
  "use strict";
  const A = window.PhishApp;
  const $ = (id) => document.getElementById(id);
  const SVG_NS = "http://www.w3.org/2000/svg";
  const LABELS = { Safe: "Low-risk", Suspicious: "Phishing-risk (moderate)", Phishing: "Phishing-risk (high)" };
  const PAGE_SIZE = 10;
  const state = { page: 1, pages: 0, prediction: "", q: "" };

  function svg(tag, attrs, text) {
    const node = document.createElementNS(SVG_NS, tag);
    Object.keys(attrs || {}).forEach((k) => node.setAttribute(k, String(attrs[k])));
    if (text !== undefined) node.textContent = String(text);
    return node;
  }

  function emptyChart(container, message) {
    container.replaceChildren(A.el("p", message, "muted chart-empty"));
  }

  function distributionChart(container, counts, total) {
    if (!total) return emptyChart(container, "No scans yet.");
    const list = A.el("ul", null, "dist-list");
    A.PREDICTIONS.forEach((p) => {
      const n = counts[p] || 0;
      const pct = Math.round((n / total) * 100);
      const row = A.el("li", null, "dist-row");
      row.appendChild(A.el("span", LABELS[p] + " (" + p + ")"));
      row.appendChild(A.el("span", n + " (" + pct + "%)", "dist-value"));
      const track = A.el("div", null, "dist-track");
      track.setAttribute("aria-hidden", "true");
      const bar = A.el("div", null, "dist-bar " + p.toLowerCase());
      bar.style.width = (n / total) * 100 + "%";
      track.appendChild(bar);
      row.appendChild(track);
      list.appendChild(row);
    });
    container.replaceChildren(list);
  }

  function activityChart(container, daily, days) {
    const byDate = {};
    (daily || []).forEach((d) => { byDate[d.date] = d; });
    const series = [];
    const today = new Date();
    for (let i = days - 1; i >= 0; i--) {
      const d = new Date(Date.UTC(today.getUTCFullYear(), today.getUTCMonth(), today.getUTCDate() - i));
      const key = d.toISOString().slice(0, 10);
      const row = byDate[key] || {};
      series.push({ date: key, Safe: row.Safe || 0, Suspicious: row.Suspicious || 0, Phishing: row.Phishing || 0 });
    }
    const totals = series.map((d) => d.Safe + d.Suspicious + d.Phishing);
    const sum = totals.reduce((a, b) => a + b, 0);
    if (!sum) return emptyChart(container, "No scans in the last " + days + " days.");
    const width = 320, height = 140, pad = 20, max = Math.max.apply(null, totals);
    const colW = (width - pad) / days;
    const chart = svg("svg", { viewBox: "0 0 " + width + " " + (height + 22), role: "img", class: "chart-svg",
      "aria-label": sum + " scans in the last " + days + " days; busiest day " + max + " scans." });
    chart.appendChild(svg("text", { x: 0, y: 12, class: "chart-value" }, max));
    chart.appendChild(svg("line", { x1: pad, y1: height, x2: width, y2: height, class: "axis" }));
    series.forEach((d, i) => {
      let y = height;
      A.PREDICTIONS.forEach((p) => {
        if (!d[p]) return;
        const h = (d[p] / max) * (height - 16);
        y -= h;
        const rect = svg("rect", { x: pad + i * colW + 1, y: y, width: Math.max(colW - 2, 1), height: h,
          class: "bar " + p.toLowerCase() });
        rect.appendChild(svg("title", {}, d.date + ": " + d[p] + " " + LABELS[p]));
        chart.appendChild(rect);
      });
    });
    chart.appendChild(svg("text", { x: pad, y: height + 16, class: "chart-label" }, series[0].date));
    chart.appendChild(svg("text", { x: width, y: height + 16, class: "chart-label", "text-anchor": "end" },
      series[series.length - 1].date));
    container.replaceChildren(chart);
  }

  async function loadStats() {
    const box = $("stats-error");
    try {
      const s = await A.api("/api/stats?days=30");
      box.hidden = true;
      const p = s.by_prediction || {};
      const risky = (p.Suspicious || 0) + (p.Phishing || 0);
      $("stat-total").textContent = s.total;
      $("stat-risk").textContent = risky;
      $("stat-risk-split").textContent = (p.Phishing || 0) + " high, " + (p.Suspicious || 0) + " moderate";
      $("stat-low").textContent = p.Safe || 0;
      $("stat-last").textContent = s.last_scan_at ? A.formatDate(s.last_scan_at) : "No scans yet";
      const src = s.by_source || {};
      $("stat-sources").textContent = "web " + (src.web || 0) + " · extension " + (src.extension || 0) + " · API " +
        (src.api || 0);
      distributionChart($("chart-distribution"), p, s.total);
      activityChart($("chart-activity"), s.daily, s.daily_window_days || 30);
    } catch (err) {
      box.textContent = err.code === "HISTORY_UNAVAILABLE" ? "Statistics are unavailable because the scan history " +
        "database cannot be read right now." : "Statistics could not be loaded: " + err.message;
      box.hidden = false;
      ["stat-total", "stat-risk", "stat-low", "stat-last"].forEach((id) => { $(id).textContent = "–"; });
      emptyChart($("chart-distribution"), "Not available.");
      emptyChart($("chart-activity"), "Not available.");
    }
  }

  function messageRow(text) {
    const tr = document.createElement("tr");
    const td = A.el("td", text, "muted");
    td.colSpan = 7;
    tr.appendChild(td);
    return tr;
  }

  function historyRow(item) {
    const tr = document.createElement("tr");
    tr.appendChild(A.el("td", A.formatDate(item.scanned_at), "nowrap"));
    const urlCell = A.el("td", null, "url-cell");
    const code = A.el("code", item.url);
    code.title = item.url;  // full URL on hover; the cell truncates visually
    urlCell.appendChild(code);
    tr.appendChild(urlCell);
    const pred = A.el("td");
    pred.appendChild(A.el("span", item.prediction, "pill " + A.predictionClass(item.prediction)));
    tr.appendChild(pred);
    tr.appendChild(A.el("td", item.risk_level));
    tr.appendChild(A.el("td", A.formatPercent(item.confidence)));
    tr.appendChild(A.el("td", item.source));
    const actions = A.el("td", null, "actions");
    const view = A.el("a", "View", "button-link small");
    view.href = "/inspect?id=" + encodeURIComponent(item.id);
    view.setAttribute("aria-label", "View scan " + item.id);
    const del = A.el("button", "Delete", "secondary small");
    del.type = "button";
    del.setAttribute("aria-label", "Delete scan " + item.id);
    del.addEventListener("click", () => deleteScan(item.id, del));
    actions.append(view, del);
    tr.appendChild(actions);
    return tr;
  }

  async function loadHistory() {
    const body = $("history-rows");
    const msg = $("history-message");
    const params = new URLSearchParams({ page: state.page, limit: PAGE_SIZE });
    if (state.prediction) params.set("prediction", state.prediction);
    if (state.q) params.set("q", state.q);
    try {
      const data = await A.api("/api/history?" + params.toString());
      if (!Array.isArray(data.items)) throw new A.ApiError("The server returned an unexpected response.", "BAD_RESPONSE", 200);
      msg.hidden = true;
      if (data.items.length === 0 && state.page > 1 && data.total > 0) {  // page emptied by a delete
        state.page = Math.max(1, data.pages);
        return loadHistory();
      }
      state.pages = data.pages;
      body.replaceChildren();
      if (!data.items.length) {
        body.appendChild(messageRow(state.q || state.prediction ? "No scans match the current filter." : "No scans yet."));
      } else {
        data.items.forEach((item) => body.appendChild(historyRow(item)));
      }
      $("page-info").textContent = data.total ? "Page " + data.page + " of " + data.pages + " · " + data.total + " scans" : "";
    } catch (err) {
      state.pages = 0;
      body.replaceChildren(messageRow("History not available."));
      msg.textContent = err.code === "HISTORY_UNAVAILABLE" ? "Scan history is temporarily unavailable." :
        "Scan history could not be loaded: " + err.message;
      msg.hidden = false;
      $("page-info").textContent = "";
    }
    $("prev-page").disabled = state.page <= 1;
    $("next-page").disabled = state.page >= state.pages;
  }

  async function deleteScan(id, button) {
    if (!window.confirm("Delete this scan from the history?")) return;
    button.disabled = true;
    try {
      await A.api("/api/history/" + encodeURIComponent(id), { method: "DELETE" });
    } catch (err) {
      $("history-message").textContent = "The scan could not be deleted: " + err.message;
      $("history-message").hidden = false;
      button.disabled = false;
      return;
    }
    await Promise.all([loadHistory(), loadStats()]);
  }

  async function clearHistory() {
    if (!window.confirm("Delete ALL scans from the history? This cannot be undone.")) return;
    const button = $("clear-button");
    button.disabled = true;
    try {
      await A.api("/api/history", { method: "DELETE" });
      state.page = 1;
    } catch (err) {
      $("history-message").textContent = "The history could not be cleared: " + err.message;
      $("history-message").hidden = false;
    }
    button.disabled = false;
    await Promise.all([loadHistory(), loadStats()]);
  }

  document.addEventListener("DOMContentLoaded", () => {
    let timer = null;
    $("history-search").addEventListener("input", (e) => {
      clearTimeout(timer);
      timer = setTimeout(() => {
        state.q = e.target.value.trim();
        state.page = 1;
        loadHistory();
      }, 300);
    });
    $("history-filters").addEventListener("submit", (e) => e.preventDefault());
    $("history-filter").addEventListener("change", (e) => {
      state.prediction = e.target.value;
      state.page = 1;
      loadHistory();
    });
    $("prev-page").addEventListener("click", () => { if (state.page > 1) { state.page -= 1; loadHistory(); } });
    $("next-page").addEventListener("click", () => { if (state.page < state.pages) { state.page += 1; loadHistory(); } });
    $("refresh-button").addEventListener("click", () => { loadStats(); loadHistory(); });
    $("clear-button").addEventListener("click", clearHistory);
    loadStats();
    loadHistory();
  });
})();
