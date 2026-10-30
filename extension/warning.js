/* Warning page shown by background.js when the API returns a high risk level for the site in this tab.
 * The warning (URL and API result) is read from the background worker for THIS tab only; nothing is
 * taken from this page's own URL. All text is written with textContent (no innerHTML).
 */
"use strict";

const $ = (id) => document.getElementById(id);
const MAX_REASONS = 6;
const SEVERITY = { risk: "risk", caution: "caution", info: "info" };

async function send(type) {
  try {
    return await chrome.runtime.sendMessage({ type: type });
  } catch (err) {
    return null;
  }
}

function render(warning) {
  const result = warning.result || {};
  $("host").textContent = warning.host;
  $("url").textContent = warning.url;
  $("verdict").textContent = result.verdict || result.prediction || "not available";
  $("risk").textContent = result.risk_level || "not available";
  $("score").textContent = typeof result.phishing_probability === "number"
    ? result.phishing_probability.toFixed(2) + " (0 = least, 1 = most phishing-like; not a certainty)"
    : "not available";
  $("model-input").textContent = result.model_input || "not available";
  $("model-version").textContent = result.model_version || "not available";
  $("summary").textContent = result.summary || "";
  const reasons = $("reasons");
  reasons.replaceChildren();
  (Array.isArray(result.explanations) ? result.explanations : []).slice(0, MAX_REASONS).forEach((item) => {
    const li = document.createElement("li");
    li.className = SEVERITY[item.severity] || "info";
    const tag = document.createElement("span");
    tag.className = "tag";
    tag.textContent = item.source === "observation" ? "observation" : "model feature";
    li.append(tag, document.createTextNode(String(item.message)));
    reasons.appendChild(li);
  });
  if (result.disclaimer) $("disclaimer").textContent = result.disclaimer;
  $("details").hidden = false;
  $("proceed").hidden = false;
  $("proceed-note").hidden = false;
}

function setBusy(busy) {
  $("back").disabled = busy;
  $("proceed").disabled = busy;
}

function actionFailed(message) {
  setBusy(false);
  $("action-error").textContent = message;
  $("action-error").hidden = false;
}

async function goBack() {
  setBusy(true);
  const reply = await send("warning:back");
  if (!reply || !reply.ok) location.assign("safe.html"); // never leave the user stuck on this page
}

async function proceed() {
  setBusy(true);
  const reply = await send("warning:proceed");
  if (!reply || !reply.ok) {
    $("details").hidden = true;
    $("proceed").hidden = true;
    $("proceed-note").hidden = true;
    $("missing").hidden = false;
    actionFailed("This warning is no longer active, so Continue Anyway is not available. Use Go Back to Safety, " +
      "or open the address again.");
  }
}

document.addEventListener("DOMContentLoaded", async () => {
  $("back").addEventListener("click", goBack);
  $("proceed").addEventListener("click", proceed);
  const reply = await send("warning:get");
  if (reply && reply.ok && reply.warning) render(reply.warning);
  else $("missing").hidden = false;
  document.body.dataset.ready = "true";
});
