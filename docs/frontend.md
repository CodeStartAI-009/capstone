# Web frontend

The frontend is served by the same Flask app as the API: Jinja templates plus
static CSS and JavaScript. There's no build step, framework or CDN; the Content
Security Policy allows only same-origin scripts and styles. **It contains no
prediction logic.** Every result comes from `POST /api/predict`, and every
number on the dashboard comes from `GET /api/stats` / `GET /api/history`.

```
browser ── POST /api/predict ──> Flask ──> ml.predictor ──> final model
        <── JSON (prediction, verdict, confidence, explanation, disclaimer, history id)
```

## Pages

| Route | Template | Script | Content |
|---|---|---|---|
| `/` | `index.html` | `scanner.js` | Landing page: scanner (compact result + "Full analysis" link), recent scans, how it works, limitations with the real test recall/FPR |
| `/inspect` | `inspect.html` | `scanner.js` | Full scanner: result, explanation, the 17 feature values; "About the model" (test metrics, confusion matrix, thresholds, feature schema). `/inspect?id=N` shows saved scan N from history |
| `/dashboard` | `dashboard.html` | `dashboard.js` | Stat cards, prediction-distribution and 30-day activity charts, history table (search, filter, pagination, view, delete, clear) |

Shared files:
- `base.html`: header, nav, offline banner, footer disclaimer.
- `_scanner.html`: the scanner form and result card, used by both `/` and
  `/inspect`.
- `static/js/main.js`: API client and helpers.
- `static/css/style.css`.

## Risk presentation

- The model's labels (`Safe` / `Suspicious` / `Phishing`) are shown alongside
  risk-signal wording from the API: **"Low-risk prediction"**, **"Phishing-risk
  prediction (moderate/high)"**. The UI never says "safe" as a verdict.
- The confidence shown is the API's **model confidence**. The meter shows the
  model's own phishing score against its real thresholds, which come from
  `/api/model-info`. No separate risk score is invented.
- Every result shows the sentence "This result is an automated machine-learning
  risk assessment and is not a guarantee that a website is safe." It is then
  replaced by the API disclaimer, which quotes the measured test recall of the deployed model (56.7% for v2.0.0)
  and FPR (5.5%). The footer and the landing page's Limitations section repeat
  this, with numbers loaded from `/api/model-info`.
- "Why this result?" lists the API's explanation items, labelled either *model
  feature* (an unusual value of a model input) or *observation* (a rule-based
  URL fact the model does not use).

## Behaviour and error states

| Situation | What the user sees |
|---|---|
| Empty input | Field message "Please enter a URL to scan."; no request is sent |
| Invalid / unsupported / internal URL, too long | The API's message under the input (`aria-invalid`) |
| API unreachable | "Service unavailable" card plus the offline banner |
| No response within 15 s | "Request timed out" |
| Non-JSON or malformed response | "Unexpected response" |
| 5xx with an error object | The API's friendly message; never an exception or stack trace |
| Model not loaded | Banner (from `/api/health`) and a "Model not available" card |
| Scan succeeded but was not saved | Result shown with "This result could not be saved to the scan history." |
| History/stats unavailable (503) | Dashboard error boxes and an empty table; no fabricated values |

While a scan is running, the button is disabled, the input is read-only and
repeated submits are ignored, so there are no duplicate scans.

## Security

- **No `innerHTML`.** Every API value and user input is written with
  `textContent` / DOM APIs (`main.js` `el()`). A scanned URL such as
  `https://example.com/"><svg/onload=…>` is displayed as text. A browser test
  checks that no script runs and no element is created, on both the result card
  and the dashboard.
- **Scanned URLs are never links.** They are shown in `<code>`, never used as
  `href`, and never opened or navigated to. The only links built from data are
  `/inspect?id=<integer>`.
- **Strict CSP:** `script-src 'self'; style-src 'self'`. There are no inline
  scripts or styles (dynamic widths use the CSSOM, which the CSP allows). A
  browser test fails on any console or CSP error.
- Validation in the browser is only a convenience (empty input). All validation
  happens on the server.

## Responsive design

A CSS grid layout with breakpoints at 900, 720 and 560 px:
- the header navigation wraps;
- stat cards go from 4 to 2 columns;
- charts stack;
- tables scroll horizontally inside their card;
- long URLs wrap in the result card and are truncated, with a hover title, in
  tables.

The browser tests render `/`, `/inspect` and `/dashboard` at 375×812, 768×1024
and 1280×900, and assert that none has horizontal overflow. Screenshots were
reviewed manually. That review found and fixed three bugs:
- the `hidden` attribute was being overridden by component CSS;
- absolutely positioned labels were widening the page;
- two sections had no side padding.

## Tests

`tests/browser/test_frontend_browser.py` runs headless Chrome against a live
Flask server over the DevTools protocol (`tests/browser/cdp.py`, standard
library only), with 21 tests. It is skipped automatically when Chrome isn't
installed.

| Area | Tests |
|---|---|
| Scans | Low-risk scan (matches the API), phishing-risk scan, saved-scan view |
| Input | Empty input (no request), malformed / `javascript:` / localhost URLs, duplicate submissions |
| Security | XSS payload |
| Failures | API unavailable, malformed response, server error, 15 s timeout |
| Dashboard | Statistics equal to `/api/stats`, search, filter, pagination, delete (with confirm), cancelled clear, clear, history failure |
| Rendering | Hidden states not rendered, no console/CSP errors, responsive layouts |

Run them with `python -m pytest tests/browser`. Set
`BROWSER_ARTIFACTS=/some/dir` to save screenshots.
