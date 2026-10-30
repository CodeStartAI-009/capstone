# Project Knowledge and Viva Guide

**AI-Powered Real-Time Phishing URL Detection Using Machine Learning and Browser Extension**

This handbook explains the whole project in beginner-friendly English. Each topic starts with a simple
explanation, followed by the actual implementation with file references. Every number comes from a file in
this repository; the source is named next to it. Where something is not implemented or not measured, the
handbook says so.

How to read the evidence labels:
- **Measured:** produced by code in this repository and re-checked on 2026-10-29.
- **Historical:** recorded earlier in the repository (for example `docs/data/*.json`) and not re-measured.
- **Simulated:** tested with a fake browser API, not a real browser.
- **Not verified:** stated somewhere but not checked.

Companion documents:
- `docs/REVIEW_2_VIVA_PREPARATION.md`: speaking notes and demo script.
- `docs/IMPLEMENTATION_AND_VALIDATION_REPORT.md`: what changed in this round and how it was verified.

---

## 1. Project overview in simple English

When you click a link, you cannot always tell whether the website is real or a fake made to steal your
password (a *phishing* site). This project gives a **second opinion** about a website address (URL):

1. A **machine-learning model** looks at the site's domain name, for example `secure-login-verify.xyz`, and
   estimates how much it resembles phishing domains it saw during training.
2. A **Flask web server** runs the model and offers it as a REST API, a web page scanner and a dashboard of
   past scans stored in **SQLite**.
3. A **Chrome extension** checks each page you open automatically. It shows a coloured badge (LOW / MED /
   HIGH) and, for high-risk sites, a warning page with **Go Back to Safety** and **Continue Anyway**.

The result is a **risk estimate, not proof**. On held-out test data, the deployed model detected 56.7% of
phishing URLs and wrongly flagged 5.5% of legitimate ones (`models/model_metadata.json`, `test_metrics`).

## 2. Problem statement

Phishing sites imitate trusted brands to steal credentials and payments. Blacklists only know sites that
have already been reported, so new phishing domains are missed in the hours after they appear. Users need a
fast, privacy-respecting signal at the moment they open a site, which does not depend on the site already
being reported.

The project asks two questions:
- How well can a model that sees **only the site's address** detect phishing when it is evaluated honestly,
  without data leakage?
- How can such a model warn a user in the browser without collecting page contents?

## 3. Objectives

| # | Objective | Status |
|---|---|---|
| 1 | Extract URL features automatically, identically for training and live prediction | Implemented and tested (`ml/feature_extractor.py`, `tests/test_pipeline.py`) |
| 2 | Train and select a model with a leakage-controlled split and validation-only decisions | Implemented (`ml/train_model.py`); metrics reproduced on 2026-10-29 (§18) |
| 3 | Serve predictions through a validated, secure REST API | Implemented (`backend/`, `docs/security.md`) |
| 4 | Store scan history and show a dashboard | Implemented (`database/`, `/dashboard`) |
| 5 | Chrome MV3 extension: automatic checks, warning, Go Back to Safety, Continue Anyway | Implemented in this round (`extension/`); tested in real headless Chrome and in simulation |
| 6 | Honest reporting of limitations | Disclaimers in every UI, built from measured test metrics |
| 7 | User feedback that improves the model | **Not implemented.** There is no feedback table or endpoint, and nothing retrains from user input. |

## 4. Existing system versus proposed system

| | Typical existing approaches | This project |
|---|---|---|
| Blacklists (e.g. Google Safe Browsing) | Accurate for known sites; miss new domains until reported | Scores any domain immediately from its name; an optional, disabled-by-default Safe Browsing lookup exists (`services/threat_intelligence.py`) and is shown separately |
| ML on dataset columns | Often reports ~99.9% accuracy using columns that cannot be computed for a new URL, or that leak the label | Uses only 17 features recomputed from the URL; excludes the leaky `URLSimilarityIndex` (§14) |
| Random train/test split | Related URLs of one site land in both splits, which inflates scores | Split grouped by registrable domain: 0 shared domains between splits (§15) |
| Page-content analysis | Needs to download the page, which is slow and risky | Never fetches the page; no server-side request forgery surface |
| Extension | Many read all page content | No content scripts; automatic checks send only the site's origin |

## 5. Research gap and contribution

The gap: many published phishing-URL results use features or splits that do not carry over to real URLs.
In this dataset that includes the same-dataset similarity score, and every legitimate URL being a homepage.

What this project contributes, as recorded in the repository:
1. **A leakage analysis of the PhiUSIIL dataset** (`docs/model_evaluation.md`, `docs/dataset.md`).
   - The near-perfect ~0.9997 F1 comes from the leaky `URLSimilarityIndex`, and from dataset construction:
     every legitimate URL is a bare `https://www.<host>` homepage, and a no-ML rule reaches 0.9960 F1.
   - Duplicate URLs had no material effect.
   - Re-checked on 2026-10-29: all 20 research-script models in `models/*.joblib` and `models/clean/*.joblib`
     use `URLSimilarityIndex` and score 0.9997–1.0 accuracy on their test files
     (`docs/data/model_inventory.json`).
2. **A documented false-positive investigation** (`docs/false_positive_investigation.md`).
   - The host-view model flagged legitimate subdomain sites such as `admob.google.com` (P = 0.98), because
     in the training data 99.7% of legitimate `.com` hosts have no subdomain.
   - The fix was to score the registrable domain, with a stated decision rule. The trade-off was measured:
     recall fell from 0.6801 to 0.5675 on the same test set.
3. **A stricter, registrable-domain-grouped split.** The earlier host-grouped split let 14.1% of test rows
   share a registrable domain with training data.
4. **A privacy-minimising browser integration.** The extension reads no page content, and automatic checks
   send only the origin, which is enough because the model only uses the registrable domain.

These are engineering and evaluation contributions on an existing public dataset. **No new dataset and no new
learning algorithm** are claimed.

## 6. Literature review and references

The repository contains **no literature review and no citation list**. Only the dataset is named ("PhiUSIIL
Phishing URL Dataset", `models/model_metadata.json`). The entries below are the software and data the code
actually uses. Add your team's paper references here and check each one yourself; none were invented for
this guide.

| Item | Used for | Where |
|---|---|---|
| PhiUSIIL Phishing URL Dataset | Training and evaluation data (235,795 rows) | `data/*.csv`, `docs/dataset.md` |
| Public Suffix List, bundled with `tldextract` 5.1.2 (offline snapshot) | Registrable-domain extraction | `ml/url_utils.py` (`PSL_SOURCE`) |
| scikit-learn 1.6.1 | Models, metrics | `requirements.txt`, `ml/model_utils.py` |
| Flask 3 | Web server and API | `backend/` |
| SQLite (Python `sqlite3`) | Scan history | `database/` |
| Chrome Extensions Manifest V3 | Browser extension | `extension/manifest.json` |

Citation to verify before submission (from general knowledge, **not recorded in the repository**): the
PhiUSIIL dataset is commonly cited as A. Prasad and S. Chandra, "PhiUSIIL: A diverse security profile
empowered phishing URL detection framework based on similarity index and incremental learning", *Computers &
Security*, 2024, and is available from the UCI Machine Learning Repository. Check the exact details against
the source before using it.

## 7. System architecture

```
          ┌────────────────────────┐                ┌───────────────────────────────────────┐
          │ Web browser (any page) │                │ Chrome extension (MV3)                │
          │  /  /inspect /dashboard│                │  background.js  (service worker)      │
          │  static/js/*.js        │                │  popup.html/js, warning.html/js       │
          └───────────┬────────────┘                └──────────────┬────────────────────────┘
                      │ fetch, same origin                         │ fetch, host_permissions
                      ▼                                            ▼
          ┌───────────────────────────────────────────────────────────────────────────────┐
          │ Flask app   app.py → backend/__init__.py:create_app                           │
          │  routes:   /api/predict · /api/health · /api/model-info · /api/features ·     │
          │            /api/history[/<id>] · /api/stats · pages / /inspect /dashboard    │
          │  utils:    validation · errors · security headers/CORS · rate limit          │
          │  services: PredictionService · HistoryService · explanation_engine           │
          └────────┬─────────────────────────────┬────────────────────────────┬──────────┘
                   ▼                             ▼                            ▼
          ┌──────────────────┐        ┌────────────────────┐       ┌──────────────────────┐
          │ ml/predictor.py  │        │ database/ (SQLite) │       │ models/              │
          │ url_utils →      │        │ instance/          │       │ phishing_model.pkl   │
          │ feature_extractor│        │ scan_history.db    │       │ model_metadata.json  │
          │ → model → risk   │        │ table scan_history │       │ tld_legitimate_prob  │
          └──────────────────┘        └────────────────────┘       └──────────────────────┘
```

Beginner explanation of each box:
- **Frontend:** HTML pages with JavaScript that call the API and display the JSON result.
- **Extension:** a small program inside Chrome. Its *service worker* is a background script that wakes up on
  browser events, such as "a tab loaded a new page".
- **Flask app:** a Python web server. A *route* is a function that runs for one URL path, such as
  `/api/predict`.
- **Predictor:** turns a URL into 17 numbers (features), asks the model for a probability, and maps it to a
  risk level.
- **Database:** one SQLite file holding past scans.
- **Model files:** the trained model, its metadata (thresholds, metrics, feature order) and the TLD table.

### 7.1 Tracing one URL through the whole system

Example: the user opens `https://secure-login-verify-account.example/login` (a synthetic, reserved-TLD name).
The values are the real outputs measured on 2026-10-29.

| # | Step | File and function | Input → output | Purpose |
|---|---|---|---|---|
| 1 | Browser navigation | Chrome | User action → `tabs.onUpdated(tabId, {url})` | Chrome tells the extension the tab's new URL |
| 2 | Extension receives it | `extension/background.js` `chrome.tabs.onUpdated` listener → `handleNavigation(tabId, url, "navigation")` | URL → origin `https://secure-login-verify-account.example` | Skip unsupported schemes; end a bypass if the site changed; check the cache |
| 3 | URL extraction and API request | `background.js` `scanOrigin` → `scan-core.js` `callApi(origin + "/", record)` | `POST /api/predict {"url": "https://secure-login-verify-account.example/", "source": "extension", "record": false}` | Send only the origin; 8 s timeout; `credentials: "omit"` |
| 4 | Flask route | `backend/routes/prediction.py` `predict()` | HTTP request → `(url, source, record)` | Rate limit (60/min), then parse the JSON (`parse_predict_payload`) |
| 5 | URL validation | `backend/utils/validation.py` `validate_url` → `ml/url_utils.py` `normalize_url` | Raw string → normalised URL; 400 on a bad scheme, host or length | http(s) only; no private or internal hosts |
| 6 | Normalisation and registrable domain | `ml/feature_extractor.py` `model_input(url, "registrable")` → `ml/url_utils.py` `split_registrable` (PSL) | URL → `https://www.secure-login-verify-account.example` (`.example` is not in the PSL, so the whole host is used) | Decide what the model sees |
| 7 | Feature extraction | `ml/feature_extractor.py` `compute_features` | Model input → 17 numbers, e.g. `DomainLength` 39, `TLDLegitimateProb` 0.0, `TLDLength` 7 | Same code as training |
| 8 | Feature order and schema checks | `extract_features` → `validate_vector`; `Predictor.__init__` checks at start-up | Dict → list in `FEATURE_NAMES` order; type and range checked | Prevents silent mismatches |
| 9 | Preprocessing | none beyond the above: tree models use the raw values (no scaler) | n/a | n/a |
| 10 | Active model | `ml/predictor.py` `Predictor.predict` → `model.predict_proba` (`models/phishing_model.pkl`, GradientBoosting v2.0.0, loaded once at start-up) | 1×17 DataFrame → P(phishing) 0.8387 | The ML step |
| 11 | Thresholds → risk level | `Predictor.classify` with metadata thresholds 0.5200 / 0.6443 | 0.8387 → `Phishing`, `High` | Fixed rule from validation data |
| 12 | Explanation | `services/explanation_engine.py` `explain` | Features + URL facts + training percentiles → items such as "The assessed domain is 39 characters long; 95% of legitimate training domains are at most 28." | Human-readable reasons from computed values |
| 13 | Wording and disclaimer | `services/prediction_service.py` `_risk_signal`, `disclaimer` | → `verdict` "Phishing-risk prediction (high)", `summary`, `disclaimer` with test recall and FPR | Honest, consistent wording |
| 14 | History (optional) | `services/history_service.py` `record` → `redact_url` → `database/repository.py` `add` | Only if `record` is true → row id | Popup scans are recorded; automatic checks are not by default |
| 15 | JSON response | `prediction.py` `jsonify` | `{"success": true, "prediction": "Phishing", "risk_level": "High", ...}` | API contract |
| 16 | Extension decision | `scan-core.js` checks the response; `background.js` `applyOutcome` | High and no bypass → badge `HIGH`, store the warning, `tabs.update(tab, "warning.html")` | Warn the user |
| 17 | Warning page | `extension/warning.js` → `warning:get` | Shows host, URL, verdict, score, reasons, disclaimer; Go Back / Continue | User decision |
| 18 | Dashboard | `static/js/dashboard.js` → `GET /api/stats`, `GET /api/history` | Rows → charts and table | Only for recorded scans |

The web scanner follows steps 4–15 with `source: "web"`, `record: true` and the full URL, and shows the result
in `templates/_scanner.html` via `static/js/scanner.js`.

## 8. Complete folder and file map (most important first)

| Path | Purpose | Functions and classes reviewers should know |
|---|---|---|
| `app.py` | Entry point; sets `OMP_NUM_THREADS` from `ML_THREADS`, creates the app | `app = create_app()` |
| `config.py` | All settings from environment variables, with safe defaults | `Config` (`MODEL_PATH`, `DATABASE_PATH`, `RATE_LIMIT_PER_MINUTE`, `MAX_URL_LENGTH`…) |
| `backend/__init__.py` | Application factory: loads the model once, sets up the DB, blueprints, headers | `create_app()` |
| `backend/routes/prediction.py` | `POST /api/predict` | `predict()` |
| `backend/routes/history.py` | History and stats endpoints | `history_list`, `history_get`, `history_delete`, `history_clear`, `stats` |
| `backend/routes/model.py` | `GET /api/model-info`, `GET /api/features` | `model_info`, `features` |
| `backend/routes/health.py` | `GET /api/health` | `health` |
| `backend/utils/validation.py` | Request and URL policy (schemes, private hosts, length, fields) | `parse_predict_payload`, `validate_url`, `is_internal_host` |
| `backend/utils/errors.py` | One JSON error format; no stack traces to clients | `ApiError`, `register_error_handlers` |
| `backend/utils/security.py` | Security headers, strict CORS allow-list | `apply_security_headers`, `parse_origins` |
| `backend/utils/rate_limit.py` | 60 predictions/minute/client (sliding window) | `RateLimiter.check` |
| `services/prediction_service.py` | Wraps the predictor; adds verdict wording and the disclaimer from metadata | `PredictionService.predict`, `_risk_signal`, `disclaimer`, `model_info` |
| `services/explanation_engine.py` | Human-readable reasons from computed values only | `explain` |
| `services/history_service.py` | Builds and redacts history records | `HistoryService.record`, `redact_url` |
| `services/threat_intelligence.py` | Optional Google Safe Browsing lookup (off by default) | `from_environment`, `GoogleSafeBrowsing` |
| `ml/feature_schema.py` | **Single source of truth** for the 17 features, their order, types, ranges; excluded columns; label convention | `FEATURE_SCHEMA`, `FEATURE_NAMES`, `EXCLUDED_FEATURES`, `DEFAULT_MODEL_INPUT_VIEW` |
| `ml/url_utils.py` | URL validation and normalisation; Public Suffix List | `normalize_url`, `split_registrable`, `describe_url` |
| `ml/feature_extractor.py` | URL → model input string → 17 features | `model_input`, `compute_features`, `extract_features`, `validate_vector` |
| `ml/predictor.py` | Loads and checks the model; predicts; risk levels | `Predictor.from_paths`, `Predictor.predict`, `Predictor.classify` |
| `ml/dataset.py` | Loads PhiUSIIL, deduplicates, grouped split | `prepare_rows`, `host_grouped_split`, `load_registrable_grouped_split` |
| `ml/model_utils.py` | Candidate models, metrics, thresholds, save/load | `model_grid`, `binary_metrics`, `threshold_for_max_fpr` |
| `ml/train_model.py` | Training, selection, thresholds, one test evaluation, metadata | `main`, `bootstrap_recall_gain`, `subdomain_fpr_check` |
| `ml/view_experiment.py`, `ml/evaluate_model.py`, `ml/error_analysis.py` | Experiments behind the docs | `main` |
| `database/models.py` | Schema v2 and migrations | `SCHEMA`, `MIGRATIONS` |
| `database/database.py` | Connections, WAL, migrations | `Database.initialize`, `Database.run` |
| `database/repository.py` | All SQL, parameterised | `ScanRepository.add/get/list/delete/clear/stats` |
| `templates/*.html`, `static/js/*.js`, `static/css/style.css` | Web UI | `main.js: api(), el()`, `scanner.js: scan(), render()`, `dashboard.js: loadStats(), loadHistory()` |
| `extension/manifest.json` | MV3 manifest: `tabs`, `storage`, API origin; service worker | n/a |
| `extension/config.js` | API location and scan settings | `API_BASE`, `AUTO_SCAN_DEFAULT`, `SCAN_CACHE_TTL_MS`, `BYPASS_TTL_MS` |
| `extension/scan-core.js` | Shared API call and URL checks | `callApi`, `unsupportedReason`, `ScanError` |
| `extension/background.js` | Automatic checks, badge, warning redirect, Go Back / Continue | `handleNavigation`, `scanOrigin`, `applyOutcome`, `goBack`, `proceed` |
| `extension/warning.html/js/css`, `safe.html` | Warning interstitial and safe fallback page | `render`, `goBack`, `proceed` |
| `extension/popup.html/js/css` | Manual scan, status line, settings | `scan`, `render`, `loadSettings`, `loadAutoStatus` |
| `models/` | Deployed model v2.0.0 and archived models (§16) | n/a |
| `data/` | PhiUSIIL CSV files (read-only) | n/a |
| `scripts/` | Audits, benchmark, model inventory | `dataset_audit.py`, `benchmark_api.py`, `model_inventory.py` |
| `tests/` | pytest suite, Node simulated tests, headless-Chrome tests (§22) | n/a |
| `train_models*.py`, `ensemble*.py`, `feature_ablation*.py`, `train_distilbert*.py`, `predict.py`, `create_clean_split.py`, `analyze_feature_importance.py` | Original research scripts. **Not used by the application** | n/a |

## 9. Frontend explanation

**Simple idea.** The browser shows HTML pages. JavaScript in those pages sends the URL you typed to the
server, receives JSON (structured data), and fills in the page.

**Implementation.**

| Route | Template | Script | What it shows |
|---|---|---|---|
| `/` | `templates/index.html` (+ `_scanner.html`) | `static/js/scanner.js` | Scanner, recent scans, how it works, limitations |
| `/inspect` | `templates/inspect.html` | `scanner.js` | Full result: explanation, the 17 feature values, model information; `/inspect?id=N` shows saved scan N |
| `/dashboard` | `templates/dashboard.html` | `static/js/dashboard.js` | Stat cards, prediction distribution, 30-day activity chart (SVG built in JS), history table with search, filter, pagination and delete |

How it talks to Flask:
- `static/js/main.js` `api(path, options)` wraps `fetch()`. It adds a timeout (15 s), JSON parsing and one
  error format (`NETWORK`, `TIMEOUT`, `BAD_RESPONSE`, or the API's code).
- The scanner sends `POST /api/predict {"url": …, "source": "web"}`.
- The dashboard uses `GET /api/stats?days=30` and `GET /api/history?...`.

States: idle, loading (the button is disabled to prevent duplicate scans), result, error ("Service
unavailable", "Request timed out", "Model not available"…), and empty ("No scans yet").

**Displaying results safely.** All API values are written with `textContent` or `document.createElement`
(`main.js` `el()`), never `innerHTML`. A scanned URL is never turned into a clickable link. The CSP allows
only same-origin scripts. Evidence: `tests/browser/test_frontend_browser.py`, `tests/test_client_code.py`.

## 10. Backend explanation

**Simple idea.** Flask receives an HTTP request, checks it, calls the model, and returns JSON.

- **Entry point:** `python app.py` → `backend.create_app()`. The model is loaded **once at start-up**
  (`Predictor.from_paths`). If it fails to load, the server still starts: `/api/health` reports
  `model_loaded: false` and `/api/predict` returns 503.
- **Routes:** see §11.
- **Validation** (`backend/utils/validation.py`):
  - JSON object only, with allowed fields `url`, `source`, `record`;
  - `url` must be a non-empty string of at most 2,048 characters;
  - only `http`/`https` schemes;
  - localhost, private IPs (including tricks such as `2130706433` and `0x7f.1`) and internal names are
    rejected unless `ALLOW_PRIVATE_HOSTS=true`.
- **Errors** (`backend/utils/errors.py`): every error is `{"success": false, "error": {"code", "message"}}`.
  Details are logged on the server, never sent to the client.
- **Prediction service** (`services/prediction_service.py`): calls `Predictor.predict`, then adds:
  - `verdict` ("Low-risk prediction" / "Phishing-risk prediction (moderate|high)");
  - `summary` (states the score and thresholds);
  - `explanation` (messages sorted risk → caution → info);
  - `disclaimer` (built from the metadata's test recall and FPR);
  - `model_version` and `scanned_at`.
- **Explanation engine** (`services/explanation_engine.py`) produces two kinds of items:
  - *model feature* items: a model input whose value is beyond the 95th/99th percentile of legitimate
    training URLs (percentiles stored in `model_metadata.json` → `legitimate_reference`);
  - *observation* items: facts the model does **not** use, such as no HTTPS, a non-standard port, `@` in
    the URL, punycode, or another domain name inside the subdomain.

  These are **not** per-prediction attributions (such as SHAP); they describe unusual inputs.
- **Configuration and secrets:** environment variables only (`config.py`, `.env.example`). `.env` is
  git-ignored, and no secret is in the code.
- **Security controls:** §21.

## 11. REST API reference

All responses are JSON. Base URL in development: `http://127.0.0.1:5000`. On this Mac port 5000 is taken by
macOS ControlCenter, so the verification used `API_PORT=5051`.

| Method and path | Purpose | Input | Success | Errors | Called by | DB |
|---|---|---|---|---|---|---|
| `POST /api/predict` | Score one URL | JSON `{"url": str, "source": "web"\|"extension"\|"api" (default api), "record": bool (default true)}` | 200: prediction object (below) incl. `history: {"saved": true, "id": n}` or `{"saved": false, ...}` | 400 `MISSING_URL`, `INVALID_URL`, `UNSUPPORTED_SCHEME`, `UNSUPPORTED_HOST`, `URL_TOO_LONG`, `INVALID_TYPE`, `INVALID_JSON`, `UNEXPECTED_FIELD`, `INVALID_FIELD`; 413; 415; 422 `FEATURE_EXTRACTION_FAILED`; 429 `RATE_LIMITED`; 500 `PREDICTION_FAILED`; 503 `MODEL_UNAVAILABLE` | `scanner.js`, `extension/scan-core.js` (popup and worker) | writes one row if `record` is true |
| `GET /api/health` | Liveness and whether the model loaded | none | `{"status": "ok", "model_loaded": true}` | none | `main.js` (offline banner) | no |
| `GET /api/model-info` | Public model metadata: version, features, thresholds, test metrics, disclaimer | none | 200 | 503 `MODEL_UNAVAILABLE` | `main.js`, `scanner.js` | no |
| `GET /api/features` | The feature schema and excluded features | none | 200 | none | `scanner.js` | no |
| `GET /api/history` | Paginated history, newest first | `page` ≥1, `limit` 1–100, `prediction`, `q` (≤200 chars) | `{"items", "page", "limit", "total", "pages"}` | 400 `INVALID_PARAMETER`; 503 `HISTORY_UNAVAILABLE` | `dashboard.js`, `scanner.js` (recent) | reads |
| `GET /api/history/<id>` | One scan with features and indicators | positive integer id | `{"item": {...}}` | 400 `INVALID_ID`, 404 `SCAN_NOT_FOUND`, 503 | `scanner.js` (`/inspect?id=`) | reads |
| `DELETE /api/history/<id>` | Delete one scan | id | `{"deleted": 1}` | 400, 404, 503 | `dashboard.js` | writes |
| `DELETE /api/history` | Delete all scans | none | `{"deleted": n}` | 503 | `dashboard.js` | writes |
| `GET /api/stats` | Totals and daily counts | `days` 1–365 (default 30) | `{"total", "by_prediction", "by_risk_level", "by_source", "first_scan_at", "last_scan_at", "daily", ...}` | 400, 503 | `dashboard.js` | reads |
| `GET /`, `/inspect`, `/dashboard` | HTML pages | none | HTML | none | browser | no |

**Verified request and response** (real `python app.py`, 2026-10-29, response fields trimmed):

```bash
curl -s -X POST http://127.0.0.1:5051/api/predict -H "Content-Type: application/json" \
     -d '{"url": "https://secure-login-verify-account.example/", "source": "api", "record": false}'
```
```json
{"success": true, "url": "https://secure-login-verify-account.example/", "prediction": "Phishing",
 "label": 0, "risk_level": "High", "confidence": 0.8387, "phishing_probability": 0.8387,
 "model_input": "https://www.secure-login-verify-account.example",
 "features": {"URLLength": 47, "DomainLength": 39, "...": "17 values"},
 "explanations": [{"source": "model_feature", "severity": "risk", "feature": "DomainLength",
                   "message": "The assessed domain is 39 characters long; 95% of legitimate training domains are at most 28."}],
 "model_version": "2.0.0", "verdict": "Phishing-risk prediction (high)",
 "summary": "Phishing-risk prediction (high): the model's phishing score (0.84) is at or above its high-confidence level (0.64). ...",
 "disclaimer": "This is a machine-learning risk signal computed from the site's registrable domain name only; ...",
 "history": {"saved": false, "reason": "not requested"}}
```

Python example:

```python
import json, urllib.request
req = urllib.request.Request("http://127.0.0.1:5000/api/predict", method="POST",
                             data=json.dumps({"url": "https://example.com/", "record": False}).encode(),
                             headers={"Content-Type": "application/json"})
print(json.load(urllib.request.urlopen(req))["risk_level"])   # "Low" (P = 0.3704, measured 2026-10-29)
```

Error example (verified): `{"url": "javascript:alert(1)"}` returns 400
`{"success": false, "error": {"code": "UNSUPPORTED_SCHEME", "message": "Only http:// and https:// URLs can be scanned."}}`.

## 12. Database and data flow

**Simple idea.** SQLite is a database stored in one file. No database server is needed.

- Path: `instance/scan_history.db` (default; `DATABASE_PATH` changes it). It is git-ignored and created
  automatically.
- Table `scan_history` (schema version 2, `database/models.py`): `id`, `scanned_at`, `url`,
  `normalized_url`, `host`, `prediction` (CHECK Safe/Suspicious/Phishing), `risk_level` (CHECK
  Low/Medium/High), `confidence`, `phishing_probability`, `model_version`, `processing_ms`, `source` (CHECK
  web/extension/api), `features` (JSON), `indicators` (JSON). Indexes on `scanned_at` and `prediction`.
- **Migrations:** a version-1 file is upgraded in place with `ALTER TABLE … ADD COLUMN`
  (`database/database.py`, `PRAGMA user_version`).
- **Lifecycle:** `POST /api/predict` with `record: true` → `HistoryService.record` → `redact_url` (query
  values become `[redacted]`, the password and fragment are dropped) → `ScanRepository.add` (bound
  parameters) → the id is returned in the response.

  If the database fails, the prediction is still returned with `history.saved: false`. Delete one scan or
  clear all from the dashboard; there is no automatic expiry.
- **Feedback:** **there is no feedback table, endpoint or UI.** User decisions (for example Continue Anyway)
  are not stored, and nothing retrains the model from user input.
- **Relationships:** one table, no foreign keys.

## 13. URL preprocessing

**Simple idea.** Before measuring a URL, the project tidies it up and decides which part of it the model
looks at.

1. **Validation and normalisation** (`ml/url_utils.py:normalize_url`):
   - trim spaces;
   - reject control characters, spaces and over-long input;
   - add `https://` if the scheme is missing;
   - lower-case the scheme and host;
   - convert Unicode hosts to punycode (IDNA);
   - keep the path, query and fragment unchanged.
2. **Registrable domain** (`ml/url_utils.py:split_registrable`): uses the Public Suffix List to split a host
   into *subdomain* and *registrable domain* (eTLD+1).
3. **Model input view** (`ml/feature_extractor.py:model_input`, `view="registrable"`): the model sees the
   canonical string `https://www.<registrable domain>`.

Worked example (measured with the real code):

| Input URL | Registrable domain | Model input | Result |
|---|---|---|---|
| `https://admob.google.com/v2/home` | `google.com` (sub `admob`) | `https://www.google.com` | Safe / Low, P = 0.4212 |
| `http://login.paypal.com.secure-verify.xyz/signin?user=a%40b.c` | `secure-verify.xyz` (sub `login.paypal.com`) | `https://www.secure-verify.xyz` | Phishing / High, P = 0.9079 |
| `https://abc.firebaseapp.com/` | `abc.firebaseapp.com` (`firebaseapp.com` is a PSL shared-hosting suffix) | `https://www.abc.firebaseapp.com` | depends on the name |
| `https://secure-login-verify-account.example/` | none: `.example` is not in the PSL, so the whole host is used | `https://www.secure-login-verify-account.example` | Phishing / High, P = 0.8387 |

**What is lost by scoring the registrable domain:**
- the subdomain (`login.paypal.com.` above);
- the path and the query;
- whether the original used `http` or `https`;
- the port and any `@` userinfo.

Two of these are shown to the user as **observations**: "The subdomain contains another domain name
(paypal.com)…" and "Connection does not use HTTPS." These observations **never change the score**
(`tests/test_pipeline.py::test_subdomain_observations_do_not_change_the_score`).

Because of this design:
- every site on one registrable domain gets the same score (good for `mail.google.com`, bad for an attacker
  who owns `evil.xyz` and uses `login.paypal.com.evil.xyz`);
- hosted sites on shared platforms that are **not** in the PSL inherit the platform's score, for example
  `…z1.web.core.windows.net` → `windows.net` (`docs/false_positive_investigation.md` §6).

## 14. Feature-by-feature ML explanation

**Simple idea.** A *feature* is a number that describes the input, such as "how long is the domain?". The
model learns which combinations of these numbers are typical of phishing.

Terms (`ml/feature_schema.py`), all computed on the model input `https://www.<registrable domain>`:
- `url`: that model input string;
- `host`: the part after `https://`;
- `body`: `url` with `https://`, `http://` and `www.` removed;
- `core`: the host without `www.` and without its last label.

Example values are for `https://admob.google.com/v2/home` (model input `https://www.google.com`). The
importances are the deployed model's `feature_importances_` (impurity-based, computed on training data,
measured 2026-10-29).

| # | Feature | Meaning | How it is calculated | Example | Why it may help | Importance |
|---|---|---|---|---|---|---|
| 1 | `URLLength` | Length of the model input | `len(url)` | 22 | Long names hide brands and keywords | 0.038 |
| 2 | `DomainLength` | Length of the host | `len(host)` incl. `www.` | 14 | Same | 0.023 |
| 3 | `IsDomainIP` | Host is an IP address | dotted IPv4 pattern or IP literal | 0 | Phishing sometimes uses raw IPs | 0.000 |
| 4 | `CharContinuationRate` | How "regular" the name is | (longest letter run + longest digit run + longest symbol run) / `len(core)` | 1.0 | Random-looking mixes such as `x1-a9b` are unusual for brands | 0.023 |
| 5 | `TLDLegitimateProb` | How often the TLD appears among legitimate sites | Lookup in `models/tld_legitimate_prob.json` (652 TLDs, from the training split); 0.0 if unknown | 0.5229 (`com`) | Some cheap TLDs are mostly phishing in the data | **0.457** |
| 6 | `TLDLength` | Length of the last label | `len(tld)` | 3 | Long new gTLDs are rarer for legitimate sites in the data | 0.067 |
| 7 | `NoOfSubDomain` | Number of dots in the host minus one | `max(host.count('.') - 1, 0)` | 1 | Registrable view: more than 1 only for multi-part suffixes such as `co.uk` | 0.060 |
| 8 | `NoOfLettersInURL` | ASCII letters | count in `body` | 9 | Name length and composition | 0.014 |
| 9 | `LetterRatioInURL` | Letters / length | rounded to 3 decimals | 0.409 | Same | 0.019 |
| 10 | `NoOfDegitsInURL` | Digits | count in `body` | 0 | Digits are rare in legitimate brand domains | 0.069 |
| 11 | `DegitRatioInURL` | Digits / length | rounded | 0.0 | Same | **0.178** |
| 12 | `NoOfEqualsInURL` | `=` characters | count in `body` | 0 | Constant 0 in the registrable view | 0.000 |
| 13 | `NoOfQMarkInURL` | `?` characters | count in `body` | 0 | Constant 0 | 0.000 |
| 14 | `NoOfAmpersandInURL` | **`%` characters** (the dataset column is misnamed) | count of `%` in `body` | 0 | Constant 0 | 0.000 |
| 15 | `NoOfOtherSpecialCharsInURL` | Other symbols (`.`, `-`, …) | non-alphanumerics other than `=?%` in `body` | 1 | Hyphenated keyword domains (`secure-login-…`) | 0.011 |
| 16 | `SpacialCharRatioInURL` | All special characters / length | rounded | 0.045 | Same | 0.041 |
| 17 | `IsHTTPS` | `https` appears in the URL | `'https' in url` | 1 | Constant 1 in the registrable view | 0.000 |

**Important honesty points (measured on the training split, 2026-10-29):**
- Because the model input is always `https://www.<domain>`, `IsHTTPS` is always 1, and `NoOfEqualsInURL`,
  `NoOfQMarkInURL` and `NoOfAmpersandInURL` are always 0. `URLLength` always equals `DomainLength + 8`.
  These five inputs carry no extra information, and four of them have importance exactly 0.
- The 17-feature schema is kept so that all model versions (host view, full-URL experiments) share one
  validated schema. **Effectively the deployed model uses about 12 informative inputs.**
- `TLDLegitimateProb` alone accounts for 45.7% of the importance. This prior comes from the dataset's
  stored column, which the dataset authors derived from their own legitimate-URL source list
  (`docs/dataset.md`). It is fitted from the training split only (`ml/dataset.py:build_tld_table`).

**Why are there 17 features?**
- PhiUSIIL has 22 URL-derived columns. Five are excluded (`EXCLUDED_FEATURES`):
  - `URLSimilarityIndex`: **label leakage**. It equals 100 for 100% of legitimate rows, because it measures
    similarity to the authors' legitimate-URL list.
  - `URLCharProb`: needs the authors' external character corpus; the best reconstruction reached only 0.22%
    exact parity.
  - `HasObfuscation`, `NoOfObfuscatedChar`, `ObfuscationRatio`: the original rule could not be reproduced
    (99.79% parity, below the 99.9% bar).
- The remaining 17 were reverse-engineered and checked against all 235,795 stored rows
  (`scripts/feature_parity_audit.py`, `docs/data/feature_parity.json`).
- The 28 page-content columns (HTML, forms, images…) are not used, because the system never downloads the
  page.

**Why the exact same preprocessing and order matter.**
- A model receives a list of numbers and only knows feature 5 by its position. If training used one order
  or formula and inference another, the model would silently read the wrong values.
- Training and inference therefore call the same `compute_features`.
- The order comes only from `FEATURE_NAMES`.
- At start-up `Predictor.__init__` refuses a model whose metadata feature list, `n_features_in_` or
  `feature_names_in_` differ from the schema.
- Every vector is checked for count, types, finiteness and ranges (`validate_vector`).
- `tests/test_pipeline.py::test_training_and_prediction_features_are_identical` checks the parity.

## 15. Dataset and leakage prevention

| Item | Value | Source |
|---|---|---|
| Dataset | PhiUSIIL Phishing URL Dataset | `models/model_metadata.json` |
| Raw rows / columns | 235,795 / 56 | `docs/dataset.md` |
| Labels | `label`: **0 = phishing, 1 = legitimate** (the model internally uses 1 = phishing) | `ml/feature_schema.py`, `ml/dataset.py` |
| Duplicate URL rows removed | 425 (each duplicate had a single label) | metadata `dataset.preparation` |
| Rejected by URL validation | 8 | same |
| Rows used / registrable-domain groups | 235,362 / 196,046 | same |
| Class distribution used | 100,512 phishing (42.71%) / 134,850 legitimate | same |
| Train | 187,523 rows (79,617 phishing / 107,906 legitimate) | same |
| Validation | 24,784 rows (11,275 / 13,509) | same |
| Test | 23,055 rows (9,620 / 13,435) | same |
| URL overlap between splits | 0 / 0 / 0 | `overlap_between_splits` |
| Model-input overlap between splits | 0 / 0 / 0 | same |

Pipeline (`ml/train_model.py`, `ml/dataset.py`):
1. Load the three CSVs (read-only) and concatenate them (`load_original_rows`).
2. Drop duplicate URLs, keeping the first; abort if a URL has conflicting labels.
3. Normalise each URL and drop the 8 that fail validation.
4. Group by registrable domain and split the **groups** 80/10/10, stratified by the group's label, seed 42.
   Every host of `evil.com` (`a.evil.com`, `b.evil.com`) lands in one split.
5. Fit training-only artefacts: the TLD prior table, class weights and the explanation percentiles.
6. Fit 12 candidates on train (§17) and score them on validation.
7. Select the model and both thresholds using validation only.
8. Score the test split **once**, at the chosen threshold.
9. Save `phishing_model.pkl` (joblib, compress=3), `model_metadata.json` (with split SHA-256 fingerprints)
   and the TLD table. The previous production model is archived first.

**Why random splitting misleads.**
- If `a.evil.com` is in training and `b.evil.com` is in test, the model has effectively seen the answer.
- On the earlier host-grouped split, 3,317 of 23,536 test rows (14.1%) shared a registrable domain with
  training data (`docs/false_positive_investigation.md` §3.4).
- Duplicate URLs across splits are the simplest form of leakage: 63 test URLs in the original split.

**Dataset bias found (measured in the repository):**
- 100% of legitimate training URLs are bare `https://www.<host>` homepages, so a full-URL model learns
  "has a path → phishing". This is why paths are not used.
- 99.69% of legitimate `.com` hosts have no subdomain, against 50.1% of phishing ones. A host-view model
  learns "subdomain → phishing", which is why the registrable view is used.

**Why a high score on an easy test set is not real-world performance.** The test set has the same biases as
training: popular legitimate homepages and phishing URLs collected in a specific way. Real traffic contains
obscure legitimate sites, compromised legitimate domains and phishing on trusted platforms, which this
benchmark under-represents.

## 16. Every discovered model and artifact

Re-scoring evidence: `python scripts/model_inventory.py` → `docs/data/model_inventory.json` (2026-10-29,
read-only). The four versioned models reproduce their recorded test metrics **exactly**, confusion matrices
included.

| Model | Algorithm | Artifact path | Active or experimental | Dataset / split / view | Test metrics (Acc / Prec / Rec / F1 / AUC / FPR) | Purpose |
|---|---|---|---|---|---|---|
| **v2.0.0** | `GradientBoostingClassifier` (200 trees, depth 3, lr 0.1, unweighted, seed 42) | `models/phishing_model.pkl` + `model_metadata.json` + `tld_legitimate_prob.json` | **Active**: loaded by Flask (`config.MODEL_PATH`) | PhiUSIIL, registrable-grouped, registrable view, 17 features | 0.7872 / 0.8801 / 0.5675 / 0.6900 / 0.8524 / 0.0554 (n = 23,055, thr 0.5200) | Deployed model |
| v1.3.0 | `HistGradientBoostingClassifier` (300 iter, lr 0.1, balanced weights) | `models/alternatives/host_view_v1.3.0/` | Alternative (not served) | Same split as v2.0.0; host view | 0.8369 / 0.9055 / 0.6801 / 0.7768 / 0.8906 / 0.0508 (n = 23,055, thr 0.5015) | Shows the recall-vs-false-alarm trade-off; fails the subdomain FPR rule (17.8% vs 4.99%) |
| v1.2.0 | `HistGradientBoostingClassifier` (balanced weights) | `models/previous_v1.2.0/` | Archived (previous production) | Host-grouped split, host view | 0.8578 / 0.9140 / 0.7363 / 0.8156 / 0.8990 / 0.0516 (n = 23,536, thr 0.4991) | History; flagged legitimate subdomain sites |
| v1.1.0 | `HistGradientBoostingClassifier` (`class_weight="balanced"`) | `models/baseline_v1.1.0/` | Baseline | Host-grouped, host view | 0.8578 / 0.9146 / 0.7357 / 0.8155 / 0.8990 / 0.0512 (n = 23,536, thr 0.5) | First leakage-controlled baseline |
| Research models, 50 columns (×6: logistic regression, LinearSVC, random forest, gradient boosting, MLP, XGBoost) | as named | `models/{name}.joblib` | Experimental, **not usable for live URLs** | Original random split (`data/test.csv`), 50 stored columns incl. `URLSimilarityIndex` and page HTML | 0.9999–1.0 on all metrics; measured 2026-10-29 | Original experiments (`train_models_full_features.py`) |
| Research models, 22 URL columns (×6) | as named | `models/{name}_url_only.joblib` | Experimental, not usable | Original split, 22 stored URL columns incl. `URLSimilarityIndex` | 0.9997–0.9998 accuracy | `train_models.py` |
| Research models, clean split (×6) | as named | `models/clean/{name}.joblib` | Experimental, not usable | URL-grouped `data/clean_split`, 50 stored columns | 0.9997–1.0 | `train_models_clean.py` |
| Ablation (×2) | Random forest, 300 trees | `models/ablation_url_only.joblib`, `models/ablation_url_plus_html.joblib` | Experimental | `data/clean_split`, 22 / 50 columns | 0.9999 / 1.0 | `feature_ablation.py` |
| DistilBERT | Transformer (`distilbert-base-uncased`, 1 epoch) | Script output `distilbert_model/` | **No artifact in the repository** | n/a | Not recorded | `train_distilbert*.py` |
| Original notebook model | `GradientBoostingClassifier`, 21 UCI-style features | `../projectcopy/url/Phishing_model.pkl` (outside the repository) | Unused | Kaggle `phishing.csv` | Not verified here: the path does not exist on this machine | Replaced; cannot load in scikit-learn ≥ 1.4 (`docs/dataset.md`) |

Notes:
- The three XGBoost `.joblib` files load and predict, but `get_params()` fails with the installed xgboost
  (`'XGBModel' object has no attribute 'feature_weights'`), a version mismatch.
- The research models need stored dataset columns (including page HTML features and the leaky similarity
  index), so they cannot score a new URL. Their near-perfect scores show the leakage, not real-world ability.
- **Do not compare rows across different splits as if they were equivalent.** v2.0.0 and v1.3.0 share one
  test set; v1.2.0 and v1.1.0 share another; the research models use different files and features.
- Single-row inference: GradientBoosting about 0.3 ms per `predict_proba`, measured in-process
  (`model_inventory.json`, indicative). HistGradientBoosting rows were about 24 ms in the same script,
  because it used the default OpenMP threads rather than the API's `ML_THREADS=1` (see §22 for API
  latency).

**How do you know Flask uses the intended model?** Three checks:
- `GET /api/model-info` returns `GradientBoostingClassifier`, version `2.0.0`, view `registrable`, and
  thresholds 0.5200 / 0.6443 (verified against the real server on 2026-10-29);
- every prediction carries `model_version`, which the extension's warning page displays;
- the predictor refuses a model whose feature schema differs.

## 17. Model-selection rationale

Recorded in `models/model_metadata.json` (`selection_criteria`, `candidates`):

1. **Candidates:**
   - 6 families: logistic regression, decision tree, random forest, gradient boosting, histogram gradient
     boosting, and a larger histogram gradient boosting;
   - × 2 weightings (none, balanced sample weights) = 12 candidates;
   - all on the same training split.
2. **Metric:** validation **recall at each model's own 5% false-positive-rate threshold**. Every model is
   compared at the same false-alarm rate, so calibration differences don't matter.
3. **Rule:** keep the incumbent (`hist_gradient_boosting__balanced`, the v1.1.0 configuration) unless a
   challenger's recall gain is significant in a paired, class-stratified bootstrap of the validation set.
4. **Deployment check:** the validation FPR on legitimate URLs **with a subdomain** must be ≤ 2× the overall
   FPR (`MAX_SUBDOMAIN_FPR_RATIO`). v2.0.0: 0.95% vs 4.99% (ratio 0.19), **passes**. The host-view
   alternative fails: 17.8% vs 4.99%.
5. **Result:** `gradient_boosting__none` gained +0.1395 recall (95% CI [+0.1317, +0.1482]) over the
   incumbent at 5% FPR on validation (0.5675 vs about 0.43), so it was selected.

Validation recall at the 5% FPR cap, from the metadata:

| Candidate | none | balanced |
|---|---|---|
| Logistic regression | 0.287 | 0.286 |
| Decision tree | 0.424 | 0.426 |
| Random forest | 0.426 | 0.424 |
| **Gradient boosting** | **0.567** | 0.433 |
| HistGradientBoosting | 0.429 | 0.428 (incumbent) |
| HistGradientBoosting (large) | 0.426 | 0.425 |

**Why Gradient Boosting?**
- It builds many small decision trees, each correcting the previous ones' mistakes.
- It handles features on different scales without normalisation and captures interactions, such as "a long
  domain **and** a rare TLD".
- Here it had the highest validation recall at equal false alarms, by a statistically significant margin.
- Single-row inference is fast (about 0.3 ms).

**Thresholds** (`thresholds` in the metadata):
- **Flag threshold 0.5200:** the lowest threshold whose validation FPR is ≤ 5% ("at most 1 in 20
  legitimate URLs flagged").
- **High-confidence threshold 0.6443:** the lowest threshold with ≥ 95% validation precision.

| Phishing probability P | Prediction | Risk level |
|---|---|---|
| P < 0.5200 | Safe | Low |
| 0.5200 ≤ P < 0.6443 | Suspicious | Medium |
| P ≥ 0.6443 | Phishing | High |

The extension's interstitial is shown only for High. **The thresholds were not changed for the extension or
the demo.**

## 18. Evaluation results and confusion matrix

**Metrics in simple terms** (phishing is the "positive" class):
- **Accuracy:** the fraction of all URLs labelled correctly. It can mislead when the classes are unbalanced.
- **Precision:** of the URLs we flagged, how many really were phishing? A high value means few false alarms.
- **Recall (detection rate):** of the real phishing URLs, how many did we catch?
- **F1-score:** a single number balancing precision and recall (their harmonic mean).
- **ROC-AUC:** the probability that a random phishing URL gets a higher score than a random legitimate one.
  It does not depend on the threshold; 0.5 is chance and 1.0 is perfect.
- **False-positive rate (FPR):** the fraction of legitimate URLs wrongly flagged.
- **Calibration:** whether "score 0.8" means about 80% of such URLs really are phishing.
- **Inference latency:** time per prediction. It is different from API latency, which includes HTTP and the
  database, and from end-to-end extension time, which also includes the browser.

**v2.0.0 held-out test results** (evaluated once, threshold 0.5200, n = 23,055; reproduced exactly on
2026-10-29):

| Accuracy | Precision | Recall | F1 | ROC-AUC | FPR |
|---|---|---|---|---|---|
| 0.7872 | 0.8801 | 0.5675 | 0.6900 | 0.8524 | 0.0554 |

| | Predicted legitimate | Predicted phishing (Suspicious or Phishing) |
|---|---|---|
| **Actually legitimate** (13,435) | **12,691** true negatives | **744** false positives |
| **Actually phishing** (9,620) | **4,161** false negatives (missed) | **5,459** true positives (caught) |

How to read it:
- 5,459 of 9,620 phishing URLs were caught (recall 56.7%);
- 744 of 13,435 legitimate URLs were wrongly flagged (FPR 5.5%);
- of the 6,203 flagged URLs, 5,459 really were phishing (precision 88.0%).

By risk level (`risk_levels_by_true_class`):
- phishing → Safe 4,161 / Suspicious 498 / Phishing 4,961;
- legitimate → Safe 12,691 / Suspicious 467 / Phishing 277.

So the **High** level that triggers the extension's warning was given to 4,961 phishing and 277 legitimate
test URLs.

The validation results (used for decisions) are similar: recall 0.5675, FPR 0.0499, precision 0.9047,
ROC-AUC 0.8581. Similar validation and test results mean the model is not overfitting to the validation set.

**Calibration** (`docs/data/calibration.json`, validation, historical): v2.0.0 has ECE 0.061 and Brier score
0.156. It is **not well calibrated**: for example, URLs scored 0.5–0.6 were phishing 83% of the time. So the
score is a ranking signal, not a literal probability. The UI calls it "model confidence" or "model phishing
score".

**Why is recall not higher?**
- Many phishing URLs use domains that look ordinary: shared hosting, compromised sites, plain words.
- From the domain name alone they look like legitimate sites.
- Recall was also deliberately traded for fewer false alarms on legitimate subdomain sites (v1.3.0 → v2.0.0:
  0.6801 → 0.5675).

## 19. Chrome extension architecture

**Simple idea.** A Chrome extension is a bundle of HTML, JavaScript and a `manifest.json` describing what it
may do. *Manifest V3* (MV3) is the current format: background code runs in a **service worker**, which Chrome
starts when an event arrives and stops when idle.

| Part | Role |
|---|---|
| `manifest.json` | Permissions `tabs`, `storage`; `host_permissions` for the API origin only; `background.service_worker`; popup; CSP `script-src 'self'` |
| `config.js` | `API_BASE`, timeouts, defaults |
| `scan-core.js` | `callApi(url, record)`: POST with `credentials: "omit"`, 8 s timeout, and strict response checks (`success === true`, a known prediction, and the matching risk level) |
| `background.js` | Listens to `tabs.onUpdated`, `onActivated`, `onReplaced`, `onRemoved` and `storage.onChanged`; caches per origin; sets the badge; redirects High results to `warning.html`; handles the warning page's messages |
| `warning.html/js` | The interstitial |
| `safe.html` | Local fallback |
| `popup.html/js` | Manual scan (full URL, stored), the automatic status line and two settings |

Communication:
- popup and worker → Flask: `fetch` to `API_BASE` (allowed by `host_permissions`, no CORS needed);
- warning page and popup → worker: `chrome.runtime.sendMessage`;
- worker → tab: `chrome.tabs.update`.

The worker accepts messages only from its own extension pages. There are no content scripts, so no web page
can talk to it.

## 20. Automatic warning and Continue Anyway workflow

```
user opens https://secure-login-verify-account.example/login
 1 tabs.onUpdated(url)                         background.js handleNavigation
 2 skip? chrome://, file://, data:, javascript:, the API's own pages, extension pages → yes: no request
 3 origin = https://secure-login-verify-account.example
 4 cache (storage.session, 5 min)? → hit: reuse result, no API call
 5 badge "…" ; scanOrigin → POST /api/predict {"url": origin + "/", "source": "extension", "record": false}
 6 response: prediction Phishing, risk_level High, P 0.8387
 7 stale? (newer navigation of this tab, or the tab is no longer on this origin) → drop
 8 High and no bypass → store warning {url, origin, result} for this tab; badge HIGH
 9 chrome.tabs.update(tab, warning.html)
10 warning page → warning:get → shows host, URL, verdict, risk, score, reasons, disclaimer
   ├─ Go Back to Safety → tab's lastSafeUrl (last page checked successfully and not High) or safe.html
   └─ Continue Anyway   → bypass {origin, expires: now + 30 min} for THIS tab → navigate to stored URL
                          → step 8 sees the bypass: badge HIGH "You chose Continue Anyway", no redirect
11 the tab leaves the origin → bypass removed; coming back later warns again
```

Guarantees and limits:
- An unchecked or failed page is **never** shown as low risk: the badge is `?` or `N/A`.
- The user is never trapped: both buttons work even when automatic checks are off, and if the worker cannot
  be reached the page falls back to `safe.html`.
- **Not guaranteed:** blocking before the page loads. The warning appears after navigation starts
  (`docs/extension.md`, "What Manifest V3 can and cannot guarantee").
- The browser's Back button from the warning page returns to the flagged page, which is warned again; use
  Go Back to Safety.

## 21. Security and privacy

| Threat | Simple explanation | Protection in this project (verified in code and tests) |
|---|---|---|
| **SSRF** (server-side request forgery) | Tricking a server into requesting internal URLs | The server **never fetches or resolves** a submitted URL; features come from the string. Private and internal hosts are rejected anyway. `test_security.py::test_scanning_never_opens_network_connections` patches sockets and DNS to fail during scans. |
| **XSS** (cross-site scripting) | Getting the page to run injected JavaScript | `textContent` only, no `innerHTML` (enforced by `test_client_code.py`); CSP `script-src 'self'`; URLs shown as text, never as links; browser tests inject `"><img onerror=…>` and check nothing runs, also on the warning page |
| **SQL injection** | Smuggling SQL through inputs | Every value is a bound parameter (`database/repository.py`); LIKE wildcards escaped; ids validated (`test_security.py::test_sql_injection_*`) |
| Malformed requests | Broken or unexpected input | JSON-object check, allowed fields, type checks, 16 KB body limit (413), 2,048-character URL limit |
| Abuse | Flooding the API | 60 predictions per minute per client (429 with `Retry-After`) |
| CORS | Other websites calling the API from your browser | No cross-origin access unless an exact origin is in `CLIENT_ORIGIN`; `*` is refused |
| Information leaks | Exposing internals | Generic JSON errors; `Server: phishing-detector`; debug off by default. Under the dev server Werkzeug adds its own version header too (observed). |
| Secrets | Keys in code | Environment variables only; `.env` git-ignored; scanned URL secrets redacted before storage |
| Extension permissions | Over-broad access | `tabs`, `storage` and the API origin only; no content scripts, `<all_urls>`, cookies, history or scripting |
| Extension redirect abuse | Making the warning page open an attacker's URL | Targets come only from the tab's own stored state, never from messages or the API |

Privacy summary:
- **Automatic checks** send only the origin, and nothing is stored by default.
- **Manual popup scans** send the full URL, which is stored with query values redacted.
- **No page contents, form fields, passwords or cookies** are ever read.
- **Residual risk:** with automatic checks on, whoever runs the API sees which sites are visited. It is
  localhost by default.

## 22. Testing and measured performance

| Test category | What is tested | Test file | Actual result (2026-10-29) | Evidence |
|---|---|---|---|---|
| Feature extractor | Schema, types, ranges, dataset parity | `tests/test_features.py` | 24 passed | pytest run |
| URL handling | Normalisation, held-out URLs | `tests/test_urls.py` | 13 passed | pytest run |
| Pipeline | URL → features → model, train/predict parity, split reproducibility, registrable view, preserved models load | `tests/test_pipeline.py` | 44 passed in the final run (2 failed in earlier runs while two archived TLD files were deleted; see §29) | pytest run |
| Model selection | Threshold rules, bootstrap | `tests/test_model_selection.py` | 7 passed | pytest run |
| Predictor | Loading checks, risk mapping, thread safety | `tests/test_predictor.py` | 12 passed | pytest run |
| API integration | Every endpoint and error | `tests/test_api.py` | 49 passed | pytest run |
| Database | Schema, migration, CRUD, redaction, failures | `tests/test_database.py` | 38 passed | pytest run |
| Security | Rate limit, headers, CORS, SSRF, SQLi, traversal | `tests/test_security.py` | 58 passed | pytest run |
| Client static checks | Manifest permissions, origin-only request, no unsafe DOM | `tests/test_client_code.py` | 7 passed | pytest run |
| Extension logic (**simulated**) | Worker logic with a fake `chrome` API: 47 cases | `tests/extension/background.test.js` via `tests/test_extension_logic.py` | 47/47 passed | `node --test` |
| Extension automatic checks (**real Chrome**) | Badges, warning, Go Back, Continue, failures, stale responses, worker restart | `tests/browser/test_extension_autoscan.py` | 23 passed | pytest (headless Chrome) |
| Extension popup (real Chrome) | Popup results and errors | `tests/browser/test_extension_browser.py` | 14 passed | pytest |
| Web UI (real Chrome) | Pages, XSS, responsiveness | `tests/browser/test_frontend_browser.py` | 21 passed | pytest |
| End-to-end (real Chrome) | Web/extension → API → ML → DB → dashboard | `tests/browser/test_e2e.py` | 21 passed | pytest |
| Acceptance | 13 steps against the real `python app.py` | `docs/testing.md` | 13/13 as expected | `docs/testing.md` |
| Performance | API latency and throughput | `scripts/benchmark_api.py` | see below | `docs/data/performance_2026-10-29_python3.14.json` |

**Performance** (measured 2026-10-29, real `python app.py`, macOS arm64, Python 3.14.8, 200 held-out
test-split URLs; the historical 2026-09-29 Python 3.9.6 numbers are in `docs/data/performance.json`):

| Measurement | 2026-10-29 | 2026-09-29 (historical) |
|---|---|---|
| Server-side extraction + inference, median | 0.49 ms | 0.79 ms |
| `POST /api/predict` with history write, client median (p95) | 1.44 ms (1.69) | 4.17 ms (5.16) |
| `POST /api/predict` without history write, client median | 0.86 ms | 1.81 ms |
| 8 concurrent clients, throughput | 909.4 /s | 862.1 /s |
| Start-up until the model is loaded | 877 ms | 878 ms |

The end-to-end extension response time (navigation → badge) was not benchmarked. In the real-Chrome tests
the badge typically appeared well under the tests' waiting limits, but these were not timing measurements.

## 23. Known limitations

1. **Recall 0.5675:** 43.3% of phishing test URLs are missed. A low-risk result is not a safety guarantee.
2. **URL-only and registrable-domain-only.** The model does not see:
   - subdomains (`login.paypal.com.evil.xyz` is scored as `evil.xyz`);
   - paths, queries or page content;
   - compromised legitimate domains;
   - phishing hosted on platforms that are not in the PSL.
3. **Dataset bias:** the legitimate class consists of popular homepages, and the TLD prior comes from the
   dataset authors' list. Real-world performance on obscure legitimate sites is likely lower.
4. **Five of the 17 inputs carry no information** in the deployed view (§14).
5. **Uncalibrated scores** (ECE 0.061).
6. **The extension warns after navigation starts** and cannot guarantee a block before the page loads.
7. **Privacy trade-off:** automatic checks reveal visited origins to the API operator.
8. **No authentication and a development server.** Not ready for shared or production deployment.
9. **No feedback loop and no retraining from users.**
10. The research-script models are not usable for live URLs; the DistilBERT experiment has no stored
    artifact.

## 24. Future enhancements (not implemented)

- A more representative legitimate class (deep links, subdomains, less popular sites), which addresses the
  root cause in §15.
- Domain age (WHOIS/RDAP), DNS and certificate signals, and reputation feeds, combined with the ML score.
- Optional page-content analysis inside the browser (forms asking for passwords on unknown domains), with
  user consent.
- Score calibration (isotonic or Platt) on validation data, so the score can be read as a probability.
- A user feedback table ("report false positive"), reviewed by people rather than retrained automatically,
  to avoid poisoning.
- Earlier interception with `declarativeNetRequest` for domains already known to be high-risk.
- Production deployment: WSGI server, HTTPS, authentication, a shared rate-limit store, and a privacy notice
  for automatic checks.
- Better phishing-subdomain detection that does not penalise legitimate subdomains, which needs better data.

## 25. Installation and setup

Prerequisites: Python 3.9+ (verified with 3.9.6 historically and 3.14.8 on 2026-10-29), Google Chrome,
optionally Node.js 18+ for the simulated extension tests.

```bash
cd capstone
python3 -m venv .venv && source .venv/bin/activate
python -m pip install -r requirements.txt pytest
```

`scikit-learn==1.6.1` is pinned because the saved model was trained with it.

## 26. How to run the project locally

```bash
source .venv/bin/activate
python app.py                         # http://127.0.0.1:5000  (web UI + API)
# macOS, if port 5000 is taken by ControlCenter/AirPlay:
API_PORT=5051 python app.py           # then use 5051 in extension/config.js and manifest.json
curl -s http://127.0.0.1:5000/api/health      # {"model_loaded": true, "status": "ok"}
```

Open `http://127.0.0.1:5000/` (scanner), `/inspect` and `/dashboard`.

## 27. How to run tests

```bash
python -m pytest                                  # everything: 332 tests (about 85 s)
python -m pytest tests/browser                    # real headless-Chrome tests only
python -m pytest tests/browser/test_extension_autoscan.py   # automatic checks / warning page
node --test tests/extension/                      # simulated extension logic (47 tests)
python scripts/model_inventory.py                 # re-score every model artifact (read-only)
python scripts/benchmark_api.py                   # API latency (overwrites docs/data/performance.json)
```

## 28. How to load the Chrome extension in developer mode

1. Start Flask (§26).
2. Chrome → `chrome://extensions` → switch on **Developer mode**.
3. **Load unpacked** → choose the `extension/` folder.
4. Pin "Phishing URL Scanner (Capstone)". Open any site and watch the badge. Click it for the popup.
5. If Flask runs on another port, edit `API_BASE` in `extension/config.js` and `host_permissions` in
   `extension/manifest.json` to the same origin, then click **Reload**.

## 29. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `python app.py` fails with "Address already in use" on macOS | ControlCenter/AirPlay holds port 5000 | `API_PORT=5051 python app.py` and update the two extension settings |
| Badge shows `?` on every site | API not running, wrong port, or `host_permissions` not matching `API_BASE` | Start Flask, check both extension settings, Reload the extension |
| Badge `N/A` | Localhost, private IP or the scanner's own pages: not checkable by design | n/a |
| Badge `OFF` | Automatic checks switched off in the popup | Tick "Check pages automatically…" |
| Warning keeps reappearing when pressing the browser Back button | The flagged page is behind the warning in history | Use **Go Back to Safety** |
| `/api/health` says `model_loaded: false` | Model, metadata or TLD file missing or incompatible (scikit-learn version) | `pip install -r requirements.txt`; check `models/` |
| `test_preserved_models_still_load` fails | An archived `tld_legitimate_prob.json` is missing from the working tree | `git restore models/previous_v1.2.0/tld_legitimate_prob.json models/alternatives/host_view_v1.3.0/tld_legitimate_prob.json` |
| Browser tests skipped | Chrome not installed | Install Chrome or set `CHROME_PATH` |
| `test_extension_logic.py` skipped | Node.js not installed | Install Node 18+ |
| 429 errors while browsing | Many new sites within a minute (limit 60/min) | Wait; results are cached per site for 5 minutes |

## 30. Glossary

| Term | Meaning |
|---|---|
| Phishing | A fake site or message that tricks people into revealing secrets |
| URL / host / origin | `https://a.example.com:8443/p?q=1`; host = `a.example.com`; origin = `https://a.example.com:8443` |
| Registrable domain (eTLD+1) | The part of a host someone registers, e.g. `example.co.uk` for `www.shop.example.co.uk` |
| Public Suffix List (PSL) | A public list of suffixes like `.com`, `.co.uk`, `firebaseapp.com` under which names are registered |
| TLD | Top-level domain, the last label (`com`, `xyz`) |
| Feature | A number describing the input that the model uses |
| Label | The correct answer in training data (phishing or legitimate) |
| Training / validation / test split | Data to learn from / to make choices on / to measure once at the end |
| Data leakage | Information about the answer reaching training or evaluation unfairly, which inflates scores |
| Overfitting | Memorising training data instead of learning patterns that generalise |
| Threshold | The score above which we flag a URL |
| False positive / negative | A legitimate site flagged / a phishing site missed |
| Precision, recall, F1, ROC-AUC, FPR | See §18 |
| Calibration | Whether scores match real frequencies |
| Gradient Boosting | An ensemble of small decision trees trained one after another to fix earlier errors |
| Bootstrap | Resampling data many times to estimate uncertainty |
| REST API | A web interface where URLs name resources and HTTP methods act on them, returning JSON here |
| Flask / blueprint | Python web framework / a group of routes |
| SQLite / WAL | A file-based database / write-ahead logging, so reads don't block writes |
| Manifest V3 | The current Chrome extension format |
| Service worker | Event-driven background script of an MV3 extension; Chrome stops it when idle |
| Content script | A script an extension injects into web pages. **This project has none.** |
| Badge | The small text on the extension's toolbar icon |
| Interstitial | A full-page warning shown before or instead of the page |
| CSP | Content Security Policy: a header limiting where scripts can come from |
| CORS | Rules about which other websites may call an API from a browser |
| SSRF / XSS / SQL injection | See §21 |

## 31. Viva questions and answers

Format: **Q.** question. **Short:** one sentence for quick revision. **More:** an expanded technical
answer, with file references.

### A. Project fundamentals

1. **Q. What problem does your project solve?**
   **Short:** It gives a fast, privacy-respecting phishing-risk estimate for a website address, in a web app
   and automatically in Chrome.
   **More:** Blacklists miss new domains. Our model scores any domain immediately from its name. The Flask
   API serves the model; the extension warns before high-risk sites (`extension/background.js`).

2. **Q. Why did you choose machine learning?**
   **Short:** Phishing domains share statistical patterns (length, digits, TLD, symbols) that a model can
   learn from about 187,000 labelled examples better than hand-written rules.
   **More:** A model also generalises to unseen domains, which a blacklist cannot. We still report its
   limits honestly (recall 0.5675).

3. **Q. Why not use only a blacklist?**
   **Short:** Blacklists only know reported sites, while new phishing domains appear constantly.
   **More:** The ideal is both. We have an optional Safe Browsing hook (`services/threat_intelligence.py`),
   disabled by default, that would be shown separately and never changes the ML score.

4. **Q. What is your strongest contribution?**
   **Short:** An honest, leakage-controlled evaluation with a measured trade-off, plus a privacy-minimising
   extension.
   **More:** We showed why roughly 99.97% results on this dataset come from a leaky column and dataset bias.
   We grouped splits by registrable domain, fixed a systematic false-positive class, and send only origins
   from the extension (§5).

5. **Q. What is the biggest weakness?**
   **Short:** It misses 43% of phishing URLs, because it sees only the domain name.
   **More:** Phishing on ordinary-looking or compromised domains is indistinguishable by name. The dataset's
   legitimate class is also unrepresentative (§23).

### B. Frontend and JavaScript

6. **Q. How does the web page get a prediction?**
   **Short:** `scanner.js` calls `fetch("POST /api/predict")` with JSON and renders the JSON reply.
   **More:** `main.js` `api()` adds a 15 s timeout, JSON parsing and error codes. The button is disabled
   during a scan to avoid duplicates.

7. **Q. How do you display results safely?**
   **Short:** We only use `textContent` and DOM element creation, never `innerHTML`.
   **More:** Enforced by `tests/test_client_code.py::test_no_unsafe_dom_apis_in_client_code`. Browser tests
   inject markup in URLs and check nothing executes.

8. **Q. Are the dashboard charts real data?**
   **Short:** Yes. They come from `GET /api/stats` and `GET /api/history` over the SQLite table.
   **More:** `dashboard.js` builds SVG charts itself (no external library, allowed by the CSP), and the
   empty and error states show no fabricated values.

9. **Q. What happens in the UI when the API is down?**
   **Short:** The page shows "Service unavailable" and an offline banner; it never shows a fake result.
   **More:** `main.js` `checkHealth()` uses `/api/health`; tested in `test_e2e.py::test_7_api_down`.

### C. Flask and backend

10. **Q. What is Flask's role?**
    **Short:** Flask is the Python web server that hosts the API, serves the pages and runs the model.
    **More:** `backend/__init__.py:create_app` loads the model once, registers blueprints, error handlers
    and security headers.

11. **Q. Where and when is the model loaded?**
    **Short:** Once at start-up from `models/phishing_model.pkl` via `Predictor.from_paths`.
    **More:** Paths come from `config.py`. If loading fails, the app still starts: health reports
    `model_loaded: false` and predict returns 503
    (`test_api.py::test_model_is_loaded_once_at_startup_not_per_request`).

12. **Q. How does Flask invoke the prediction?**
    **Short:** Route → `validate_url` → `PredictionService.predict` → `Predictor.predict` → JSON.
    **More:** See the step-by-step trace in §7.1 and `backend/routes/prediction.py`.

13. **Q. How are errors handled?**
    **Short:** Every error is a JSON `{code, message}` with a proper HTTP status; details are only logged.
    **More:** `backend/utils/errors.py`; tests assert that no traceback or file path appears in responses.

### D. REST APIs and HTTP

14. **Q. What is the purpose of each endpoint?**
    **Short:**
    - `predict` scores a URL;
    - `health` reports liveness;
    - `model-info` and `features` describe the model;
    - `history` and `stats` read and delete scans.

    **More:** See the table in §11.

15. **Q. Why POST for predict and not GET?**
    **Short:** It sends a JSON body and may create a history record, so it is not a safe, repeatable read.
    **More:** It also keeps long URLs and their query strings out of server access logs.

16. **Q. What status codes do you use?**
    **Short:** 200, 400, 404, 413, 415, 422, 429, 500 and 503.
    **More:** For example, 400 `UNSUPPORTED_SCHEME` for `javascript:`, 429 with `Retry-After` for flooding,
    503 when the model or DB is unavailable.

17. **Q. Show a request to the prediction API.**
    **Short:** `curl -X POST http://127.0.0.1:5000/api/predict -H "Content-Type: application/json" -d '{"url":"https://example.com/"}'`.
    **More:** The verified response is in §11.

### E. SQLite and database

18. **Q. Why SQLite?**
    **Short:** A single-file database with no server, built into Python, enough for a local single-user tool.
    **More:** WAL mode lets the dashboard read during writes. A multi-user deployment would move to
    PostgreSQL, and only `database/` would change.

19. **Q. What is stored for each scan?**
    **Short:** The redacted URL, host, prediction, risk, scores, model version, time, source, the 17
    features and the indicators.
    **More:** Never IPs, headers, cookies or page content (`database/models.py`).

20. **Q. How do you prevent SQL injection?**
    **Short:** Every value is passed as a bound parameter, never concatenated into SQL.
    **More:** `database/repository.py`; LIKE wildcards are escaped; ids must be positive integers; tests use
    `' OR 1=1 --`-style payloads.

21. **Q. Does user feedback retrain the model?**
    **Short:** No. There is no feedback feature, and nothing retrains from user actions.
    **More:** Continue Anyway is not stored and does not change scores. Feedback is future work and would be
    reviewed by people, to prevent poisoning.

### F. Machine-learning fundamentals

22. **Q. What is a feature?**
    **Short:** A number describing the input that the model uses, such as domain length.
    **More:** We use 17, defined once in `ml/feature_schema.py` and computed in `ml/feature_extractor.py`.

23. **Q. What is overfitting?**
    **Short:** When a model memorises training data and does worse on new data.
    **More:** We check validation against test. v2.0.0 has validation recall 0.5675 and test recall 0.5675,
    and validation FPR 0.050 against test 0.055, so there is no sign of overfitting to the validation set.

24. **Q. What is data leakage?**
    **Short:** When information about the answer sneaks into training or evaluation, making scores look
    better than reality.
    **More:** Examples here: the `URLSimilarityIndex` column, duplicate URLs across splits, and sibling
    subdomains across splits.

25. **Q. What does the model's probability represent?**
    **Short:** The model's estimate that the domain resembles phishing domains in the training data, used as
    a ranking score.
    **More:** It is not a calibrated probability of real-world phishing (ECE 0.061), and it applies to the
    training distribution.

26. **Q. Is the score calibrated?**
    **Short:** Only approximately: validation ECE 0.061 and Brier score 0.156.
    **More:** For example, URLs scored 0.5–0.6 were phishing 83% of the time on validation
    (`docs/data/calibration.json`). Calibration is listed as future work.

### G. Dataset and preprocessing

27. **Q. Which dataset did you use?**
    **Short:** PhiUSIIL: 235,795 URLs, 0 = phishing and 1 = legitimate.
    **More:** After removing 425 duplicates and 8 invalid URLs: 235,362 rows, 42.7% phishing (§15).

28. **Q. Why split by registrable domain?**
    **Short:** So that no site, including its sibling subdomains, appears in both training and test.
    **More:** The earlier host split let 14.1% of test rows share a registrable domain with training data.
    Now the overlap is 0.

29. **Q. How is URL normalisation done?**
    **Short:** Trim, add `https://` if missing, lower-case the scheme and host, and convert Unicode hosts to
    punycode; the path is kept.
    **More:** `ml/url_utils.py:normalize_url`. Invalid or non-http(s) input raises an error that becomes a
    400.

30. **Q. Which preprocessing is fitted on training data only?**
    **Short:** The TLD prior table, the class weights and the explanation percentiles.
    **More:** Thresholds and model choice use validation only; test is used once (`ml/train_model.py`).

31. **Q. Is the dataset biased?**
    **Short:** Yes. Every legitimate URL is a bare homepage, and 99.7% of legitimate `.com` hosts have no
    subdomain.
    **More:** That is why we ignore paths and score the registrable domain
    (`docs/false_positive_investigation.md`).

### H. Feature extraction

32. **Q. Why are there 17 features?**
    **Short:** They are the dataset's URL-derived features that we could recompute exactly from the URL,
    after excluding 5 leaky or irreproducible ones.
    **More:** Each was checked against all 235,795 stored rows. Under the registrable view, 5 of them are
    constant or redundant (§14).

33. **Q. Which feature matters most?**
    **Short:** `TLDLegitimateProb`, at 45.7% of the model's impurity importance, followed by the digit ratio
    at 17.8%.
    **More:** Measured from `feature_importances_`. This dependence on a dataset-derived TLD prior is a
    limitation to mention.

34. **Q. Why exclude `URLSimilarityIndex`?**
    **Short:** It leaks the label: it is 100 for every legitimate row, and it cannot be computed for new URLs.
    **More:** All 20 research models that used it score about 0.9997–1.0, which shows the leak
    (`docs/data/model_inventory.json`).

35. **Q. Why must inference use the same feature order?**
    **Short:** The model identifies features by position; a different order silently gives wrong inputs.
    **More:** The order lives only in `FEATURE_NAMES`, and the predictor refuses mismatched models.

36. **Q. What is lost by scoring only the registrable domain?**
    **Short:** Subdomains, path, query, scheme, port and userinfo.
    **More:** So `login.paypal.com.evil.xyz` is judged as `evil.xyz`. A rule-based observation warns about
    the embedded domain but does not change the score.

### I. Model algorithms and selection

37. **Q. Why Gradient Boosting?**
    **Short:** It had the highest validation recall at the same 5% false-alarm rate, by a statistically
    significant margin.
    **More:** +0.1395 recall over the incumbent (95% CI [0.1317, 0.1482]). It is also fast: about 0.3 ms per
    row.

38. **Q. Which alternatives were tested?**
    **Short:** Logistic regression, decision tree, random forest and two histogram gradient boosting
    variants, each with and without class weighting: 12 candidates.
    **More:** The host-view model (v1.3.0) and earlier versions are preserved too (§16).

39. **Q. Why not the host-view model, which has higher recall (0.68)?**
    **Short:** It flagged 17.8% of legitimate subdomain sites, failing our stated deployment rule.
    **More:** The rule was decided on validation data before testing: subdomain FPR ≤ 2× overall FPR.

40. **Q. How did you choose the threshold?**
    **Short:** The lowest threshold that keeps validation false positives at or below 5%: 0.5200.
    **More:** "Phishing (high)" starts at 0.6443, where validation precision is at least 95%. These were
    chosen before the test was run.

41. **Q. How do you reproduce the evaluation?**
    **Short:** `python -m ml.train_model` retrains deterministically (seed 42);
    `python scripts/model_inventory.py` re-scores the saved models.
    **More:** On 2026-10-29 the saved models reproduced their recorded test metrics exactly. Retraining
    under Python 3.14 also gave identical test metrics.

### J. Evaluation metrics and confusion matrix

42. **Q. What is a false positive?**
    **Short:** A legitimate site flagged as phishing: 744 of 13,435 in our test set (5.5%).

43. **Q. What is a false negative?**
    **Short:** A phishing site the model missed: 4,161 of 9,620 (43.3%).

44. **Q. What is the difference between precision and recall?**
    **Short:** Precision asks how many flagged sites are really phishing (88.0%); recall asks how many
    phishing sites we caught (56.7%).

45. **Q. What does the confusion matrix show?**
    **Short:** Correct and incorrect predictions per class: TN 12,691, FP 744, FN 4,161, TP 5,459.

46. **Q. Why is your recall not higher?**
    **Short:** Many phishing domains look ordinary by name, and we traded some recall for fewer false alarms
    on legitimate subdomains.
    **More:** v1.3.0 → v2.0.0: 0.68 → 0.57. Domain-only features lack the needed information (§18).

47. **Q. Why do false positives matter?**
    **Short:** Users quickly ignore a warning that fires on real sites, so false alarms destroy trust.
    **More:** That is why we cap validation FPR at 5% and why we fixed the subdomain false positives.

48. **Q. Why is accuracy 0.79 but ROC-AUC 0.85?**
    **Short:** Accuracy is measured at one threshold; ROC-AUC measures ranking across all thresholds.

### K. Chrome Manifest V3 extension

49. **Q. How does the extension scan automatically?**
    **Short:** Its service worker listens to `tabs.onUpdated` and `onActivated`, then sends the page's
    origin to the API.
    **More:** `extension/background.js:handleNavigation`. Results are cached per origin for 5 minutes, and
    stale responses are dropped.

50. **Q. How do Go Back to Safety and Continue Anyway work?**
    **Short:** Go Back opens the tab's last checked non-high-risk page, or a local safe page. Continue
    allows the site once, in that tab only, until you leave it.
    **More:** Targets come from the extension's stored state, never from messages or the API. The bypass
    lasts at most 30 minutes and never changes the score (§20).

51. **Q. Does the extension inspect passwords or page contents?**
    **Short:** No. It has no content scripts and cannot read pages; it only reads tab URLs.
    **More:** Automatic checks send only the origin; the manifest lists only `tabs` and `storage`
    (enforced by `test_client_code.py`).

52. **Q. Does it block a page before it loads?**
    **Short:** No. It warns as soon as Chrome reports the navigation, so the page may start loading first.
    **More:** A pre-load block would need a decision before the request is sent. We document this honestly.

53. **Q. What happens when Flask is offline?**
    **Short:** The badge shows `?`, "could NOT be checked". It is never shown as safe, and the page is not
    blocked.
    **More:** Tested in real Chrome for down, timeout, non-JSON and invalid JSON
    (`test_api_failure_is_reported_as_not_checked`).

54. **Q. What happens if Chrome stops the service worker?**
    **Short:** State lives in `chrome.storage.session` and listeners are top-level, so the restarted worker
    continues.
    **More:** Tested with `ServiceWorker.stopAllWorkers` in real Chrome.

55. **Q. Why the `tabs` permission?**
    **Short:** To read tab URLs on navigation without a click; it gives no access to page content.
    **More:** Version 1.1.0 used only `activeTab` (scan on click). Automatic warnings need `tabs`, which is a
    privacy trade-off that we mitigate.

### L. Security and privacy

56. **Q. How do you prevent SSRF?**
    **Short:** The server never fetches or resolves submitted URLs; it only analyses the string.
    **More:** A test makes all sockets and DNS fail during scans and checks that scans still work.

57. **Q. How do you prevent XSS?**
    **Short:** We never use `innerHTML`, we have a strict CSP, and URLs are text, never links.

58. **Q. What data leaves the user's computer?**
    **Short:** Only URLs (origins for automatic checks) go to the project API, which is localhost by default.
    **More:** The optional Safe Browsing lookup, off by default, would send scanned URLs to Google.

59. **Q. What security is missing?**
    **Short:** Authentication, HTTPS deployment and a production server.
    **More:** Anyone who can reach the API can read or clear the history; this is acceptable only for local
    use.

### M. Testing and performance

60. **Q. How did you test the extension?**
    **Short:** With 23 real headless-Chrome tests plus 47 simulated logic tests.
    **More:** Real Chrome loads the unpacked extension over the DevTools protocol, the API is a recording
    proxy in front of the real model, and pages are served by request interception. The simulated tests run
    the real `background.js` with a fake `chrome` API.

61. **Q. Do all tests pass?**
    **Short:** In the final run, all 332 passed after the two archived TLD files were restored; earlier runs
    had 2 failures caused only by those deleted files.
    **More:** See `docs/IMPLEMENTATION_AND_VALIDATION_REPORT.md`. Skipped tests are not counted as passed;
    there were 0 skipped.

62. **Q. How fast is a prediction?**
    **Short:** About 0.5 ms on the server and about 1.4 ms per API call including the database write
    (2026-10-29).
    **More:** These are API latency numbers; ML metrics, throughput (909 per second with 8 clients) and
    extension end-to-end time are different things.

### N. Research contribution and limitations

63. **Q. Why can legitimate websites be flagged?**
    **Short:** Their domain may share traits with phishing domains in the data: a rare TLD, digits or
    hyphens.
    **More:** 277 legitimate test URLs reached High. The warning page therefore says it may be wrong.

64. **Q. Why is a URL-only model limited?**
    **Short:** Many phishing sites use normal-looking or compromised domains, and the URL alone cannot reveal
    that.

65. **Q. Your earlier version had 0.74 recall. Did the project get worse?**
    **Short:** Its test set had leakage between sibling subdomains, and it systematically flagged legitimate
    subdomain sites. The new number is lower but more honest.
    **More:** On the same test set, the host view gives 0.68 against 0.57 for the registrable view: a stated
    trade-off.

### O. Future work and difficult reviewer questions

66. **Q. What would you improve with more time?**
    **Short:** Better legitimate data, domain-age and reputation signals, calibration, and optional in-browser
    page signals.

67. **Q. A student says 99.9% accuracy is easy on this dataset. Why is yours 79%?**
    **Short:** We showed that 99.9% comes from a leaky column and homepage bias; with honest features and
    splits, about 79% is what remains.

68. **Q. How do you know the extension uses the intended model?**
    **Short:** The warning page shows `model_version` 2.0.0 from the API, and `/api/model-info` confirms
    `GradientBoostingClassifier` v2.0.0.

69. **Q. Can an attacker bypass your system?**
    **Short:** Yes. They can host on a trusted platform or a compromised domain, or use a plain domain name.
    **More:** This is why it is a risk signal to combine with other defences, not a guarantee.

70. **Q. If you cut 5 constant features, would the model change?**
    **Short:** Its predictions would not change materially, because those features have zero importance;
    they are kept for one shared schema across model versions.
    **More:** Not re-trained to confirm; it would be a reproducible experiment with the same split and seed.

## 32. Review-2 presentation speaking notes

See `docs/REVIEW_2_VIVA_PREPARATION.md` for timed scripts and the demo. Key messages:
1. Problem and why an honest evaluation matters.
2. Architecture: Flask API is the single source of truth; web UI, dashboard and extension all call it.
3. ML: 17 URL features, registrable-domain view, grouped split, validation-only decisions, test once.
4. Results: recall 0.57, precision 0.88, FPR 5.5%, ROC-AUC 0.85. Say plainly what is missed.
5. Extension: automatic check → badge → warning → Go Back or Continue, privacy by design.
6. Testing: 332 tests including real Chrome; acceptance on the real server.
7. Limitations and future work.
