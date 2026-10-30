# Testing

## Running the tests

```bash
source .venv/bin/activate
python -m pytest              # everything (about 70 s)
python -m pytest tests/browser                # real-browser tests only
node --test tests/extension/                  # simulated extension-logic tests only (Node.js 18+)
BROWSER_ARTIFACTS=/tmp/shots python -m pytest tests/browser   # also save screenshots
```

Browser tests drive the installed Google Chrome (or `CHROME_PATH`) headlessly
over the DevTools protocol (`tests/browser/cdp.py`, standard library only).
They are **skipped automatically** if Chrome isn't installed. Each test starts
its own Flask server on a free port with a temporary SQLite file, so the real
`instance/` database is never touched.

## Automated suite: 332 tests (latest run: 332 passed, 0 failed, 0 skipped)

Latest full run (2026-10-29, extension 2.0.0 and model v2.0.0; macOS arm64, Python **3.14.8** in `.venv`,
scikit-learn 1.6.1, Google Chrome headless, Node.js 26 for the simulated extension tests): **`332 passed in
86.10s`**.

Three earlier runs the same day gave identical results each time, `2 failed, 330 passed`, so there were no
flaky tests. Those 2 failures were **not caused by code**. `tests/test_pipeline.py::test_preserved_models_still_load` (two
parameters) loads every archived model with its TLD table, and in the working tree two archived files are
deleted but not committed:
- `models/previous_v1.2.0/tld_legitimate_prob.json`
- `models/alternatives/host_view_v1.3.0/tld_legitimate_prob.json`

The two files were later restored in the working tree (byte-identical to `HEAD`), and the final run above
passed completely. Before the extension work started, the suite had `2 failed, 305 passed` for the same
reason.

The earlier record of `307 passed` (2026-09-29) was measured with Python 3.9.6 before those files were
deleted.

| File | Tests | Covers |
|---|---|---|
| `tests/test_features.py` | 24 | Feature schema, extractor, types/ranges, dataset parity |
| `tests/test_urls.py` | 13 | URL normalisation, model on held-out URLs |
| `tests/test_pipeline.py` | 44 | URL → features → model end to end, train/predict parity, split reproducibility, metadata, registrable-domain view (subdomains cannot change the score, PSL cases, observations), preserved models load |
| `tests/test_model_selection.py` | 7 | Threshold rules, bootstrap selection, recorded decision |
| `tests/test_predictor.py` | 12 | Predictor loading checks, risk mapping, thread count does not change predictions |
| `tests/test_api.py` | 49 | Every endpoint, error contract and leak checks, extractor/model failure, model loaded once, OpenMP limit in request threads |
| `tests/test_database.py` | 38 | Schema/migration, CRUD, pagination, filters, invalid ids, long/duplicate URLs, redaction, database failure |
| `tests/test_security.py` | 58 | Rate limit, headers, CORS, no network access, internal hosts, SQL injection, path traversal, reflection, debug off, leak checks |
| `tests/test_client_code.py` | 7 | Extension manifest and permissions, origin-only automatic request, single API config, no unsafe DOM APIs / inline scripts / secrets |
| `tests/test_extension_logic.py` | 1 (runs 47 Node tests) | **Simulated**: `tests/extension/background.test.js` runs the real `background.js` with a fake `chrome` API (skipped if Node.js is missing) |
| `tests/browser/test_frontend_browser.py` | 21 | Web UI (Phase 4); see `docs/frontend.md` |
| `tests/browser/test_extension_browser.py` | 14 | Extension popup (automatic checks off in this build); see `docs/extension.md` |
| `tests/browser/test_extension_autoscan.py` | 23 | **Real Chrome**: automatic checks, warning page, Go Back to Safety, Continue Anyway, failures, stale responses, service-worker restart; see `docs/extension.md` |
| `tests/browser/test_e2e.py` | 21 | Integration (Phase 6), below |

## End-to-end tests (`tests/browser/test_e2e.py`)

| # | Scenario | Test | What is checked |
|---|---|---|---|
| 1, 3 | Frontend → API → ML → database → dashboard | `test_1_3_frontend_scan_is_stored_and_shown_on_dashboard` | UI result equals the stored row (source `web`), stored URL is redacted, dashboard row and counters appear |
| 2 | Extension → API → ML → result | `test_2_extension_and_web_app_agree` | Popup and web page show identical prediction, risk, confidence and verdict; both rows stored with the same probability |
| 4 | Multiple consecutive scans | `test_4_consecutive_scans` | 9 UI scans in order; history order; recent-scans list |
| 5, 10, 11 | Invalid, too long, unsupported URLs | `test_5_10_11_bad_urls_rejected_by_live_api`, `test_10_long_url_in_ui` | Live server returns the right 400 code; UI shows the message |
| 6 | Malformed requests | `test_6_malformed_requests` | Broken JSON, array, wrong type, manual features, form body, 20 KB body → 400/415/413 |
| 7 | API unavailable | `test_7_api_down` | Server stopped with the page open → "Service unavailable" and banner |
| 8 | Database failure | `test_8_database_failure` | Unusable DB path: scan still works, "could not be saved" note, dashboard shows history unavailable |
| 9 | Model loading failure | `test_9_model_loading_failure` | Missing model file: health `model_loaded: false`, banner, "Model not available", 503 without a file path |
| 12 | Concurrent / repeated requests | `test_12_concurrent_requests`, `test_12_rate_limit_on_live_server` | 60 predictions over 12 threads plus 20 concurrent reads: all 200, 60 unique rows; rate limit gives 5×200 then 429 |

## Extension 2.0.0 acceptance walkthrough (2026-10-29)

Run against the **real** `python app.py` (port 5051, because macOS ControlCenter holds port 5000), in headless
Chrome. The extension copy differed from `extension/` only in `API_BASE`/`host_permissions` (5051) and
`AUTO_SCAN_DEFAULT`, checked with `diff -r`. Web pages were served by request interception, and the "high-risk"
sites were synthetic `.example` names, so no real or malicious site was contacted.

| Step | Result |
|---|---|
| 1. `https://www.wikipedia.org/` | Badge `LOW`, tooltip "…not a guarantee that it is safe." |
| 2. `https://shop.example/` | Badge `MED`, tab not redirected |
| 3. `https://secure-login-verify-account.example/login` | Tab moved to `warning.html`: host, "Phishing-risk prediction (high)", High, score 0.84, model 2.0.0 |
| 4. Go Back to Safety | Returned to `https://shop.example/` (the previous checked page) |
| 5. Continue Anyway | Stayed on the flagged URL after 1.5 s; badge `HIGH`, "You chose Continue Anyway…" |
| 6. Same site in a second tab | Warned again (the bypass is tab-specific) |
| 7. Go Back with no previous page | `safe.html` |
| 8. Popup on the allowed tab | "Phishing-risk prediction (high)"; automatic line describes the Continue Anyway choice |
| 9–10. History and stats | 4 rows, all `source=extension`, origin-only URLs for automatic checks; by_prediction Safe 1, Suspicious 1, Phishing 2 |
| 11. Model served | `GradientBoostingClassifier` v2.0.0, registrable view, thresholds 0.5200 / 0.6443 |
| 12. Dashboard | 4 rows rendered, no console errors |
| 13. Server stopped | New page: badge `?`, "This site could NOT be checked: Cannot reach the scanner API…"; not redirected, not labelled low risk |

The server log had no errors or tracebacks. Not performed: installing through the native **Load unpacked**
folder picker, and clicking the real toolbar button in a headed browser.

## Manual acceptance walkthrough (performed 2026-09-29)

These are the 15 acceptance steps, run against the **real** `python app.py`
process and real internet pages, with headless Chrome performing the clicks.
Port 5000 on this Mac is held by the macOS AirPlay receiver, so the server ran
on 5051. The extension was loaded unpacked from a copy that differs from
`extension/` **only** in the two documented lines (`API_BASE` and
`host_permissions`), verified with `diff -r`.

| Step | Result |
|---|---|
| 1. Start backend | `/api/health` → `{"status": "ok", "model_loaded": true}` |
| 2. Start frontend | Served by Flask: `GET /` → 200 |
| 3–5. Open scanner, submit `https://www.wikipedia.org/`, receive prediction | "Low-risk prediction", Safe, Low, model confidence 89.3% |
| 6. History record | id 1, source `web`, prediction Safe, confidence 0.8931 |
| 7–8. Dashboard | Total scans 1; the URL appears in the table |
| 9. Install extension | Loaded unpacked |
| 10–11. Open a normal page (real Wikipedia over the internet), click the toolbar action | Popup: "Low-risk prediction", Safe, Low, 89.3% |
| 12. API received the extension request | History id 2, source `extension` |
| 13. Extension result equals web app for the same URL | True |
| 14. Unsupported URLs | Extension on `chrome://version`: "This page cannot be scanned…"; web app with `javascript:alert(1)`: "Only http:// and https:// URLs can be scanned." |
| 15. API failure | Server stopped. Extension: "Cannot reach the scanner API at http://127.0.0.1:5051…"; web app: "Service unavailable" with banner |

The server log contained no errors or tracebacks, only Flask's standard
development-server warning. The Load-unpacked *folder picker* on
`chrome://extensions` is a native dialog and was not automated; the same folder
was loaded with `Extensions.loadUnpacked`.

## Acceptance re-run with model v2.0.0 (2026-09-29, 23:29 IST)

The same 15 steps, real server on port 5051, real internet pages. All passed:
- web and extension both gave `https://www.wikipedia.org/` "Low-risk prediction", Safe, 91.1%;
- the history recorded source `web` then `extension`;
- the extension refused `chrome://version`;
- the API-down message was shown.

Extra check: the extension on `https://admob.google.com/v2/home`, a reported v1.2.0
false positive. In a fresh (logged-out) browser this redirects to
`accounts.google.com/v3/signin/…`, and the extension scanned that current tab URL:
"Low-risk prediction", Safe, 57.9%. `admob.google.com` itself scores Safe
(P 0.421) via the API.

## Performance with model v2.0.0 (`python scripts/benchmark_api.py`, `docs/data/performance.json`)

| Measurement (median) | Value |
|---|---|
| Server-side extraction + inference | 0.79 ms |
| `POST /api/predict` with history write, client (p95) | 4.17 ms (5.16) |
| `POST /api/predict` without history write, client | 1.81 ms |
| 8 concurrent clients: mean / p95 latency | 8.65 / 14.97 ms |
| 8 concurrent clients: throughput | 862.1 /s |
| Start-up until the model is loaded | 878 ms |
| `GET /api/health` / `history` / `stats` | 0.78 / 1.19 / 1.47 ms |

The v2.0.0 model (`GradientBoostingClassifier`) doesn't use OpenMP when
predicting, so `ML_THREADS` has no effect on it; the setting is kept for
HistGradientBoosting models. The v1.2.0 measurements below are preserved in
`docs/data/performance_v1.2.0.json`.

## Performance with model v1.2.0 (historical)

These are real measurements against a real `python app.py` process on loopback
HTTP: 200 held-out test-split URLs, a temporary database, rate limiting off.
The machine is macOS arm64 with 10 cores and Python 3.9.6. Raw results are in
`docs/data/performance.json`.

| Measurement | Before | After `ML_THREADS=1` |
|---|---|---|
| Server-side extraction + inference, median | 4.59 ms | **1.22 ms** |
| `POST /api/predict` with history write, client median / p95 | 6.82 / 8.52 ms | **3.85 / 4.34 ms** |
| `POST /api/predict` without history write, client median | 5.21 ms | **1.94 ms** |
| 8 concurrent clients, mean latency | 190.9 ms | **18.6 ms** |
| 8 concurrent clients, throughput | 41.8 /s | **426.7 /s** |
| Start-up until the model is loaded | 1905 ms | 826 ms (single run; varies with file cache) |
| `GET /api/health`, `/api/history`, `/api/stats`, median | 0.37 / 0.76 / 0.98 ms | 0.38 / 0.77 / 0.99 ms |

**The bottleneck found.** The model (`HistGradientBoostingClassifier`) ran an
OpenMP thread pool sized to all 10 cores for every single-row prediction. With
concurrent requests those pools oversubscribed the CPU.

**The fix.** `app.py` sets `OMP_NUM_THREADS=1` (`ML_THREADS`) before
scikit-learn loads. A first attempt with `threadpoolctl` inside
`create_app` had no measurable effect: an OpenMP thread count is per-thread
state and didn't reach Flask's request threads. That result is why the final
fix uses the environment variable, and a test now checks the count from a new
thread in a fresh process.

Supporting checks:
- `test_predictor.py::test_thread_limit_does_not_change_predictions` confirms
  that the thread count doesn't change predictions.
- `test_api.py::test_model_is_loaded_once_at_startup_not_per_request` confirms
  the model is loaded once at start-up, not per request.
