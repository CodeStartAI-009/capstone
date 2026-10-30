# Implementation and Validation Report (2026-10-29)

Scope of this round:
- automatic phishing warnings in the Chrome extension (Phase 2);
- a complete model audit (Phase 3);
- the knowledge and viva documentation (Phases 4–11);
- validation (Phase 12).

Nothing was committed or pushed. All changes are in the working tree on `main`.

## 1. Starting point (audit before editing)

| Area | State found |
|---|---|
| Git | `main`, up to date with `origin/main`. Uncommitted: deletion of `models/previous_v1.2.0/tld_legitimate_prob.json` and `models/alternatives/host_view_v1.3.0/tld_legitimate_prob.json`; untracked `docs/CP1_Phase3_Workbook_Filling_Guide.pdf` (left untouched) |
| Tests | `2 failed, 305 passed`. Both failures were `test_preserved_models_still_load`, caused by the two deleted TLD files |
| Extension | v1.1.0: popup only (`activeTab`). No automatic scanning, no warning page |
| Feedback | Not implemented anywhere (no table, endpoint or UI) |
| Inconsistencies | README said the v2.0.0 test split has 23,536 URLs (the metadata says 23,055); `/api/model-info` described v2.0.0's split as "host-grouped" (it is registrable-domain-grouped); docs list Python 3.9.6 but `.venv` is Python 3.14.8 |

## 2. Files changed

**Extension (new behaviour)**

| File | Change |
|---|---|
| `extension/background.js` | **New.** Service worker: automatic checks on `tabs.onUpdated` / `onActivated` / `onReplaced`; origin-only requests; per-origin cache in `storage.session`; in-flight de-duplication; stale-response protection; badges; High → `warning.html`; Go Back / Continue handlers; sender checks on messages |
| `extension/scan-core.js` | **New.** `callApi`, `unsupportedReason` and `ScanError`, moved out of `popup.js` so the popup and the worker share them. It now also checks that `risk_level` matches `prediction` |
| `extension/warning.html`, `warning.js`, `warning.css` | **New.** "Potential Phishing Risk" interstitial |
| `extension/safe.html` | **New.** Local fallback for Go Back to Safety |
| `extension/manifest.json` | Version 2.0.0; permissions `tabs`, `storage` (was `activeTab`); `background.service_worker`; `minimum_chrome_version` 116 |
| `extension/config.js` | Added `AUTO_SCAN_DEFAULT`, `RECORD_AUTO_SCANS_DEFAULT`, `SCAN_CACHE_TTL_MS`, `BYPASS_TTL_MS` |
| `extension/popup.html/js/css` | Uses `scan-core.js`; shows the tab's automatic-check status; two settings (automatic checks on/off, save automatic checks to history) |

**Backend**

| File | Change |
|---|---|
| `services/prediction_service.py` | `/api/model-info` `evaluation.split` now comes from the metadata, so v2.0.0 is no longer described as "host-grouped" |

**Tests**

| File | Change |
|---|---|
| `tests/extension/harness.js`, `tests/extension/background.test.js` | **New.** 47 simulated tests (Node, fake `chrome` API) |
| `tests/test_extension_logic.py` | **New.** Runs the Node tests under pytest (skipped without Node) |
| `tests/browser/test_extension_autoscan.py` | **New.** 23 real headless-Chrome tests |
| `tests/browser/test_extension_browser.py` | The test build sets `AUTO_SCAN_DEFAULT = false`, so the popup tests are not affected by automatic checks. The `chrome://` / `about:` / `data:` expectations were updated: with `tabs` the popup now names the page type |
| `tests/test_client_code.py` | New permission set and the checks for it; origin-only automatic request; all extension HTML pages checked for inline scripts |

**Scripts and data**

| File | Change |
|---|---|
| `scripts/model_inventory.py` | **New.** Read-only re-scoring of every model artifact |
| `docs/data/model_inventory.json` | **New.** Its output |
| `docs/data/performance_2026-10-29_python3.14.json` | **New.** Benchmark run. The historical `docs/data/performance.json` was kept unchanged |

**Documentation**

| File | Change |
|---|---|
| `docs/PROJECT_KNOWLEDGE_AND_VIVA_GUIDE.md` | **New** |
| `docs/REVIEW_2_VIVA_PREPARATION.md` | **New** |
| `docs/IMPLEMENTATION_AND_VALIDATION_REPORT.md` | **New** (this file) |
| `docs/extension.md` | Rewritten |
| `docs/security.md` | Rows 7 and 16 updated, row 20 added, residual risks extended |
| `docs/database.md`, `docs/testing.md`, `docs/architecture.md`, `docs/api.md`, `README.md`, `extension/README.md` | Updated |
| `docs/REVIEW_2_AND_VIVA_GUIDE.md`, `docs/VIVA_QUICK_REFERENCE.md`, `docs/PROJECT_KNOWLEDGE_MAP.md` | A dated note that their extension sections are out of date |

**Not changed by this work:**
- no file in `models/` and no dataset file;
- no thresholds;
- no API endpoint or request/response contract (the extension uses the existing `POST /api/predict`).

## 3. Changes made by someone else during this session (not by this work)

Between 18:28 and 18:44 IST, while this work was editing documentation, another process in the same
project did the following:
- ran the README's ML pipeline: `scripts/dataset_audit.py`, `python -m ml.train_model`,
  `ml.view_experiment`, `ml.evaluate_model` and `ml.error_analysis`. This rewrote
  `models/phishing_model.pkl`, `models/model_metadata.json`, `models/tld_legitimate_prob.json`,
  `docs/data/{dataset_audit,error_analysis,evaluation,view_experiment}.json` and
  `docs/model_evaluation_tables.md`;
- restored the two deleted archived TLD files;
- started a `python app.py` on `127.0.0.1:5000`.

These changes were inspected and **left as they are**:
- The retrained model is the same configuration (`gradient_boosting__none`, v2.0.0, threshold 0.5200345…).
- Its recorded test accuracy, precision, recall, F1, ROC-AUC and confusion matrix are **identical** to the
  committed metadata.
- Only `trained_at` (2026-10-29T13:01:08Z), the environment (Python 3.14.8, numpy 2.5.3) and the pickle bytes
  differ.
- The restored TLD files are byte-identical to `HEAD`.

Decide whether to keep or `git restore` these files before committing. Restoring them returns the committed
2026-09-29 artifacts; keeping them records a reproducibility retrain under Python 3.14.

## 4. Features implemented

| Requirement | Implemented as | Verified by |
|---|---|---|
| Automatic scan on navigation | `tabs.onUpdated` → `handleNavigation` | Real Chrome: `test_low_risk_page_is_checked_automatically_sending_only_the_origin`; acceptance step 1 |
| Scan when the active tab changes | `tabs.onActivated`: scans tabs never checked (or whose check failed); otherwise re-shows the badge | Real Chrome: `test_tab_switch_checks_a_tab_that_was_not_checked_yet`; simulated |
| SPA URL changes | `onUpdated` with a new `url` (pushState); same origin → cache | Real Chrome: `test_repeated_navigation_to_one_site_is_scanned_once`; simulated |
| No duplicate scans | Per-origin cache (5 min, `storage.session`) + in-flight map | Real Chrome and simulated (two tabs, one request) |
| Unsupported schemes ignored | `unsupportedReason`; extension pages and the API origin skipped | Real Chrome: `chrome://`, `about:`, `data:`, `file:` → 0 requests; simulated: 10 kinds |
| Missing URLs, restricted pages, API failures, timeouts | `?` badge, "could NOT be checked", not cached | Real Chrome: down / slow / HTML / invalid; simulated: 9 failure kinds |
| Service-worker restarts | State in `storage.session`; top-level listeners; origin re-check | Real Chrome: `ServiceWorker.stopAllWorkers` twice; simulated restarts |
| Stale responses | Per-tab navigation token + current-origin check | Real Chrome: `test_stale_response_does_not_redirect_a_tab_that_moved_on`; simulated |
| Only the URL is sent | Origin only for automatic checks, `credentials: "omit"`; no content scripts | Exact request body asserted in real Chrome; static check |
| Enable/disable control | Popup checkbox → `storage.local.autoScan`; badge OFF | Real Chrome and simulated |
| Badge states | `…`, LOW, MED, HIGH, `?`, N/A, OFF | Real Chrome |
| Warning interface | `warning.html`: title, host, URL (text), verdict, risk, score, model input and version, summary, reasons, disclaimer, fixed "may be wrong" note, both buttons | Real Chrome: `test_high_risk_page_is_replaced_by_the_warning_page`, `test_warning_page_renders_the_url_as_inert_text` |
| Go Back to Safety | `lastSafeUrl` of the tab, or `safe.html`; never from a message or the API; no loop | Real Chrome: both cases; simulated: "never returns to high-risk or unchecked" |
| Continue Anyway | Per tab, per origin, at most 30 min; ends on leaving the site; score, cache and history unchanged | Real Chrome: `test_continue_anyway_allows_the_site_once_in_this_tab_only`; simulated: TTL, tab-specific, message URL ignored |
| Redirects | Final committed URL is checked; new high-risk destinations warned | Real Chrome: `test_server_redirect_to_a_high_risk_site_is_warned_about`; simulated |
| Risk-level behaviour | Low: badge; Medium: amber badge, no interstitial; High: interstitial; unavailable: never "safe" | Real Chrome |
| Retry after failure | Failures are not cached; the next navigation or reload retries; the popup has "Scan again". The warning page has no retry button, because it only appears after a successful High result and the model is deterministic | Real Chrome: reload after a failure shows the warning |

**MV3 limitation stated in the UI docs:** the warning appears after the navigation has started. The page may
begin to load before the tab is moved, so the extension does not claim a pre-load block
(`docs/extension.md`).

## 5. Tests run and real results

| Run | Command | Result |
|---|---|---|
| Baseline, before any change | `python -m pytest -q` | `2 failed, 305 passed` (deleted TLD files) |
| After the extension work, 3 runs | `python -m pytest -q -rs` | `2 failed, 330 passed` each time (85–87 s), same 2 failures, 0 skipped |
| Final run, after the archived TLD files were restored by the other process | `python -m pytest -q -rsfE` | **`332 passed in 86.10s`**: 0 failed, 0 skipped |
| Simulated extension logic | `node --test tests/extension/` | `tests 47, pass 47, fail 0` |
| New real-Chrome extension tests | `python -m pytest tests/browser/test_extension_autoscan.py` | `23 passed` |
| Popup + end-to-end real-Chrome tests after the manifest change | `python -m pytest tests/browser/test_extension_browser.py tests/browser/test_e2e.py` | `35 passed` |

**Browser tests actually performed:**
- **Real Chrome** (headless Google Chrome, unpacked extension loaded over the DevTools protocol, pages served
  by request interception): `test_extension_autoscan.py` (23), `test_extension_browser.py` (14),
  `test_e2e.py` (21) and `test_frontend_browser.py` (21).
- **Real Chrome with real DNS** (no interception, scratch script) for non-existent `.example` names, as used
  in the demo script:
  - `https://shop.example/` → badge `MED`;
  - `https://secure-login-verify-account.example/login` → warning page;
  - after Continue Anyway → Chrome's "This site can't be reached" with badge `HIGH`.

  `.example` is reserved and never resolves, so nothing was contacted.
- **Simulated** (no browser): `tests/extension/background.test.js` (47).
- **Not performed:**
  - a headed (visible) browser;
  - the native **Load unpacked** folder picker;
  - clicking the real toolbar button with a mouse;
  - any real phishing site.

## 6. API, model and history verification (real `python app.py`, port 5051)

Measured 2026-10-29:

| Check | Result |
|---|---|
| `GET /api/health` | `{"model_loaded": true, "status": "ok"}` |
| `POST /api/predict` `https://secure-login-verify-account.example/` | Phishing / High, P 0.8387, `model_version` 2.0.0, model input `https://www.secure-login-verify-account.example` |
| `POST /api/predict` `https://example.com/` | Safe / Low, P 0.3704, saved to history (id 1) |
| `POST /api/predict` `javascript:alert(1)` | 400 `UNSUPPORTED_SCHEME` |
| `GET /api/model-info` | `GradientBoostingClassifier` 2.0.0, thresholds 0.5200 / 0.6443, split text now registrable-domain-grouped |
| History and stats | Correct after each step (acceptance steps 9–10 in `docs/testing.md`) |
| High result reaches the warning page | Yes (acceptance step 3) |
| Go Back to Safety | Previous checked page (step 4); `safe.html` without one (step 7) |
| Continue Anyway limited to tab and site | Yes (steps 5–6) |
| API failure never "safe" | Badge `?`, "could NOT be checked" (step 13) |
| Dashboard | 4 rows rendered, no console errors (step 12) |
| Server log | No errors or tracebacks |
| Extension uses the intended API and model | The warning page and popup show `model_version` 2.0.0 from the API; the test extension differed from `extension/` only in `API_BASE`/`host_permissions` and `AUTO_SCAN_DEFAULT` (`diff -r`) |

**Benchmark:** `scripts/benchmark_api.py` on 2026-10-29 (Python 3.14.8) gave:
- server-side median 0.49 ms;
- client median with history write 1.44 ms (p95 1.69);
- throughput with 8 concurrent clients 909.4 per second.

See `docs/data/performance_2026-10-29_python3.14.json`. The extension's navigation-to-badge time was not
benchmarked.

## 7. Model artifacts inspected

`python scripts/model_inventory.py` → `docs/data/model_inventory.json`. The full inventory table is in
`docs/PROJECT_KNOWLEDGE_AND_VIVA_GUIDE.md` §16.

- **v2.0.0** (deployed), **v1.3.0** (alternative), **v1.2.0** (archived) and **v1.1.0** (baseline): every
  test metric and confusion matrix was re-computed from the saved artifact on its recorded split and
  threshold, and matches the metadata exactly.
- **20 research artifacts** (`models/*.joblib`, `models/clean/*.joblib`): all load, and all use the leaky
  `URLSimilarityIndex` (22 or 50 stored columns). They score 0.9997–1.0 accuracy on their test files and
  cannot score live URLs. They were undocumented before this round. The three XGBoost files predict but fail
  `get_params()` with the installed xgboost.
- **DistilBERT:** scripts only, no stored artifact or metrics.
- **Original notebook model** (`../projectcopy/url/…`): the path does not exist on this machine, so it was not
  verified.
- **New measured fact:** under the deployed registrable view, five of the 17 inputs carry no information:
  - `IsHTTPS` is always 1;
  - the `=`, `?` and `%` counts are always 0;
  - `URLLength` is always `DomainLength + 8`.

  Four of them have zero importance; `TLDLegitimateProb` has 45.7% of the importance.

## 8. Other findings (not fixed)

- Behind `python app.py`, Werkzeug's development server adds `Server: Werkzeug/3.1.9 Python/3.14.8` next to
  `Server: phishing-detector` (observed with `curl -i` on an `OPTIONS` response). The tests use the WSGI test
  client and do not see it. A production WSGI server avoids it. Documented in `docs/security.md`.
- `.example`, `.test` and similar names are not in the Public Suffix List, so the registrable view scores the
  whole host for them (documented in §13 of the guide).
- The browser's Back button from the warning page returns to the flagged page, which is warned again
  (documented; Go Back to Safety is the intended way out).

## 9. Known limitations and incomplete work

- No pre-load blocking (MV3 limitation with a per-URL API decision).
- With automatic checks on, the origins of visited http(s) sites go to the API; it is localhost by default.
- Model limits (recall 0.5675, uncalibrated scores, domain-only view): unchanged and documented.
- **Not implemented:** user feedback, authentication, production deployment, an end-to-end extension latency
  benchmark.
- The team contribution table is a template: Git history cannot show who did what
  (`docs/REVIEW_2_VIVA_PREPARATION.md` §9).
- The literature review is a placeholder: the repository contains no citations, and none were invented.

## 10. Commands to reproduce the verification

```bash
source .venv/bin/activate
python -m pytest -q                                       # full suite
node --test tests/extension/                              # simulated extension logic
python -m pytest tests/browser/test_extension_autoscan.py # real-Chrome automatic checks
python scripts/model_inventory.py                         # model re-scoring (read-only)
API_PORT=5051 python app.py                               # real server (port 5000 is taken by macOS ControlCenter here)
curl -s http://127.0.0.1:5051/api/health
curl -s -X POST http://127.0.0.1:5051/api/predict -H "Content-Type: application/json" \
     -d '{"url": "https://secure-login-verify-account.example/", "record": false}'
```

## 11. Actions for you

1. **Decide about the files changed by the parallel pipeline run** (§3): keep them, or
   `git restore models/ docs/data/dataset_audit.json docs/data/error_analysis.json docs/data/evaluation.json docs/data/view_experiment.json docs/model_evaluation_tables.md`.
   Look at `git diff` first.
2. **Reload the extension** in your own Chrome (`chrome://extensions` → Reload). It now asks for the `tabs`
   permission ("Read your browsing history"); Chrome may show this when the extension is reloaded.
3. If you run Flask on 5051, edit `API_BASE` in `extension/config.js` and `host_permissions` in
   `extension/manifest.json`.
4. Do a manual check in a **visible** Chrome window with the demo URLs in `docs/REVIEW_2_VIVA_PREPARATION.md`
   §4, and take the screenshots in §5.
5. Fill in the team contribution table and the literature references (check the PhiUSIIL citation).
6. Review and commit (nothing has been committed).
