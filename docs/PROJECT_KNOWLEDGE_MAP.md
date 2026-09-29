# Project Knowledge Map

Each requirement mapped to its module, files, technology, responsible member,
tests and a likely reviewer question. Every file and test named here exists in
the repository (checked on 2026-09-29).

Members: **M1** ML / data · **M2** Backend / database · **M3** Frontend ·
**M4** Extension / security / testing.

| Requirement | Module | File(s) | Technology | Owner | Test(s) | Reviewer question |
|---|---|---|---|---|---|---|
| Automatic URL feature extraction | ML feature extraction | `ml/feature_extractor.py`, `ml/feature_schema.py` | Python | M1 | `tests/test_features.py`, `tests/test_pipeline.py::test_pipeline_stages_agree` | "How do you convert a URL into model input?" |
| Fixed feature order | Feature schema | `ml/feature_schema.py`, `ml/predictor.py` | Python, scikit-learn | M1 | `tests/test_features.py::test_vector_follows_schema_order_exactly`, `tests/test_predictor.py::test_rejects_model_with_different_feature_order` | "What if features arrive in the wrong order?" |
| URL validation and normalisation | URL utilities | `ml/url_utils.py` | Python (`urllib`, `ipaddress`, IDNA) | M1 / M2 | `tests/test_urls.py::test_normalisation`, `tests/test_features.py::test_malformed_input_is_rejected` | "How do you handle malformed URLs?" |
| Registrable-domain model input (false-positive fix) | URL utilities + extractor | `ml/url_utils.py` (`split_registrable`, `registrable_domain`), `ml/feature_extractor.py` (`model_input`) | tldextract (Public Suffix List) | M1 | `tests/test_pipeline.py::test_split_registrable`, `::test_subdomains_cannot_change_the_prediction`, `::test_shared_hosting_sites_keep_their_own_identity` | "Isn't the PSL a whitelist?" |
| Training-time / prediction-time parity | Dataset + extractor | `ml/dataset.py`, `ml/feature_extractor.py` | pandas | M1 | `tests/test_pipeline.py::test_training_and_prediction_features_are_identical` | "Are features computed the same way in training and prediction?" |
| Dataset audit (duplicates, leakage) | Data audit | `scripts/dataset_audit.py`, `docs/data/dataset_audit.json` | pandas | M1 | `tests/test_pipeline.py::test_split_reproduces_metadata_and_has_no_leakage` | "How many duplicates? Any overlap?" |
| Leakage-controlled split | Dataset | `ml/dataset.py` (`load_registrable_grouped_split`) | scikit-learn `train_test_split` (grouped, stratified) | M1 | `tests/test_pipeline.py::test_split_reproduces_metadata_and_has_no_leakage` | "How do you prevent data leakage?" |
| Model training and selection | Training | `ml/train_model.py`, `ml/model_utils.py` | scikit-learn | M1 | `tests/test_model_selection.py` | "Why this model?" |
| Threshold policy | Training | `ml/train_model.py` (`MAX_VALIDATION_FPR`), `ml/model_utils.py` (`threshold_for_max_fpr`) | numpy | M1 | `tests/test_model_selection.py::test_fpr_threshold_is_lowest_threshold_meeting_the_cap`, `::test_recorded_decision_is_consistent` | "Why 0.52?" |
| Model metadata and versioning | Model artefacts | `models/model_metadata.json`, `models/previous_v1.2.0/`, `models/baseline_v1.1.0/`, `models/alternatives/host_view_v1.3.0/` | JSON, joblib | M1 | `tests/test_pipeline.py::test_metadata_records_view_decision_and_previous_models`, `::test_preserved_models_still_load` | "Where is the old model?" |
| False-positive investigation | Experiment + docs | `ml/view_experiment.py`, `scripts/feature_comparison.py`, `docs/false_positive_investigation.md` | scikit-learn | M1 | `tests/test_pipeline.py::test_subdomains_cannot_change_the_prediction` | "Why was AdMob flagged, and how did you fix it?" |
| Leaky vs controlled comparison | Evaluation (historical) | `ml/evaluate_model.py`, `docs/model_evaluation.md` | scikit-learn | M1 | (analysis script; results in `docs/data/evaluation.json`) | "Why not report 99.9%?" |
| Error analysis / feature importance | Error analysis (v1.2.0) | `ml/error_analysis.py`, `docs/ml_error_analysis.md` | scikit-learn | M1 | (analysis script; reproducibility checked) | "Why is recall limited?" |
| Probability calibration check | Analysis | `scripts/calibration_report.py`, `docs/data/calibration.json` | numpy | M1 | (analysis script) | "Is 98% confidence reliable?" |
| Prediction with probability and risk | Predictor | `ml/predictor.py` | scikit-learn | M1 / M2 | `tests/test_predictor.py::test_risk_mapping_thresholds`, `::test_confidence_is_probability_of_reported_class` | "How is confidence computed?" |
| Explanations | Explanation engine | `services/explanation_engine.py` | Python | M1 / M2 | `tests/test_pipeline.py::test_subdomain_observations_do_not_change_the_score`, `tests/test_urls.py::test_describe_url_facts` | "Are explanations invented?" |
| REST API: predict | Flask route | `backend/routes/prediction.py`, `services/prediction_service.py` | Flask | M2 | `tests/test_api.py::test_predict_valid_url`, `::test_prediction_matches_direct_pipeline` | "What happens when a request arrives?" |
| Input validation | Validation | `backend/utils/validation.py` | Python | M2 | `tests/test_api.py` (`test_missing_url`, `test_malformed_url`, `test_unsupported_scheme`, `test_manual_feature_values_are_rejected`), `tests/test_security.py::test_internal_targets_rejected_by_default` | "How is user input validated?" |
| Error contract | Errors | `backend/utils/errors.py` | Flask | M2 | `tests/test_api.py::test_model_failure_returns_500_without_internals`, `::test_extractor_failure_returns_422` | "Can stack traces leak?" |
| Health / model-info endpoints | Routes | `backend/routes/health.py`, `backend/routes/model.py` | Flask | M2 | `tests/test_api.py::test_health`, `::test_model_info_uses_real_metadata` | "Are metrics hard-coded?" |
| Model loaded once | App factory | `backend/__init__.py`, `app.py` | Flask | M2 | `tests/test_api.py::test_model_is_loaded_once_at_startup_not_per_request` | "Is the model loaded per request?" |
| Scan history storage | Database | `database/database.py`, `database/models.py`, `database/repository.py`, `services/history_service.py` | SQLite | M2 | `tests/test_database.py` (38 tests) | "What do you store, and why?" |
| History API | Routes | `backend/routes/history.py` | Flask | M2 | `tests/test_database.py::test_history_list_shape_and_pagination`, `::test_delete_one_and_clear`, `::test_invalid_ids` | "How does pagination work?" |
| Schema migration | Database | `database/database.py`, `database/models.py` | SQLite `PRAGMA user_version` | M2 | `tests/test_database.py::test_v1_database_is_migrated_in_place` | "How do you upgrade an old database?" |
| URL secret redaction | History service | `services/history_service.py` (`redact_url`) | Python | M2 | `tests/test_database.py::test_urls_are_redacted_before_storage`, `::test_secrets_in_scanned_url_never_reach_the_database` | "Do you store sensitive data?" |
| CORS | Security | `backend/utils/security.py`, `config.py` (`CLIENT_ORIGIN`) | Flask | M2 / M4 | `tests/test_security.py::test_cors_only_for_allow_listed_origins`, `::test_client_origin_setting_and_wildcard_refused` | "What is CORS, and why no `*`?" |
| Rate limiting | Security | `backend/utils/rate_limit.py` | Python | M2 | `tests/test_security.py::test_rate_limit_returns_429_with_retry_after`, `tests/browser/test_e2e.py::test_12_rate_limit_on_live_server` | "How do you prevent abuse?" |
| Security headers | Security | `backend/utils/security.py` | Flask | M2 / M4 | `tests/test_security.py::test_security_headers`, `::test_hardening_headers_and_no_version_disclosure` | "Which headers, and why?" |
| Web scanner | Frontend | `templates/_scanner.html`, `templates/inspect.html`, `templates/index.html`, `static/js/scanner.js`, `static/js/main.js` | HTML, JS, CSS | M3 | `tests/browser/test_frontend_browser.py::test_low_risk_scan_matches_api`, `::test_phishing_risk_scan` | "How does the page call Flask?" |
| Frontend error states | Frontend | `static/js/main.js`, `static/js/scanner.js` | JS | M3 | `tests/browser/test_frontend_browser.py::test_api_unavailable`, `::test_request_timeout`, `::test_malformed_api_response`, `::test_server_error_shows_friendly_message` | "What if the API is down?" |
| Dashboard and history UI | Frontend | `templates/dashboard.html`, `static/js/dashboard.js` | JS, SVG | M3 | `tests/browser/test_frontend_browser.py::test_dashboard_statistics_and_table_match_api`, `::test_dashboard_pagination`, `::test_dashboard_delete_and_clear` | "Are chart values real?" |
| Responsive design | Frontend | `static/css/style.css` | CSS | M3 | `tests/browser/test_frontend_browser.py::test_responsive_layout_has_no_horizontal_overflow` | "Does it work on mobile?" |
| XSS-safe rendering | Frontend + extension | `static/js/main.js` (`el`), `extension/popup.js` | JS DOM | M3 / M4 | `tests/browser/test_frontend_browser.py::test_scanned_url_cannot_inject_markup_or_script`, `tests/test_client_code.py::test_no_unsafe_dom_apis_in_client_code` | "How do you prevent XSS?" |
| Chrome MV3 extension | Extension | `extension/manifest.json`, `extension/popup.html`, `extension/popup.js`, `extension/popup.css` | Chrome extension APIs | M4 | `tests/browser/test_extension_browser.py` (14 tests), `tests/test_client_code.py::test_manifest_is_mv3_with_minimal_permissions` | "Why Manifest V3?" |
| Current-tab scanning | Extension | `extension/popup.js` | `chrome.tabs`, `activeTab` | M4 | `tests/browser/test_extension_browser.py::test_https_page_matches_web_app_prediction` | "How does the extension get the URL?" |
| Unsupported pages in the extension | Extension | `extension/popup.js` (`unsupportedReason`) | JS | M4 | `tests/browser/test_extension_browser.py::test_unsupported_schemes_are_not_sent`, `::test_file_page_is_not_sent` | "What happens on `chrome://` pages?" |
| Configurable API URL | Extension config | `extension/config.js`, `extension/manifest.json` | JS, JSON | M4 | `tests/test_client_code.py::test_api_base_is_configured_in_one_place_and_matches_host_permissions` | "How do you change the API URL?" |
| Extension failure handling | Extension | `extension/popup.js` | JS | M4 | `tests/browser/test_extension_browser.py::test_api_unavailable`, `::test_api_timeout`, `::test_api_error_responses` | "What if the API is unavailable?" |
| SSRF avoidance | Architecture | `ml/`, `services/` (no fetching), `backend/utils/validation.py` | — | M4 | `tests/test_security.py::test_scanning_never_opens_network_connections` | "How do you prevent SSRF?" |
| SQL injection resistance | Database | `database/repository.py` | SQLite parameters | M2 / M4 | `tests/test_security.py::test_sql_injection_in_search_is_inert`, `::test_sql_injection_in_url_and_id_is_inert` | "How do you prevent SQL injection?" |
| Path traversal / local files | Flask static | Flask | Flask | M4 | `tests/test_security.py::test_path_traversal_is_refused` | "Can someone read `config.py`?" |
| End-to-end integration | Integration | `tests/browser/test_e2e.py` | pytest + Chrome | M4 | 21 tests (scenarios 1–12) | "How do you know the parts work together?" |
| Performance measurement | Benchmark | `scripts/benchmark_api.py`, `docs/data/performance.json` | Python | M2 / M4 | (measurement script) | "How fast is a prediction?" |
| Browser automation harness | Testing | `tests/browser/cdp.py`, `tests/browser/conftest.py` | Chrome DevTools Protocol | M4 | used by all browser tests | "How did you test the extension automatically?" |
| Configuration and secrets | Config | `config.py`, `.env.example`, `.gitignore` | env vars | M2 | `tests/test_api.py::test_secrets_never_returned` | "Where are secrets kept?" |

## How the pieces connect (for every member)

```
URL ─▶ backend/routes/prediction.py ─▶ backend/utils/validation.py ─▶ services/prediction_service.py
    ─▶ ml/predictor.py ─▶ ml/feature_extractor.py (+ ml/url_utils.py, ml/feature_schema.py)
    ─▶ models/phishing_model.pkl ─▶ services/explanation_engine.py
    ─▶ services/history_service.py ─▶ database/repository.py ─▶ SQLite
    ─▶ JSON ─▶ static/js/scanner.js (web)  |  extension/popup.js (extension) ─▶ static/js/dashboard.js
```
