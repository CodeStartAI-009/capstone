# Security review

Scope: Flask API, web frontend, SQLite history and Chrome extension, as
implemented. Each row names the tests that check it, and all of those tests
pass (`docs/testing.md`). The final section lists what is **not** protected.

## Threats, mitigations and evidence

| # | Threat | Mitigation | Tested by |
|---|---|---|---|
| 1 | **XSS through a submitted URL** | Frontend and popup write all API data with `textContent`/DOM APIs, never `innerHTML`. A scanned URL is never used as a link. | `test_frontend_browser.py::test_scanned_url_cannot_inject_markup_or_script` (payload `"><svg/onload=…><img/src/onerror=…>` on result card and dashboard: no script ran, no element created); `test_extension_browser.py::test_popup_rendering_and_safe_dom`; `test_client_code.py::test_no_unsafe_dom_apis_in_client_code` |
| 2 | **HTML injection** | Jinja autoescaping; pages never reflect query parameters; API responses are `application/json` with `nosniff` | `test_security.py::test_query_parameters_are_not_reflected_into_html`, `::test_json_responses_cannot_be_sniffed_as_html` |
| 3 | **JavaScript injection** | CSP `script-src 'self'` and `object-src 'none'`; no inline scripts, styles or event handlers; extension CSP `script-src 'self'` | `test_client_code.py::test_no_inline_scripts_or_handlers_in_templates_and_popup`; `test_frontend_browser.py::test_pages_load_without_console_or_csp_errors` (no CSP violations) |
| 4 | **SQL injection** | Every SQL value is a bound parameter; LIKE wildcards escaped; ids must be positive integers | `test_security.py::test_sql_injection_in_search_is_inert`, `::test_sql_injection_in_url_and_id_is_inert` (4 payloads each; table intact); `test_database.py::test_filter_and_search_are_parameterised`, `::test_invalid_ids` |
| 5 | **Path traversal** | Only Flask's static handler serves files; ids are validated integers | `test_security.py::test_path_traversal_is_refused` (7 encodings, including `%2e%2e`, `%5c`, `/../.env`) |
| 6 | **SSRF** | The server **never fetches or resolves** a submitted URL. Features come from the string. The only outbound request is the optional, disabled-by-default Safe Browsing call to a fixed endpoint. | `test_security.py::test_scanning_never_opens_network_connections` (socket connect and DNS patched to fail during scans), `::test_threat_intel_only_contacts_fixed_endpoint_and_is_separate_from_model` |
| 7 | **Dangerous URL schemes** | Server allow-list: http/https only (`javascript:`, `data:`, `file:`, `ftp:`, `mailto:`, `vbscript:` → 400 `UNSUPPORTED_SCHEME`). The extension refuses non-http(s) tabs locally and sends nothing. | `test_api.py::test_unsupported_scheme`; `test_e2e.py::test_5_10_11_bad_urls_rejected_by_live_api`; `test_extension_browser.py::test_unsupported_schemes_are_not_sent`, `::test_file_page_is_not_sent` |
| 8 | **Internal / private targets** | localhost, private, loopback, link-local and reserved IPs (including `2130706433`, `0x7f.1`, `[::ffff:127.0.0.1]`), single-label and `.local`/`.internal` names → 400 `UNSUPPORTED_HOST` (`ALLOW_PRIVATE_HOSTS=false`) | `test_security.py::test_internal_targets_rejected_by_default` (19 forms) |
| 9 | **Oversized request bodies** | `MAX_CONTENT_LENGTH` 16 KB → 413 | `test_api.py::test_oversized_body_rejected`; `test_e2e.py::test_6_malformed_requests` |
| 10 | **Excessive URL length** | 2048-character limit (server-side, before parsing) → 400 `URL_TOO_LONG`; stored URLs capped at 2048 | `test_api.py::test_extremely_long_url`; `test_e2e.py::test_10_long_url_in_ui`; `test_database.py::test_duplicate_and_long_urls` |
| 11 | **Malformed JSON / unexpected payloads** | Content type, JSON object, known fields and types checked → 400/415. Client-supplied feature values are rejected (`UNEXPECTED_FIELD`). | `test_api.py` (`test_malformed_json`, `test_invalid_utf8_body`, `test_manual_feature_values_are_rejected`, …); `test_e2e.py::test_6_malformed_requests` |
| 12 | **Information leakage** | `Server: phishing-detector` (no Werkzeug/Python version); debug off by default; model-info excludes file paths, candidates and training statistics | `test_security.py::test_hardening_headers_and_no_version_disclosure`, `::test_debug_mode_off_by_default`; `test_api.py::test_model_info_uses_real_metadata` |
| 13 | **Stack-trace leakage** | Every error is JSON `{code, message}`; exceptions are logged server-side only | `test_api.py::assert_error` on every error case (no `Traceback`, `File "`, paths, `.py`); `::test_extractor_failure_returns_422`, `::test_model_failure_returns_500_without_internals`; `test_database.py::test_database_failure_keeps_prediction_and_hides_internals`; `test_security.py::test_errors_never_reveal_internals` |
| 14 | **Secret leakage** | Secrets only in environment variables (`.env` git-ignored, `.env.example` placeholders only); never returned or stored; URL secrets redacted before storage | `test_api.py::test_secrets_never_returned`; `test_database.py::test_secrets_in_scanned_url_never_reach_the_database`; `test_client_code.py::test_no_prediction_logic_or_secrets_in_client_code` |
| 15 | **Unsafe CORS** | No cross-origin access by default. Exact origins in `CLIENT_ORIGIN` only; `*` ignored; credentials never allowed; preflights from unlisted origins get no grant. | `test_security.py::test_cors_only_for_allow_listed_origins`, `::test_client_origin_setting_and_wildcard_refused`, `::test_cors_preflight_from_unlisted_origin_gets_no_grant`, `::test_default_config_allows_no_cross_origin` |
| 16 | **Insecure extension permissions** | `activeTab` plus the API origin only. No `tabs`, `history`, `storage`, `scripting`, content scripts or background worker. MV3 CSP. | `test_client_code.py::test_manifest_is_mv3_with_minimal_permissions`, `::test_api_base_is_configured_in_one_place_and_matches_host_permissions` |
| 17 | **Unsafe DOM rendering** | See 1; `[hidden]` states verified not rendered | `test_frontend_browser.py::test_hidden_elements_are_not_rendered` |
| 18 | **Clickjacking** | `X-Frame-Options: DENY` and CSP `frame-ancestors 'none'` | `test_security.py::test_security_headers`, `::test_hardening_headers_and_no_version_disclosure` |
| 19 | **Abuse / flooding** | 60 predictions per minute per client (in-memory sliding window) → 429 with `Retry-After` | `test_security.py::test_rate_limit_returns_429_with_retry_after`; `test_e2e.py::test_12_rate_limit_on_live_server` |

## Rate limiting

- Existing mechanism, kept (`backend/utils/rate_limit.py`, no new dependency).
- Applies to `POST /api/predict`: `RATE_LIMIT_PER_MINUTE` (default 60) per
  client address, sliding window.
- It is the only endpoint that runs the model and writes to the database.
  History and stats reads are cheap (under 1 ms measured); `DELETE` is not
  rate-limited.

## Security headers

Every response carries:

| Header | Value |
|---|---|
| `Content-Security-Policy` | `default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'` |
| `X-Content-Type-Options` | `nosniff` |
| `X-Frame-Options` | `DENY` |
| `Referrer-Policy` | `no-referrer` |
| `Permissions-Policy` | camera, microphone, geolocation, payment and USB disabled |
| `Cross-Origin-Opener-Policy` | `same-origin` |
| `Cross-Origin-Resource-Policy` | `same-origin` |
| `Server` | `phishing-detector` |

API responses also send `Cache-Control: no-store`, and responses over HTTPS
add `Strict-Transport-Security`. After the headers were added, all 56 browser
tests (frontend, extension, end-to-end) were re-run and passed.

## Not protected / residual risks

- **No authentication.** Anyone who can reach the API can scan, read history
  and clear it. This is acceptable for the intended single-user local
  deployment and must be added before any shared deployment. Browser-based
  cross-site requests are blocked by CORS (JSON `POST` and `DELETE` need a
  preflight, which unlisted origins don't get), but non-browser clients are not.
- **Development server.** `python app.py` uses Flask's development server.
  Production needs a WSGI server (e.g. gunicorn) behind HTTPS.
- **Rate limiting is per process and per IP address.** It resets on restart
  and can't be shared across workers.
- **URL paths are stored unredacted.** Only query values, passwords and
  fragments are removed.
- **The model is not a security control.** Model v2.0.0 misses 43.3% of phishing URLs
  (test recall 0.5675), and every UI carries that disclaimer. The system has no
  real-time threat intelligence or reputation feeds unless the optional Safe
  Browsing lookup is configured, which it isn't by default.
- **Dependency vulnerabilities were not audited** (no `pip-audit` run).
