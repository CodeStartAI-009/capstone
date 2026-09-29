# REST API

The Flask API wraps the ML pipeline in `ml/`. It does not re-implement feature
extraction or prediction:

```
client -> Flask route (backend/routes/prediction.py)
       -> request + URL validation (backend/utils/validation.py)
       -> PredictionService (services/prediction_service.py)
       -> ml.predictor.Predictor: URL normalisation -> feature extraction (17 features)
                                  -> final model -> risk level -> explanations
       -> HistoryService (services/history_service.py, SQLite)
       -> JSON response
```

The API accepts **only a URL**. Feature values cannot be supplied by the client:
unknown fields such as `features` are rejected.

## Important: what a prediction means

The response is a **machine-learning risk signal**, not a verdict. It is
computed from the site's registrable domain only (e.g. `google.com` for
`admob.google.com`); the page is never visited.

On the held-out test split (23,055 URLs; `models/model_metadata.json`) at the
deployed threshold of 0.5200, model v2.0.0:
- detected **56.7%** of phishing URLs (recall 0.5675), so it **misses 43.3%**;
- flagged 5.5% of legitimate URLs (precision 0.8801, F1 0.6900, ROC-AUC 0.8524).

A `Safe` / low-risk prediction therefore does **not** mean a site is safe.
Every prediction response carries a `disclaimer` built from these measured
numbers. See `docs/ml_error_analysis.md` for why recall is limited: phishing on
ordinary-looking domains is indistinguishable from legitimate sites using host
features alone.

## Running the server

```bash
source .venv/bin/activate          # Python 3.9, scikit-learn 1.6.1
pip install -r requirements.txt pytest
cp .env.example .env                # optional; edit, then: set -a; source .env; set +a
python app.py                       # http://127.0.0.1:5000
```

On macOS the AirPlay receiver may already use port 5000; set `API_PORT=5051`
(or any free port). The model is loaded once at start-up. If the model files are
missing or incompatible, the server still starts:
- `/api/health` reports `"model_loaded": false`;
- prediction endpoints return 503.

Tests: `python -m pytest`.

## Endpoints

### `GET /api/health`

```json
{"status": "ok", "model_loaded": true}
```

### `POST /api/predict`

Request (`Content-Type: application/json`, body ≤ 16 KB):

```json
{"url": "https://github.com/pallets/flask"}
```

| Field | Type | Required | Meaning |
|---|---|---|---|
| `url` | string | yes | URL to assess (≤ 2048 characters). A missing scheme defaults to `https://`. |
| `source` | `"web"` \| `"extension"` \| `"api"` | no (default `"api"`) | Recorded in history. |
| `record` | boolean | no (default `true`) | `false` = do not store this scan in history. |

Response `200` (real output, abridged):

```json
{
  "success": true,
  "url": "https://github.com/pallets/flask",
  "prediction": "Safe",
  "label": 1,
  "risk_level": "Low",
  "confidence": 0.7051,
  "phishing_probability": 0.2949,
  "verdict": "Low-risk prediction",
  "summary": "Low-risk prediction: the model's phishing score (0.29) is below its decision threshold (0.50). The host name does not show the characteristics the model associates with phishing.",
  "explanation": ["No host feature is outside the range typical of legitimate training URLs."],
  "disclaimer": "This is a machine-learning risk signal computed from the site's registrable domain name only; the page itself is not visited or checked. On held-out test data the model detected 56.7% of phishing URLs (missing 43.3%) and flagged 5.5% of legitimate URLs, so a low-risk prediction does not mean a site is safe.",
  "model_input": "https://www.github.com",
  "feature_names": ["URLLength", "DomainLength", "..."],
  "features": {"URLLength": 22, "DomainLength": 14, "IsDomainIP": 0, "...": "..."},
  "url_facts": {"scheme": "https", "host": "github.com", "has_path": true, "...": "..."},
  "explanations": [{"source": "model_feature", "severity": "info", "feature": null,
                    "message": "No host feature is outside the range typical of legitimate training URLs."}],
  "timing_ms": {"feature_extraction": 0.42, "model_inference": 4.8, "total": 5.26},
  "scanned_at": "2026-09-29T13:11:03+00:00",
  "model_version": "2.0.0",
  "history": {"saved": true, "id": 42}
}
```

Field meanings:

| Field | Meaning |
|---|---|
| `prediction` | The project's labels: `Safe`, `Suspicious` or `Phishing` (see below). |
| `verdict` | The same label in risk-signal wording: `Low-risk prediction`, `Phishing-risk prediction (moderate)` or `Phishing-risk prediction (high)`. |
| `risk_level` | `Low` / `Medium` / `High`. |
| `label` | Dataset convention: `0` = phishing (flagged), `1` = legitimate (not flagged). |
| `phishing_probability` | The model's P(phishing) score. |
| `confidence` | The model's probability for the reported side of the decision threshold. It is not a guarantee of correctness. |
| `features` | The exact 17-value vector the model received, in schema order. |
| `model_input` | The string it was computed from: `https://www.<host>`. |
| `explanation` | Plain sentences, most severe first. |
| `explanations` | The same items, structured: `source` is `model_feature` (a model input unusual for legitimate training URLs) or `observation` (a fact about the URL the model does **not** use, e.g. `http://`, a port, `@`, punycode). Explanations describe only computed values; they are not per-prediction attributions. |
| `scanned_at` | ISO-8601 UTC time of the scan; the stored history row has the same value. |
| `history` | `{"saved": true, "id": n}`; `{"saved": false, "reason": "not requested"}` for `record: false`; `{"saved": false}` if the database failed (the prediction is still returned, HTTP 200). |
| `threat_intelligence` | Present only if a provider is configured. It is separate from, and never changes, the model output. |

How the labels are assigned (thresholds from `model_metadata.json`, chosen on
validation data only):

| P(phishing) | `prediction` | `risk_level` |
|---|---|---|
| < 0.5200 | `Safe` | `Low` |
| 0.5200 – 0.6443 | `Suspicious` | `Medium` |
| ≥ 0.6443 | `Phishing` | `High` |

### `GET /api/model-info`

Values come directly from `models/model_metadata.json`:

```json
{
  "success": true,
  "model": "GradientBoostingClassifier",
  "version": "2.0.0",
  "feature_count": 17,
  "features": ["URLLength", "DomainLength", "..."],
  "prediction_labels": ["Safe", "Suspicious", "Phishing"],
  "risk_levels": {"Safe": "Low", "Suspicious": "Medium", "Phishing": "High"},
  "thresholds": {"flag": 0.4990604516298321, "high_confidence_phishing": 0.605002221055304},
  "evaluation": {
    "split": "held-out test split (host-grouped, never used for training or tuning)",
    "rows": 23536, "threshold": 0.4990604516298321,
    "accuracy": 0.7872, "precision": 0.8801, "recall": 0.5675,
    "f1": 0.6900, "roc_auc": 0.8524, "false_positive_rate": 0.0554,  // rounded here; the API returns full precision
    "confusion_matrix": {"legitimate_correct_TN": 12790, "legitimate_flagged_FP": 696,
                         "phishing_missed_FN": 2650, "phishing_caught_TP": 7400}
  },
  "training_data": {"name": "PhiUSIIL Phishing URL Dataset", "...": "..."},
  "disclaimer": "..."
}
```

It also returns `model_name`, `model_version`, `feature_names`, `schema_version`,
`model_input_view`, `trained_at` and `sklearn_version`, which the web UI uses.
File paths, training candidates and per-feature training statistics are not
exposed.

### Other endpoints

| Endpoint | Purpose |
|---|---|
| `GET /api/features` | Feature schema: names, types, ranges, descriptions, excluded features. |
| `GET /api/history?page=1&limit=20&prediction=&q=` | Paginated scan history `{"items", "page", "limit", "total", "pages"}` |
| `GET /api/history/<id>` | One stored scan, including features and indicators |
| `DELETE /api/history/<id>` / `DELETE /api/history` | Delete one scan / clear all |
| `GET /api/stats?days=30` | Counts by prediction, risk level and source, plus daily counts for charts |

Details of history and stats: `docs/database.md`.

## Errors

Every error has the same shape; `code` is stable, `message` is for people:

```json
{"success": false, "error": {"code": "UNSUPPORTED_SCHEME", "message": "Only http:// and https:// URLs can be scanned."}}
```

| HTTP | `code` | When |
|---|---|---|
| 400 | `INVALID_JSON` | Body is not valid JSON or not a JSON object |
| 400 | `MISSING_URL` | `url` absent, empty or whitespace |
| 400 | `INVALID_TYPE` | `url` not a string, or `record` not a boolean |
| 400 | `INVALID_FIELD` | `source` not one of `web`, `extension`, `api` |
| 400 | `UNEXPECTED_FIELD` | Any field other than `url`, `source`, `record` (e.g. manual `features`) |
| 400 | `URL_TOO_LONG` | URL longer than `MAX_URL_LENGTH` (2048) |
| 400 | `INVALID_URL` | Malformed: spaces or control characters, bad host name, bad port, no host |
| 400 | `UNSUPPORTED_SCHEME` | `javascript:`, `data:`, `file:`, `ftp:`, `mailto:`, … |
| 400 | `UNSUPPORTED_HOST` | localhost, private/loopback/link-local/reserved IPs (including forms like `2130706433` or `0x7f.1`), single-label or `.local`/`.internal` names |
| 400 | `INVALID_PARAMETER` | Bad query parameter (e.g. `/api/history?limit=abc`) |
| 400 | `INVALID_ID` | History id not a positive integer |
| 404 | `SCAN_NOT_FOUND` | No stored scan with that id |
| 503 | `HISTORY_UNAVAILABLE` | History database cannot be read or written |
| 404 | `NOT_FOUND` | Unknown `/api/` path |
| 405 | `METHOD_NOT_ALLOWED` | e.g. `GET /api/predict` |
| 413 | `PAYLOAD_TOO_LARGE` | Body larger than `MAX_CONTENT_LENGTH` (16 KB) |
| 415 | `UNSUPPORTED_MEDIA_TYPE` | Body is not `application/json` |
| 422 | `FEATURE_EXTRACTION_FAILED` | URL passed validation but features could not be computed |
| 429 | `RATE_LIMITED` | More than `RATE_LIMIT_PER_MINUTE` predictions per client per minute (`Retry-After` header) |
| 500 | `PREDICTION_FAILED` | The model failed on a valid feature vector |
| 500 | `INTERNAL_ERROR` | Any other unexpected error |
| 503 | `MODEL_UNAVAILABLE` | The model is not loaded |

Details of 422/500 errors are written to the server log. Stack traces, file
paths and exception text are never returned; `tests/test_api.py` checks this for
every error case.

## Environment variables

See `.env.example`. None are required; defaults are shown.

| Variable | Default | Meaning |
|---|---|---|
| `API_HOST` / `API_PORT` | `127.0.0.1` / `5000` | Listen address |
| `FLASK_DEBUG` | `false` | Never enable in production |
| `MODEL_PATH`, `MODEL_METADATA_PATH`, `TLD_TABLE_PATH` | `models/...` | Model artefacts |
| `DATABASE_PATH` | `instance/scan_history.db` | SQLite history |
| `MAX_CONTENT_LENGTH` | `16384` | Max request body (bytes) |
| `MAX_URL_LENGTH` | `2048` | Max URL length |
| `RATE_LIMIT_PER_MINUTE` | `60` | Per client address; `0` disables |
| `HISTORY_LIMIT` | `100` | Max rows returned by `/api/history` |
| `CLIENT_ORIGIN` | empty | Comma-separated exact origins allowed cross-origin (e.g. `https://phishing-ui.example.org`). `CORS_ORIGINS` is accepted as an older alias. |
| `ALLOW_PRIVATE_HOSTS` | `false` | Allow scoring localhost/private/internal hosts |
| `ML_THREADS` | `1` | OpenMP threads per prediction, applied as `OMP_NUM_THREADS` in `app.py`; `0` = library default. The value 1 was measured to raise concurrent throughput from 41.8 to 426.7 predictions/s (`docs/testing.md`). |
| `THREAT_INTEL_PROVIDER`, `GOOGLE_SAFE_BROWSING_API_KEY` | empty | Optional Safe Browsing lookup (secret; set only in the environment) |

## Security considerations

- **No fetching, no DNS.** Features are computed from the URL string. The server
  never requests or resolves the submitted URL, so it can't be used as an SSRF
  proxy. A test blocks socket access during scans to check this. The only
  outbound request is the optional Safe Browsing lookup to a fixed Google
  endpoint, with a 3-second timeout. Its failure is reported in
  `threat_intelligence` and never fails the scan.
- **Untrusted input.** The URL goes through several layers:
  - length limits on both the body (16 KB) and the URL (2048 characters);
  - rejection of control characters and whitespace;
  - an http/https-only scheme allow-list;
  - IDNA host validation;
  - the internal-host policy.

  JSON bodies must be objects with known fields and correct types.
- **Internal targets.** localhost and private-network hosts are rejected by
  default. This isn't an SSRF control, since nothing is fetched; it's there
  because the model was trained on public web URLs and its score for such hosts
  would be meaningless.
- **CORS.** No cross-origin access by default. Only exact origins listed in
  `CLIENT_ORIGIN` get `Access-Control-Allow-Origin`; `*` and malformed entries
  are ignored, with a warning. Credentials are never allowed. The bundled web UI
  is same-origin, and the extension uses `host_permissions`, so neither needs an
  entry.
- **Headers.** Every response carries:
  - `X-Content-Type-Options: nosniff` and `X-Frame-Options: DENY`;
  - a strict CSP (`script-src 'self'; object-src 'none'; frame-ancestors 'none'`);
  - `Referrer-Policy: no-referrer`;
  - `Permissions-Policy`, `Cross-Origin-Opener-Policy` and
    `Cross-Origin-Resource-Policy: same-origin`;
  - `Server: phishing-detector` (no version disclosure).

  API responses add `Cache-Control: no-store`. HSTS is added when served over
  HTTPS.
- **Rate limiting.** 60 predictions per minute per client address
  (`RATE_LIMIT_PER_MINUTE`). It is in-memory and per process, adequate for a
  single local process; a multi-process deployment needs a shared store such
  as Redis.
- **Privacy.** History stores the redacted URL, the result, the model version
  and the explanation items. It stores no IP address, user agent, headers or
  cookies. Query values, userinfo passwords and fragments are removed before
  storage (`docs/database.md`). The extension scans only when the user clicks
  its icon.
- Full security review and test evidence: `docs/security.md`.
- **Deployment.** `python app.py` uses Flask's development server. For
  production, run behind a WSGI server (e.g. `gunicorn "app:app"`) and HTTPS,
  with `FLASK_DEBUG=false`.
