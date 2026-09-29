# Architecture

One Flask process serves the web pages and the REST API, and it is the **single
source of truth for predictions**. The web frontend and the Chrome extension
contain no model or prediction logic; both call `POST /api/predict`.

```
 ┌──────────────────────┐        ┌──────────────────────────┐
 │ Web frontend         │        │ Chrome extension (MV3)   │
 │ templates/ + static/ │        │ extension/ (activeTab)   │
 └──────────┬───────────┘        └────────────┬─────────────┘
            │ same origin                      │ host_permissions → API origin
            ▼                                  ▼
 ┌──────────────────────────────────────────────────────────────────┐
 │ Flask app (app.py → backend/create_app)                          │
 │  backend/routes/   health · prediction · model · history          │
 │  backend/utils/    validation · errors · security headers/CORS ·  │
 │                    rate limit                                     │
 │  services/         PredictionService · HistoryService ·           │
 │                    explanation_engine · threat_intelligence (off) │
 └──────┬──────────────────────────┬───────────────────────┬────────┘
        ▼                          ▼                       ▼
 ┌───────────────┐       ┌──────────────────┐     ┌────────────────────┐
 │ ml/predictor  │       │ database/        │     │ models/            │
 │ url_utils →   │       │ Database (WAL,   │     │ phishing_model.pkl │
 │ feature_      │       │ migrations)      │     │ model_metadata.json│
 │ extractor →   │       │ ScanRepository   │     │ tld_legitimate_    │
 │ final model   │       │ (parameterised)  │     │ prob.json          │
 └───────────────┘       └────────┬─────────┘     └────────────────────┘
                                  ▼
                        instance/scan_history.db (SQLite)
```

## Request flow: `POST /api/predict`

1. **Rate limit** per client address (`backend/utils/rate_limit.py`).
2. **Request validation** (`backend/utils/validation.py`): JSON object, known
   fields and types, URL length, scheme allow-list, normalisation, internal-host
   policy.
3. **`PredictionService.predict`** calls `ml.predictor.Predictor.predict`, which:
   - normalises the URL;
   - extracts the 17 schema features from the model input
     `https://www.<registrable domain>` (`ml/feature_extractor.py` +
     `ml.url_utils.split_registrable`, order from `ml/feature_schema.py`);
   - validates the vector;
   - runs `predict_proba`;
   - applies the thresholds from `model_metadata.json` (Safe / Suspicious /
     Phishing);
   - builds the explanation items (`services/explanation_engine.py`).

   The service then adds risk-signal wording, the disclaimer built from
   measured test metrics, `model_version` and `scanned_at`.
4. **`HistoryService.record`** redacts URL secrets and stores the scan
   (`database/repository.py`). A storage failure never fails the prediction.
5. JSON response. Errors use one shape, `{"success": false, "error": {code, message}}`,
   with no internals.

## Loading and lifecycle

- **Model:** loaded **once** in `create_app` and shared by all requests.
  `Predictor` checks the feature count, order and names against the schema on
  load. If loading fails, the app still starts, `/api/health` reports
  `model_loaded: false`, and prediction endpoints return 503.
- **Database:** initialised (and migrated) at start-up. If that fails,
  predictions still work, history endpoints return 503, and initialisation is
  retried per call.
- **Threads:** `app.py` sets `OMP_NUM_THREADS=1` before scikit-learn loads. This
  measured 10× higher concurrent throughput (see `docs/testing.md`).

## Where things live

| Concern | Location | Docs |
|---|---|---|
| ML pipeline, schema, training, evaluation | `ml/`, `models/`, `scripts/` | `docs/dataset.md`, `docs/model_evaluation.md`, `docs/ml_error_analysis.md` |
| REST API | `backend/`, `services/`, `config.py` | `docs/api.md` |
| Scan history | `database/`, `services/history_service.py` | `docs/database.md` |
| Web UI | `templates/`, `static/` | `docs/frontend.md` |
| Extension | `extension/` | `docs/extension.md` |
| Security | Cross-cutting | `docs/security.md` |
| Tests | `tests/`, `tests/browser/` | `docs/testing.md` |

## Model in one paragraph

GradientBoostingClassifier v2.0.0 (scikit-learn 1.6.1), trained on the PhiUSIIL
dataset with a registrable-domain-grouped, leakage-controlled 80/10/10 split.
It uses 17 lexical features of the site's **registrable domain** (Public Suffix
List eTLD+1; `admob.google.com` → `google.com`). Thresholds were chosen on
validation only: 0.5200 to flag, 0.6443 for high confidence. Held-out test
results:

| Accuracy | Precision | Recall | F1 | ROC-AUC | FPR |
|---|---|---|---|---|---|
| 0.7872 | 0.8801 | **0.5675** | 0.6900 | 0.8524 | 0.0554 |

It misses 43% of phishing URLs: phishing on subdomains of attacker-owned
domains, on ordinary-looking or compromised domains, or on hosting platforms not
listed in the PSL. In exchange it no longer systematically flags legitimate
subdomain services, which the previous host-view model v1.2.0 did (see
`docs/false_positive_investigation.md`). Every user-facing result carries that
caveat.
