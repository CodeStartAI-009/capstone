# AI-Powered Phishing URL Detection (final-year capstone)

A machine-learning phishing **risk assessment** for URLs. The project has four
parts:
- a **Flask REST API**, which runs the trained model;
- a **web scanner and dashboard**, backed by SQLite scan history;
- a **Chrome Manifest V3 extension**, which checks the current tab;
- a reproducible, leakage-controlled **ML pipeline**.

> **Limitation:** results are automated risk signals, not guarantees. On
> held-out test data the deployed model (v2.0.0) detected **56.7%** of phishing
> URLs (recall 0.5675), so it **missed 43.3%**. It also flagged **5.5%** of
> legitimate URLs. It judges the site's registrable domain only (e.g.
> `google.com` for `admob.google.com`) and never visits the page. Why recall
> fell from the earlier 73.6% (v1.2.0) is explained in
> [docs/false_positive_investigation.md](docs/false_positive_investigation.md).

## Quick start

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt pytest
python app.py                       # http://127.0.0.1:5000
```

- **Backend and frontend:** `python app.py` serves both the API and the web
  pages. There is no separate frontend server.
  - `http://127.0.0.1:5000/` is the landing page and scanner.
  - `/inspect` is the full scanner with model details.
  - `/dashboard` shows history and statistics.
- **Database:** created automatically at `instance/scan_history.db`, or wherever
  `DATABASE_PATH` points. No setup is needed.
- **Chrome extension:** open `chrome://extensions`, enable Developer mode, click
  **Load unpacked** and select `extension/`. Then click the icon on any web page.
- **macOS:** if port 5000 is taken by the AirPlay receiver, run
  `API_PORT=5051 python app.py`. Then set the same origin in
  `extension/config.js` (`API_BASE`) and `extension/manifest.json`
  (`host_permissions`); see [docs/extension.md](docs/extension.md).
- **Configuration:** environment variables, listed in
  [.env.example](.env.example) and [docs/api.md](docs/api.md).

```bash
curl -s -X POST http://127.0.0.1:5000/api/predict -H "Content-Type: application/json" \
     -d '{"url": "https://github.com/pallets/flask"}'
```

## Tests

```bash
python -m pytest            # 289 tests: ML, API, database, security, plus 56 headless-Chrome tests
python scripts/benchmark_api.py   # measured API latency/throughput → docs/data/performance.json
```

Browser tests use the installed Google Chrome and are skipped if it is missing.
See [docs/testing.md](docs/testing.md).

## Measured results

**Model** (test split, 23,536 URLs, never used for training or tuning):

| Model | Split / view | Accuracy | Precision | Recall | F1 | ROC-AUC |
|---|---|---|---|---|---|---|
| **v2.0.0 GradientBoosting (deployed)** | registrable-grouped / registrable domain | 0.7872 | 0.8801 | 0.5675 | 0.6900 | 0.8524 |
| v1.3.0 HistGradientBoosting (alternative) | registrable-grouped / full host | 0.8369 | 0.9055 | 0.6801 | 0.7768 | 0.8906 |
| v1.2.0 HistGradientBoosting (archived) | host-grouped / full host | 0.8578 | 0.9140 | 0.7363 | 0.8156 | 0.8990 |

v1.2.0 flagged legitimate subdomain sites (AdMob, Cloudflare dashboard, Gmail, …)
as phishing because the dataset's legitimate URLs almost never have subdomains.
v2.0.0 removes that systematic false-positive class at a measured cost in
recall. v1.2.0's split also leaked sibling subdomains between train and test.
See [docs/false_positive_investigation.md](docs/false_positive_investigation.md).

**API** (real `python app.py`, macOS arm64):

| Median `POST /api/predict` latency | Server time | Throughput, 8 concurrent clients |
|---|---|---|
| 4.17 ms (including the history write) | 0.79 ms | 862.1 predictions/s |

The original notebook's ~99.97% accuracy came from a leaky feature and from how
the dataset was built (every legitimate URL is a bare homepage). Duplicate URLs
didn't cause it. See [docs/model_evaluation.md](docs/model_evaluation.md).

## Documentation

| Topic | File |
|---|---|
| System architecture | [docs/architecture.md](docs/architecture.md) |
| REST API | [docs/api.md](docs/api.md) |
| Scan history database | [docs/database.md](docs/database.md) |
| Web frontend | [docs/frontend.md](docs/frontend.md) |
| Chrome extension | [docs/extension.md](docs/extension.md) |
| Security review | [docs/security.md](docs/security.md) |
| Testing, acceptance, performance | [docs/testing.md](docs/testing.md) |
| Dataset and leakage audit | [docs/dataset.md](docs/dataset.md) |
| False-positive investigation (v2.0.0) | [docs/false_positive_investigation.md](docs/false_positive_investigation.md) |
| Review-2 / viva preparation | [docs/REVIEW_2_AND_VIVA_GUIDE.md](docs/REVIEW_2_AND_VIVA_GUIDE.md), [docs/VIVA_QUICK_REFERENCE.md](docs/VIVA_QUICK_REFERENCE.md), [docs/PROJECT_KNOWLEDGE_MAP.md](docs/PROJECT_KNOWLEDGE_MAP.md) |
| Model evaluation, error analysis | [docs/model_evaluation.md](docs/model_evaluation.md), [docs/ml_error_analysis.md](docs/ml_error_analysis.md) |

## Project layout

```text
app.py, config.py         Flask entry point and configuration
backend/                  API routes, validation, errors, security headers, rate limit
services/                 prediction, history, explanation, optional threat intelligence
ml/                       feature schema, extractor, predictor, training, evaluation, error analysis
database/                 SQLite schema, migrations, repository
models/                   deployed model v2.0.0, metadata, TLD table; previous_v1.2.0/, baseline_v1.1.0/,
                          alternatives/host_view_v1.3.0/ (preserved earlier/alternative models)
templates/, static/       web frontend (no external assets)
extension/                Chrome MV3 extension
scripts/                  dataset audit, feature parity, benchmark, icon generator
tests/, tests/browser/    automated tests (browser tests drive headless Chrome)
data/                     PhiUSIIL dataset splits (read-only)
```

## ML pipeline (reproducible)

```bash
python scripts/dataset_audit.py   # dataset, duplicate and leakage audit
python -m ml.train_model          # retrains the deployed model (deterministic, seed 42)
python -m ml.view_experiment      # host vs registrable-domain view (validation only)
python -m ml.evaluate_model       # methodology comparison
python -m ml.error_analysis       # error and feature analysis
```

## Original research scripts

The initial experiment scripts are kept for reference and are **not** used by
the application:
- `train_models.py`, `train_models_clean.py`, `train_models_full_features.py`
- `ensemble*.py`, `feature_ablation*.py`, `analyze_feature_importance.py`
- `train_distilbert*.py`, `predict.py`

They trained six models (and DistilBERT) on the stored dataset columns. Those
columns include the leaky `URLSimilarityIndex`, which is why their near-perfect
scores don't carry over to real URLs. The earlier notebook model
(`../projectcopy/url/Phishing_model.pkl`) is preserved unchanged and unused. It
cannot be loaded with scikit-learn 1.6.1 (see [docs/dataset.md](docs/dataset.md)).

Dataset label convention: `0` = phishing, `1` = legitimate.
