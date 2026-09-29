# Model evaluation

Generated numbers:
- `models/model_metadata.json` (`python -m ml.train_model`)
- `docs/data/evaluation.json` and `docs/model_evaluation_tables.md` (`python -m ml.evaluate_model`)

Phishing is the positive class for every metric.

> **Superseded.** The deployed model is now **v2.0.0** (registrable-domain view,
> registrable-grouped split). This document records model v1.2.0 and the
> original-vs-leakage-controlled methodology study, which remain valid as
> history. v1.2.0 is archived in `models/previous_v1.2.0/`. For v2.0.0, why it
> replaced v1.2.0 and its metrics, see `docs/false_positive_investigation.md`.

## Model v1.2.0 (archived; was the final model before v2.0.0)

Model selection, class weighting, threshold choice and error analysis are in
`docs/ml_error_analysis.md`.

| Item | Value |
|---|---|
| Model | `HistGradientBoostingClassifier` (max_iter=300, learning_rate=0.1, balanced sample weights, random_state=42); v1.2.0: a deterministic refit of v1.1.0 with bit-identical scores on all splits (the pickle bytes differ) |
| File | `models/phishing_model.pkl` (+ `models/model_metadata.json`, `models/tld_legitimate_prob.json`); v1.1.0 copy in `models/baseline_v1.1.0/` |
| Input | 17 features from `ml/feature_schema.py`, computed from the host view `https://www.<host>` |
| Split | host-grouped 80/10/10, seed 42 (see `docs/dataset.md`) |
| Selection | 12 candidates compared at validation FPR ≤ 5%. The incumbent is kept unless a challenger's recall gain is significant (paired bootstrap); none was. |
| Threshold | 0.4991: the lowest threshold with validation FPR ≤ 5%. Test used once. |
| Environment | Python 3.9.6, scikit-learn 1.6.1, numpy 2.0.2 |

Test results (23,536 URLs; threshold 0.4991):

| Accuracy | Precision | Recall | F1 | ROC-AUC | FPR |
|---|---|---|---|---|---|
| 0.8578 | 0.9140 | 0.7363 | 0.8156 | 0.8990 | 0.0516 |

| | Predicted legitimate | Predicted phishing |
|---|---|---|
| **Legitimate** (13,486) | 12,790 | 696 |
| **Phishing** (10,050) | 2,650 | 7,400 |

| Class | Precision | Recall | F1 | Support |
|---|---|---|---|---|
| legitimate | 0.8284 | 0.9484 | 0.8843 | 13,486 |
| phishing | 0.9140 | 0.7363 | 0.8156 | 10,050 |

Training time for the selected model: 2.0 s. The saved model scores identically to
a fresh refit in `ml.evaluate_model` (experiment C), which confirms training is
reproducible.

Risk levels: P(phishing) < 0.4991 is **Safe**. P ≥ 0.605 is **Phishing**, the
lowest threshold with ≥ 95% validation precision. Anything in between is
**Suspicious**.

## Original vs leakage-controlled methodology

HistGradientBoosting, test split, threshold 0.5 for all rows (full tables in `docs/model_evaluation_tables.md`):

| Experiment | Split | Features | Accuracy | F1 | ROC-AUC |
|---|---|---|---|---|---|
| A | original random | 22 stored columns incl. URLSimilarityIndex | 0.9998 | 0.9997 | 0.9999 |
| A2 | original random | 17 recomputed, host view | 0.8569 | 0.8131 | 0.9013 |
| B2 | URL-grouped | 17 recomputed, host view | 0.8543 | 0.8099 | 0.9000 |
| **C** | **host-grouped** | **17 recomputed, host view (final)** | **0.8578** | **0.8155** | **0.8990** |

**Did duplicate URLs materially affect the results? No.**
- Only 63 test URLs also appear in train in the original split (0.27% of test).
- A2, B2 and C use the same features and models and differ only in how leakage is
  controlled. Their F1 differs by at most 0.006 and ROC-AUC by at most 0.003, and
  these do not move in the direction leakage would predict.
- The model-input overlap is larger (2,025–2,042 test rows) but does not inflate
  the scores. On those rows the model's recall is 0.78–0.79, against 0.71 on the
  rest. Their precision is 0.999, but at least 99.7% of those rows are phishing, so that
  number is not meaningful.

The ~0.9997 of the original methodology comes from two other things:
1. **Leaky features.** `URLSimilarityIndex` is similarity to the dataset authors'
   legitimate-URL list and equals 100 for every legitimate row. It can't be
   computed for new URLs, so it is excluded.
2. **Dataset construction bias.** Every legitimate URL is a bare
   `https://www.<host>` homepage. A rule with no ML ("phishing unless the URL is
   exactly `https://www.<host>`") scores 0.9960 F1 on the original test split. A
   model on the full URL (experiment B1: 0.9974 F1) learns the same shortcut: in
   the bias probe it flags 8/8 legitimate deep links and 5/6 legitimate homepages
   without `www`.

The deployed model therefore judges only the host (experiment C). In the same
probe it flags 0/12 legitimate homepages and 2/8 deep links: `docs.python.org`
and `en.wikipedia.org`, because of their subdomain structure. The probe is a
hand-picked illustration, not a population estimate.

## Limitations

- Recall is 0.736: about a quarter of phishing URLs have hosts that look ordinary,
  e.g. on shared hosting or URL shorteners, and are missed. URL-string features
  alone cannot catch these.
- The model ignores path, query and scheme by design. The submitted scheme, port,
  userinfo and similar details are reported to the user as observations
  (`url_facts`, explanation engine), not used as model inputs.
- PhiUSIIL legitimate URLs are popular sites' homepages, so performance on
  obscure legitimate hosts is likely lower than the test figures.

## Environment

- The original model needs scikit-learn 1.2.1 and cannot be loaded with the
  installed 1.6.1. The new model was trained and tested with 1.6.1. The
  predictor checks feature count, order and names when it loads.
- With numpy 2.0.2 on macOS (Apple Accelerate), logistic regression emits
  "divide by zero / overflow / invalid value encountered in matmul"
  RuntimeWarnings. These were checked, not just suppressed: the fitted
  coefficients are finite (converged in 56 iterations), and predictions match a
  BLAS-free `einsum` computation within 6e-16. `pytest.ini` filters only this
  warning.
