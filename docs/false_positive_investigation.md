# False-positive investigation (model v1.2.0 → v2.0.0)

Evidence files (all regenerable):

| File | Produced by |
|---|---|
| `docs/data/view_experiment.json` | `python -m ml.view_experiment` (validation only) |
| `docs/data/feature_comparison.md` / `.json` | `python scripts/feature_comparison.py` |
| `docs/data/dataset_audit.json` | `python scripts/dataset_audit.py` |
| `docs/data/calibration.json` | `python scripts/calibration_report.py` |
| `models/model_metadata.json` and `models/alternatives/host_view_v1.3.0/model_metadata.json` | `python -m ml.train_model` |

**No whitelist, allow-list or per-domain override is used anywhere.**

## 1. The observed problem

The deployed v1.2.0 model classified these legitimate URLs as **Phishing / High**
(taken from `instance/scan_history.db`, extension scans):

| URL | P(phishing) |
|---|---|
| `https://admob.google.com/v2/home` | 0.9801 |
| `https://publisher.unity.com/packages` | 0.9707 |
| `https://dashboard.render.com/` | 0.9762 |
| `https://dash.cloudflare.com/…/r2/overview` | 0.9820 |

`https://claude.ai/chat/…` was **Safe** (0.1796).

## 2. Production pipeline at the time (v1.2.0)

URL → `ml.url_utils.normalize_url` → model input `https://www.<host>`
(`ml.feature_extractor.model_input`, **host view**) → 17 lexical features
(`ml.feature_schema`, fixed order) → `HistGradientBoostingClassifier`
(`models/phishing_model.pkl`) → `predict_proba` P(phishing) → thresholds
(0.4991 flag, 0.6050 high) → Safe / Suspicious / Phishing → Flask API → SQLite
→ web UI / extension.

There is no scaling or other preprocessing step; tree models use the raw
feature values. Paths and query strings are never model inputs.

## 3. Root cause, with evidence

### 3.1 Counterfactual test on the production predictor

With everything else fixed, **adding any subdomain flips the prediction**:

| URL | v1.2.0 model input | Prediction | P |
|---|---|---|---|
| `https://google.com` | `https://www.google.com` | Safe | 0.295 |
| `https://admob.google.com` | `https://www.admob.google.com` | Phishing | 0.980 |
| `https://mail.google.com` | `https://www.mail.google.com` | Phishing | 0.985 |
| `https://render.com` | `https://www.render.com` | Safe | 0.295 |
| `https://dashboard.render.com/` | `https://www.dashboard.render.com` | Phishing | 0.976 |
| `https://example.com` | `https://www.example.com` | Safe | 0.299 |
| `https://a.example.com` | `https://www.a.example.com` | Phishing | 0.954 |
| `https://a.b.example.com` | `https://www.a.b.example.com` | Phishing | 0.943 |

`a.example.com` is flagged at 0.954 even though the subdomain `a` carries no
meaning, and `claude.ai` was Safe because it has no subdomain. The changed
features are:
- `NoOfSubDomain` (1 → 2);
- `DomainLength`;
- `CharContinuationRate`;
- `NoOfOtherSpecialCharsInURL` (one extra dot).

### 3.2 Dataset evidence (PhiUSIIL training split)

- **Legitimate URLs are homepages.** 100% of legitimate training URLs are
  exactly `https://www.<host>`.
- **For `.com` hosts,** a subdomain below the registrable domain appears in:
  - **0.31%** of legitimate hosts (169 of 55,005);
  - **49.9%** of phishing hosts (17,601 of 35,283).

  In the training data, a `.com` host with a subdomain is phishing ≈ 99% of
  the time.
- **By label count** (excluding `www`), for 3 or more labels: 15,953
  legitimate vs 45,946 phishing. Most legitimate 3-label hosts are
  country-code second-level domains such as `co.uk`.

The model learned this correlation correctly. **The cause is dataset
construction:** the legitimate class does not represent real-world legitimate
subdomain traffic such as dashboards, mail and docs.

### 3.3 Causes ruled out

| Candidate | Finding |
|---|---|
| Feature extraction mismatch | Training and prediction use the same function; `tests/test_pipeline.py::test_training_and_prediction_features_are_identical` passes |
| Feature encoding / order | Validated on every prediction (`validate_vector`, `Predictor` checks `feature_names_in_`) |
| Path, token, query or HTTPS features | Not model inputs in the host view; the counterfactuals vary only the host |
| Threshold | P = 0.94–0.99 is far above any reasonable threshold. The threshold table (`docs/ml_error_analysis.md`) shows no operating point that separates these without also passing most phishing. |
| Calibration | v1.2.0 is well calibrated in-distribution (validation ECE 0.035, `docs/data/calibration.json`). The 0.98 is a faithful estimate of P(phishing given "subdomain present") **in the training distribution**; the error comes from the distribution shift, not from calibration. |
| Class imbalance | 42.7% phishing (mild); weighting did not change behaviour (`docs/ml_error_analysis.md`) |
| Overfitting | Validation and test metrics agree; the pattern is systematic, not noise |
| Duplicate-URL leakage | Ruled out earlier (`docs/model_evaluation.md`) |

### 3.4 A leakage problem found in the process

The v1.2.0 split grouped by **host**, so sibling hosts of one registrable domain
(`a.evil.com` in train, `b.evil.com` in test) could span splits. Measured in
`docs/data/dataset_audit.json`:

| Split | Test rows sharing a registrable domain with train |
|---|---|
| host-grouped (v1.2.0) | **3,317 of 23,536 (14.1%)** |
| registrable-grouped (v2.0.0) | 0 |

On the stricter split, the same host-view configuration scores **0.6475**
validation recall at FPR ≤ 5%, against 0.7134 on the host-grouped split. Part
of v1.2.0's reported recall came from these near-duplicates. The test sets
differ, so the size of the effect is indicative rather than exact.

## 4. Fix considered: registrable-domain view

The model judges the site's **registrable domain**: the Public Suffix List
eTLD+1, computed with `ml.url_utils.split_registrable`, `tldextract` 5.1.2 and
its bundled offline PSL snapshot.

| URL | Model input |
|---|---|
| `https://admob.google.com/v2/home` | `https://www.google.com` |
| `http://login.paypal.com.evil.xyz/` | `https://www.evil.xyz` (not treated as trusted) |
| `https://abc.firebaseapp.com/` | `https://www.abc.firebaseapp.com` (`firebaseapp.com` is a PSL shared-hosting suffix, so each hosted site stays separate) |

The PSL describes **domain registration structure**. It contains no
information about which sites are trustworthy, and no domain is treated
specially.

### 4.1 Controlled experiment (validation only; `docs/data/view_experiment.json`)

Both views were trained with the same 12 model configurations on the same
registrable-grouped split. The table shows HistGradientBoosting (balanced) at
each view's validation FPR ≤ 5% threshold:

| Metric (validation) | Host view | Registrable view |
|---|---|---|
| Overall recall | 0.6475 | 0.4277 (−0.2196, 95% CI [−0.2277, −0.2114]) |
| FPR on legitimate URLs **with a subdomain** (422 rows) | **17.8%** | **1.2%** |
| Recall on phishing on **subdomains of the attacker's domain** (3,663) | 0.991 | 0.328 |
| Recall on phishing on **shared-hosting** suffixes (2,454) | 0.990 | 0.988 |
| Hand-picked real legitimate URLs flagged (20; illustrative) | 13 | 0 |

A third option gave the model both views' features (34 features). It
reproduced the host-view behaviour: recall 0.6473, legitimate-subdomain FPR
18.5%, 13/20 probe URLs flagged. Whenever subdomain information is visible, the
model learns "subdomain → phishing", because the data supports that almost
perfectly.

**Conclusion:** this dataset cannot teach the difference between legitimate and
phishing subdomains. The choice between views is a genuine trade-off.

### 4.2 Decision rule (validation data only, stated before test evaluation)

A deployable model must not concentrate its false alarms on a whole structural
class of legitimate URLs. Its validation FPR on legitimate URLs with a
subdomain must be ≤ 2× its overall validation FPR (`MAX_SUBDOMAIN_FPR_RATIO` in
`ml/train_model.py`). Among models that pass, the existing rule selects: highest
recall at FPR ≤ 5%, and a challenger replaces the incumbent only with a
significant paired-bootstrap gain.

| Model | Legitimate-subdomain FPR | Overall FPR | Ratio | Passes |
|---|---|---|---|---|
| Host view (v1.3.0 alternative) | 17.8% | 4.99% | 3.56 | no |
| Registrable view (v2.0.0) | 0.95% | 4.99% | 0.19 | yes |

## 5. Result: model v2.0.0 (deployed)

- **Model:** `GradientBoostingClassifier` (scikit-learn; 200 trees, depth 3,
  learning rate 0.1, unweighted, seed 42). It was selected because its
  validation recall gain over the incumbent HistGradientBoosting was
  significant: +0.1395, 95% CI [+0.1317, +0.1482].
- **Input:** 17 features (schema unchanged), registrable view.
- **Split:** registrable-grouped 80/10/10, seed 42.
- **Thresholds:** 0.5200 (validation FPR ≤ 5%) and 0.6443 for "Phishing (high)".

Held-out test results, evaluated once. **These are not directly comparable,
because the rows differ in both split and view:**

| Model | Split / view | Accuracy | Precision | **Recall** | F1 | ROC-AUC | FPR | TN | FP | FN | TP |
|---|---|---|---|---|---|---|---|---|---|---|---|
| v1.2.0 (archived) | host-grouped / host | 0.8578 | 0.9140 | 0.7363 | 0.8156 | 0.8990 | 0.0516 | 12,790 | 696 | 2,650 | 7,400 |
| v1.3.0 alternative | registrable-grouped / host | 0.8369 | 0.9055 | 0.6801 | 0.7768 | 0.8906 | 0.0508 | 12,752 | 683 | 3,077 | 6,543 |
| **v2.0.0 deployed** | registrable-grouped / registrable | **0.7872** | **0.8801** | **0.5675** | **0.6900** | 0.8524 | 0.0554 | 12,691 | 744 | 4,161 | 5,459 |

v1.3.0 and v2.0.0 share the same test set, so they compare directly.

**The v2.0.0 trade-off, stated plainly:** phishing recall falls from 0.6801 to
**0.5675**, so the model misses 43.3% of phishing URLs in the test set. In
return, legitimate subdomain URLs are no longer systematically flagged: 0.95%
instead of 17.8% on validation, and 0/20 instead of 13/20 on the real-world
probe.

The reported URLs under v2.0.0 (`docs/data/feature_comparison.md`):

| URL | v2.0.0 | P |
|---|---|---|
| `admob.google.com` | Safe | 0.421 |
| `publisher.unity.com` | Safe | 0.443 |
| `dashboard.render.com` | Safe | 0.421 |
| `dash.cloudflare.com` | Safe | 0.483 |
| `claude.ai` | Safe | 0.249 |

These scores sit just below the 0.52 threshold. They are low-risk predictions,
not confident ones.

## 6. Remaining limitations of v2.0.0

1. **Phishing on subdomains of an attacker-owned domain** is judged only by
   that domain (e.g. `login.paypal.com.evil.xyz` becomes `evil.xyz`). Recall on
   this class is 0.328 on validation. The explanation adds a rule-based
   *observation* when a subdomain contains another domain name ("The subdomain
   contains another domain name (paypal.com) …"). That observation **never
   changes the score**; `tests/test_pipeline.py::test_subdomain_observations_do_not_change_the_score`
   checks this.
2. **Shared-hosting platforms missing from the PSL** lose their per-site
   identity. Example: `bnqqwuvsqnogdme18.z1.web.core.windows.net` (phishing) is
   judged as `windows.net` and scored Safe (0.364). The `ipfs.io` gateway
   behaves similarly.
3. **Compromised legitimate domains** can't be detected from the domain name.
4. **Uncalibrated scores.** v2.0.0 has validation ECE 0.061 and Brier 0.156;
   for example, URLs scored 0.5–0.6 were phishing 83% of the time. The UI
   calls the value "model confidence", never certainty.
5. **The root cause remains:** the dataset has almost no legitimate subdomain
   URLs. The real fix is a more representative legitimate class (future work).

## 7. Reproducibility

| Model | Location |
|---|---|
| v1.1.0 | `models/baseline_v1.1.0/` |
| v1.2.0 | `models/previous_v1.2.0/` (archived automatically by `ml.train_model` before v2.0.0 was written) |
| v1.3.0 (host-view alternative) | `models/alternatives/host_view_v1.3.0/` |
| v2.0.0 (deployed) | `models/` |

- Every model directory holds its metadata: seed, split, view, class
  distribution, hyperparameters, metrics, confusion matrix, Python and
  scikit-learn versions, training date.
- To serve a different model, point `MODEL_PATH`, `MODEL_METADATA_PATH` and
  `TLD_TABLE_PATH` at its directory. The predictor reads the view from the
  metadata.
- The historical analyses (`ml.evaluate_model`, `ml.error_analysis`) are pinned
  to the archived v1.2.0 and reproduce their earlier outputs exactly.
