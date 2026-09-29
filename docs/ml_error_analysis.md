# ML improvement and error analysis

> **Scope:** this analysis is of model **v1.2.0** (host view). It is kept
> because its findings led to v2.0.0: the false-negative patterns, the finding
> that recall is limited by features rather than the model, and the threshold
> policy. The deployed model is now v2.0.0 (see
> `docs/false_positive_investigation.md`). `python -m ml.error_analysis`
> reproduces this analysis from the archived v1.2.0 model.

Sources of every number:
- `models/model_metadata.json` (`python -m ml.train_model`): candidates, thresholds, test result
- `docs/data/error_analysis.json` (`python -m ml.error_analysis`): error patterns, feature analysis

Split: the host-grouped 80/10/10 split (seed 42), identical for every model. Phishing is the positive class.

## Summary

- **Recall is limited by the features, not by the model, the class balance or
  the threshold.**
  - The 188,550 training rows collapse to only 23,882 distinct 17-feature
    vectors, and 66% of rows share their exact vector with a row of the other
    class.
  - Even a perfect classifier on these features makes at least 12.5% training
    error.
  - At the most-accurate operating point, recall can be at most **0.733**. The
    model's test recall is 0.736.
- **No alternative model is better.** Twelve candidates were compared (5
  families, unweighted and class-weighted) at the same 5% false-positive rate.
  None beats the current model by more than the validation sampling error; LR,
  DT, RF and classic GB are significantly worse.
- **Class imbalance is not the cause.** Classes are 43% / 57%. Class weighting
  only moves scores along the same ROC curve: at a fixed FPR, weighted and
  unweighted versions are indistinguishable.
- **Threshold.** Chosen on validation as the lowest threshold with FPR ≤ 5%:
  0.4991, practically the old 0.5. More recall is only available by flagging
  far more legitimate sites. Recall 0.79 costs 17% FPR; recall 0.97 costs 65%.
- **Final model: unchanged** (v1.1.0 HistGradientBoosting). The retrain
  re-saved the pickle, so the file bytes differ, but it is a deterministic refit
  with bit-identical scores on every train, validation and test row. Only the
  documented threshold changed.

## Baseline (v1.1.0, before this phase)

HistGradientBoostingClassifier with balanced class weights, threshold 0.5. Copy
kept in `models/baseline_v1.1.0/`. On test: accuracy 0.8578, precision 0.9146,
recall 0.7357, F1 0.8155, ROC-AUC 0.8990.

## Task 1: error analysis

The final model at threshold 0.4991:

| Split | TP | FN | FP | TN |
|---|---|---|---|---|
| Validation | 6,985 | 2,806 | 673 | 12,812 |
| Test | 7,400 | 2,650 | 696 | 12,790 |

The table below compares missed phishing (FN) with caught phishing (TP) and
correctly passed legitimate URLs (TN), on test (validation shares are within ±0.06):

| | TP (caught) | **FN (missed)** | TN (legit) |
|---|---|---|---|
| Host is a subdomain of a hosting platform* | 53.9% | **7.1%** | 12.1% |
| All 7 summary features inside legitimate 5th–95th percentile | 10.1% | **83.1%** | 83.2% |
| Median host length (`www.` included) | 28 | **19** | 19 |
| Median subdomain levels | 2 | **1** | 1 |
| Mean TLDLegitimateProb | 0.171 | **0.350** | 0.284 |
| Submitted with `http://` | 41.9% | **76.0%** | 0% |
| Has a path or query | 29.8% | **23.8%** | 0% |
| Path contains `.php` / `wp-` | 4.9% | **9.2%** | 0% |
| Median P(phishing) | 0.997 | **0.255** | 0.239 |

\*A parent domain that hosts ≥ 20 distinct training hosts, e.g. `web.app`,
`firebaseapp.com`, `repl.co`, `weeblysite.com` (210 such parents, taken from the
training split).

**The "ordinary-looking host" observation holds.**
- In the model's feature space, missed phishing looks the same as legitimate
  sites: 83% of FNs fall inside the legitimate 5–95% range on every summary
  feature, like 83% of TNs and only 10% of TPs.
- The FN and TN feature medians are identical.
- Their scores overlap as well: median P(phishing) is 0.255 for FNs and 0.239
  for TNs.

**What the model catches** is mostly phishing on free hosting and app
platforms:

| Platform | Test TPs |
|---|---|
| `web.app` | 618 |
| `firebaseapp.com` | 560 |
| `repl.co` | 377 |
| `weeblysite.com` | 330 |
| `pinata.cloud` | 275 |
| `bit.ly` | 150 |

These have long, multi-level hosts.

**What it misses** falls into two groups:
1. **Plain registered domains** (`http://www.<name>.<tld>`), often on country-code
   second-level domains: `com.br` 39, `com.au` 39, `co.uk` 35 in the test FNs.
   Nothing in the host string separates them from a small legitimate site.
2. **Compromised legitimate sites hosting a phishing kit**, where the evidence is
   only in the path (`/wp-content/…/rgn.php`, `/ibg/client/ispc.php`). About 24%
   of FNs have a path and 9% a `.php`/WordPress path.

Representative test false negatives (defanged; from the public dataset):

| URL | P(phishing) |
|---|---|
| `hxxp://www[.]globaltopgarlic[.]com` | 0.2368 |
| `hxxp://pancakeswaaps[.]com` | 0.2426 |
| `hxxp://www[.]tytalrecoverysolutions[.]com` | 0.2851 |
| `hxxp://www[.]librarycollection[.]org` | 0.0619 |
| `hxxps://www[.]blogschain[.]com/fold/prohqcker[.]php` | 0.2545 |
| `hxxps://ganzeweltreisen[.]de/wp-content/uploads/2023/fr/ca/…/rgn[.]php?particulier` | 0.1444 |
| `hxxps://therecipemtf[.]com/ibg/client/ispc[.]php` | 0.2426 |

More examples are in `docs/data/error_analysis.json` (25 FNs, 15 FPs).

**False positives** (696 on test) are legitimate sites with unusual-looking hosts:
- digits, as in `2009gtr.com` and `12news.com`;
- hyphens, as in `watching-grass-grow.com`;
- deeper hosts, as in `town.north-haven.ct.us`;
- rare TLDs, as in `.news` and `.nyc`.

### Does the feature set lack discriminative information? Yes.

1. **Ambiguity.** 188,550 training rows map to only 23,882 distinct feature
   vectors, and 66.1% of rows share their exact vector with a row of the other
   class. Since identical inputs must get identical predictions:
   - minimum possible training error for any classifier is 12.49%;
   - recall at the most-accurate operating point is at most 0.733.

   The model reaches 0.736 recall on test, so it already sits at this limit.
2. **Degenerate features in the host view:**
   - `IsHTTPS` is always 1.
   - `NoOfEqualsInURL`, `NoOfQMarkInURL` and `NoOfAmpersandInURL` are always 0.
   - `URLLength` is always `DomainLength + 8`.

   So only 12 of the 17 inputs carry independent information.
3. **The signals that do separate FNs can't be learned from this dataset.**
   76% of FNs use `http://` and 24% have a path, but 0 of 107,879 legitimate
   training URLs do either. A model given the scheme or path would learn "http
   or any path ⇒ phishing"; that was experiment B1 in `docs/model_evaluation.md`,
   which flagged 8/8 legitimate deep links.
4. **Richer host lexical features help only a little** (diagnostic, validation
   only). Adding hyphen count, character entropy, vowel ratio, longest
   consonant run, phishing keywords and a hosting-platform flag to the same
   model:

   | | Validation recall at FPR ≤ 5% | ROC-AUC |
   |---|---|---|
   | 17 features | 0.7134 | 0.8938 |
   | 23 features | 0.7189 (+0.0055) | 0.8980 |

   These features were designed after looking at FNs, so they aren't adopted
   and would need a fresh evaluation. Either way, the host string holds little
   more signal.

The missing information is outside the host string:
- page content;
- domain age / WHOIS;
- reputation feeds (e.g. Safe Browsing);
- the path, which would need a training set whose legitimate URLs include
  paths.

## Task 2: model comparison (validation, threshold 0.5)

| Model | Weighting | Accuracy | Precision | Recall | F1 | ROC-AUC | TN | FP | FN | TP |
|---|---|---|---|---|---|---|---|---|---|---|
| logistic_regression | none | 0.7776 | 0.8628 | 0.5603 | 0.6794 | 0.7898 | 12613 | 872 | 4305 | 5486 |
| logistic_regression | balanced | 0.7741 | 0.8141 | 0.5998 | 0.6907 | 0.7903 | 12144 | 1341 | 3918 | 5873 |
| decision_tree | none | 0.8465 | 0.9391 | 0.6791 | 0.7882 | 0.8875 | 13054 | 431 | 3142 | 6649 |
| decision_tree | balanced | 0.8449 | 0.9068 | 0.7036 | 0.7924 | 0.8883 | 12777 | 708 | 2902 | 6889 |
| random_forest | none | 0.8492 | 0.9303 | 0.6936 | 0.7947 | 0.8884 | 12976 | 509 | 3000 | 6791 |
| random_forest | balanced | 0.8480 | 0.9112 | 0.7076 | 0.7966 | 0.8880 | 12810 | 675 | 2863 | 6928 |
| gradient_boosting (sklearn) | none | 0.8462 | 0.9264 | 0.6892 | 0.7904 | 0.8863 | 12949 | 536 | 3043 | 6748 |
| gradient_boosting (sklearn) | balanced | 0.8380 | 0.8754 | 0.7170 | 0.7883 | 0.8863 | 12486 | 999 | 2771 | 7020 |
| hist_gradient_boosting | none | 0.8514 | 0.9407 | 0.6903 | 0.7963 | 0.8940 | 13059 | 426 | 3032 | 6759 |
| **hist_gradient_boosting** | **balanced** | **0.8506** | **0.9127** | **0.7130** | **0.8006** | **0.8938** | 12817 | 668 | 2810 | 6981 |
| hist_gradient_boosting_large | none | 0.8516 | 0.9395 | 0.6917 | 0.7968 | 0.8944 | 13049 | 436 | 3019 | 6772 |
| hist_gradient_boosting_large | balanced | 0.8504 | 0.9085 | 0.7164 | 0.8011 | 0.8936 | 12779 | 706 | 2777 | 7014 |

At a fixed threshold of 0.5, models trade precision against recall differently,
so they can't be ranked fairly from that table. Selection therefore compares
every model at the **same false-positive rate** (≤ 5%, each model's own
validation threshold):

| Model | Weighting | Threshold | Precision | Recall | F1 | FPR | Avg precision | Recall gain vs incumbent [95% CI] | Fit s |
|---|---|---|---|---|---|---|---|---|---|
| logistic_regression | none | 0.5508 | 0.8871 | 0.5408 | 0.6720 | 0.0500 | 0.8119 | −0.1734 [−0.1843, −0.1626] | 0.17 |
| logistic_regression | balanced | 0.6219 | 0.8871 | 0.5407 | 0.6719 | 0.0500 | 0.8120 | −0.1737 [−0.1845, −0.1633] | 0.20 |
| decision_tree | none | 0.4230 | 0.9137 | 0.6976 | 0.7912 | 0.0478 | 0.8856 | −0.0157 [−0.0228, −0.0097] | 0.20 |
| decision_tree | balanced | 0.5082 | 0.9107 | 0.7002 | 0.7917 | 0.0498 | 0.8880 | −0.0145 [−0.0214, −0.0085] | 0.22 |
| random_forest | none | 0.4354 | 0.9113 | 0.7074 | 0.7965 | 0.0500 | 0.8952 | −0.0066 [−0.0132, −0.0009] | 2.59 |
| random_forest | balanced | 0.5002 | 0.9113 | 0.7076 | 0.7966 | 0.0500 | 0.8949 | −0.0066 [−0.0131, −0.0008] | 2.60 |
| gradient_boosting (sklearn) | none | 0.4675 | 0.9102 | 0.6964 | 0.7890 | 0.0499 | 0.8904 | −0.0174 [−0.0246, −0.0115] | 17.14 |
| gradient_boosting (sklearn) | balanced | 0.5383 | 0.9101 | 0.6967 | 0.7892 | 0.0500 | 0.8901 | −0.0172 [−0.0243, −0.0111] | 16.81 |
| hist_gradient_boosting | none | 0.4301 | 0.9123 | 0.7164 | 0.8026 | 0.0500 | 0.8989 | +0.0022 [−0.0030, +0.0057] | 2.15 |
| **hist_gradient_boosting** | **balanced** | 0.4991 | 0.9121 | 0.7134 | 0.8006 | 0.0499 | 0.8988 | incumbent (= v1.1.0) | 2.04 |
| hist_gradient_boosting_large | none | 0.4321 | 0.9123 | 0.7146 | 0.8014 | 0.0499 | 0.8995 | +0.0009 [−0.0046, +0.0051] | 5.96 |
| hist_gradient_boosting_large | balanced | 0.5088 | 0.9120 | 0.7138 | 0.8008 | 0.0500 | 0.8989 | +0.0000 [−0.0050, +0.0044] | 6.52 |

Configurations are in `ml/model_utils.py:model_grid`. `hist_gradient_boosting_large`
means 600 iterations, learning rate 0.05, 63 leaves. The grid's
`hist_gradient_boosting / balanced` reproduces the v1.1.0 model exactly.

**Selection rule.** The incumbent is kept unless a challenger's validation
recall gain at FPR ≤ 5% is significant: the 95% interval of a paired,
class-stratified bootstrap (1,000 resamples, threshold re-derived in each) must
lie entirely above 0. No challenger qualifies.

**Disclosure.** The first run of this phase used a fixed tie margin of 0.002
recall. It selected `hist_gradient_boosting_large / none` (threshold 0.4321),
and that model was scored on test once:

| Accuracy | Precision | Recall | F1 | ROC-AUC | TN | FP | FN | TP |
|---|---|---|---|---|---|---|---|---|
| 0.8590 | 0.9166 | 0.7368 | 0.8169 | 0.8991 | 12,812 | 674 | 2,645 | 7,405 |

The margin was then found to be smaller than the validation sampling error
(about 0.005 recall), and it was replaced by the bootstrap rule above, using
validation data only. That test score played no part in the decision. It also
agrees with the conclusion: a +0.0005 recall difference from the final model.

## Task 3: class imbalance

- **Distribution.** 100,512 phishing / 134,850 legitimate (42.7% phishing).
  Per split, train is 80,671 / 107,879, validation 9,791 / 13,485 and test
  10,050 / 13,486.
- **Method.** Balanced sample weights (n / (2·n_class)), computed on the
  training split and applied the same way to every family. There is no over- or
  undersampling, and validation and test are never reweighted.
- **Result.** At threshold 0.5, weighting raises recall (HistGradientBoosting
  0.6903 → 0.7130) by lowering precision (0.9407 → 0.9127): that is the same as
  moving the threshold. At a fixed 5% FPR, weighted and unweighted versions are
  indistinguishable for every family (e.g. HistGradientBoosting 0.7134 vs
  0.7164, CI of the difference includes 0; RF 0.7076 vs 0.7074).
- **Conclusion.** Imbalance is mild and does not explain the missed phishing.

## Task 4: threshold analysis (validation only)

Criterion, fixed before the test evaluation: **maximise recall subject to
validation FPR ≤ 5%**. The threshold is the lowest one at which at most 1 in 20
legitimate URLs is flagged.
- A browser warning that fires on legitimate sites teaches users to ignore it.
- In real traffic phishing is far rarer than 43%, so each point of FPR costs
  more precision in use than it does here.

The cap is `MAX_VALIDATION_FPR` in `ml/train_model.py`; changing it is a policy
decision and needs retraining with `python -m ml.train_model`.

| Threshold | Precision | Recall | F1 | F2 | FPR |
|---|---|---|---|---|---|
| 0.10 | 0.4737 | 0.9896 | 0.6407 | 0.8126 | 0.7984 |
| 0.20 | 0.5157 | 0.9682 | 0.6730 | 0.8237 | 0.6601 |
| 0.25 | 0.6095 | 0.8877 | 0.7227 | 0.8134 | 0.4129 |
| 0.30 | 0.7670 | 0.7896 | 0.7782 | 0.7850 | 0.1741 |
| 0.35 | 0.8209 | 0.7685 | 0.7938 | 0.7784 | 0.1217 |
| 0.40 | 0.8574 | 0.7501 | 0.8002 | 0.7693 | 0.0905 |
| 0.45 | 0.8838 | 0.7358 | 0.8030 | 0.7613 | 0.0702 |
| **0.4991** | **0.9121** | **0.7134** | **0.8006** | **0.7459** | **0.0499** |
| 0.55 | 0.9322 | 0.6961 | 0.7971 | 0.7333 | 0.0368 |
| 0.60 | 0.9483 | 0.6832 | 0.7942 | 0.7236 | 0.0271 |
| 0.70 | 0.9703 | 0.6630 | 0.7877 | 0.7078 | 0.0148 |
| 0.80 | 0.9820 | 0.6462 | 0.7795 | 0.6936 | 0.0086 |
| 0.90 | 0.9907 | 0.6218 | 0.7641 | 0.6718 | 0.0042 |

Alternative criteria (validation):

| Criterion | Threshold | Precision | Recall | F1 | F2 | FPR |
|---|---|---|---|---|---|---|
| fixed 0.5 | 0.5000 | 0.9127 | 0.7130 | 0.8006 | 0.7456 | 0.0495 |
| FPR ≤ 1% | 0.7793 | 0.9794 | 0.6497 | 0.7812 | 0.6966 | 0.0099 |
| FPR ≤ 2% | 0.6602 | 0.9607 | 0.6718 | 0.7907 | 0.7148 | 0.0199 |
| **FPR ≤ 5% (chosen)** | **0.4991** | **0.9121** | **0.7134** | **0.8006** | **0.7459** | **0.0499** |
| FPR ≤ 10% | 0.3749 | 0.8462 | 0.7562 | 0.7987 | 0.7726 | 0.0998 |
| max F1 | 0.4958 | 0.9086 | 0.7200 | 0.8034 | 0.7512 | 0.0526 |
| max F2 (recall-weighted) | 0.2091 | 0.5181 | 0.9675 | 0.6748 | 0.8245 | 0.6534 |

Recall is almost flat between thresholds 0.3 and 0.9 and then jumps. That
matches the ambiguity finding: many phishing and legitimate hosts receive the
same low scores because they have identical feature vectors, so lowering the
threshold catches them only together with the legitimate ones.

The "Phishing" (high-confidence) tier is unchanged: P ≥ 0.6050, the lowest
threshold with validation precision ≥ 95%.

## Final test result (evaluated once, threshold 0.4991)

| Accuracy | Precision | Recall | F1 | ROC-AUC | FPR |
|---|---|---|---|---|---|
| 0.8578 | 0.9140 | 0.7363 | 0.8156 | 0.8990 | 0.0516 |

| | Predicted legitimate | Predicted phishing |
|---|---|---|
| **Legitimate** (13,486) | 12,790 | 696 |
| **Phishing** (10,050) | 2,650 | 7,400 |

Test FPR (5.16%) is slightly above the 5% validation target, which is normal
sampling variation for a threshold set on another split.

Risk tiers on test:
- **Phishing URLs:** 7,109 Phishing, 291 Suspicious, 2,650 Safe.
- **Legitimate URLs:** 333 Phishing, 363 Suspicious, 12,790 Safe.

## Task 5: feature importance (final model, validation)

Permutation importance measures the drop in validation ROC-AUC when a feature
is shuffled (10 repeats):

| Feature | AUC drop | | Feature | AUC drop |
|---|---|---|---|---|
| TLDLegitimateProb | 0.1199 | | LetterRatioInURL | 0.0043 |
| NoOfSubDomain | 0.0567 | | NoOfLettersInURL | 0.0035 |
| NoOfDegitsInURL | 0.0438 | | DegitRatioInURL | 0.0029 |
| URLLength | 0.0230 | | DomainLength | 0.0000 |
| TLDLength | 0.0188 | | IsDomainIP | 0.0000 |
| SpacialCharRatioInURL | 0.0120 | | NoOfEqualsInURL | 0.0000 |
| CharContinuationRate | 0.0103 | | NoOfQMarkInURL | 0.0000 |
| NoOfOtherSpecialCharsInURL | 0.0047 | | NoOfAmpersandInURL, IsHTTPS | 0.0000 |

- **Most important:** TLDLegitimateProb, NoOfSubDomain, NoOfDegitsInURL, then
  host length (URLLength / DomainLength). Random Forest impurity importance
  gives the same top group: TLDLegitimateProb 0.275, CharContinuationRate 0.135,
  NoOfSubDomain 0.110.
- **DomainLength shows 0 only because it is duplicated by URLLength**
  (r = 1.0): shuffling one leaves the other. It isn't uninformative; alone it
  has validation AUC 0.705.
- **Weak / uninformative:**
  - IsHTTPS, NoOfEqualsInURL, NoOfQMarkInURL and NoOfAmpersandInURL are
    constant in the host view, with zero information by construction.
  - IsDomainIP is nearly never 1 (single-feature AUC 0.503).
  - Other highly correlated pairs: DomainLength–NoOfLettersInURL (0.94) and
    NoOfDegitsInURL–DegitRatioInURL (0.93).
- **No features were removed.** Constant features cannot change a tree model's
  output. Removing them would change the schema shared with the extractor,
  API and explanation engine for no gain in accuracy. They are recorded here as
  candidates for a future schema version.

## Recommendations (not implemented)

1. Keep this model for the API, and present its output as a risk signal, not a
   verdict. Its expected miss rate is about 26% of phishing URLs.
2. Recall can only rise substantially with information outside the host
   string: a reputation lookup (the backend already has a threat-intelligence
   hook), domain age, or a training set whose legitimate URLs include deep
   links and `http://` so path and scheme features become learnable.
