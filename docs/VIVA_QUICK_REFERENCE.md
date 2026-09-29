# Viva Quick Reference

AI-Powered Real-Time Phishing URL Detection Using Machine Learning and Browser
Extension. This is a short revision sheet; details are in
`docs/REVIEW_2_AND_VIVA_GUIDE.md`.

## 1-minute explanation

We built a system that gives a **phishing-risk prediction for a URL** without
visiting the page.
1. A Flask API validates the URL.
2. It reduces the URL to the site's *registrable domain* (e.g.
   `admob.google.com` → `google.com`).
3. It computes 17 numeric features.
4. A Gradient Boosting model trained on the PhiUSIIL dataset estimates the
   probability of phishing.
5. The result, with reasons, is shown in a web scanner and dashboard and in a
   Chrome MV3 extension, and saved in SQLite.

Evaluated honestly on a leakage-controlled test set, the model catches 57% of
phishing URLs and wrongly flags 5.5% of legitimate ones, so we present it as a
risk signal, not a guarantee.

## 3-minute explanation

Add to the 1-minute version:

- **Why URL-only:** it's fast and private, and nothing is downloaded, so there
  is no SSRF risk.
- **Data honesty.** The dataset's legitimate URLs are all bare homepages:
  - a simple rule gets 99.6% F1 on a random split;
  - a leaky column gives 99.97%.

  We excluded the leaky feature and split the data so that no URL, host or
  registrable domain appears in both training and test.
- **False positives.** Our earlier model flagged Google AdMob and the Cloudflare
  dashboard as phishing, because in the dataset 99% of `.com` hosts with a
  subdomain are phishing. We proved it with counterfactuals: `google.com`
  scores 0.30, `admob.google.com` 0.98. We fixed it without a whitelist by
  scoring the registrable domain from the Public Suffix List.
- **The cost:** recall dropped (0.68 → 0.57 on the same test set), mostly on
  phishing hidden in subdomains of attacker domains. We document that trade-off.
- **Engineering:** a validated API with JSON errors, rate limiting, security
  headers and CORS; secrets redacted before storage; an `activeTab`-only
  extension.
- **Evidence:** 307 automated tests (56 in real Chrome), all passing, plus a
  15-step acceptance test.

## Architecture

```
Web scanner (templates/, static/js)     Chrome extension (extension/popup.js)
          \                                   /
           POST /api/predict  (Flask: app.py, backend/)
                     |
   validation (backend/utils/validation.py)
                     |
   PredictionService (services/prediction_service.py)
                     |
   Predictor (ml/predictor.py) → feature extractor (ml/feature_extractor.py, ml/url_utils.py)
                     |                     → model v2.0.0 (models/phishing_model.pkl)
   explanations (services/explanation_engine.py)
                     |
   HistoryService → SQLite (database/, instance/scan_history.db) → Dashboard (/dashboard)
```

## ML pipeline

URL → normalise (scheme, lower-case, IDNA) → registrable domain (PSL) →
`https://www.<domain>` → 17 features (fixed order) → `GradientBoostingClassifier`
→ P(phishing) → thresholds → verdict and explanations.

| Stage | Detail |
|---|---|
| Training data | PhiUSIIL: 235,795 rows → 235,362 after 425 duplicate and 8 invalid URLs removed; 42.7% phishing |
| Split | 80/10/10, grouped by registrable domain, seed 42: train 187,523 / validation 24,784 / test 23,055 |
| Selection | Validation only: 12 candidates compared at 5% false-alarm rate; bootstrap significance; legitimate-subdomain FPR check |
| Final evaluation | Test set used once |

## Features (in order)

1. `URLLength`
2. `DomainLength`
3. `IsDomainIP`
4. `CharContinuationRate`
5. `TLDLegitimateProb`
6. `TLDLength`
7. `NoOfSubDomain`
8. `NoOfLettersInURL`
9. `LetterRatioInURL`
10. `NoOfDegitsInURL`
11. `DegitRatioInURL`
12. `NoOfEqualsInURL`
13. `NoOfQMarkInURL`
14. `NoOfAmpersandInURL` (counts `%`)
15. `NoOfOtherSpecialCharsInURL`
16. `SpacialCharRatioInURL`
17. `IsHTTPS`

Features 12–14 and 17 are constant in our view. That's known and documented;
they were kept so the schema stays stable.

## Model

- **Algorithm:** `GradientBoostingClassifier`, 200 trees, depth 3, learning
  rate 0.1, seed 42, scikit-learn 1.6.1.
- **Thresholds:** P < 0.52 → Safe (Low); 0.52–0.644 → Suspicious (Medium);
  ≥ 0.644 → Phishing (High).

## Key metrics (v2.0.0, test, evaluated once)

| Accuracy | Precision | **Recall** | F1 | ROC-AUC | FPR |
|---|---|---|---|---|---|
| 0.7872 | 0.8801 | **0.5675** | 0.6900 | 0.8524 | 0.0554 |

Confusion matrix: TN 12,691 · FP 744 · FN 4,161 · TP 5,459.

Performance: 0.79 ms model time; 4.2 ms per API request with a history write;
862 req/s with 8 concurrent clients.

## API endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/api/health` | Status and model loaded |
| POST | `/api/predict` | `{"url": "..."}` → prediction, verdict, risk, confidence, features, explanation, disclaimer, history id |
| GET | `/api/model-info` | Model, version, features, thresholds, test metrics |
| GET | `/api/features` | Feature schema |
| GET | `/api/history?page&limit&prediction&q` | Paginated history |
| GET / DELETE | `/api/history/<id>` | One scan: view / delete |
| DELETE | `/api/history` | Clear all |
| GET | `/api/stats` | Dashboard counts |

Errors: `{"success": false, "error": {"code", "message"}}`. Codes include 400
(invalid URL, scheme, host, JSON), 413, 415, 422, 429, 500 and 503.

## Database

- **Engine:** SQLite, schema v2.
- **Table:** `scan_history` (14 columns): time, redacted URL, host,
  prediction, risk, confidence, probability, model version, processing time,
  source, features, indicators.
- **Indexes:** time, prediction.
- **Redaction:** query values, passwords and fragments are removed before
  storage.
- **Never stored:** IP addresses, user agents, cookies.

## Extension

- **Manifest V3.** Permissions: `activeTab` plus the API origin only. No
  background worker, no content script.
- **Flow:** click the icon → read the current tab URL → reject `chrome://`,
  `file://` and similar locally → POST to `API_BASE/api/predict` → show the
  result.
- **API URL:** set in `extension/config.js`, plus the matching
  `host_permissions`.
- **Behaviour:** no model inside, never blocks pages, scans only on click.

## Security

| Threat | Control |
|---|---|
| XSS | `textContent` only, strict CSP |
| SQL injection | Parameterised queries |
| SSRF | The server never fetches URLs |
| Bad input | Server-side validation: schemes, length, internal hosts |
| Cross-origin requests | Exact-origin CORS, no credentials |
| Abuse | Rate limit 60/min |
| Leakage | JSON errors without stack traces; `Server` header hidden |
| Secrets | Environment variables; `.env` and `*.pem` git-ignored |

Every item is tested (`docs/security.md`).

## Team roles

| Member | Area | Main files |
|---|---|---|
| 1 | ML / data | `ml/`, `models/`, `scripts/` |
| 2 | Backend / DB | `app.py`, `backend/`, `services/`, `database/` |
| 3 | Frontend | `templates/`, `static/` |
| 4 | Extension / security / testing | `extension/`, `tests/browser/`, `tests/test_security.py` |

## False positives: the exact explanation

The old model (v1.2.0) judged the **full host name**. In PhiUSIIL almost no
legitimate site has a subdomain:

| `.com` hosts with a subdomain | Share |
|---|---|
| Legitimate | 0.31% |
| Phishing | 49.9% |

So "has a subdomain" meant phishing ≈ 99% of the time, and the model gave
`admob.google.com` 0.98. The code was correct; the **dataset was
unrepresentative**.

The new model (v2.0.0) judges the **registrable domain** from the Public Suffix
List, so `admob.google.com` is scored as `google.com` (0.42, low-risk). This is
not a whitelist: `admob.evil.com` is scored as `evil.com`, and shared-hosting
sites (`x.firebaseapp.com`) stay separate.

The cost: phishing hidden in subdomains of attacker domains is caught less
often. That's why recall is 0.57 rather than 0.68 for the host view on the
same test set.

## Limitations

- **Misses 43% of phishing:** attacker subdomains, compromised domains,
  ordinary-looking names, and hosting platforms not in the PSL.
- **URL-only.** No page content, domain age, DNS or reputation.
- **Unrepresentative dataset.** The legitimate class is popular homepages only.
- **Uncalibrated confidence** (ECE 0.061).
- **On-click checking only.** No real-time protection and no blocking.
- **Local development server.** No authentication.

## Future work

- More representative legitimate data (subdomains, deep links).
- Reputation and threat intelligence evaluated as a separate signal.
- Domain age, DNS and certificate features; content and visual analysis (with
  safe fetching).
- Calibration.
- A deep-learning comparison on the leakage-controlled split.
- Proper deployment (HTTPS, authentication).
- Automatic warnings in the extension, with a privacy design.

## 30 most important viva questions (short answers)

1. **What does it do?** A URL phishing-risk prediction via API, web UI and
   extension.
2. **Does it open the page?** No. It analyses the URL string only.
3. **Dataset?** PhiUSIIL: 235,795 URLs; 0 = phishing, 1 = legitimate.
4. **How many features?** 17, computed from the registrable domain.
5. **Why is feature order important?** Models read features by position; it is
   enforced by the schema and load checks.
6. **Model?** `GradientBoostingClassifier` (200 trees, depth 3).
7. **Why that model?** The only significant recall gain at 5% FPR on
   validation.
8. **Recall?** 0.5675 on test.
9. **Precision?** 0.8801.
10. **Confusion matrix?** TN 12,691, FP 744, FN 4,161, TP 5,459.
11. **Threshold?** 0.52: the lowest threshold with validation FPR ≤ 5%.
12. **What is leakage?** Test information influencing training. We prevent it
    with registrable-domain grouping, and we excluded `URLSimilarityIndex`.
13. **Why not report 99.9%?** It came from a leaky feature and a biased split.
14. **What is a false positive?** A legitimate URL flagged (744 in the test
    set).
15. **What is a false negative?** Missed phishing (4,161).
16. **Which matters more?** Missing phishing, but false alarms must be capped.
17. **Why was AdMob flagged before?** The dataset has almost no legitimate
    subdomains.
18. **How was it fixed?** By scoring the registrable domain from the Public
    Suffix List. It's not a whitelist.
19. **What did the fix cost?** Recall on attacker-subdomain phishing.
20. **Is the confidence reliable?** It's an uncalibrated model probability
    (ECE 0.061).
21. **Why "Low-risk prediction", not "Safe"?** Because 43% of phishing is
    missed.
22. **How does the extension get the URL?** `activeTab`, granted when the icon
    is clicked.
23. **Extension permissions?** `activeTab` plus the API origin.
24. **How is SSRF avoided?** The server never fetches URLs; this is tested.
25. **How is XSS prevented?** `textContent` only and CSP; tested with payloads.
26. **How is SQL injection prevented?** Parameterised queries; tested.
27. **Why SQLite?** Local, single-user, standard library, zero configuration.
28. **What happens if the model is missing?** 503, with health reporting
    `model_loaded: false`.
29. **How many tests?** 307, all passing, 56 of them in real Chrome.
30. **Contribution?** Leakage-controlled methodology, false-positive root
    cause and principled fix, and an integrated, tested system.

## Common mistakes to avoid in the viva

- Saying "accuracy is 99%": that was the leaky experiment. Say **recall 0.57,
  precision 0.88 on a leakage-controlled test set**.
- Calling the output "safe" or "guaranteed". Say "low-risk prediction" and
  "model confidence".
- Claiming reputation or threat-intelligence checking. The code exists but is
  disabled and unevaluated.
- Claiming real-time protection or blocking. The extension checks on click and
  never blocks.
- Calling the PSL a whitelist. It describes domain structure, not trust.
- Saying the extension reads the page or has its own model. It sends only the
  URL to the API.
- Forgetting the trade-off. Fixing false positives cost recall, and we measured
  it.
