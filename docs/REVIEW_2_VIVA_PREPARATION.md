# Review-2 Viva Preparation

Speaking notes, the demo script and likely questions. The detailed explanations and the 70-question bank are
in `docs/PROJECT_KNOWLEDGE_AND_VIVA_GUIDE.md`; section numbers below (§) refer to that file. All numbers
come from `models/model_metadata.json` (test split, evaluated once) unless stated otherwise.

**Numbers to know by heart:**

| Item | Value |
|---|---|
| Deployed model | v2.0.0 GradientBoosting |
| Input | 17 URL features of the registrable domain |
| Test set | 23,055 URLs: 9,620 phishing and 13,435 legitimate |
| Recall | 0.5675: catches 56.7% of phishing |
| Precision | 0.8801 |
| False-positive rate | 5.5% |
| F1 | 0.6900 |
| ROC-AUC | 0.8524 |
| Accuracy | 0.7872 |
| Confusion matrix | TN 12,691 · FP 744 · FN 4,161 · TP 5,459 |
| Thresholds | Flag 0.5200 (validation FPR ≤ 5%); High 0.6443 (validation precision ≥ 95%) |
| Tests | 332 automated tests: pytest, 47 simulated extension tests, and real headless-Chrome tests |

---

## 1. 30-second introduction

"Our project is an AI-powered phishing URL detector with a Chrome extension. When you open a website, the
extension sends the site's address, and only the address, to our Flask server. There a machine-learning
model trained on about 187,000 labelled URLs estimates its phishing risk. Low and medium results appear on
the toolbar badge; a high-risk result opens a warning page where you can go back to safety or continue.

We focused on honest evaluation. On held-out test data the model catches 57% of phishing URLs while
flagging 5.5% of legitimate ones, and we explain exactly why it cannot do better from the address alone."

## 2. Two-minute explanation

1. **Problem (20 s).** Phishing sites steal passwords. Blacklists only know sites that were already
   reported, so new phishing domains get through.
2. **Idea (20 s).** Phishing domain names have statistical patterns: long names, digits, hyphens, unusual
   top-level domains. A model can learn these and score a brand-new domain instantly.
3. **System (30 s).** Flask serves a REST API, a web scanner and a dashboard backed by SQLite. The Chrome
   Manifest V3 extension checks each page automatically through the same API. There is one model and one
   source of truth.
4. **Honest ML (30 s).**
   - The dataset's published ~99.9% accuracy comes from a column that leaks the answer, and from every
     legitimate URL being a homepage.
   - We removed the leaky column and recompute 17 features from the URL.
   - We split the data so that no website appears in both training and test, made every decision on
     validation data, and tested once.
5. **Result and limits (20 s).** Recall 0.57, precision 0.88, false-positive rate 5.5%, ROC-AUC 0.85.
   It misses phishing on normal-looking domains, so it is a risk signal, not a guarantee.

## 3. Five-minute technical walkthrough

| Time | Topic | What to say | Show |
|---|---|---|---|
| 0:00 | Architecture | Browser and extension → Flask (`backend/create_app`) → `PredictionService` → `ml/predictor.py` → model; SQLite for history | §7 diagram |
| 0:45 | One URL's journey | Origin → `validate_url` → `normalize_url` → registrable domain (Public Suffix List) → 17 features → `predict_proba` → thresholds → risk level → explanation → JSON | §7.1 table |
| 1:45 | Features | Name 4–5: `TLDLegitimateProb` (45.7% importance), digit ratio, TLD length, domain length, special characters. Be honest that 5 are constant in our view. | §14 |
| 2:30 | Dataset and leakage | Duplicates removed; registrable-domain grouping (14.1% of test rows shared a domain before); TLD table fitted on training data only | §15 |
| 3:15 | Model selection | 12 candidates compared at the same 5% FPR; Gradient Boosting +0.14 recall (significant); subdomain false-positive rule | §17 |
| 4:00 | Results | Confusion matrix; recall vs false alarms; calibration not perfect | §18 |
| 4:30 | Extension and security | Origin only, no content scripts, warning after navigation (not a pre-load block), Go Back / Continue logic, `textContent` only | §19–§21 |

## 4. Complete demonstration script (about 8 minutes)

### Before the review (do this the day before and again 30 minutes before)

```bash
cd capstone && source .venv/bin/activate
python -m pytest -q                       # expect: 332 passed (note the time and count)
lsof -iTCP:5000 -sTCP:LISTEN              # macOS: ControlCenter often holds port 5000
API_PORT=5051 python app.py               # if 5000 is busy; otherwise python app.py
```

If you use 5051, set `const API_BASE = "http://127.0.0.1:5051";` in `extension/config.js` and
`"host_permissions": ["http://127.0.0.1:5051/*"]` in `extension/manifest.json`. Then go to
`chrome://extensions` → Developer mode → **Load unpacked** → `extension/` (or **Reload** if already loaded).
Pin the extension.

**Choose demo URLs.** Use only **reserved, non-existent names** under `.example` for the risky cases. The
real model scores these High, and they do not exist, so Chrome shows its own "This site can't be reached"
page behind our warning, and nothing malicious is contacted. Verified scores (2026-10-29):

| Purpose | URL | Model result |
|---|---|---|
| Low risk (real site) | `https://www.wikipedia.org/` | Safe / Low, P 0.09 |
| Medium (non-existent) | `https://shop.example/` | Suspicious / Medium, P 0.55 |
| High (non-existent) | `https://secure-login-verify-account.example/` | Phishing / High, P 0.84 |
| High, second example | `https://my-account-security-check-2024.example/` | Phishing / High, P 0.92 |

**Never open real phishing links in the demo.**

Optionally, in the popup, tick **Save automatic checks to the scan history** so the automatic checks
appear on the dashboard.

### Demo sequence

| # | Action | What the audience sees | What to say |
|---|---|---|---|
| 1 | Terminal: `curl -s http://127.0.0.1:5051/api/health` | `{"model_loaded":true,"status":"ok"}` | "The model is loaded once at start-up." |
| 2 | Browser: `http://127.0.0.1:5051/` and scan `https://www.wikipedia.org/` | "Low-risk prediction", score meter, reasons | "Every number comes from the API; the page has no model logic." |
| 3 | `/inspect` with the same URL | The 17 features, model info, confusion matrix | "These are the exact inputs the model saw: the registrable domain only." |
| 4 | New tab: `https://www.wikipedia.org/` | Badge **LOW** | "I didn't click anything; the extension checked the origin automatically." |
| 5 | In the same tab: `https://shop.example/` | Badge **MED**, page not interrupted | "Medium is a caution, not a block." |
| 6 | In the same tab: `https://secure-login-verify-account.example/login` | **Potential Phishing Risk** page: site, verdict, score 0.84, reasons, disclaimer | "Only High interrupts. It says clearly it may be wrong." |
| 7 | Click **Go Back to Safety** | Back on `shop.example` | "It returns to the last page that was checked and not high-risk, never to an address from the network." |
| 8 | Open the high-risk URL again; click **Continue Anyway** | The original page loads (here Chrome's "can't be reached", because the name doesn't exist); badge stays **HIGH** | "Allowed once, in this tab only. It doesn't change the score and isn't saved." |
| 9 | Reload the page | No warning loop | "No endless loop. Leaving the site ends the permission." |
| 10 | New tab with the same high-risk URL | Warning again | "The permission is tab-specific; there is no global whitelist." |
| 11 | Click the toolbar icon on that tab | Popup: result plus "Automatic check…" line and the two settings | "The popup scan sends the full URL and saves it to history; automatic checks send only the origin." |
| 12 | `http://127.0.0.1:5051/dashboard` | Totals, charts, history rows with `source = extension` | "Data from SQLite through `/api/history` and `/api/stats`." |
| 13 | Delete one row on the dashboard | Row removed | "`DELETE /api/history/<id>`, parameterised SQL." |
| 14 | Terminal: stop Flask (Ctrl+C). Open `https://news.example/` | Badge **?**, tooltip "could NOT be checked" | "If the API is down we never say 'safe'." |
| 15 | Restart Flask | Normal again | n/a |

**Feedback:** the project has **no feedback feature**. If asked, say it is planned future work, and that
Continue Anyway is deliberately not treated as feedback.

## 5. Screenshots and terminal outputs to capture beforehand

1. `python -m pytest -q` final line, with the date.
2. `node --test tests/extension/` summary (`tests 47, pass 47`).
3. `curl` for `/api/health`, one `/api/predict` (high example) and `/api/model-info`.
4. Web scanner result (Low) and `/inspect` feature table.
5. Extension badges LOW / MED / HIGH (three screenshots).
6. Warning page. `BROWSER_ARTIFACTS=shots python -m pytest tests/browser/test_extension_autoscan.py` saves
   `shots/extension_warning_page.png` automatically.
7. Continue Anyway result with the HIGH badge tooltip.
8. Dashboard with charts and history.
9. Badge `?` with Flask stopped.
10. `chrome://extensions` showing the loaded extension and its permissions.
11. `models/model_metadata.json` `test_metrics` block, or `docs/data/model_inventory.json`.

## 6. If a prediction is "wrong" during the demo

Say:

> "That is a real limitation, and our numbers predict it: the model misses about 43% of phishing URLs and
> flags 5.5% of legitimate ones on test data. It judges only the registrable domain name, so a legitimate
> site with an unusual name can be flagged, and phishing on an ordinary-looking or compromised domain can
> pass. That is why the warning page says it may be wrong, and why we call the result a risk signal."

If they want to see why, open `/inspect` for that URL and point to the reasons and feature values. Do
**not** change thresholds or edit anything live.

## 7. If the API or extension fails during the demo

| Problem | Quick check | Say / do |
|---|---|---|
| Badge `?` everywhere | Is Flask running? Does `API_BASE` match the port? | "The extension correctly refuses to claim 'safe' when it can't check." Restart Flask and reload the extension. |
| "Address already in use" | `lsof -iTCP:5000` | Use `API_PORT=5051` and update the 2 extension lines. |
| No badge at all | Extension disabled, or automatic checks OFF | Open the popup and tick automatic checks; Reload on `chrome://extensions`. |
| Warning doesn't appear | Was "Continue Anyway" already chosen in this tab? | Open the URL in a **new tab**. |
| Dashboard empty | Automatic checks are not saved by default | Scan via the popup or web scanner, or enable "Save automatic checks…". |
| Everything fails | n/a | Show the screenshots from §5 and the test results; explain what the real run showed. |

## 8. Likely questions (short answers; full answers in §31 of the guide)

**Dataset quality**
- *Is the dataset representative?* "Not fully. All legitimate URLs are popular homepages and 99.7% of
  legitimate `.com` hosts have no subdomain. We measured and documented this bias."
- *Why not 99.9% accuracy like others?* "That comes from a column that leaks the label
  (`URLSimilarityIndex`, 100 for every legitimate row). Our 20 preserved research models that used it all
  score 0.9997–1.0, which shows the leak."

**Recall**
- *Why only 57%?* "Many phishing domains look normal. We also chose fewer false alarms on legitimate
  subdomains, which cost recall (0.68 → 0.57 on the same test set)."

**False positives**
- *How many?* "744 of 13,435 legitimate test URLs (5.5%). 277 reached the High level that triggers the
  warning."
- *Why do they matter?* "A warning that fires on real sites gets ignored."

**Leakage**
- *How did you prevent it?* "Deduplication, registrable-domain-grouped splits with 0 overlap, training-only
  fitting of the TLD table, validation-only decisions, and the test set used once."

**Model selection**
- *Why Gradient Boosting?* "Highest validation recall at the same 5% false-alarm rate, and the gain was
  statistically significant (+0.14, 95% CI [0.13, 0.15])."
- *Why not the higher-recall host model?* "It flagged 17.8% of legitimate subdomain sites, failing our
  pre-stated rule."

**Security**
- *Does the extension read my passwords?* "No. It has no content scripts and cannot read pages. Automatic
  checks send only the origin."
- *SSRF?* "The server never fetches the URL; it analyses the string."
- *XSS?* "We never use `innerHTML` anywhere, and there is a strict CSP."
- *SQL injection?* "Every SQL value is a bound parameter."
- *Does it block the page before it loads?* "No. Chrome reports the navigation first, so the warning appears
  just after loading starts. We document that."

## 9. Contribution summary for the four team members

**What the Git history shows (verified with `git log --all`, 2026-10-29):**

| Author (as recorded) | Commits | What the commits contain |
|---|---|---|
| `varun devapathni` | 1 | `8a93bd4` Initial commit (2026-09-03) |
| `2300032701cseelge-git` | 1 | `6c4e993` Update `create_clean_split.py` (2026-09-03) |
| `unispend001` | 4 | `79f3f44` project audit (.gitignore), `cbd10f6` ML pipeline, `8c4907a` backend API, `56d3b3f` update (2026-09-29) |
| `CodeStartAI-009` | 1 | `6a1ba2f` merge of pull request #1 |

Git history alone **cannot** show who did what. Several people may share an account, work may have been
done outside Git, and the work in this round is not committed yet. Fill in the table below yourselves and
make sure each person can defend their part. The module split mirrors the suggested division in
`docs/REVIEW_2_AND_VIVA_GUIDE.md` §19, which is a suggestion, not a record.

| Member (name, roll no.) | Module | Main files | What I did (fill in) | What I can demo | Questions I must answer |
|---|---|---|---|---|---|
| ______ | ML and data | `ml/*.py`, `models/`, `scripts/dataset_audit.py`, `scripts/model_inventory.py` | | Demo steps 2–3; metrics | Recall, leakage, features, model selection |
| ______ | Backend, API, database | `app.py`, `backend/**`, `services/*.py`, `database/*.py` | | Steps 1, 12–13 | Endpoints, validation, SQL injection, SQLite |
| ______ | Frontend and dashboard | `templates/`, `static/` | | Steps 2–3, 12 | fetch, XSS, charts |
| ______ | Extension, security, testing | `extension/*`, `tests/browser/*`, `tests/extension/*`, `tests/test_security.py` | | Steps 4–11, 14 | MV3, permissions, warning flow, privacy, tests |

Every member should be able to explain the 18-step trace (§7.1) and the false-positive story (§17).
