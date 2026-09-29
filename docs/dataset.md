# Dataset and leakage audit

Generated numbers: `docs/data/dataset_audit.json` (`python scripts/dataset_audit.py`).
The original CSV files are only read; nothing in `data/` is modified.

## PhiUSIIL Phishing URL Dataset (used by this project)

| Item | Value |
|---|---|
| Files | `data/train.csv`, `data/validation.csv`, `data/test.csv` (together = `data/phishing_urls.csv`) |
| Rows / columns | 235,795 / 56 |
| Target column | `label`: 0 = phishing, 1 = legitimate |
| URL column | `URL` |
| Missing values | 0 |
| Class distribution | 100,945 phishing / 134,850 legitimate |
| Unique URLs | 235,370 |
| Duplicate URL rows (extra copies) | 425 |
| Rows affected by duplicate URLs (all copies) | 850 (425 URLs, each exactly twice) |
| URLs with conflicting labels | 0 |
| Exact duplicate rows | 0 (duplicates differ in `FILENAME` / page columns) |

The 17 model features and the 5 excluded URL columns (with reasons) are defined in
`ml/feature_schema.py`. Every model feature is recomputed from the `URL` column by
`ml/feature_extractor.py`; exact parity with the stored values is recorded in
`docs/data/feature_parity.json` (`python scripts/feature_parity_audit.py`).

## Split methodologies

"Model-input overlap" counts test rows whose model input (`https://www.<host>`,
the only thing the deployed model sees) also occurs in train, i.e. rows the model
receives with a feature vector identical to a training row.

| | Original random split | URL-grouped (`data/clean_split`) | **Host-grouped (final)** |
|---|---|---|---|
| Built by | supplied files | `create_clean_split.py` | `ml.dataset.load_host_grouped_split` (in memory) |
| Train / val / test rows | 188,636 / 23,579 / 23,580 | 188,296 / 23,537 / 23,537 unique URLs | **188,550 / 23,276 / 23,536** |
| Train phishing / legit | 80,756 / 107,880 | 80,416 / 107,880 | **80,671 / 107,879** |
| Validation phishing / legit | 10,094 / 13,485 | 10,052 / 13,485 | **9,791 / 13,485** |
| Test phishing / legit | 10,095 / 13,485 | 10,052 / 13,485 | **10,050 / 13,486** |
| URLs shared train/val, train/test, val/test | 80 / 63 / 9 | 0 / 0 / 0 | **0 / 0 / 0** |
| Test rows with model input in train | 2,025 | 2,042 | **0** |
| Val rows with model input in train | 2,039 | 2,049 | **0** |

Final split preparation: 235,795 rows → 425 duplicate-URL rows removed (first copy
kept; all copies have the same label) → 8 URLs rejected by URL validation (not
parseable as http(s) URLs) → 235,362 rows in 219,098 host groups, split 80/10/10 by
group, stratified by the group's label, seed 42. The URL list of each split is
fingerprinted (SHA-256) in `models/model_metadata.json`, and
`tests/test_pipeline.py` checks that the split is reproduced exactly.

Why group by host rather than by URL: URLs on the same host produce the same
feature vector in the host view, so a URL-grouped split still let ~8.7% of test
rows (2,021 of them phishing) appear in training under a different URL.

Known limitations:
- Sibling subdomains of one registrable domain (`a.evil.com`, `b.evil.com`) have
  different model inputs and can fall in different splits.
- `TLDLegitimateProb` is copied per TLD (647 TLDs, training split only) from the
  dataset's stored column, which the dataset authors derived from their
  legitimate-URL source list.

## Original notebook model (`../projectcopy/url`)

| Item | Value |
|---|---|
| Dataset | `phishing.csv` (Kaggle "phishing website detector", UCI-style −1/0/1 values), 11,054 rows, 30 features, no URL column |
| Target | `class`: 1 = legitimate (6,157), −1 = phishing (4,897) |
| Duplicate rows (ignoring `Index`) | 5,205, removed in the notebook, leaving 5,849 |
| Model | `Phishing_model.pkl`: `GradientBoostingClassifier` on 21 features, scikit-learn **1.2.1** |
| Loads with scikit-learn 1.6.1? | **No**: `ModuleNotFoundError: sklearn.ensemble._gb_losses` (removed in 1.4) |

Can those 21 features be extracted automatically from a URL? **No.**

| Needs | Count | Features |
|---|---|---|
| URL string only | 4 | UsingIP, PrefixSuffix-, SubDomains, HTTPSDomainURL |
| Partly in the URL | 2 | HTTPS (also certificate issuer and age), NonStdPort (server port scan) |
| Page HTML / HTTP fetch | 8 | RequestURL, AnchorURL, LinksInScriptTags, ServerFormHandler, InfoEmail, WebsiteForwarding, StatusBarCust, DisableRightClick |
| External services | 7 | AbnormalURL, AgeofDomain, DNSRecording (WHOIS/DNS), WebsiteTraffic (Alexa, retired), PageRank (not published), GoogleIndex, StatsReport |

Other blockers:
- The file has no URLs, so even the URL features' −1/0/1 thresholds cannot be
  verified.
- The notebook fitted `StandardScaler` on all rows before splitting (leakage) and
  did not save it, so raw −1/0/1 inputs can't be scaled the way the model expects.
- The old Flask app passed a 17-key dict with different feature names to this
  model.

That model and notebook are left untouched and are not used. The new model is
`models/phishing_model.pkl`.
