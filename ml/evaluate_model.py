"""Reproducible evaluation: leakage experiment, baselines and bias probe.

    python -m ml.evaluate_model

Writes docs/data/evaluation.json and docs/model_evaluation_tables.md.
Every number in docs/model_evaluation.md comes from these files.

Experiments (all metrics use PHISHING as the positive class):
  A  Original methodology: the original random split (data/{train,validation,test}.csv,
     same URL can appear in several splits) and the 22 stored URL features,
     including the leaky URLSimilarityIndex.
  B  Leakage-controlled methodology: URL-grouped split (data/clean_split), URLs
     de-duplicated within each split, the 17 schema features recomputed from the
     URL by ml.feature_extractor.
       B1  features from the full URL ("full" view)
       B2  features from the canonical host ("host" view) -- the deployed model
  Rule baseline: "phishing unless the URL is exactly https://www.<host>"; no ML.
  Bias probe: B1 and B2 models on hand-picked legitimate URLs (see PROBE_URLS).
"""
import re
import time

import numpy as np
import pandas as pd

from ml.dataset import ORIGINAL_SPLIT_DIR, ROOT, build_tld_table, featurize, load_split
from ml.feature_extractor import extract_features
from ml.feature_schema import DEFAULT_MODEL_INPUT_VIEW, FEATURE_NAMES, LABEL_PHISHING
from ml.model_utils import binary_metrics, candidate_models, load_model, phishing_probability, write_json
from ml.train_model import MODEL_PATH

ORIGINAL_22_FEATURES = [
    "URLLength", "DomainLength", "IsDomainIP", "URLSimilarityIndex", "CharContinuationRate",
    "TLDLegitimateProb", "URLCharProb", "TLDLength", "NoOfSubDomain", "HasObfuscation",
    "NoOfObfuscatedChar", "ObfuscationRatio", "NoOfLettersInURL", "LetterRatioInURL",
    "NoOfDegitsInURL", "DegitRatioInURL", "NoOfEqualsInURL", "NoOfQMarkInURL",
    "NoOfAmpersandInURL", "NoOfOtherSpecialCharsInURL", "SpacialCharRatioInURL", "IsHTTPS",
]  # as used by the original train_models.py

HOMEPAGE_RE = re.compile(r"^https://www\.[^/?#]+$")

# Hand-picked, well-known LEGITIMATE URLs chosen by the developer to probe the
# dataset-construction bias. This is an illustrative convenience sample, not a
# random sample of web traffic; results must not be read as a population rate.
PROBE_URLS = {
    "homepage (https://www.<host>, like every legitimate training URL)": [
        "https://www.google.com", "https://www.wikipedia.org", "https://www.bbc.co.uk",
        "https://www.amazon.com", "https://www.python.org", "https://www.github.com",
    ],
    "homepage without www": [
        "https://google.com", "https://wikipedia.org", "https://github.com",
        "https://python.org", "https://stackoverflow.com", "https://bbc.co.uk",
    ],
    "deep link (path/query) on legitimate site": [
        "https://github.com/pallets/flask", "https://docs.python.org/3/library/urllib.parse.html",
        "https://en.wikipedia.org/wiki/Phishing", "https://www.bbc.co.uk/news/technology",
        "https://stackoverflow.com/questions/tagged/python", "https://www.amazon.com/gp/help/customer/display.html",
        "https://scikit-learn.org/stable/modules/ensemble.html", "https://www.google.com/search?q=phishing",
    ],
}


def rule_baseline(urls):
    return np.array([0.0 if HOMEPAGE_RE.match(u) else 1.0 for u in urls])


def experiment_a():
    frames = {s: load_split(s, ORIGINAL_SPLIT_DIR) for s in ("train", "validation", "test")}
    y = {s: (d["label"].astype(int) == LABEL_PHISHING).astype(int).to_numpy() for s, d in frames.items()}
    overlap = {
        "train_validation": len(set(frames["train"].URL) & set(frames["validation"].URL)),
        "train_test": len(set(frames["train"].URL) & set(frames["test"].URL)),
        "validation_test": len(set(frames["validation"].URL) & set(frames["test"].URL)),
    }
    results = {}
    for name, model in candidate_models().items():
        model.fit(frames["train"][ORIGINAL_22_FEATURES], y["train"])
        results[name] = {
            split: binary_metrics(y[split], phishing_probability(model, frames[split][ORIGINAL_22_FEATURES]))
            for split in ("validation", "test")
        }
    results["rule_baseline"] = {"test": binary_metrics(y["test"], rule_baseline(frames["test"].URL.astype(str)))}
    sizes = {s: int(len(d)) for s, d in frames.items()}
    return {"sizes": sizes, "url_overlap_between_splits": overlap, "features": ORIGINAL_22_FEATURES, "results": results}


def experiment_b(view):
    raw = {s: load_split(s) for s in ("train", "validation", "test")}
    table = build_tld_table(raw["train"])
    data = {s: featurize(d, table, view=view) for s, d in raw.items()}
    results, fitted = {}, {}
    for name, model in candidate_models().items():
        model.fit(data["train"][0], data["train"][1])
        fitted[name] = model
        results[name] = {
            split: binary_metrics(data[split][1], phishing_probability(model, data[split][0]))
            for split in ("validation", "test")
        }
    X_te, y_te, kept_te, _ = data["test"]
    results["rule_baseline"] = {"test": binary_metrics(y_te, rule_baseline(kept_te.URL.astype(str)))}
    if view == DEFAULT_MODEL_INPUT_VIEW:
        saved = load_model(MODEL_PATH)
        results["saved_final_model"] = {"test": binary_metrics(y_te, phishing_probability(saved, X_te))}
    sizes = {s: int(len(d[1])) for s, d in data.items()}
    return {"view": view, "sizes": sizes, "features": FEATURE_NAMES, "results": results}, fitted, table


def bias_probe(model, table, view, threshold=0.5):
    out = {}
    for group, urls in PROBE_URLS.items():
        rows = []
        for url in urls:
            ext = extract_features(url, tld_table=table, view=view)
            p = float(phishing_probability(model, pd.DataFrame([ext["vector"]], columns=FEATURE_NAMES))[0])
            rows.append({"url": url, "p_phishing": round(p, 6), "flagged_phishing": p >= threshold})
        out[group] = {"flagged": sum(r["flagged_phishing"] for r in rows), "total": len(rows), "urls": rows}
    return out


def fmt(x, nd=5):
    return "n/a" if x is None else f"{x:.{nd}f}"


def table_rows(results, split):
    lines = ["| Model | Accuracy | Precision | Recall | F1 | ROC-AUC | TN (legit ok) | FP (legit flagged) | FN (phish missed) | TP (phish caught) |",
             "|---|---|---|---|---|---|---|---|---|---|"]
    for name, by_split in results.items():
        if split not in by_split:
            continue
        m = by_split[split]
        cm = m["confusion_matrix"]
        lines.append(f"| {name} | {fmt(m['accuracy'])} | {fmt(m['precision'])} | {fmt(m['recall'])} | {fmt(m['f1'])} | "
                     f"{fmt(m['roc_auc'])} | {cm['legitimate_correct_TN']} | {cm['legitimate_flagged_FP']} | "
                     f"{cm['phishing_missed_FN']} | {cm['phishing_caught_TP']} |")
    return "\n".join(lines)


def probe_md(title, probe):
    md = [f"### {title}", "", "| Group | Flagged as phishing |", "|---|---|"]
    for group, r in probe.items():
        md.append(f"| {group} | {r['flagged']} / {r['total']} |")
    md += ["", "| URL | P(phishing) | Flagged |", "|---|---|---|"]
    for r in probe.values():
        for row in r["urls"]:
            md.append(f"| `{row['url']}` | {row['p_phishing']:.4f} | {'yes' if row['flagged_phishing'] else 'no'} |")
    return md + [""]


def main():
    start = time.time()
    print("Experiment A (original methodology)...")
    a = experiment_a()
    print("Experiment B1 (leakage-controlled, full URL view)...")
    b1, fitted_b1, table = experiment_b("full")
    print("Experiment B2 (leakage-controlled, host view = deployed)...")
    b2, _, _ = experiment_b("host")
    saved = load_model(MODEL_PATH)
    probe = {
        "B1_full_view_gradient_boosting": bias_probe(fitted_b1["gradient_boosting"], table, "full"),
        "B2_host_view_saved_final_model": bias_probe(saved, table, "host"),
    }
    report = {"experiment_A_original": a, "experiment_B1_full_view": b1, "experiment_B2_host_view": b2,
              "bias_probe": probe, "probe_note": "hand-picked legitimate URLs; illustrative, not a population sample",
              "runtime_seconds": round(time.time() - start, 1)}
    write_json(report, ROOT / "docs" / "data" / "evaluation.json")

    md = ["<!-- Generated by `python -m ml.evaluate_model`. Do not edit by hand. -->", "",
          "## Experiment A: original methodology (22 stored features incl. URLSimilarityIndex, random split)", "",
          f"Split sizes: {a['sizes']}. URLs shared between splits: {a['url_overlap_between_splits']}.", "",
          "### Test", "", table_rows(a["results"], "test"), "",
          "### Validation", "", table_rows(a["results"], "validation"), ""]
    for label, b in (("B1: leakage-controlled, full-URL view", b1), ("B2: leakage-controlled, host view (deployed)", b2)):
        md += [f"## Experiment {label}", "",
               f"17 schema features recomputed from the URL. Split sizes (unique URLs): {b['sizes']}.", "",
               "### Test", "", table_rows(b["results"], "test"), "",
               "### Validation", "", table_rows(b["results"], "validation"), ""]
    md += ["## Bias probe: hand-picked legitimate URLs (illustrative, not a population sample)", ""]
    md += probe_md("B1 full-URL view (gradient boosting)", probe["B1_full_view_gradient_boosting"])
    md += probe_md("B2 host view (saved final model)", probe["B2_host_view_saved_final_model"])
    (ROOT / "docs" / "model_evaluation_tables.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    print("\n".join(md))
    print(f"\nDone in {report['runtime_seconds']}s")


if __name__ == "__main__":
    main()
