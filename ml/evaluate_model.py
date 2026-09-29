"""Reproducible evaluation: leakage experiments, baselines and bias probe.

    python -m ml.evaluate_model

Writes docs/data/evaluation.json and docs/model_evaluation_tables.md.
Every number in docs/model_evaluation.md comes from these files.

Experiments (all metrics use PHISHING as the positive class; every experiment
fits the same four candidate models from ml.model_utils with seed 42):
  A   Original methodology: the original random split (data/{train,validation,test}.csv,
      the same URL can appear in several splits) and the 22 stored URL features,
      including the leaky URLSimilarityIndex.
  A2  Original random split, but the deployed feature set: the 17 schema features
      recomputed from the host view. Isolates the effect of the split.
  B1  URL-grouped split (data/clean_split), full-URL view (feature-view experiment).
  B2  URL-grouped split, host view. No URL is shared between splits, but URLs on the
      same host (= identical model input) still are.
  C   Host-grouped split (ml.dataset.load_host_grouped_split), host view. No model
      input is shared between splits. This is the deployed methodology; the saved
      final model is scored on its test split.
  Overlap breakdown: for A2 and B2, test metrics separately for rows whose model
      input also occurs in train and for the rest -- the direct measure of leakage.
  Rule baseline: "phishing unless the URL is exactly https://www.<host>"; no ML.
  Bias probe: B1 and the saved model on hand-picked legitimate URLs (see PROBE_URLS).
"""
import re
import time

import numpy as np
import pandas as pd

from ml.dataset import (CLEAN_SPLIT_DIR, ORIGINAL_SPLIT_DIR, ROOT, SPLITS, build_tld_table, featurize, featurize_prepared,
                        load_host_grouped_split, load_split)
from ml.feature_extractor import extract_features, model_input
from ml.feature_schema import FEATURE_NAMES, LABEL_PHISHING
from ml.model_utils import (RANDOM_STATE, binary_metrics, candidate_models, load_model, phishing_probability,
                            write_json)
from ml.train_model import PREVIOUS_DIR

V12_MODEL_PATH = PREVIOUS_DIR / "phishing_model.pkl"
from ml.url_utils import normalize_url

ORIGINAL_22_FEATURES = [
    "URLLength", "DomainLength", "IsDomainIP", "URLSimilarityIndex", "CharContinuationRate",
    "TLDLegitimateProb", "URLCharProb", "TLDLength", "NoOfSubDomain", "HasObfuscation",
    "NoOfObfuscatedChar", "ObfuscationRatio", "NoOfLettersInURL", "LetterRatioInURL",
    "NoOfDegitsInURL", "DegitRatioInURL", "NoOfEqualsInURL", "NoOfQMarkInURL",
    "NoOfAmpersandInURL", "NoOfOtherSpecialCharsInURL", "SpacialCharRatioInURL", "IsHTTPS",
]  # as used by the original train_models.py

HOMEPAGE_RE = re.compile(r"^https://www\.[^/?#]+$")
GF = "gradient_boosting"  # model used for the overlap breakdown (the deployed model family)

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


def fit_and_score(data):
    """data: {split: (X, y)}. Fits every candidate on train, scores validation and test."""
    results, fitted = {}, {}
    for name, model in candidate_models().items():
        start = time.perf_counter()
        model.fit(*data["train"])
        fit_s = round(time.perf_counter() - start, 2)
        fitted[name] = model
        results[name] = {split: binary_metrics(data[split][1], phishing_probability(model, data[split][0]))
                         for split in ("validation", "test")}
        results[name]["fit_seconds"] = fit_s
    return results, fitted


def overlap_breakdown(model, X_te, y_te, test_keys, train_keys):
    """Test metrics for rows whose model input occurs in train vs rows whose does not."""
    shared = np.array([k in train_keys for k in test_keys])
    p = phishing_probability(model, X_te)
    out = {"test_rows": int(len(y_te)), "rows_with_model_input_in_train": int(shared.sum())}
    for label, mask in (("shared_with_train", shared), ("not_in_train", ~shared)):
        out[label] = binary_metrics(y_te[mask], p[mask]) if mask.any() else None
    return out


def urls_featurized(df, table, view):
    """featurize() plus each kept row's host-view model input (the leakage key)."""
    X, y, kept, _ = featurize(df, table, view=view)
    keys = [model_input(normalize_url(u), "host") for u in kept["URL"].astype(str)]
    return X, y, kept, keys


def experiment_a():
    frames = {s: load_split(s, ORIGINAL_SPLIT_DIR) for s in SPLITS}
    y = {s: (d["label"].astype(int) == LABEL_PHISHING).astype(int).to_numpy() for s, d in frames.items()}
    overlap = {
        "train_validation": len(set(frames["train"].URL) & set(frames["validation"].URL)),
        "train_test": len(set(frames["train"].URL) & set(frames["test"].URL)),
        "validation_test": len(set(frames["validation"].URL) & set(frames["test"].URL)),
    }
    results, _ = fit_and_score({s: (frames[s][ORIGINAL_22_FEATURES], y[s]) for s in SPLITS})
    results["rule_baseline"] = {"test": binary_metrics(y["test"], rule_baseline(frames["test"].URL.astype(str)))}
    sizes = {s: int(len(d)) for s, d in frames.items()}
    return {"sizes": sizes, "url_overlap_between_splits": overlap, "features": ORIGINAL_22_FEATURES,
            "results": results}


def experiment_on_csv_split(directory, view, breakdown):
    """Recomputed 17 features on a CSV split; optional overlap breakdown for the GB model."""
    raw = {s: load_split(s, directory) for s in SPLITS}
    table = build_tld_table(raw["train"])
    feats = {s: urls_featurized(d, table, view) for s, d in raw.items()}
    results, fitted = fit_and_score({s: (f[0], f[1]) for s, f in feats.items()})
    X_te, y_te, kept_te, keys_te = feats["test"]
    results["rule_baseline"] = {"test": binary_metrics(y_te, rule_baseline(kept_te.URL.astype(str)))}
    out = {"view": view, "sizes": {s: int(len(f[1])) for s, f in feats.items()}, "features": FEATURE_NAMES,
           "results": results}
    if breakdown:
        out["overlap_breakdown_gradient_boosting"] = overlap_breakdown(
            fitted[GF], X_te, y_te, keys_te, set(feats["train"][3]))
    return out, fitted, table


def experiment_c():
    splits, prep = load_host_grouped_split(RANDOM_STATE)
    table = build_tld_table(splits["train"])
    data = {s: featurize_prepared(d, table, view="host") for s, d in splits.items()}
    results, _ = fit_and_score(data)
    X_te, y_te = data["test"]
    results["rule_baseline"] = {"test": binary_metrics(y_te, rule_baseline(splits["test"].normalized_url))}
    saved = load_model(V12_MODEL_PATH)  # the model this experiment produced (archived when v2.0.0 was deployed)
    results["saved_v1_2_0_model"] = {"test": binary_metrics(y_te, phishing_probability(saved, X_te))}
    overlap = {f"{a}_{b}": len(set(splits[a].group) & set(splits[b].group))
               for a, b in (("train", "validation"), ("train", "test"), ("validation", "test"))}
    return {"view": "host", "sizes": {s: int(len(d[1])) for s, d in data.items()}, "preparation": prep,
            "model_input_overlap_between_splits": overlap, "features": FEATURE_NAMES,
            "results": results}, table


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


def metric_row(name, m):
    cm = m["confusion_matrix"]
    return (f"| {name} | {fmt(m['accuracy'])} | {fmt(m['precision'])} | {fmt(m['recall'])} | {fmt(m['f1'])} | "
            f"{fmt(m['roc_auc'])} | {cm['legitimate_correct_TN']} | {cm['legitimate_flagged_FP']} | "
            f"{cm['phishing_missed_FN']} | {cm['phishing_caught_TP']} |")


HEADER = ["| Model | Accuracy | Precision | Recall | F1 | ROC-AUC | TN (legit ok) | FP (legit flagged) | "
          "FN (phish missed) | TP (phish caught) |", "|---|---|---|---|---|---|---|---|---|---|"]


def table_rows(results, split):
    return "\n".join(HEADER + [metric_row(n, r[split]) for n, r in results.items() if split in r])


def breakdown_md(title, b):
    md = [f"### {title}", "",
          f"{b['rows_with_model_input_in_train']} of {b['test_rows']} test rows have a model input "
          "(https://www.<host>) that also occurs in train.", ""] + HEADER
    for label in ("shared_with_train", "not_in_train"):
        if b[label]:
            md.append(metric_row(f"{label} (n={b[label]['n']})", b[label]))
    return md + [""]


def comparison_md(report):
    rows = [("A: original split, 22 stored features", report["experiment_A_original"]),
            ("A2: original split, 17 host-view features", report["experiment_A2_original_split_host_view"]),
            ("B2: URL-grouped split, 17 host-view features", report["experiment_B2_url_grouped_host_view"]),
            ("C: host-grouped split, 17 host-view features (final)", report["experiment_C_host_grouped_host_view"])]
    md = ["## Methodology comparison (gradient boosting, test split)", "", *HEADER]
    for title, exp in rows:
        md.append(metric_row(title, exp["results"][GF]["test"]))
    return md + [""]


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
    print("Experiment A (original split, 22 stored features)...")
    a = experiment_a()
    print("Experiment A2 (original split, 17 host-view features)...")
    a2, _, _ = experiment_on_csv_split(ORIGINAL_SPLIT_DIR, "host", breakdown=True)
    print("Experiment B1 (URL-grouped split, full URL view)...")
    b1, fitted_b1, b1_table = experiment_on_csv_split(CLEAN_SPLIT_DIR, "full", breakdown=False)
    print("Experiment B2 (URL-grouped split, host view)...")
    b2, _, _ = experiment_on_csv_split(CLEAN_SPLIT_DIR, "host", breakdown=True)
    print("Experiment C (host-grouped split, host view = deployed)...")
    c, c_table = experiment_c()
    saved = load_model(V12_MODEL_PATH)
    probe = {
        "B1_full_view_gradient_boosting": bias_probe(fitted_b1[GF], b1_table, "full"),
        "C_host_view_saved_final_model": bias_probe(saved, c_table, "host"),
    }
    report = {"experiment_A_original": a, "experiment_A2_original_split_host_view": a2,
              "experiment_B1_url_grouped_full_view": b1, "experiment_B2_url_grouped_host_view": b2,
              "experiment_C_host_grouped_host_view": c,
              "bias_probe": probe, "probe_note": "hand-picked legitimate URLs; illustrative, not a population sample",
              "runtime_seconds": round(time.time() - start, 1)}
    write_json(report, ROOT / "docs" / "data" / "evaluation.json")

    md = ["<!-- Generated by `python -m ml.evaluate_model`. Do not edit by hand. -->", ""]
    md += comparison_md(report)
    md += ["## Experiment A: original methodology (22 stored features incl. URLSimilarityIndex, random split)", "",
           f"Split sizes: {a['sizes']}. URLs shared between splits: {a['url_overlap_between_splits']}.", "",
           "### Test", "", table_rows(a["results"], "test"), "",
           "### Validation", "", table_rows(a["results"], "validation"), ""]
    for label, exp in (("A2: original random split, 17 host-view features", a2),
                       ("B1: URL-grouped split, full-URL view", b1),
                       ("B2: URL-grouped split, host view", b2),
                       ("C: host-grouped split, host view (deployed)", c)):
        md += [f"## Experiment {label}", "",
               f"17 schema features recomputed from the URL. Split sizes (unique URLs): {exp['sizes']}.", "",
               "### Test", "", table_rows(exp["results"], "test"), "",
               "### Validation", "", table_rows(exp["results"], "validation"), ""]
        if "overlap_breakdown_gradient_boosting" in exp:
            md += breakdown_md("Test rows by model-input overlap with train (gradient boosting)",
                               exp["overlap_breakdown_gradient_boosting"])
    md += ["## Bias probe: hand-picked legitimate URLs (illustrative, not a population sample)", ""]
    md += probe_md("B1 full-URL view (gradient boosting)", probe["B1_full_view_gradient_boosting"])
    md += probe_md("C host view (saved final model)", probe["C_host_view_saved_final_model"])
    (ROOT / "docs" / "model_evaluation_tables.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    print("\n".join(md))
    print(f"\nDone in {report['runtime_seconds']}s")


if __name__ == "__main__":
    main()
