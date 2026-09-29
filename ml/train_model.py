"""Train, select and save the URL-only phishing model.

    python -m ml.train_model                                   # production model (default view)
    python -m ml.train_model --view host --out-dir models/alternatives/host_view_v1.3.0 --version 1.3.0

Steps:
  1. Load all PhiUSIIL rows (data/{train,validation,test}.csv, read-only), drop
     duplicate URLs and invalid URLs, and split 80/10/10 grouped by the model
     REGISTRABLE DOMAIN (Public Suffix List eTLD+1), so no registrable domain -- and
     therefore no model input in either view -- occurs in two splits
     (ml.dataset.load_registrable_grouped_split; v1.x used the finer host grouping,
     which let sibling subdomains of one attacker domain span splits).
  2. Build the TLD prior table from the training split and save it.
  3. Recompute the 17 schema features from the URL column (ml/dataset.py),
     using the deployed model input view (host view; see ml/feature_schema.py).
  4. Fit every model in ml.model_utils.model_grid() twice on train (no
     reweighting / balanced sample weights) and score each on validation.
  5. Select a model by SELECTION_CRITERIA and set the decision threshold by
     THRESHOLD_CRITERIA, using validation results only. The test split is not
     used for any decision.
  6. Derive the high-confidence "Phishing" threshold from validation scores.
  7. Evaluate the selected model and threshold once on test, then save the
     model, metadata and TLD table.
"""
import argparse
import hashlib
import json
import platform
import shutil
import time
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import sklearn

from sklearn.metrics import average_precision_score, classification_report

from ml.dataset import ROOT, SPLITS, build_tld_table, featurize_prepared, load_registrable_grouped_split
from ml.feature_schema import (DEFAULT_MODEL_INPUT_VIEW, EXCLUDED_FEATURES, FEATURE_COUNT, FEATURE_DESCRIPTIONS,
                               FEATURE_NAMES, FEATURE_TYPES, LABEL_LEGITIMATE, LABEL_PHISHING, SCHEMA_VERSION)
from ml.url_utils import PSL_SOURCE
from ml.model_utils import (RANDOM_STATE, WEIGHTINGS, binary_metrics, fbeta, fit_weighted, model_grid,
                            phishing_probability, save_model, threshold_for_max_fpr, threshold_table, write_json)

MODELS_DIR = ROOT / "models"
MODEL_PATH = MODELS_DIR / "phishing_model.pkl"
METADATA_PATH = MODELS_DIR / "model_metadata.json"
TLD_TABLE_PATH = MODELS_DIR / "tld_legitimate_prob.json"
MODEL_VERSION = "2.0.0"
BASELINE_DIR = MODELS_DIR / "baseline_v1.1.0"   # v1.1.0 (host view, host-grouped split)
PREVIOUS_DIR = MODELS_DIR / "previous_v1.2.0"   # v1.2.0 (host view, host-grouped split), archived before v2.0.0

# Deployment check for the model input view (docs/false_positive_investigation.md): false alarms must not
# concentrate on a whole structural class of legitimate URLs. On validation, the false-positive rate on
# legitimate URLs whose host has a subdomain below its registrable domain must be at most this multiple
# of the overall validation false-positive rate.
MAX_SUBDOMAIN_FPR_RATIO = 2.0

# Operating point. A browser warning that fires on legitimate sites is quickly ignored, so false
# alarms are capped and recall is maximised under the cap. Real traffic contains far fewer phishing
# URLs than this dataset (43%), so each point of FPR costs more precision in use than on validation.
MAX_VALIDATION_FPR = 0.05
# A flagged URL is reported as "Phishing" only where the model's validation precision is at least
# this; below it the flag is "Suspicious".
HIGH_CONFIDENCE_PRECISION = 0.95
INCUMBENT = "hist_gradient_boosting__balanced"  # same configuration as the v1.1.0 baseline
BOOTSTRAP_REPS = 1000

THRESHOLD_CRITERIA = (
    f"Decision threshold = the lowest threshold whose VALIDATION false-positive rate is <= {MAX_VALIDATION_FPR:.0%} "
    "(equivalently: maximum validation recall with at most 1 in 20 legitimate URLs flagged). Chosen before "
    "looking at test results; the test split is scored once at this threshold."
)
SELECTION_CRITERIA = (
    f"Metric: validation recall at each model's own {MAX_VALIDATION_FPR:.0%}-FPR threshold (all models compared at "
    "the same false-alarm rate, so the comparison does not depend on score calibration). The incumbent "
    f"({INCUMBENT}, the v1.1.0 configuration) is kept unless a challenger's gain over it is significant: the 95% "
    f"interval of a paired, class-stratified bootstrap of the validation set ({BOOTSTRAP_REPS} resamples, threshold "
    "re-derived in every resample) must lie entirely above zero. Among significant challengers the largest mean "
    "gain wins. Validation data only. (This rule replaced a fixed 0.002 tie margin after the first run showed "
    "that margin is smaller than the validation sampling error, ~0.005 recall.)"
)
ALTERNATIVE_CRITERIA = {
    "fixed_0.5": lambda p, y: 0.5,
    "fpr_le_1pct": lambda p, y: threshold_for_max_fpr(p, y, 0.01),
    "fpr_le_2pct": lambda p, y: threshold_for_max_fpr(p, y, 0.02),
    "fpr_le_5pct (chosen)": lambda p, y: threshold_for_max_fpr(p, y, MAX_VALIDATION_FPR),
    "fpr_le_10pct": lambda p, y: threshold_for_max_fpr(p, y, 0.10),
    "max_f1": lambda p, y: best_threshold(p, y, beta=1),
    "max_f2 (recall-weighted)": lambda p, y: best_threshold(p, y, beta=2),
}


def single_url_latency_ms(model, X, repeats=200):
    row = X.iloc[[0]]
    model.predict_proba(row)  # warm-up
    start = time.perf_counter()
    for _ in range(repeats):
        model.predict_proba(row)
    return (time.perf_counter() - start) / repeats * 1000


def best_threshold(p, y, beta):
    """Threshold (among observed scores) maximising F-beta on (p, y)."""
    order = np.argsort(-p)
    p_sorted, y_sorted = p[order], y[order]
    tp = np.cumsum(y_sorted)
    flagged = np.arange(1, len(p) + 1)
    precision, recall = tp / flagged, tp / max(y.sum(), 1)
    b2 = beta * beta
    f = np.where(precision + recall > 0, (1 + b2) * precision * recall / (b2 * precision + recall + 1e-300), 0)
    last_of_tie = np.r_[p_sorted[1:] != p_sorted[:-1], True]  # a threshold flags all tied scores together
    i = int(np.argmax(np.where(last_of_tie, f, -1)))
    return float(p_sorted[i])


def bootstrap_recall_gain(p_challenger, p_incumbent, y, reps=BOOTSTRAP_REPS, seed=RANDOM_STATE):
    """Paired, class-stratified bootstrap of recall@FPR-cap(challenger) - recall@FPR-cap(incumbent)."""
    rng = np.random.default_rng(seed)
    legit, phish = np.where(y == 0)[0], np.where(y == 1)[0]

    def recall_at_cap(p, idx_l, idx_p):
        t = threshold_for_max_fpr(p[idx_l], np.zeros(len(idx_l), dtype=int), MAX_VALIDATION_FPR)
        return float((p[idx_p] >= t).mean())

    diffs = []
    for _ in range(reps):
        il, ip = rng.choice(legit, len(legit)), rng.choice(phish, len(phish))
        diffs.append(recall_at_cap(p_challenger, il, ip) - recall_at_cap(p_incumbent, il, ip))
    diffs = np.asarray(diffs)
    return {"mean": float(diffs.mean()),
            "ci95": [float(np.percentile(diffs, 2.5)), float(np.percentile(diffs, 97.5))]}


def high_confidence_threshold(p, y, flag_threshold, target_precision=HIGH_CONFIDENCE_PRECISION):
    """Lowest t >= flag_threshold with validation precision(P >= t) >= target, else None."""
    for t in np.unique(p[p >= flag_threshold]):
        flagged = p >= t
        if y[flagged].mean() >= target_precision:
            return float(t)
    return None


def previous_summary(directory):
    """A preserved earlier model. Its test metrics were measured on ITS OWN split (not comparable 1:1)."""
    path = directory / "model_metadata.json"
    if not path.exists():
        return None
    old = json.loads(path.read_text(encoding="utf-8"))
    return {
        "model_version": old.get("model_version"),
        "model_class": old.get("model_class"),
        "model_input_view": old.get("model_input_view", "host"),
        "file": str((directory / "phishing_model.pkl").relative_to(ROOT)),
        "threshold": old.get("thresholds", {}).get("flag"),
        "split": old.get("dataset", {}).get("split"),
        "test_metrics": {k: v for k, v in old.get("test_metrics", {}).items() if k != "classification_report"},
    }


def archive_production_model():
    """Copy the current production model to models/previous_v<version>/ once, before it is replaced."""
    if not METADATA_PATH.exists():
        return None
    version = json.loads(METADATA_PATH.read_text(encoding="utf-8")).get("model_version", "unknown")
    target = MODELS_DIR / f"previous_v{version}"
    if version != MODEL_VERSION and not target.exists():
        target.mkdir(parents=True)
        for path in (MODEL_PATH, METADATA_PATH, TLD_TABLE_PATH):
            shutil.copy2(path, target / path.name)
        print(f"Archived production model v{version} -> {target}")
    return target


def subdomain_fpr_check(df, y, p, threshold, overall_fpr):
    """Validation FPR on legitimate URLs with a subdomain below the registrable domain (see MAX_SUBDOMAIN_FPR_RATIO)."""
    from ml.url_utils import split_registrable
    hosts = df["normalized_url"].str.extract(r"^https?://(?:[^@/]*@)?([^/:?#]+)")[0].str.lower()
    has_sub = hosts.map(lambda h: split_registrable(h)[0] not in ("", "www")).to_numpy()
    mask = (y == 0) & has_sub
    fpr = float((p[mask] >= threshold).mean()) if mask.any() else None
    ratio = fpr / overall_fpr if fpr is not None and overall_fpr else None
    return {"legit_with_subdomain_rows": int(mask.sum()), "legit_with_subdomain_fpr": fpr,
            "overall_fpr": overall_fpr, "ratio": ratio, "max_ratio": MAX_SUBDOMAIN_FPR_RATIO,
            "passes": ratio is not None and ratio <= MAX_SUBDOMAIN_FPR_RATIO}


def split_overlap(frames, key):
    sets = {name: set(df[key]) for name, df in frames.items()}
    return {f"{a}_{b}": len(sets[a] & sets[b])
            for a, b in (("train", "validation"), ("train", "test"), ("validation", "test"))}


def url_fingerprint(df):
    """SHA-256 of the split's sorted URLs, to verify the split is reproduced exactly."""
    return hashlib.sha256("\n".join(sorted(df["URL"].astype(str))).encode("utf-8")).hexdigest()


def legitimate_reference(X_train, y_train):
    """Per-feature percentiles over legitimate training URLs (used by the explanation engine)."""
    legit = X_train[y_train == 0]
    return {
        name: {q: float(np.percentile(legit[name], int(q[1:]))) for q in ("p1", "p5", "p50", "p95", "p99")}
        for name in FEATURE_NAMES
    }


def main():
    global MODEL_PATH, METADATA_PATH, TLD_TABLE_PATH, MODEL_VERSION
    parser = argparse.ArgumentParser()
    parser.add_argument("--view", default=DEFAULT_MODEL_INPUT_VIEW, choices=("host", "registrable"))
    parser.add_argument("--out-dir", default=str(MODELS_DIR))
    parser.add_argument("--version", default=MODEL_VERSION)
    args = parser.parse_args()
    view, out_dir = args.view, Path(args.out_dir).resolve()
    MODEL_VERSION = args.version
    production = out_dir == MODELS_DIR.resolve()
    MODEL_PATH, METADATA_PATH, TLD_TABLE_PATH = (out_dir / "phishing_model.pkl", out_dir / "model_metadata.json",
                                                 out_dir / "tld_legitimate_prob.json")
    out_dir.mkdir(parents=True, exist_ok=True)
    if production:
        archive_production_model()

    print(f"Building registrable-domain-grouped split from data/{{train,validation,test}}.csv (view: {view})")
    raw, prepare_stats = load_registrable_grouped_split(RANDOM_STATE, view)
    print(prepare_stats)
    overlap = {"url": split_overlap(raw, "URL"), "model_input": split_overlap(raw, "group")}
    print("Overlap between splits:", overlap)
    if any(v for level in overlap.values() for v in level.values()):
        raise RuntimeError(f"Leakage check failed: {overlap}")

    tld_table = build_tld_table(raw["train"])
    write_json(dict(sorted(tld_table.items())), TLD_TABLE_PATH)
    print(f"TLD prior table: {len(tld_table)} TLDs -> {TLD_TABLE_PATH}")

    data, stats = {}, {}
    for name, df in raw.items():
        X, y = featurize_prepared(df, tld_table, view=view)
        data[name] = (X, y)
        stats[name] = {"rows": int(len(y)), "groups": int(df["group"].nunique()), "phishing": int(y.sum()),
                       "legitimate": int(len(y) - y.sum()), "url_sha256": url_fingerprint(df)}
        print(f"{name:10s} rows={len(y)} phishing={int(y.sum())} legitimate={int(len(y) - y.sum())}")

    X_tr, y_tr = data["train"]
    X_va, y_va = data["validation"]
    X_te, y_te = data["test"]

    candidates, fitted = {}, {}
    for family, factory in model_grid().items():
        for weighting in WEIGHTINGS:
            name = f"{family}__{weighting}"
            model = factory()
            start = time.perf_counter()
            fit_weighted(model, X_tr, y_tr, weighting)
            fit_s = time.perf_counter() - start
            p_va = phishing_probability(model, X_va)
            t_cap = threshold_for_max_fpr(p_va, y_va, MAX_VALIDATION_FPR)
            fitted[name] = model
            candidates[name] = {
                "family": family,
                "weighting": weighting,
                "validation_at_0.5": binary_metrics(y_va, p_va, 0.5),
                "validation_at_fpr_cap": {"threshold": t_cap, **binary_metrics(y_va, p_va, t_cap)},
                "validation_average_precision": float(average_precision_score(y_va, p_va)),
                "fit_seconds": round(fit_s, 2),
                "single_url_inference_ms": round(single_url_latency_ms(model, X_va), 3),
            }
            c = candidates[name]
            print(f"{name:38s} @0.5 P={c['validation_at_0.5']['precision']:.4f} R={c['validation_at_0.5']['recall']:.4f} "
                  f"F1={c['validation_at_0.5']['f1']:.4f} | @FPR<={MAX_VALIDATION_FPR:.0%} t={t_cap:.4f} "
                  f"R={c['validation_at_fpr_cap']['recall']:.4f} F1={c['validation_at_fpr_cap']['f1']:.4f} | "
                  f"AUC={c['validation_at_0.5']['roc_auc']:.4f} AP={c['validation_average_precision']:.4f} "
                  f"fit={fit_s:.1f}s")

    scores = {n: phishing_probability(m, X_va) for n, m in fitted.items()}
    for name, c in candidates.items():
        c["recall_gain_vs_incumbent"] = (None if name == INCUMBENT else
                                         bootstrap_recall_gain(scores[name], scores[INCUMBENT], y_va))
    significant = {n: c["recall_gain_vs_incumbent"]["mean"] for n, c in candidates.items()
                   if c["recall_gain_vs_incumbent"] and c["recall_gain_vs_incumbent"]["ci95"][0] > 0}
    selected = max(significant, key=significant.get) if significant else INCUMBENT
    model = fitted[selected]
    for name, c in candidates.items():
        g = c["recall_gain_vs_incumbent"]
        if g:
            print(f"  {name:38s} gain vs incumbent {g['mean']:+.4f}  95% CI [{g['ci95'][0]:+.4f}, {g['ci95'][1]:+.4f}]")
    print(f"\nSelected: {selected} (challengers with a significant gain: {sorted(significant) or 'none'})")

    p_va = phishing_probability(model, X_va)
    decision_threshold = candidates[selected]["validation_at_fpr_cap"]["threshold"]
    grid = sorted({round(t, 2) for t in np.arange(0.05, 0.96, 0.05)} | {decision_threshold})
    threshold_analysis = {
        "table": threshold_table(p_va, y_va, grid),
        "criteria": {},
    }
    for label, rule in ALTERNATIVE_CRITERIA.items():
        t = rule(p_va, y_va)
        m = binary_metrics(y_va, p_va, t)
        threshold_analysis["criteria"][label] = {
            "threshold": t, **{k: m[k] for k in ("precision", "recall", "f1", "false_positive_rate")},
            "f2": fbeta(m["precision"], m["recall"], 2)}
        print(f"  validation {label:26s} t={t:.4f} P={m['precision']:.4f} R={m['recall']:.4f} "
              f"F1={m['f1']:.4f} FPR={m['false_positive_rate']:.4f}")

    phishing_threshold = high_confidence_threshold(p_va, y_va, decision_threshold)
    if phishing_threshold is None:
        print(f"No threshold reaches {HIGH_CONFIDENCE_PRECISION:.0%} validation precision; all flags -> Suspicious")
    else:
        flagged = p_va >= phishing_threshold
        print(f"High-confidence 'Phishing' threshold: {phishing_threshold:.6f} "
              f"(validation precision {y_va[flagged].mean():.4f}; {int(flagged.sum())} validation URLs at or above it)")

    # The only use of the test split: one evaluation of the chosen model at the chosen threshold.
    p_te = phishing_probability(model, X_te)
    test_metrics = binary_metrics(y_te, p_te, decision_threshold)
    test_metrics["threshold"] = decision_threshold
    level_cut = phishing_threshold if phishing_threshold is not None else np.inf
    levels = np.where(p_te < decision_threshold, "Safe", np.where(p_te >= level_cut, "Phishing", "Suspicious"))
    test_metrics["risk_levels_by_true_class"] = {
        cls: {lvl: int(((levels == lvl) & (y_te == code)).sum()) for lvl in ("Safe", "Suspicious", "Phishing")}
        for cls, code in (("phishing", 1), ("legitimate", 0))
    }
    y_hat = (p_te >= decision_threshold).astype(int)
    test_metrics["classification_report"] = classification_report(
        y_te, y_hat, labels=[0, 1], target_names=["legitimate", "phishing"], digits=4, output_dict=True)
    print(f"TEST: {test_metrics}")
    print(classification_report(y_te, y_hat, labels=[0, 1], target_names=["legitimate", "phishing"], digits=4))

    baseline = previous_summary(PREVIOUS_DIR) or previous_summary(BASELINE_DIR)
    structural_check = subdomain_fpr_check(raw["validation"], y_va, p_va, decision_threshold,
                                           binary_metrics(y_va, p_va, decision_threshold)["false_positive_rate"])
    print(f"Legitimate-subdomain FPR check (validation): {structural_check}")

    save_model(model, MODEL_PATH)
    metadata = {
        "model_version": MODEL_VERSION,
        "model_name": selected,
        "model_class": type(model).__name__ if not hasattr(model, "steps") else
        " -> ".join(type(s).__name__ for _, s in model.steps),
        "schema_version": SCHEMA_VERSION,
        "model_input_view": view,
        "public_suffix_list": PSL_SOURCE,
        "feature_count": FEATURE_COUNT,
        "feature_names": FEATURE_NAMES,
        "feature_order": {name: i for i, name in enumerate(FEATURE_NAMES)},
        "feature_types": FEATURE_TYPES,
        "feature_descriptions": FEATURE_DESCRIPTIONS,
        "excluded_features": EXCLUDED_FEATURES,
        "target_encoding": {
            "model_output": "predict_proba column for class 1 = P(phishing)",
            "dataset_label_phishing": LABEL_PHISHING,
            "dataset_label_legitimate": LABEL_LEGITIMATE,
        },
        "supports_probability": True,
        "thresholds": {
            "flag": decision_threshold,
            "high_confidence_phishing": phishing_threshold,
            "flag_criterion": THRESHOLD_CRITERIA,
            "definition": (
                f"P(phishing) < flag ({decision_threshold:.6f}) -> Safe; otherwise Phishing if P >= high_confidence_phishing "
                f"(lowest threshold with validation precision >= {HIGH_CONFIDENCE_PRECISION:.0%}), else Suspicious. "
                "Binary metrics treat Suspicious and Phishing together as 'flagged'."
            ),
        },
        "selection_criteria": SELECTION_CRITERIA,
        "baseline": baseline,
        "previous_models": [s for s in (previous_summary(PREVIOUS_DIR), previous_summary(BASELINE_DIR)) if s],
        "subdomain_false_positive_check": structural_check,
        "view_decision": "docs/false_positive_investigation.md; experiment data docs/data/view_experiment.json",
        "candidates": candidates,
        "class_weighting": "none = unweighted fit; balanced = sample_weight n/(2*n_class) on the training split only. "
                           "No oversampling or undersampling; validation/test untouched.",
        "threshold_analysis_validation": threshold_analysis,
        "validation_metrics": {"threshold": decision_threshold, **binary_metrics(y_va, p_va, decision_threshold)},
        "test_metrics": test_metrics,
        "training_seconds": candidates[selected]["fit_seconds"],
        "dataset": {
            "name": "PhiUSIIL Phishing URL Dataset",
            "source_files": [f"data/{s}.csv" for s in SPLITS],
            "split": f"registrable-domain-grouped 80/10/10, stratified by group label, seed {RANDOM_STATE} "
                     "(ml.dataset.load_registrable_grouped_split)",
            "split_loader": "load_registrable_grouped_split",
            "feature_source": "recomputed from the URL column by ml.feature_extractor",
            "preparation": prepare_stats,
            "splits": stats,
            "class_distribution": {
                "phishing": sum(v["phishing"] for v in stats.values()),
                "legitimate": sum(v["legitimate"] for v in stats.values()),
                "phishing_share": round(sum(v["phishing"] for v in stats.values())
                                        / sum(v["rows"] for v in stats.values()), 4),
            },
            "overlap_between_splits": overlap,
            "audit": "docs/data/dataset_audit.json (python scripts/dataset_audit.py)",
            "tld_table_entries": len(tld_table),
        },
        "leakage_handling": {
            "duplicate_urls": "Duplicate URLs (425 extra rows; every duplicate has a single label) are collapsed to "
                              "one row before splitting, so a URL can occur in only one split.",
            "grouping": "The split is grouped by registrable domain (Public Suffix List eTLD+1): every host under one "
                        "registrable domain (a.evil.com, b.evil.com, evil.com) goes to one split, so no model input in "
                        "either the host or the registrable view is shared between splits. Overlap is re-checked and "
                        "training aborts if it is non-zero. (v1.x grouped by host only, which let sibling subdomains "
                        "span splits: see docs/false_positive_investigation.md.)",
            "preprocessing": "The TLD prior table, class weights and the explanation percentiles come from the "
                             "training split only; model selection and both thresholds use validation only; test "
                             "is scored once, at the chosen threshold.",
            "excluded_features": "URLSimilarityIndex and 4 other stored columns are not used (see excluded_features).",
            "original_csv_files_modified": False,
        },
        "original_model": {
            "path": "../projectcopy/url/Phishing_model.pkl (not modified, not used)",
            "type": "GradientBoostingClassifier on 21 UCI-style -1/0/1 features (Kaggle phishing.csv)",
            "trained_with_scikit_learn": "1.2.1",
            "loads_with_current_scikit_learn": False,
            "why_replaced": "Cannot be unpickled with scikit-learn >= 1.4 (sklearn.ensemble._gb_losses removed); "
                            "15 of its 21 inputs need page HTML, WHOIS/DNS or retired ranking services; its "
                            "StandardScaler was not saved. Details: docs/data/dataset_audit.json.",
        },
        "legitimate_reference": legitimate_reference(X_tr, y_tr),
        "environment": {
            "python": platform.python_version(),
            "scikit_learn": sklearn.__version__,
            "numpy": np.__version__,
        },
        "random_state": RANDOM_STATE,
        "trained_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    write_json(metadata, METADATA_PATH)
    size_mb = Path(MODEL_PATH).stat().st_size / 1e6
    print(f"\nSaved {MODEL_PATH} ({size_mb:.2f} MB) and {METADATA_PATH}")


if __name__ == "__main__":
    main()
