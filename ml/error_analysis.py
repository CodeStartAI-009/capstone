"""Error analysis and feature analysis for the saved final model.

    python -m ml.error_analysis

Writes docs/data/error_analysis.json. Read-only with respect to models and data.

Nothing in this module feeds back into model selection or thresholds:
  * error patterns are reported for validation AND test; the test part is
    descriptive only (requested for the report);
  * permutation importance and the feature-sufficiency experiment use the
    validation split only;
  * the extended-feature experiment is a diagnostic. Its features were
    designed after looking at false negatives, so its result is not used to
    change the deployed schema and would need a fresh evaluation to be adopted.
"""
import math
import re
from collections import Counter

import numpy as np
import pandas as pd
from sklearn.inspection import permutation_importance
from sklearn.metrics import roc_auc_score
from urllib.parse import urlsplit

from ml.dataset import ROOT, build_tld_table, featurize_prepared, load_host_grouped_split
from ml.feature_schema import FEATURE_NAMES
from ml.model_utils import (RANDOM_STATE, binary_metrics, fit_weighted, load_model, model_grid, phishing_probability,
                            threshold_for_max_fpr, write_json)
from ml.train_model import MAX_VALIDATION_FPR, PREVIOUS_DIR

# This analysis documents model v1.2.0 (host view, host-grouped split); it reads the archived copy so that
# docs/ml_error_analysis.md stays reproducible after v2.0.0 replaced it in production.
MODEL_PATH = PREVIOUS_DIR / "phishing_model.pkl"
METADATA_PATH = PREVIOUS_DIR / "model_metadata.json"
VIEW = "host"

OUT_PATH = ROOT / "docs" / "data" / "error_analysis.json"
PLATFORM_MIN_HOSTS = 20  # a parent domain hosting >= this many distinct training hosts is a "hosting platform"
SUMMARY_FEATURES = ["DomainLength", "NoOfSubDomain", "TLDLegitimateProb", "CharContinuationRate",
                    "NoOfDegitsInURL", "NoOfOtherSpecialCharsInURL", "LetterRatioInURL"]
# Diagnostic only (see module docstring).
KEYWORDS = ("login", "secure", "account", "verify", "update", "bank", "pay", "support", "service", "signin",
            "wallet", "auth", "confirm", "billing", "help", "mail")


def defang(url):
    return url.replace("http", "hxxp", 1).replace(".", "[.]")


def host_of(group):
    return group[len("https://www."):]


def parent_domain(host):
    labels = host.split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else host


def url_facts(df):
    parts = df["normalized_url"].map(urlsplit)
    return pd.DataFrame({
        "has_path_or_query": parts.map(lambda p: p.path not in ("", "/") or bool(p.query)).to_numpy(),
        "scheme_http": parts.map(lambda p: p.scheme == "http").to_numpy(),
        "php_or_wp_path": df["normalized_url"].str.contains(r"\.php|wp-|/wp/", case=False, regex=True).to_numpy(),
    }, index=df.index)


def platform_parents(train_df):
    """Parent domains that host many distinct hosts in the TRAINING split (e.g. web.app)."""
    counts = Counter(parent_domain(host_of(g)) for g in set(train_df["group"]))
    return {d for d, n in counts.items() if n >= PLATFORM_MIN_HOSTS}


def outcome_frame(df, X, y, p, threshold, platforms, legit_ref):
    facts = url_facts(df)
    hosts = df["group"].map(host_of)
    out = pd.DataFrame({
        "y": y, "p": p, "flag": p >= threshold,
        "on_platform": hosts.map(lambda h: parent_domain(h) in platforms and h.count(".") >= 2).to_numpy(),
        **{c: facts[c].to_numpy() for c in facts},
    })
    inside = np.ones(len(X), dtype=bool)
    for name in SUMMARY_FEATURES:
        lo, hi = legit_ref[name]["p5"], legit_ref[name]["p95"]
        inside &= (X[name].to_numpy() >= lo) & (X[name].to_numpy() <= hi)
    out["legit_like_features"] = inside
    out["outcome"] = np.select(
        [(out.y == 1) & out.flag, (out.y == 1) & ~out.flag, (out.y == 0) & out.flag],
        ["TP", "FN", "FP"], "TN")
    return out


def pattern_table(frame, X):
    rows = {}
    for outcome in ("TP", "FN", "FP", "TN"):
        m = (frame.outcome == outcome).to_numpy()
        if not m.any():
            continue
        rows[outcome] = {
            "n": int(m.sum()),
            "share_on_hosting_platform": float(frame.on_platform[m].mean()),
            "share_with_path_or_query": float(frame.has_path_or_query[m].mean()),
            "share_http_scheme": float(frame.scheme_http[m].mean()),
            "share_php_or_wordpress_path": float(frame.php_or_wp_path[m].mean()),
            "share_all_summary_features_within_legit_p5_p95": float(frame.legit_like_features[m].mean()),
            "median_p_phishing": float(frame.p[m].median()),
            "feature_medians": {f: float(X[f].to_numpy()[m].mean() if f == "TLDLegitimateProb" else
                                         np.median(X[f].to_numpy()[m])) for f in SUMMARY_FEATURES},
        }
    return rows


def degenerate_features(X_train):
    out = {}
    for name in FEATURE_NAMES:
        n_unique = int(X_train[name].nunique())
        if n_unique <= 1:
            out[name] = f"constant ({X_train[name].iloc[0]:g}) in the host view"
    diff = (X_train["URLLength"] - X_train["DomainLength"]).unique()
    if len(diff) == 1:
        out["URLLength"] = f"always DomainLength + {diff[0]:g} in the host view (redundant)"
    return out


def correlated_pairs(X_train, min_abs=0.9):
    live = [c for c in FEATURE_NAMES if X_train[c].nunique() > 1]
    corr = X_train[live].corr()
    return [{"a": a, "b": b, "r": round(float(corr.loc[a, b]), 4)}
            for i, a in enumerate(live) for b in live[i + 1:] if abs(corr.loc[a, b]) >= min_abs]


def label_ambiguity(X, y):
    """Share of rows whose exact feature vector also occurs with the other label (irreducible for any model)."""
    key = pd.util.hash_pandas_object(X, index=False)
    labels = pd.Series(y).groupby(key.to_numpy()).nunique()
    mixed = key.map(labels) > 1
    # Lowest error ANY classifier on these features can reach on the training rows: every row of the
    # minority label within an identical-vector group is necessarily misclassified (optimistic, in-sample).
    by_vector = pd.DataFrame({"k": key.to_numpy(), "y": y}).groupby("k")["y"].agg(["sum", "count"])
    minority = np.minimum(by_vector["sum"], by_vector["count"] - by_vector["sum"]).sum()
    missed_phishing_floor = by_vector.loc[by_vector["sum"] * 2 <= by_vector["count"], "sum"].sum()
    return {"rows": int(len(X)), "rows_in_mixed_label_vectors": int(mixed.sum()),
            "share": float(mixed.mean()),
            "phishing_rows_in_mixed_label_vectors": int((mixed.to_numpy() & (y == 1)).sum()),
            "distinct_feature_vectors": int(len(by_vector)),
            "minimum_possible_training_error": float(minority / len(y)),
            "max_training_recall_if_ties_go_to_legitimate": float(1 - missed_phishing_floor / y.sum())}


def extended_features(df, platforms):
    """Diagnostic host-only lexical features (NOT part of the deployed schema)."""
    rows = []
    for group in df["group"]:
        host = host_of(group)
        core = host.rsplit(".", 1)[0]
        letters = re.sub(r"[^a-z]", "", core)
        counts = Counter(core)
        entropy = -sum(c / len(core) * math.log2(c / len(core)) for c in counts.values()) if core else 0.0
        rows.append({
            "hyphens": core.count("-"),
            "entropy": entropy,
            "vowel_ratio": sum(ch in "aeiou" for ch in letters) / len(letters) if letters else 0.0,
            "max_consonant_run": max((len(r) for r in re.findall(r"[b-df-hj-np-tv-z]+", core)), default=0),
            "keyword_hits": sum(k in core for k in KEYWORDS),
            "on_hosting_platform": int(parent_domain(host) in platforms and host.count(".") >= 2),
        })
    return pd.DataFrame(rows)


def sufficiency_experiment(splits, X, y, platforms):
    """Validation recall at the FPR cap: 17 features vs 17 + diagnostic host features (same model config)."""
    out = {}
    for label, extra in (("schema_17", False), ("schema_17_plus_diagnostic_host_features", True)):
        Xtr, Xva = X["train"], X["validation"]
        if extra:
            Xtr = pd.concat([Xtr, extended_features(splits["train"], platforms)], axis=1)
            Xva = pd.concat([Xva, extended_features(splits["validation"], platforms)], axis=1)
        model = fit_weighted(model_grid()["hist_gradient_boosting"](), Xtr, y["train"], "balanced")
        p = phishing_probability(model, Xva)
        t = threshold_for_max_fpr(p, y["validation"], MAX_VALIDATION_FPR)
        m = binary_metrics(y["validation"], p, t)
        out[label] = {"n_features": int(Xtr.shape[1]), "threshold": t,
                      **{k: m[k] for k in ("precision", "recall", "f1", "false_positive_rate", "roc_auc")}}
    return out


def importance(model, X_va, y_va, X_tr, y_tr):
    perm = permutation_importance(model, X_va, y_va, scoring="roc_auc", n_repeats=10, random_state=RANDOM_STATE,
                                  n_jobs=1)
    lr = fit_weighted(model_grid()["logistic_regression"](), X_tr, y_tr, "balanced")
    rf = fit_weighted(model_grid()["random_forest"](), X_tr, y_tr, "balanced")
    return {
        "permutation_validation_roc_auc_drop": {
            n: {"mean": float(perm.importances_mean[i]), "std": float(perm.importances_std[i])}
            for i, n in sorted(enumerate(FEATURE_NAMES), key=lambda t: -perm.importances_mean[t[0]])},
        "logistic_regression_standardised_coefficients": {
            n: float(c) for n, c in sorted(zip(FEATURE_NAMES, lr.steps[-1][1].coef_[0]), key=lambda t: -abs(t[1]))},
        "random_forest_impurity_importance": {
            n: float(v) for n, v in sorted(zip(FEATURE_NAMES, rf.feature_importances_), key=lambda t: -t[1])},
        "single_feature_validation_roc_auc": {
            n: float(max(roc_auc_score(y_va, X_va[n]), 1 - roc_auc_score(y_va, X_va[n])))
            if X_va[n].nunique() > 1 else 0.5 for n in FEATURE_NAMES},
    }


def examples(df, frame, outcome, n=25):
    rows = frame[frame.outcome == outcome].sample(min(n, int((frame.outcome == outcome).sum())),
                                                  random_state=RANDOM_STATE)
    return [{"url_defanged": defang(df["URL"].iloc[i]), "p_phishing": round(float(rows.p.loc[i]), 4)}
            for i in rows.index]


def main():
    import json
    meta = json.loads(METADATA_PATH.read_text(encoding="utf-8"))
    model = load_model(MODEL_PATH)
    threshold = meta["thresholds"]["flag"]
    splits, _ = load_host_grouped_split(RANDOM_STATE)
    table = build_tld_table(splits["train"])
    X, y = {}, {}
    for name, df in splits.items():
        X[name], y[name] = featurize_prepared(df, table, view=VIEW)
    platforms = platform_parents(splits["train"])
    legit_ref = meta["legitimate_reference"]

    report = {"model": meta["model_name"], "threshold": threshold, "hosting_platform_parents": len(platforms),
              "platform_definition": f"parent domain (last two labels) of >= {PLATFORM_MIN_HOSTS} distinct "
                                     "training hosts; a host counts as on-platform if it is a subdomain of one"}
    for name in ("validation", "test"):
        p = phishing_probability(model, X[name])
        frame = outcome_frame(splits[name], X[name], y[name], p, threshold, platforms, legit_ref)
        report[name] = {
            "counts": frame.outcome.value_counts().to_dict(),
            "patterns": pattern_table(frame, X[name]),
            "fn_top_parent_domains": Counter(
                parent_domain(host_of(g)) for g in splits[name]["group"][(frame.outcome == "FN").to_numpy()]
            ).most_common(15),
            "tp_top_parent_domains": Counter(
                parent_domain(host_of(g)) for g in splits[name]["group"][(frame.outcome == "TP").to_numpy()]
            ).most_common(15),
        }
        if name == "test":
            report[name]["false_negative_examples"] = examples(splits[name], frame, "FN")
            report[name]["false_positive_examples"] = examples(splits[name], frame, "FP", 15)

    legit_train = splits["train"][y["train"] == 0]
    report["dataset_facts"] = {
        "legitimate_train_rows_with_path_or_query": int(url_facts(legit_train).has_path_or_query.sum()),
        "legitimate_train_rows_http": int(url_facts(legit_train).scheme_http.sum()),
        "legitimate_train_rows": int(len(legit_train)),
    }
    report["feature_sufficiency"] = {
        "degenerate_features": degenerate_features(X["train"]),
        "highly_correlated_pairs_train": correlated_pairs(X["train"]),
        "label_ambiguity_train": label_ambiguity(X["train"], y["train"]),
        "extended_feature_experiment_validation": sufficiency_experiment(splits, X, y, platforms),
    }
    report["feature_importance"] = importance(model, X["validation"], y["validation"], X["train"], y["train"])
    write_json(report, OUT_PATH)
    print(json.dumps({k: v for k, v in report.items() if k != "test" or True}, indent=1, default=str)[:20000])
    print(f"\nWrote {OUT_PATH}")


if __name__ == "__main__":
    main()
