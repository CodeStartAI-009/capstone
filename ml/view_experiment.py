"""False-positive investigation: host view vs registrable-domain view (validation only).

    python -m ml.view_experiment

Both views are trained with the same candidate models on the same split, grouped
by registrable domain (so neither view shares a model input across splits).
Everything here uses the TRAIN and VALIDATION splits only; the test split is not
loaded. Writes docs/data/view_experiment.json.

Subsets reported (validation):
  legit_with_subdomain         legitimate URLs whose host has a label other than
                               "www" below its registrable domain (the failure mode
                               reported for admob.google.com, dash.cloudflare.com, ...)
  phishing_with_subdomain      phishing URLs with such a subdomain (the signal the
                               registrable view gives up, e.g. login.paypal.com.evil.xyz)
  phishing_on_shared_hosting   phishing whose registrable domain sits on a PSL private
                               suffix (firebaseapp.com, web.app, ...)
Probe: hand-picked real legitimate URLs (illustrative only, not a population sample,
not used for training or model selection).
"""
import time

import pandas as pd

from ml.dataset import ROOT, build_tld_table, featurize_prepared, load_registrable_grouped_split
from ml.feature_extractor import extract_features
from ml.feature_schema import FEATURE_NAMES
from ml.model_utils import (RANDOM_STATE, WEIGHTINGS, binary_metrics, fit_weighted, model_grid, phishing_probability,
                            threshold_for_max_fpr, write_json)
from ml.train_model import MAX_VALIDATION_FPR, bootstrap_recall_gain
from ml.url_utils import _PSL, split_registrable

OUT = ROOT / "docs" / "data" / "view_experiment.json"
VIEWS = ("host", "registrable")

PROBE_LEGITIMATE = [
    # reported in the application history
    "https://admob.google.com/v2/home", "https://publisher.unity.com/packages", "https://dashboard.render.com/",
    "https://dash.cloudflare.com/", "https://claude.ai/chat",
    # other well-known service hosts on subdomains
    "https://mail.google.com/mail/u/0/", "https://docs.python.org/3/library/urllib.parse.html",
    "https://en.wikipedia.org/wiki/Phishing", "https://console.aws.amazon.com/", "https://portal.azure.com/",
    "https://app.slack.com/client", "https://drive.google.com/drive/my-drive", "https://login.microsoftonline.com/",
    "https://github.com/pallets/flask", "https://news.bbc.co.uk/", "https://developer.mozilla.org/en-US/",
    # bare homepages (like every legitimate training URL)
    "https://www.google.com", "https://www.wikipedia.org", "https://www.python.org", "https://www.bbc.co.uk",
]


# ICANN multi-label suffixes (co.uk, com.br, ...) are registries; PSL *private* suffixes (firebaseapp.com,
# web.app, ...) are shared-hosting platforms. A suffix is private if it differs once private rules are off.
_ICANN = __import__("tldextract").TLDExtract(suffix_list_urls=(), cache_dir=None, include_psl_private_domains=False)


def is_private_suffix(host):
    return _PSL(host).suffix != _ICANN(host).suffix


def main():
    start = time.time()
    splits, prep = load_registrable_grouped_split(RANDOM_STATE)
    table = build_tld_table(splits["train"])
    overlap = {f"{a}_{b}": len(set(splits[a].group) & set(splits[b].group))
               for a, b in (("train", "validation"), ("train", "test"), ("validation", "test"))}
    va = splits["validation"]
    y_va = (va["label"] == 0).astype(int).to_numpy()
    hosts = va["normalized_url"].str.extract(r"^https?://(?:[^@/]*@)?([^/:?#]+)")[0].str.lower()
    real_sub = hosts.map(lambda h: split_registrable(h)[0] not in ("", "www")).to_numpy()
    shared = hosts.map(is_private_suffix).to_numpy()
    masks = {"legit_with_subdomain": (y_va == 0) & real_sub,
             "phishing_with_subdomain": (y_va == 1) & real_sub,
             "phishing_on_shared_hosting": (y_va == 1) & shared}

    report = {"split": "registrable-domain grouped 80/10/10, seed 42", "preparation": prep,
              "group_overlap_between_splits": overlap,
              "sizes": {s: int(len(d)) for s, d in splits.items()},
              "validation_subset_sizes": {k: int(m.sum()) for k, m in masks.items()},
              "max_validation_fpr": MAX_VALIDATION_FPR, "views": {}, "probe": {}}
    scores = {}
    for view in VIEWS:
        X_tr, y_tr = featurize_prepared(splits["train"], table, view=view)
        X_va, _ = featurize_prepared(va, table, view=view)
        report["views"][view] = {}
        for family, factory in model_grid().items():
            for weighting in WEIGHTINGS:
                name = f"{family}__{weighting}"
                model = fit_weighted(factory(), X_tr, y_tr, weighting)
                p = phishing_probability(model, X_va)
                t = threshold_for_max_fpr(p, y_va, MAX_VALIDATION_FPR)
                m = binary_metrics(y_va, p, t)
                flagged = p >= t
                entry = {"threshold": t, **{k: m[k] for k in ("accuracy", "precision", "recall", "f1", "roc_auc",
                                                            "false_positive_rate", "confusion_matrix")},
                         "subsets_at_threshold": {
                             "legit_with_subdomain_false_positive_rate": float(flagged[masks["legit_with_subdomain"]].mean()),
                             "phishing_with_subdomain_recall": float(flagged[masks["phishing_with_subdomain"]].mean()),
                             "phishing_on_shared_hosting_recall": float(flagged[masks["phishing_on_shared_hosting"]].mean()),
                         }}
                report["views"][view][name] = entry
                scores[(view, name)] = (model, p)
                s = entry["subsets_at_threshold"]
                print(f"{view:11s} {name:38s} R@5%={m['recall']:.4f} AUC={m['roc_auc']:.4f} "
                      f"legitSubFPR={s['legit_with_subdomain_false_positive_rate']:.3f} "
                      f"phishSubR={s['phishing_with_subdomain_recall']:.3f} "
                      f"sharedR={s['phishing_on_shared_hosting_recall']:.3f}", flush=True)
        model, p = scores[(view, "hist_gradient_boosting__balanced")]
        t = report["views"][view]["hist_gradient_boosting__balanced"]["threshold"]
        rows = []
        for url in PROBE_LEGITIMATE:
            ext = extract_features(url, tld_table=table, view=view)
            prob = float(phishing_probability(model, pd.DataFrame([ext["vector"]], columns=FEATURE_NAMES))[0])
            rows.append({"url": url, "model_input": ext["model_input"], "p_phishing": round(prob, 4),
                         "flagged": prob >= t})
        report["probe"][view] = {"model": "hist_gradient_boosting__balanced", "threshold": t,
                                 "flagged": sum(r["flagged"] for r in rows), "total": len(rows), "urls": rows}
    report["registrable_minus_host_recall_gain_hgb_balanced"] = bootstrap_recall_gain(
        scores[("registrable", "hist_gradient_boosting__balanced")][1],
        scores[("host", "hist_gradient_boosting__balanced")][1], y_va)
    report["runtime_seconds"] = round(time.time() - start, 1)
    write_json(report, OUT)
    for view in VIEWS:
        print(view, "probe flagged", report["probe"][view]["flagged"], "/", report["probe"][view]["total"])
    print("recall gain registrable - host:", report["registrable_minus_host_recall_gain_hgb_balanced"])
    print("subset sizes:", report["validation_subset_sizes"], "overlap:", overlap)


if __name__ == "__main__":
    main()
