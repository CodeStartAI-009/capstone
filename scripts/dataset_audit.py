"""Dataset and leakage audit. Read-only: no dataset file is modified.

    python scripts/dataset_audit.py

Writes docs/data/dataset_audit.json. Every dataset number in docs/dataset.md
and models/model_metadata.json comes from this script or ml/train_model.py.

Sections:
  phiusiil            the dataset used by this project (target/URL columns, missing
                      values, duplicate URLs, class balance)
  splits              the three split methodologies, with sizes, class balance and
                      overlap between splits at URL level and at model-input level
  original_notebook   the earlier 21-feature notebook model (../projectcopy/url):
                      whether its features can be reproduced from a URL
"""
import json
import pickletools
import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from ml.dataset import (CLEAN_SPLIT_DIR, ORIGINAL_SPLIT_DIR, ROOT, SPLITS, load_host_grouped_split,  # noqa: E402
                        load_registrable_grouped_split, load_split)
from ml.feature_extractor import model_input  # noqa: E402
from ml.feature_schema import LABEL_COLUMN, LABEL_NAMES  # noqa: E402
from ml.model_utils import RANDOM_STATE, write_json  # noqa: E402
from ml.url_utils import InvalidURLError, normalize_url  # noqa: E402

OUT_PATH = ROOT / "docs" / "data" / "dataset_audit.json"
ORIGINAL_PROJECT_DIR = ROOT.parent / "projectcopy" / "url"
PAIRS = (("train", "validation"), ("train", "test"), ("validation", "test"))

# The 21 inputs of the original notebook model (read from Phishing_model.pkl's
# feature_names_in_), classified by what is needed to compute them. Definitions
# follow the UCI "Phishing Websites" feature list the Kaggle file is derived from.
ORIGINAL_21_FEATURES = {
    "UsingIP": ("url", "IP address used as host"),
    "PrefixSuffix-": ("url", "'-' in the domain"),
    "SubDomains": ("url", "number of dots in the domain, bucketed to -1/0/1"),
    "HTTPS": ("partial", "HTTPS *and* a trusted issuer *and* certificate age >= 1 year; only the scheme is in the URL"),
    "NonStdPort": ("partial", "open-port scan of the server; only an explicit port is in the URL"),
    "HTTPSDomainURL": ("url", "'https' token inside the domain"),
    "RequestURL": ("page", "share of images/videos/sounds loaded from other domains"),
    "AnchorURL": ("page", "share of <a> tags pointing elsewhere or to '#'"),
    "LinksInScriptTags": ("page", "share of <meta>/<script>/<link> tags pointing elsewhere"),
    "ServerFormHandler": ("page", "form action empty, about:blank or another domain"),
    "InfoEmail": ("page", "mail() or mailto: used to submit data"),
    "AbnormalURL": ("external", "WHOIS identity compared with the URL"),
    "WebsiteForwarding": ("page", "number of HTTP redirects (requires fetching the page)"),
    "StatusBarCust": ("page", "onMouseOver changes the status bar"),
    "DisableRightClick": ("page", "JavaScript disables right click"),
    "AgeofDomain": ("external", "WHOIS domain age >= 6 months"),
    "DNSRecording": ("external", "DNS/WHOIS record exists"),
    "WebsiteTraffic": ("external", "Alexa rank (service retired in 2022)"),
    "PageRank": ("external", "Google PageRank (no longer published)"),
    "GoogleIndex": ("external", "page is in Google's index"),
    "StatsReport": ("external", "host/IP on PhishTank or StopBadware top lists"),
}


def class_counts(labels):
    counts = labels.astype(int).value_counts()
    return {LABEL_NAMES[k]: int(counts.get(k, 0)) for k in sorted(LABEL_NAMES)}


def host_view(raw):
    try:
        return model_input(normalize_url(raw), "host")
    except InvalidURLError:
        return None


def registrable_view(raw):
    try:
        return model_input(normalize_url(raw), "registrable")
    except InvalidURLError:
        return None


def overlap_report(frames, key):
    sets = {name: set(df[key].dropna()) for name, df in frames.items()}
    report = {}
    for a, b in PAIRS:
        shared = sets[a] & sets[b]
        report[f"{a}_{b}"] = {
            "shared_keys": len(shared),
            f"{b}_rows_with_shared_key": int(frames[b][key].isin(shared).sum()),
        }
    return report


def describe_split(frames, dedupe_urls):
    """Sizes, class balance and overlap for one split methodology."""
    out = {"rows": {}, "unique_urls": {}, "duplicate_url_rows_within_split": {}, "class_distribution": {}}
    for name, df in frames.items():
        out["rows"][name] = int(len(df))
        out["unique_urls"][name] = int(df["URL"].nunique())
        out["duplicate_url_rows_within_split"][name] = int(df["URL"].duplicated().sum())
        used = df.drop_duplicates("URL") if dedupe_urls else df
        out["class_distribution"][name] = class_counts(used[LABEL_COLUMN])
    out["url_overlap"] = overlap_report(frames, "URL")
    with_view = {n: df.assign(_view=df["URL"].astype(str).map(host_view),
                              _reg=df["URL"].astype(str).map(registrable_view)) for n, df in frames.items()}
    out["model_input_overlap"] = overlap_report(with_view, "_view")
    # near-duplicates: different hosts under one registrable domain (a.evil.com / b.evil.com)
    out["registrable_domain_overlap"] = overlap_report(with_view, "_reg")
    return out


def audit_phiusiil(df):
    dup_mask = df["URL"].duplicated(keep=False)
    labels_per_url = df.groupby("URL")[LABEL_COLUMN].nunique()
    return {
        "name": "PhiUSIIL Phishing URL Dataset",
        "source_files": [f"data/{s}.csv" for s in SPLITS],
        "rows": int(len(df)),
        "columns": int(df.shape[1]),
        "target_column": LABEL_COLUMN,
        "target_mapping": {str(k): v for k, v in LABEL_NAMES.items()},
        "url_column": "URL",
        "missing_values_total": int(df.isna().sum().sum()),
        "missing_values_by_column": {c: int(v) for c, v in df.isna().sum().items() if v},
        "unique_urls": int(df["URL"].nunique()),
        "duplicate_url_rows": int(df["URL"].duplicated().sum()),
        "urls_that_are_duplicated": int(df.loc[dup_mask, "URL"].nunique()),
        "rows_affected_by_duplicate_urls": int(dup_mask.sum()),
        "exact_duplicate_rows": int(df.duplicated().sum()),
        "urls_with_conflicting_labels": int((labels_per_url > 1).sum()),
        "class_distribution": class_counts(df[LABEL_COLUMN]),
    }


def audit_original_notebook():
    csv_path = ORIGINAL_PROJECT_DIR / "phishing.csv"
    pkl_path = ORIGINAL_PROJECT_DIR / "Phishing_model.pkl"
    out = {"location": str(ORIGINAL_PROJECT_DIR.relative_to(ROOT.parent)), "found": csv_path.exists()}
    if not csv_path.exists():
        return out
    df = pd.read_csv(csv_path)
    features = df.drop(columns=["Index", "class"])
    out["dataset"] = {
        "file": "phishing.csv (Kaggle 'phishing website detector', UCI-style -1/0/1 encoding)",
        "rows": int(len(df)),
        "feature_columns": int(features.shape[1]),
        "target_column": "class (1 = legitimate, -1 = phishing)",
        "has_url_column": "URL" in df.columns,
        "missing_values_total": int(df.isna().sum().sum()),
        "duplicate_rows_ignoring_index": int(df.drop(columns=["Index"]).duplicated().sum()),
        "class_distribution": {str(k): int(v) for k, v in df["class"].value_counts().sort_index().items()},
    }
    if pkl_path.exists():
        # Inspect the pickle without unpickling it (it cannot be loaded by the installed scikit-learn).
        strings = [arg for _, arg, _ in pickletools.genops(pkl_path.read_bytes()) if isinstance(arg, str)]
        version = strings[strings.index("_sklearn_version") + 1] if "_sklearn_version" in strings else None
        out["model"] = {
            "file": "Phishing_model.pkl (left untouched)",
            "estimator_modules": sorted({s for s in strings if s.startswith("sklearn.")}),
            "trained_with_scikit_learn": version,
            "input_features": [f for f in ORIGINAL_21_FEATURES if f in strings],
        }
    by_kind = {}
    for name, (kind, _) in ORIGINAL_21_FEATURES.items():
        by_kind.setdefault(kind, []).append(name)
    out["feature_reproducibility"] = {
        "definitions": {n: {"needs": k, "definition": d} for n, (k, d) in ORIGINAL_21_FEATURES.items()},
        "summary": {k: len(v) for k, v in by_kind.items()},
        "by_requirement": by_kind,
    }
    out["conclusion"] = (
        f"Not reproducible from a URL: only {len(by_kind['url'])} of 21 features are pure URL-string features, "
        f"{len(by_kind['partial'])} are only partly in the URL, and {len(by_kind['page']) + len(by_kind['external'])} "
        "need the page HTML, HTTP redirects, WHOIS/DNS or third-party ranking services (two of which no longer "
        "exist). The file has no URL column, so even the URL features' -1/0/1 bucket thresholds cannot be checked. "
        "The model was also fitted on StandardScaler output (scaler fitted on all rows before the split and not "
        "saved), so raw -1/0/1 values cannot be fed to it correctly."
    )
    return out


def main():
    original = {s: load_split(s, ORIGINAL_SPLIT_DIR) for s in SPLITS}
    url_grouped = {s: load_split(s, CLEAN_SPLIT_DIR) for s in SPLITS}
    host_grouped, prepare_stats = load_host_grouped_split(RANDOM_STATE)
    reg_grouped, reg_stats = load_registrable_grouped_split(RANDOM_STATE)

    report = {
        "phiusiil": audit_phiusiil(pd.concat(original.values(), ignore_index=True)),
        "splits": {
            "original_random": {
                "description": "data/{train,validation,test}.csv as supplied: random row-level split; "
                               "the same URL can occur in several splits.",
                **describe_split(original, dedupe_urls=False),
            },
            "url_grouped": {
                "description": "data/clean_split (create_clean_split.py): stratified 80/10/10 over unique URLs, "
                               f"seed {RANDOM_STATE}. Class distribution counts unique URLs.",
                **describe_split(url_grouped, dedupe_urls=True),
            },
            "registrable_grouped": {
                "description": "ml.dataset.load_registrable_grouped_split (final, model v2.0.0): URLs deduplicated "
                               "and validated, then a stratified 80/10/10 split over registrable domains (Public "
                               f"Suffix List eTLD+1), seed {RANDOM_STATE}. Built in memory; no files written.",
                "preparation": reg_stats,
                **describe_split(reg_grouped, dedupe_urls=True),
            },
            "host_grouped": {
                "description": "ml.dataset.load_host_grouped_split (models v1.1.0/v1.2.0): URLs deduplicated and "
                               "validated, then a "
                               "stratified 80/10/10 split over model-input groups (https://www.<host>), "
                               f"seed {RANDOM_STATE}. Built in memory; no files written.",
                "preparation": prepare_stats,
                **describe_split(host_grouped, dedupe_urls=True),
            },
        },
        "original_notebook": audit_original_notebook(),
    }
    write_json(report, OUT_PATH)
    print(json.dumps(report, indent=2))
    print(f"\nWrote {OUT_PATH}")


if __name__ == "__main__":
    main()
