"""Dataset loading and feature-matrix construction shared by training and evaluation.

Final methodology (ml/train_model.py; audit in docs/data/dataset_audit.json):
  * Source: all PhiUSIIL rows from data/{train,validation,test}.csv. The
    original CSV files are only read, never modified.
  * Duplicate URLs (always single-label) are collapsed to one row and URLs that
    fail ml.url_utils validation are dropped (prepare_rows).
  * Split: stratified 80/10/10, grouped by the model input (host view), seed 42
    (host_grouped_split), so no URL and no model input occurs in two splits.
  * Features are recomputed from the URL column with ml.feature_extractor,
    using the same normalisation and model input view as the live API, instead
    of the stored columns. The stored URL-level counts contain a
    collection-batch artefact (for 79% of rows they were computed on the URL
    minus its final character), so they cannot be reproduced at inference time.
  * The TLD prior table is built from the training split only.

The URL-grouped split in data/clean_split (create_clean_split.py) and the
original random split are still loaded by ml/evaluate_model.py for the
methodology comparison (load_split / featurize).
"""
from pathlib import Path

import numpy as np
import pandas as pd

from ml.feature_extractor import compute_features, model_input
from ml.feature_schema import DEFAULT_MODEL_INPUT_VIEW, FEATURE_NAMES, LABEL_COLUMN, LABEL_PHISHING
from ml.url_utils import InvalidURLError, normalize_url

ROOT = Path(__file__).resolve().parent.parent
CLEAN_SPLIT_DIR = ROOT / "data" / "clean_split"
ORIGINAL_SPLIT_DIR = ROOT / "data"
SPLITS = ("train", "validation", "test")


def load_split(name, directory=CLEAN_SPLIT_DIR):
    """One CSV split file (default: the URL-grouped split in data/clean_split)."""
    return pd.read_csv(Path(directory) / f"{name}.csv", low_memory=False)


def build_tld_table(train_df):
    """TLD -> TLDLegitimateProb, taken from the (deterministic per-TLD) stored column."""
    tlds = train_df["TLD"].astype(str).str.lower()
    return train_df.assign(_tld=tlds).groupby("_tld")["TLDLegitimateProb"].first().astype(float).to_dict()


def featurize(df, tld_table, view=DEFAULT_MODEL_INPUT_VIEW):
    """Recompute schema features from df['URL'] using the given model input view.

    Returns (X, y_phishing, kept_df, stats). y_phishing is 1 for phishing
    (the positive class for all reported metrics) and 0 for legitimate.
    """
    df = df.drop_duplicates(subset="URL").reset_index(drop=True)
    rows, keep = [], []
    rejected = 0
    for i, raw in enumerate(df["URL"].astype(str)):
        try:
            url = normalize_url(raw)
        except InvalidURLError:
            rejected += 1
            continue
        feats = compute_features(model_input(url, view), tld_table)
        rows.append([feats[name] for name in FEATURE_NAMES])
        keep.append(i)
    kept = df.iloc[keep].reset_index(drop=True)
    X = pd.DataFrame(np.asarray(rows, dtype=float), columns=FEATURE_NAMES)
    y = (kept[LABEL_COLUMN].astype(int) == LABEL_PHISHING).astype(int).to_numpy()
    stats = {"rows_after_url_dedup": int(len(df)), "rejected_by_url_validation": rejected, "rows_used": int(len(kept))}
    return X, y, kept, stats


# ---------------------------------------------------------------------------
# Host-grouped split (final methodology)
#
# The deployed model only sees the host view ("https://www.<host>"), so two
# different URLs on the same host produce the SAME feature vector. A URL-grouped
# split still lets 8.6% of test rows (almost all phishing) share their host --
# and therefore their exact model input -- with a training row. Grouping the
# split by the host view removes that: no model input string appears in more
# than one split. See docs/dataset.md and docs/data/dataset_audit.json.
# ---------------------------------------------------------------------------
SPLIT_FRACTIONS = {"train": 0.8, "validation": 0.1, "test": 0.1}


def load_original_rows():
    """All PhiUSIIL rows: the committed original split files, concatenated (read-only)."""
    frames = [load_split(name, ORIGINAL_SPLIT_DIR) for name in SPLITS]
    return pd.concat(frames, ignore_index=True)


def prepare_rows(df, view=DEFAULT_MODEL_INPUT_VIEW, group_view=None):
    """Deduplicate URLs, drop URLs that fail validation and attach the model-input group key.

    Returns (prepared_df, stats). Duplicate URLs always carry the same label in
    PhiUSIIL (checked here); the first occurrence is kept.
    """
    conflicting = int((df.groupby("URL")[LABEL_COLUMN].nunique() > 1).sum())
    if conflicting:
        raise ValueError(f"{conflicting} URLs have conflicting labels")
    deduped = df.drop_duplicates(subset="URL").reset_index(drop=True)
    urls, groups, keep = [], [], []
    for i, raw in enumerate(deduped["URL"].astype(str)):
        try:
            url = normalize_url(raw)
        except InvalidURLError:
            continue
        keep.append(i)
        urls.append(url)
        groups.append(model_input(url, group_view or view))
    out = deduped.iloc[keep].reset_index(drop=True)
    out["normalized_url"] = urls
    out["group"] = groups
    stats = {
        "input_rows": int(len(df)),
        "duplicate_url_rows_removed": int(len(df) - len(deduped)),
        "rejected_by_url_validation": int(len(deduped) - len(out)),
        "rows_used": int(len(out)),
        "groups": int(out["group"].nunique()),
    }
    return out, stats


def host_grouped_split(prepared, seed=42):
    """Stratified 80/10/10 split in which every group (host view) lands in exactly one split.

    Groups are stratified by their majority label (ties -> phishing). Returns {split: DataFrame}.
    """
    from sklearn.model_selection import train_test_split

    group_label = (
        prepared.assign(_phish=(prepared[LABEL_COLUMN] == LABEL_PHISHING).astype(int))
        .groupby("group")["_phish"].mean().ge(0.5).astype(int)
        .sort_index()  # deterministic order independent of row order
    )
    groups = group_label.index.to_numpy()
    held_out = SPLIT_FRACTIONS["validation"] + SPLIT_FRACTIONS["test"]
    g_train, g_rest, _, y_rest = train_test_split(
        groups, group_label.to_numpy(), test_size=held_out, random_state=seed, stratify=group_label.to_numpy())
    g_val, g_test = train_test_split(
        g_rest, test_size=SPLIT_FRACTIONS["test"] / held_out, random_state=seed, stratify=y_rest)
    assignment = {g: "train" for g in g_train}
    assignment.update({g: "validation" for g in g_val})
    assignment.update({g: "test" for g in g_test})
    split_of = prepared["group"].map(assignment)
    return {name: prepared[split_of == name].reset_index(drop=True) for name in SPLITS}


def featurize_prepared(df, tld_table, view=DEFAULT_MODEL_INPUT_VIEW):
    """Features for rows from prepare_rows() (already validated and deduplicated). Returns (X, y)."""
    rows = []
    for url in df["normalized_url"]:
        feats = compute_features(model_input(url, view), tld_table)
        rows.append([feats[name] for name in FEATURE_NAMES])
    X = pd.DataFrame(np.asarray(rows, dtype=float), columns=FEATURE_NAMES)
    y = (df[LABEL_COLUMN].astype(int) == LABEL_PHISHING).astype(int).to_numpy()
    return X, y


def load_host_grouped_split(seed=42, view="host"):
    """(splits, prepare_stats) grouped by the host view (model v1.1.0/v1.2.0); deterministic for a given seed."""
    prepared, stats = prepare_rows(load_original_rows(), view)
    return host_grouped_split(prepared, seed), stats


def load_registrable_grouped_split(seed=42, view="registrable"):
    """(splits, prepare_stats) grouped by registrable domain (PSL eTLD+1).

    Coarser than host grouping: all hosts under one registrable domain (a.evil.com, b.evil.com)
    land in the same split, so neither the host view nor the registrable view shares a model
    input across splits.
    """
    prepared, stats = prepare_rows(load_original_rows(), view, group_view="registrable")
    return host_grouped_split(prepared, seed), stats
