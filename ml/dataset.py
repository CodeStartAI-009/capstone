"""Dataset loading and feature-matrix construction shared by training and evaluation.

Methodology (leakage-controlled):
  * Split: data/clean_split/, created by create_clean_split.py. It is an
    80/10/10 stratified split grouped by URL (seed 42), so no URL appears
    in more than one split. The original data/*.csv files are never modified.
  * Within each split, duplicate URLs are collapsed to a single row.
  * Features are recomputed from the URL column with ml.feature_extractor,
    using the same normalisation as the live API, instead of the stored
    columns. The stored URL-level counts contain a collection-batch artefact
    (for 79% of rows they were computed on the URL minus its final
    character), so they cannot be reproduced at inference time.
  * Features are computed from the model input view (ml.feature_schema,
    DEFAULT_MODEL_INPUT_VIEW = "host"), exactly as at inference time.
  * The TLD prior table is built from the training split only.
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
