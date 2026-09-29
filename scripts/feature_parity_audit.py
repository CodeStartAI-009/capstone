"""Feature parity audit: ml.feature_extractor vs the stored PhiUSIIL values.

For every schema feature, compares compute_features() against the dataset's
stored column on all rows of data/{train,validation,test}.csv, under:

  oracle      URL-level counts computed on URL[:-1] for rows whose stored URLLength
              is len(URL) - 1 (the hidden collection-batch rule); host-level
              features from the full URL. This validates the
              reconstructed *definitions*; it is not available at inference time.
  full URL    features computed on the URL as given, which is what the live
              extractor does.

Also reports how the live normaliser treats the dataset URLs.

usage: python scripts/feature_parity_audit.py [--json out.json]
"""
import argparse
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from ml.dataset import ORIGINAL_SPLIT_DIR, SPLITS, build_tld_table, load_split  # noqa: E402
from ml.feature_extractor import compute_features  # noqa: E402
from ml.feature_schema import FEATURE_NAMES  # noqa: E402
from ml.url_utils import InvalidURLError, normalize_url  # noqa: E402

RATIO_TOLERANCE = 0.0015  # stored ratios are rounded to 3 decimals
EXACT_TOLERANCE = 1e-6


# In the dataset these were computed from the full host even in the truncated batches.
HOST_LEVEL = {"DomainLength", "IsDomainIP", "CharContinuationRate", "TLDLegitimateProb", "TLDLength",
              "NoOfSubDomain", "IsHTTPS"}


def parity(df, urls, table, host_urls=None):
    cand = pd.DataFrame([compute_features(u, table) for u in urls])
    if host_urls is not None:
        host_cand = pd.DataFrame([compute_features(u, table) for u in host_urls])
        for name in HOST_LEVEL:
            cand[name] = host_cand[name]
    out = {}
    for name in FEATURE_NAMES:
        tol = RATIO_TOLERANCE if "Ratio" in name else EXACT_TOLERANCE
        out[name] = float(np.isclose(df[name].astype(float), cand[name].astype(float), atol=tol).mean() * 100)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--json")
    args = ap.parse_args()

    frames = [load_split(s, ORIGINAL_SPLIT_DIR) for s in SPLITS]
    df = pd.concat(frames, ignore_index=True)
    table = build_tld_table(frames[0])  # train split only
    urls = df["URL"].astype(str).tolist()
    offset = (df["URLLength"] - df["URL"].astype(str).str.len()).tolist()

    oracle = parity(df, [u[:-1] if o == -1 else u for u, o in zip(urls, offset)], table, host_urls=urls)
    full = parity(df, urls, table)

    result = pd.DataFrame({"oracle_%": oracle, "full_url_%": full})
    print(f"rows: {len(df):,}")
    print(result.round(4).to_string())

    rejected = changed = 0
    for u in urls:
        try:
            changed += normalize_url(u) != u
        except InvalidURLError:
            rejected += 1
    print(f"\nnormalize_url on dataset URLs: rejected={rejected}, changed={changed}, unchanged={len(urls) - rejected - changed}")
    print("batch offset counts (stored URLLength - len(URL)):", pd.Series(offset).value_counts().to_dict())

    if args.json:
        Path(args.json).write_text(json.dumps({
            "rows": len(df), "oracle": oracle, "full_url": full,
            "normalize": {"rejected": rejected, "changed": changed},
            "offset_counts": {str(k): int(v) for k, v in pd.Series(offset).value_counts().items()},
        }, indent=2))


if __name__ == "__main__":
    main()
