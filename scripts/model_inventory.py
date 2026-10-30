"""Model inventory: re-score every saved model artifact on its recorded test split. Read-only.

    python scripts/model_inventory.py

Writes docs/data/model_inventory.json. Nothing is trained, and no file in models/ or data/ is written.

  versioned models   v2.0.0 (deployed, models/), v1.3.0 (models/alternatives/host_view_v1.3.0/),
                     v1.2.0 (models/previous_v1.2.0/), v1.1.0 (models/baseline_v1.1.0/): the 17-feature
                     URL models. Each is re-scored on the split recorded in its metadata, at its recorded
                     threshold, and compared with the metadata's test_metrics.
  legacy models      the research-script artifacts in models/*.joblib and models/clean/*.joblib. They use 22
                     or 50 STORED dataset columns (including the leaky URLSimilarityIndex and page-HTML
                     columns), so they cannot score a live URL and are not used by the application. Scored
                     on the CSV split their script used (data/test.csv or data/clean_split/test.csv).

Archived TLD tables: models/previous_v1.2.0/ and models/alternatives/host_view_v1.3.0/ hold copies of the
TLD table that are byte-identical to models/baseline_v1.1.0/tld_legitimate_prob.json and
models/tld_legitimate_prob.json respectively (same MD5 in git), so those two files are used here.
Single-row timings are measured in this process with the library's default thread settings, not under
the API's ML_THREADS=1, so they are indicative only (see docs/testing.md for API latency).
"""
import json
import sys
import time
import warnings
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import confusion_matrix, roc_auc_score

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from ml.dataset import featurize_prepared, load_host_grouped_split, load_registrable_grouped_split  # noqa: E402
from ml.feature_extractor import load_tld_table  # noqa: E402
from ml.model_utils import binary_metrics, phishing_probability  # noqa: E402

OUTPUT = ROOT / "docs" / "data" / "model_inventory.json"
warnings.filterwarnings("ignore")
out = {}

def rnd(m):
    return {k: (round(v, 4) if isinstance(v, float) else v) for k, v in m.items()}

reg, _ = load_registrable_grouped_split()
host, _ = load_host_grouped_split()
cur_tld = load_tld_table(Path(ROOT / "models/tld_legitimate_prob.json"))
old_tld = load_tld_table(Path(ROOT / "models/baseline_v1.1.0/tld_legitimate_prob.json"))  # byte-identical to HEAD copy of previous_v1.2.0's
for name, mdir, split, view, tld in [
    ("v2.0.0", "models", reg, "registrable", cur_tld),
    ("v1.3.0", "models/alternatives/host_view_v1.3.0", reg, "host", cur_tld),
    ("v1.2.0", "models/previous_v1.2.0", host, "host", old_tld),
    ("v1.1.0", "models/baseline_v1.1.0", host, "host", old_tld)]:
    meta = json.loads((ROOT / mdir / "model_metadata.json").read_text())
    model = joblib.load(ROOT / mdir / "phishing_model.pkl")
    X, y = featurize_prepared(split["test"], tld, view)
    p = phishing_probability(model, X)
    t = meta["test_metrics"]["threshold"] if "threshold" in meta["test_metrics"] else meta["thresholds"]["flag"]
    m = binary_metrics(y, p, t)
    rec = meta["test_metrics"]
    same = all(abs(m[k] - rec[k]) < 1e-9 for k in ("accuracy", "precision", "recall", "f1", "roc_auc")) and m["confusion_matrix"] == rec["confusion_matrix"]
    t0 = time.perf_counter(); [model.predict_proba(X.iloc[[i]]) for i in range(200)]; ms = (time.perf_counter() - t0) / 200 * 1000
    out[name] = {"threshold": t, "measured": rnd({k: m[k] for k in ("accuracy","precision","recall","f1","roc_auc","false_positive_rate","n")}),
                 "confusion_matrix": m["confusion_matrix"], "matches_metadata_exactly": same, "single_row_predict_proba_ms_indicative": round(ms, 3), "metadata_dataset_split": meta["dataset"]["split"], "model_input_view": view}
    print(name, out[name])

def legacy(path, test_csv):
    try:
        model = joblib.load(ROOT / path)
    except Exception as e:
        return {"loads": False, "error": f"{type(e).__name__}: {e}"}
    df = pd.read_csv(ROOT / test_csv, low_memory=False)
    cols = list(model.feature_names_in_)
    X, y_phish = df[cols], (df["label"].astype(int) == 0).astype(int).to_numpy()
    pred_phish = (np.asarray(model.predict(X)).astype(int) == 0).astype(int)
    final = model.steps[-1][1] if hasattr(model, "steps") else model
    if hasattr(model, "predict_proba"):
        score = model.predict_proba(X)[:, list(final.classes_).index(0)]
    else:
        score = -model.decision_function(X)
    tn, fp, fn, tp = confusion_matrix(y_phish, pred_phish, labels=[0, 1]).ravel()
    return rnd({"loads": True, "features": len(cols), "uses_URLSimilarityIndex": "URLSimilarityIndex" in cols, "test_csv": test_csv,
            "n": int(len(y_phish)), "accuracy": float((tp + tn) / len(y_phish)), "precision": float(tp / (tp + fp)) if tp + fp else 0.0,
            "recall": float(tp / (tp + fn)), "f1": float(2 * tp / (2 * tp + fp + fn)), "roc_auc": float(roc_auc_score(y_phish, score)),
            "false_positive_rate": float(fp / (fp + tn)), "TN": int(tn), "FP": int(fp), "FN": int(fn), "TP": int(tp)})

L = {}
for f in ["logistic_regression", "svm", "random_forest", "gradient_boosting", "mlp", "xgboost"]:
    L[f"models/{f}.joblib"] = legacy(f"models/{f}.joblib", "data/test.csv")
    L[f"models/{f}_url_only.joblib"] = legacy(f"models/{f}_url_only.joblib", "data/test.csv")
    L[f"models/clean/{f}.joblib"] = legacy(f"models/clean/{f}.joblib", "data/clean_split/test.csv")
for f in ["ablation_url_only", "ablation_url_plus_html"]:
    L[f"models/{f}.joblib"] = legacy(f"models/{f}.joblib", "data/clean_split/test.csv")
for k, v in L.items(): print(k, v)
out["legacy"] = L
OUTPUT.write_text(json.dumps(out, indent=1) + "\n", encoding="utf-8")
print("wrote", OUTPUT.relative_to(ROOT))
