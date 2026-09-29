"""Train, select and save the URL-only phishing model.

    python -m ml.train_model

Steps:
  1. Load the URL-grouped split (data/clean_split); dedupe URLs within each split.
  2. Build the TLD prior table from the training split and save it.
  3. Recompute the 17 schema features from the URL column (ml/dataset.py),
     using the deployed model input view (host view; see ml/feature_schema.py).
  4. Fit every candidate model on train; score each on validation.
  5. Select a model by the documented criteria (SELECTION_CRITERIA), using
     validation results only. The test split is not used for any decision.
  6. Derive the "Suspicious" threshold from validation scores.
  7. Evaluate the selected model once on test, then save the model,
     metadata and TLD table.
"""
import platform
import time
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import sklearn

from ml.dataset import CLEAN_SPLIT_DIR, ROOT, build_tld_table, featurize, load_split
from ml.feature_schema import (DEFAULT_MODEL_INPUT_VIEW, EXCLUDED_FEATURES, FEATURE_COUNT, FEATURE_NAMES, LABEL_LEGITIMATE,
                               LABEL_PHISHING, SCHEMA_VERSION)
from ml.model_utils import (RANDOM_STATE, binary_metrics, candidate_models, phishing_probability,
                            save_model, write_json)

MODELS_DIR = ROOT / "models"
MODEL_PATH = MODELS_DIR / "phishing_model.pkl"
METADATA_PATH = MODELS_DIR / "model_metadata.json"
TLD_TABLE_PATH = MODELS_DIR / "tld_legitimate_prob.json"
MODEL_VERSION = "1.0.0"

DECISION_THRESHOLD = 0.5
# A flagged URL (P >= DECISION_THRESHOLD) is reported as "Phishing" only where the
# model's validation precision is at least this; below it the flag is "Suspicious".
HIGH_CONFIDENCE_PRECISION = 0.95
F1_TIE_MARGIN = 0.001

SELECTION_CRITERIA = (
    "Highest validation F1 for the phishing class (balances missed phishing against false alarms). "
    f"Models within {F1_TIE_MARGIN} F1 of the best are treated as tied and the tie is broken by higher "
    "validation ROC-AUC, then by faster single-URL inference. Only validation data is used; the test split "
    "is evaluated once, after selection."
)


def single_url_latency_ms(model, X, repeats=200):
    row = X.iloc[[0]]
    model.predict_proba(row)  # warm-up
    start = time.perf_counter()
    for _ in range(repeats):
        model.predict_proba(row)
    return (time.perf_counter() - start) / repeats * 1000


def high_confidence_threshold(p, y, target_precision=HIGH_CONFIDENCE_PRECISION):
    """Lowest t >= DECISION_THRESHOLD with validation precision(P >= t) >= target, else None."""
    for t in np.unique(p[p >= DECISION_THRESHOLD]):
        flagged = p >= t
        if y[flagged].mean() >= target_precision:
            return float(t)
    return None


def legitimate_reference(X_train, y_train):
    """Per-feature percentiles over legitimate training URLs (used by the explanation engine)."""
    legit = X_train[y_train == 0]
    return {
        name: {q: float(np.percentile(legit[name], int(q[1:]))) for q in ("p1", "p5", "p50", "p95", "p99")}
        for name in FEATURE_NAMES
    }


def main():
    print("Loading URL-grouped split from", CLEAN_SPLIT_DIR)
    raw = {name: load_split(name) for name in ("train", "validation", "test")}

    tld_table = build_tld_table(raw["train"])
    write_json(dict(sorted(tld_table.items())), TLD_TABLE_PATH)
    print(f"TLD prior table: {len(tld_table)} TLDs -> {TLD_TABLE_PATH}")

    data, stats = {}, {}
    for name, df in raw.items():
        X, y, _, st = featurize(df, tld_table)
        data[name] = (X, y)
        stats[name] = {**st, "phishing": int(y.sum()), "legitimate": int(len(y) - y.sum())}
        print(f"{name:10s} {st} phishing={int(y.sum())} legitimate={int(len(y) - y.sum())}")

    X_tr, y_tr = data["train"]
    X_va, y_va = data["validation"]
    X_te, y_te = data["test"]

    candidates = {}
    for name, model in candidate_models().items():
        start = time.perf_counter()
        model.fit(X_tr, y_tr)
        fit_s = time.perf_counter() - start
        p_va = phishing_probability(model, X_va)
        candidates[name] = {
            "model": model,
            "validation": binary_metrics(y_va, p_va, DECISION_THRESHOLD),
            "fit_seconds": round(fit_s, 2),
            "single_url_inference_ms": round(single_url_latency_ms(model, X_va), 3),
        }
        m = candidates[name]["validation"]
        print(f"{name:20s} val F1={m['f1']:.5f} AUC={m['roc_auc']:.5f} acc={m['accuracy']:.5f} "
              f"fit={fit_s:.1f}s infer={candidates[name]['single_url_inference_ms']}ms")

    best_f1 = max(c["validation"]["f1"] for c in candidates.values())
    tied = [n for n, c in candidates.items() if best_f1 - c["validation"]["f1"] <= F1_TIE_MARGIN]
    selected = sorted(
        tied,
        key=lambda n: (-candidates[n]["validation"]["roc_auc"], candidates[n]["single_url_inference_ms"]),
    )[0]
    model = candidates[selected]["model"]
    print(f"\nSelected: {selected} (tied set: {tied})")

    p_va = phishing_probability(model, X_va)
    phishing_threshold = high_confidence_threshold(p_va, y_va)
    if phishing_threshold is None:
        print(f"No threshold reaches {HIGH_CONFIDENCE_PRECISION:.0%} validation precision; all flags -> Suspicious")
    else:
        flagged = p_va >= phishing_threshold
        print(f"High-confidence 'Phishing' threshold: {phishing_threshold:.6f} "
              f"(validation precision {y_va[flagged].mean():.4f}; {int(flagged.sum())} validation URLs at or above it)")

    p_te = phishing_probability(model, X_te)
    test_metrics = binary_metrics(y_te, p_te, DECISION_THRESHOLD)
    level_cut = phishing_threshold if phishing_threshold is not None else np.inf
    levels = np.where(p_te < DECISION_THRESHOLD, "Safe", np.where(p_te >= level_cut, "Phishing", "Suspicious"))
    test_metrics["risk_levels_by_true_class"] = {
        cls: {lvl: int(((levels == lvl) & (y_te == code)).sum()) for lvl in ("Safe", "Suspicious", "Phishing")}
        for cls, code in (("phishing", 1), ("legitimate", 0))
    }
    print(f"TEST: {test_metrics}")

    save_model(model, MODEL_PATH)
    metadata = {
        "model_version": MODEL_VERSION,
        "model_name": selected,
        "model_class": type(model).__name__ if not hasattr(model, "steps") else
        " -> ".join(type(s).__name__ for _, s in model.steps),
        "schema_version": SCHEMA_VERSION,
        "model_input_view": DEFAULT_MODEL_INPUT_VIEW,
        "feature_count": FEATURE_COUNT,
        "feature_names": FEATURE_NAMES,
        "excluded_features": EXCLUDED_FEATURES,
        "target_encoding": {
            "model_output": "predict_proba column for class 1 = P(phishing)",
            "dataset_label_phishing": LABEL_PHISHING,
            "dataset_label_legitimate": LABEL_LEGITIMATE,
        },
        "supports_probability": True,
        "thresholds": {
            "flag": DECISION_THRESHOLD,
            "high_confidence_phishing": phishing_threshold,
            "definition": (
                f"P(phishing) < {DECISION_THRESHOLD} -> Safe; otherwise Phishing if P >= high_confidence_phishing "
                f"(lowest threshold with validation precision >= {HIGH_CONFIDENCE_PRECISION:.0%}), else Suspicious. "
                "Binary metrics treat Suspicious and Phishing together as 'flagged'."
            ),
        },
        "selection_criteria": SELECTION_CRITERIA,
        "candidates": {
            n: {k: v for k, v in c.items() if k != "model"} for n, c in candidates.items()
        },
        "test_metrics": test_metrics,
        "dataset": {
            "name": "PhiUSIIL Phishing URL Dataset",
            "split": "data/clean_split (URL-grouped 80/10/10, stratified, seed 42; create_clean_split.py)",
            "feature_source": "recomputed from the URL column by ml.feature_extractor",
            "splits": stats,
            "tld_table_entries": len(tld_table),
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
