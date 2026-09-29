"""Model factory, metrics and persistence helpers."""
import json
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import GradientBoostingClassifier, HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (accuracy_score, confusion_matrix, f1_score, precision_score,
                             recall_score, roc_auc_score)
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.tree import DecisionTreeClassifier
from sklearn.utils.class_weight import compute_sample_weight

RANDOM_STATE = 42


def candidate_models():
    """Candidate classifiers. All support predict_proba (needed for risk levels)."""
    return {
        "logistic_regression": make_pipeline(
            StandardScaler(), LogisticRegression(max_iter=5000, class_weight="balanced", random_state=RANDOM_STATE)
        ),
        "decision_tree": DecisionTreeClassifier(
            max_depth=12, min_samples_leaf=5, class_weight="balanced", random_state=RANDOM_STATE
        ),
        "random_forest": RandomForestClassifier(
            n_estimators=200, min_samples_leaf=2, class_weight="balanced_subsample", n_jobs=-1,
            random_state=RANDOM_STATE
        ),
        "gradient_boosting": HistGradientBoostingClassifier(
            max_iter=300, learning_rate=0.1, class_weight="balanced", random_state=RANDOM_STATE
        ),
    }


def phishing_probability(model, X):
    """P(phishing) for each row. Models are trained with y=1 meaning phishing."""
    classes = list(model.classes_)
    return model.predict_proba(X)[:, classes.index(1)]


def binary_metrics(y_true, p_phishing, threshold=0.5):
    """Metrics with PHISHING as the positive class (flagged when p >= threshold)."""
    y_true = np.asarray(y_true)
    y_pred = (np.asarray(p_phishing) >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    out = {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
        "roc_auc": None,
        "confusion_matrix": {
            "legitimate_correct_TN": int(tn), "legitimate_flagged_FP": int(fp),
            "phishing_missed_FN": int(fn), "phishing_caught_TP": int(tp),
        },
        "false_positive_rate": float(fp / (fp + tn)) if (fp + tn) else None,
        "n": int(len(y_true)),
    }
    if len(np.unique(y_true)) == 2 and len(np.unique(p_phishing)) > 1:
        out["roc_auc"] = float(roc_auc_score(y_true, p_phishing))
    return out


def save_model(model, path):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, path, compress=3)


def load_model(path):
    return joblib.load(path)


def write_json(obj, path):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps(obj, indent=2, sort_keys=False) + "\n", encoding="utf-8")


# ---------------------------------------------------------------------------
# Model-improvement grid (ml/train_model.py)
#
# Every family is fitted twice on the same host-grouped training split:
#   "none"      no reweighting
#   "balanced"  sample_weight = n / (2 * n_class), passed to fit() for EVERY
#               family, so the weighting mechanism is identical across models.
# No resampling is used: nothing is duplicated or removed, and the validation
# and test sets are never reweighted.
# ---------------------------------------------------------------------------
WEIGHTINGS = ("none", "balanced")


def model_grid():
    """name -> factory for an unfitted model (fresh object per call, seed fixed)."""
    return {
        "logistic_regression": lambda: make_pipeline(
            StandardScaler(), LogisticRegression(max_iter=5000, random_state=RANDOM_STATE)),
        "decision_tree": lambda: DecisionTreeClassifier(
            max_depth=12, min_samples_leaf=5, random_state=RANDOM_STATE),
        "random_forest": lambda: RandomForestClassifier(
            n_estimators=200, min_samples_leaf=2, n_jobs=-1, random_state=RANDOM_STATE),
        "gradient_boosting": lambda: GradientBoostingClassifier(
            n_estimators=200, max_depth=3, learning_rate=0.1, random_state=RANDOM_STATE),
        # Same configuration as the v1.1.0 baseline (default early_stopping="auto").
        "hist_gradient_boosting": lambda: HistGradientBoostingClassifier(
            max_iter=300, learning_rate=0.1, random_state=RANDOM_STATE),
        "hist_gradient_boosting_large": lambda: HistGradientBoostingClassifier(
            max_iter=600, learning_rate=0.05, max_leaf_nodes=63, min_samples_leaf=40, early_stopping=False,
            random_state=RANDOM_STATE),
    }


def fit_weighted(model, X, y, weighting):
    """Fit with optional balanced sample weights (works for plain estimators and pipelines)."""
    if weighting == "none":
        return model.fit(X, y)
    if weighting != "balanced":
        raise ValueError(f"unknown weighting {weighting!r}")
    weights = compute_sample_weight("balanced", y)
    if hasattr(model, "steps"):
        return model.fit(X, y, **{f"{model.steps[-1][0]}__sample_weight": weights})
    return model.fit(X, y, sample_weight=weights)


def threshold_for_max_fpr(p, y, max_fpr):
    """Lowest threshold whose false-positive rate on (p, y) is <= max_fpr (maximises recall under the cap)."""
    legit = np.sort(p[y == 0])[::-1]
    allowed = int(np.floor(max_fpr * len(legit)))  # legitimate rows that may score >= t
    if allowed >= len(legit):
        return 0.0
    # Any t just above the (allowed+1)-th highest legitimate score flags exactly `allowed` of them.
    return float(np.nextafter(legit[allowed], np.inf))


def threshold_table(p, y, thresholds):
    """Metrics at each threshold (for the validation threshold analysis)."""
    rows = []
    for t in thresholds:
        m = binary_metrics(y, p, t)
        rows.append({"threshold": round(float(t), 6), **{k: m[k] for k in ("accuracy", "precision", "recall", "f1",
                                                                            "false_positive_rate")},
                     "f2": fbeta(m["precision"], m["recall"], 2), "confusion_matrix": m["confusion_matrix"]})
    return rows


def fbeta(precision, recall, beta):
    b2 = beta * beta
    return float((1 + b2) * precision * recall / (b2 * precision + recall)) if precision + recall else 0.0
