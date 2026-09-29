"""Model factory, metrics and persistence helpers."""
import json
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (accuracy_score, confusion_matrix, f1_score, precision_score,
                             recall_score, roc_auc_score)
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.tree import DecisionTreeClassifier

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
    """Metrics with PHISHING as the positive class."""
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
