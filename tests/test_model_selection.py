"""Threshold helpers and the recorded model-selection decision (validation only)."""
import json

import numpy as np
import pytest

from ml.model_utils import binary_metrics, compute_sample_weight, fit_weighted, threshold_for_max_fpr
from ml.predictor import DEFAULT_METADATA_PATH
from ml.train_model import MAX_VALIDATION_FPR, best_threshold, bootstrap_recall_gain


@pytest.fixture(scope="module")
def scores():
    rng = np.random.default_rng(0)
    y = (rng.random(5000) < 0.4).astype(int)
    p = np.clip(rng.normal(0.35 + 0.3 * y, 0.2), 0, 1).round(2)  # rounded -> many tied scores
    return p, y


@pytest.mark.parametrize("cap", [0.01, 0.05, 0.2])
def test_fpr_threshold_is_lowest_threshold_meeting_the_cap(scores, cap):
    p, y = scores
    t = threshold_for_max_fpr(p, y, cap)
    assert binary_metrics(y, p, t)["false_positive_rate"] <= cap
    lower = p[p < t].max()  # the next lower achievable threshold
    assert binary_metrics(y, p, lower)["false_positive_rate"] > cap


def test_best_threshold_maximises_f1_over_observed_scores(scores):
    p, y = scores
    t = best_threshold(p, y, beta=1)
    best = binary_metrics(y, p, t)["f1"]
    assert all(binary_metrics(y, p, c)["f1"] <= best + 1e-12 for c in np.unique(p))


def test_bootstrap_gain_of_identical_models_is_zero(scores):
    p, y = scores
    g = bootstrap_recall_gain(p, p, y, reps=50)
    assert g["mean"] == 0 and g["ci95"] == [0.0, 0.0]


def test_balanced_weighting_uses_training_labels_only():
    from sklearn.tree import DecisionTreeClassifier
    y = np.array([0, 0, 0, 1])
    X = np.arange(4).reshape(-1, 1)
    model = fit_weighted(DecisionTreeClassifier(random_state=0), X, y, "balanced")
    assert model.tree_.weighted_n_node_samples[0] == pytest.approx(compute_sample_weight("balanced", y).sum())


def test_recorded_decision_is_consistent():
    meta = json.loads(DEFAULT_METADATA_PATH.read_text(encoding="utf-8"))
    selected = meta["model_name"]
    cand = meta["candidates"][selected]
    assert meta["thresholds"]["flag"] == cand["validation_at_fpr_cap"]["threshold"]
    assert meta["validation_metrics"]["false_positive_rate"] <= MAX_VALIDATION_FPR
    assert meta["test_metrics"]["threshold"] == meta["thresholds"]["flag"]
    # a challenger may only replace the incumbent with a significant validation gain
    if cand["recall_gain_vs_incumbent"] is not None:
        assert cand["recall_gain_vs_incumbent"]["ci95"][0] > 0
    assert meta["baseline"]["test_metrics"]["f1"] > 0
