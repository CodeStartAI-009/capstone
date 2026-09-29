"""Predictor: loading checks, input shape, risk mapping, no invented confidence."""
import json

import numpy as np
import pandas as pd
import pytest
from sklearn.svm import LinearSVC

from ml.feature_schema import FEATURE_COUNT, FEATURE_NAMES
from ml.predictor import ModelNotAvailableError, Predictor
from ml.url_utils import InvalidURLError


@pytest.fixture(scope="module")
def predictor():
    return Predictor.from_paths()


def test_saved_model_matches_schema(predictor):
    assert predictor.model.n_features_in_ == FEATURE_COUNT
    assert list(predictor.model.feature_names_in_) == FEATURE_NAMES
    assert predictor.metadata["feature_names"] == FEATURE_NAMES
    assert predictor.supports_probability


def test_valid_url_returns_complete_result(predictor):
    r = predictor.predict("https://www.example.com/login")
    assert r["prediction"] in {"Safe", "Suspicious", "Phishing"}
    assert r["risk_level"] == {"Safe": "Low", "Suspicious": "Medium", "Phishing": "High"}[r["prediction"]]
    assert 0.0 <= r["phishing_probability"] <= 1.0 and 0.5 <= r["confidence"] <= 1.0
    assert r["label"] in (0, 1)
    assert list(r["features"]) == FEATURE_NAMES
    assert r["explanations"] and all("message" in e for e in r["explanations"])


def test_invalid_url_raises(predictor):
    with pytest.raises(InvalidURLError):
        predictor.predict("not a url")


def test_label_follows_dataset_convention(predictor):
    r = predictor.predict("https://www.wikipedia.org")
    assert r["prediction"] == "Safe" and r["label"] == 1  # 1 = legitimate
    r = predictor.predict("http://192.168.10.5:8080/secure/login.php")
    assert r["prediction"] != "Safe" and r["label"] == 0  # 0 = phishing


def test_risk_mapping_thresholds(predictor):
    t = predictor.phishing_threshold
    assert predictor.flag_threshold == 0.5 and t is not None and 0.5 <= t <= 1.0
    assert predictor.classify(0.0) == ("Safe", "Low")
    assert predictor.classify(0.4999) == ("Safe", "Low")
    assert predictor.classify(0.5) == ("Suspicious", "Medium") or t == 0.5
    assert predictor.classify(t) == ("Phishing", "High")
    assert predictor.classify(1.0) == ("Phishing", "High")


def test_confidence_is_probability_of_reported_class(predictor):
    r = predictor.predict("https://www.example.com")
    p = r["phishing_probability"]
    expected = p if p >= 0.5 else 1 - p
    assert r["confidence"] == pytest.approx(expected, abs=1e-4)


def _toy_training_data():
    rng = np.random.default_rng(0)
    X = pd.DataFrame(rng.random((40, FEATURE_COUNT)), columns=FEATURE_NAMES)
    y = np.array([0, 1] * 20)
    return X, y


def test_model_without_predict_proba_reports_null_confidence(predictor):
    X, y = _toy_training_data()
    svm = LinearSVC().fit(X, y)
    assert not hasattr(svm, "predict_proba")
    p = Predictor(svm, predictor.metadata, predictor.tld_table)
    r = p.predict("https://www.example.com")
    assert r["confidence"] is None and r["phishing_probability"] is None
    assert r["prediction"] in {"Safe", "Phishing"}


def test_rejects_model_with_wrong_feature_count(predictor):
    from sklearn.tree import DecisionTreeClassifier
    X, y = _toy_training_data()
    bad = DecisionTreeClassifier().fit(X.iloc[:, :5], y)
    with pytest.raises(ModelNotAvailableError):
        Predictor(bad, predictor.metadata, predictor.tld_table)


def test_rejects_model_with_different_feature_order(predictor):
    from sklearn.tree import DecisionTreeClassifier
    X, y = _toy_training_data()
    bad = DecisionTreeClassifier().fit(X[list(reversed(FEATURE_NAMES))], y)
    with pytest.raises(ModelNotAvailableError):
        Predictor(bad, predictor.metadata, predictor.tld_table)


def test_rejects_metadata_for_other_schema(predictor):
    meta = json.loads(json.dumps(predictor.metadata))
    meta["feature_names"] = FEATURE_NAMES[:-1]
    with pytest.raises(ModelNotAvailableError):
        Predictor(predictor.model, meta, predictor.tld_table)


def test_missing_artefacts_raise_clean_error(tmp_path):
    with pytest.raises(ModelNotAvailableError):
        Predictor.from_paths(model_path=tmp_path / "missing.pkl")
