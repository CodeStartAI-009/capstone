"""End to end: URL -> feature extraction -> exact feature vector -> model -> result.

Also checks that training-time and prediction-time features are identical and
that the saved model/metadata match the reproducible host-grouped split.
"""
import json

import numpy as np
import pandas as pd
import pytest

from ml.dataset import build_tld_table, featurize_prepared, load_registrable_grouped_split
from ml.feature_extractor import extract_features
from ml.feature_schema import FEATURE_COUNT, FEATURE_NAMES, FEATURE_TYPES, LABEL_PHISHING
from ml.predictor import DEFAULT_METADATA_PATH, predict_url
from ml.train_model import url_fingerprint
from ml.url_utils import MAX_URL_LENGTH, InvalidURLError

# Phishing (label 0) URL from the final model's held-out test split.
DATASET_PHISHING_URL = "https://jhjhgfg-3176c.firebaseapp.com/"


@pytest.fixture(scope="module")
def split():
    return load_registrable_grouped_split()  # the split model v2.0.0 was trained and tested on


def run_pipeline(predictor, url):
    """Each stage explicitly, so the test can check what flows between them."""
    extracted = extract_features(url, tld_table=predictor.tld_table, view=predictor.view)
    vector = extracted["vector"]
    X = pd.DataFrame([vector], columns=FEATURE_NAMES)
    p_direct = float(predictor.model.predict_proba(X)[0][list(predictor.model.classes_).index(1)])
    return extracted, vector, p_direct, predictor.predict(url)


CASES = {
    "known safe": "https://www.wikipedia.org",
    "dataset phishing": DATASET_PHISHING_URL,
    "ip address": "http://192.168.10.5:8080/secure/login.php",
    "https": "https://www.python.org/downloads/",
    "subdomains": "https://login.secure.accounts.example-bank.com/",
    "suspicious characters": "http://paypal.com-verify%20account@evil.example/?a=1&b=2&c=%3D",
    "long": "https://" + "a" * 40 + ".example.com/" + "x/" * 400,
}


@pytest.mark.parametrize("name", CASES)
def test_pipeline_stages_agree(real_predictor, name):
    extracted, vector, p_direct, result = run_pipeline(real_predictor, CASES[name])
    assert len(vector) == FEATURE_COUNT and extracted["feature_names"] == FEATURE_NAMES
    for feature, value in zip(FEATURE_NAMES, vector):
        assert isinstance(value, int if FEATURE_TYPES[feature] == "int" else float) and not isinstance(value, bool)
    assert list(result["features"].values()) == vector          # the model saw exactly this vector
    assert result["phishing_probability"] == round(p_direct, 4)  # and produced exactly this score
    assert result["prediction"] in {"Safe", "Suspicious", "Phishing"}
    assert (result["label"] == 0) == (p_direct >= real_predictor.flag_threshold)


def test_expected_outcomes(real_predictor):
    assert real_predictor.predict(CASES["known safe"])["prediction"] == "Safe"
    assert real_predictor.predict(DATASET_PHISHING_URL)["prediction"] == "Phishing"
    ip = real_predictor.predict(CASES["ip address"])
    assert ip["features"]["IsDomainIP"] == 1 and ip["prediction"] != "Safe"


def test_feature_values_for_url_shapes(real_predictor):
    subs = real_predictor.predict(CASES["subdomains"])
    # registrable view: the model sees https://www.example-bank.com; the subdomain is reported separately
    assert subs["model_input"] == "https://www.example-bank.com" and subs["features"]["NoOfSubDomain"] == 1
    assert subs["url_facts"]["subdomain"] == "login.secure.accounts"
    assert any(e.get("check") == "deep_subdomain" for e in subs["explanations"])
    special = real_predictor.predict(CASES["suspicious characters"])
    assert special["url_facts"]["has_userinfo"] and special["model_input"] == "https://www.evil.example"
    long_result = real_predictor.predict(CASES["long"])
    assert long_result["features"]["DomainLength"] == len("www.example.com")
    assert long_result["url_facts"]["subdomain"] == "a" * 40


def test_http_scheme_is_reported_as_observation_not_feature(real_predictor):
    # The host view is always "https://www.<host>", so IsHTTPS is constant for the model;
    # the submitted scheme is reported through url_facts instead.
    r = real_predictor.predict("http://example.com/")
    assert r["url_facts"]["scheme"] == "http" and r["features"]["IsHTTPS"] == 1


@pytest.mark.parametrize("bad", ["", "   ", None, 42, "not a url", "http://", "https://exa mple.com",
                                 "javascript:alert(1)", "ftp://example.com/file", "http://-bad-.com/",
                                 "https://example.com/" + "a" * MAX_URL_LENGTH])
def test_malformed_and_empty_urls_rejected(bad):
    with pytest.raises(InvalidURLError):
        predict_url(bad)


def test_predict_url_interface():
    r = predict_url("wikipedia.org")
    assert r["success"] is True and r["url"] == "https://wikipedia.org"
    for key in ("prediction", "label", "risk_level", "confidence", "phishing_probability", "features",
                "feature_names", "url_facts", "explanations"):
        assert key in r


def test_training_and_prediction_features_are_identical(real_predictor, split):
    splits, _ = split
    sample = splits["test"].sample(500, random_state=0)
    X_train_path, _ = featurize_prepared(sample, real_predictor.tld_table)
    X_predict_path = np.array([extract_features(u, tld_table=real_predictor.tld_table)["vector"]
                               for u in sample["URL"]], dtype=float)
    np.testing.assert_array_equal(X_train_path.to_numpy(), X_predict_path)


def test_saved_tld_table_is_training_split_only(real_predictor, split):
    splits, _ = split
    assert real_predictor.tld_table == build_tld_table(splits["train"])


def test_split_reproduces_metadata_and_has_no_leakage(split):
    splits, prep = split
    meta = json.loads(DEFAULT_METADATA_PATH.read_text(encoding="utf-8"))
    assert meta["dataset"]["preparation"] == prep
    for name, df in splits.items():
        recorded = meta["dataset"]["splits"][name]
        assert url_fingerprint(df) == recorded["url_sha256"]
        assert int((df.label == LABEL_PHISHING).sum()) == recorded["phishing"]
    for key in ("URL", "group"):
        sets = {n: set(df[key]) for n, df in splits.items()}
        assert not sets["train"] & sets["validation"]
        assert not sets["train"] & sets["test"]
        assert not sets["validation"] & sets["test"]


def test_metadata_is_complete():
    meta = json.loads(DEFAULT_METADATA_PATH.read_text(encoding="utf-8"))
    assert meta["feature_names"] == FEATURE_NAMES and meta["feature_count"] == FEATURE_COUNT
    assert meta["feature_order"] == {n: i for i, n in enumerate(FEATURE_NAMES)}
    for key in ("model_name", "model_class", "target_encoding", "trained_at", "random_state", "environment",
                "test_metrics", "validation_metrics", "leakage_handling", "original_model", "dataset"):
        assert meta.get(key) is not None, key
    for metric in ("accuracy", "precision", "recall", "f1", "roc_auc", "confusion_matrix", "classification_report"):
        assert metric in meta["test_metrics"]


# --- v2.0.0: registrable-domain model input (docs/false_positive_investigation.md) -------------------------
@pytest.mark.parametrize("host,expected", [
    ("admob.google.com", ("admob", "google.com")),
    ("news.bbc.co.uk", ("news", "bbc.co.uk")),                          # ICANN multi-label suffix
    ("jhjhgfg-3176c.firebaseapp.com", ("", "jhjhgfg-3176c.firebaseapp.com")),  # PSL private (shared hosting)
    ("x.web.app", ("", "x.web.app")),
    ("login.paypal.com.evil.xyz", ("login.paypal.com", "evil.xyz")),
    ("192.168.1.1", ("", "192.168.1.1")),
    ("localhost", ("", "localhost")),
])
def test_split_registrable(host, expected):
    from ml.url_utils import split_registrable
    assert split_registrable(host) == expected


def test_subdomains_cannot_change_the_prediction(real_predictor):
    """Registrable view: a URL is scored exactly like https://www.<registrable domain>."""
    for url, bare in [("https://admob.google.com/v2/home", "https://www.google.com"),
                      ("https://dash.cloudflare.com/x/r2/overview", "https://cloudflare.com"),
                      ("http://login.paypal.com.evil.xyz/signin", "https://evil.xyz")]:
        a, b = real_predictor.predict(url), real_predictor.predict(bare)
        assert a["model_input"] == b["model_input"] and a["features"] == b["features"]
        assert a["phishing_probability"] == b["phishing_probability"]


def test_shared_hosting_sites_keep_their_own_identity(real_predictor):
    r = real_predictor.predict("https://jhjhgfg-3176c.firebaseapp.com/")
    assert r["model_input"] == "https://www.jhjhgfg-3176c.firebaseapp.com" and r["prediction"] == "Phishing"


def test_subdomain_observations_do_not_change_the_score(real_predictor):
    r = real_predictor.predict("http://login.paypal.com.evil.xyz/signin")
    checks = {e["check"]: e for e in r["explanations"] if e["source"] == "observation"}
    assert "embedded_domain" in checks and "paypal.com" in checks["embedded_domain"]["message"]
    assert checks["subdomain"]["severity"] == "info"
    assert r["phishing_probability"] == real_predictor.predict("https://evil.xyz")["phishing_probability"]


def test_metadata_records_view_decision_and_previous_models():
    meta = json.loads(DEFAULT_METADATA_PATH.read_text(encoding="utf-8"))
    assert meta["model_input_view"] == "registrable" and meta["model_version"] == "2.0.0"
    check = meta["subdomain_false_positive_check"]
    assert check["passes"] is True and check["ratio"] <= check["max_ratio"]
    assert "Public Suffix List" in meta["public_suffix_list"]
    assert {m["model_version"] for m in meta["previous_models"]} == {"1.2.0", "1.1.0"}


@pytest.mark.parametrize("directory,view", [("previous_v1.2.0", "host"), ("baseline_v1.1.0", "host"),
                                            ("alternatives/host_view_v1.3.0", "host")])
def test_preserved_models_still_load(directory, view):
    from ml.predictor import Predictor
    from pathlib import Path
    d = Path(__file__).resolve().parent.parent / "models" / directory
    p = Predictor.from_paths(d / "phishing_model.pkl", d / "model_metadata.json", d / "tld_legitimate_prob.json")
    assert p.view == view and p.predict("https://admob.google.com")["prediction"] in {"Suspicious", "Phishing"}


@pytest.mark.parametrize("host,expected", [("login.paypal.com", "paypal.com"), ("login.secure.accounts", ""),
                                           ("10.0.0.1", ""), ("mail", "")])
def test_registrable_domain_is_empty_without_a_known_suffix(host, expected):
    from ml.url_utils import registrable_domain
    assert registrable_domain(host) == expected
