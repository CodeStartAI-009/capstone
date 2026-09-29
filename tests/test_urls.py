"""URL normalisation, plus behaviour of the real model on dataset URLs."""
import pandas as pd
import pytest

from ml.dataset import load_registrable_grouped_split
from ml.url_utils import InvalidURLError, describe_url, normalize_url


@pytest.mark.parametrize("raw,expected", [
    ("example.com", "https://example.com"),
    ("  https://Example.COM/Path?Q=1#Frag  ", "https://example.com/Path?Q=1#Frag"),
    ("HTTP://EXAMPLE.com", "http://example.com"),
    ("example.com:8080/x", "https://example.com:8080/x"),
    ("http://127.0.0.1:5000/", "http://127.0.0.1:5000/"),
    ("http://localhost/", "http://localhost/"),
    ("https://bücher.de/", "https://xn--bcher-kva.de/"),
    ("https://user:pw@Example.com/", "https://user:pw@example.com/"),
    ("https://[2001:DB8::1]:8443/a", "https://[2001:db8::1]:8443/a"),
])
def test_normalisation(raw, expected):
    assert normalize_url(raw) == expected


def test_too_long_url_rejected():
    with pytest.raises(InvalidURLError):
        normalize_url("https://example.com/" + "a" * 3000)


def test_describe_url_facts():
    facts = describe_url("http://user@xn--pypal-4ve.com:8080/login")
    assert facts["has_userinfo"] and facts["is_punycode"] and facts["non_standard_port"]
    assert describe_url("http://10.0.0.1/")["is_private_or_local"]
    assert not describe_url("https://www.example.com/")["is_private_or_local"]


@pytest.fixture(scope="module")
def predictor():
    from ml.predictor import Predictor
    return Predictor.from_paths()


@pytest.fixture(scope="module")
def test_sample():
    df = load_registrable_grouped_split()[0]["test"]  # the deployed model's held-out split
    return pd.concat([df[df.label == 1].sample(150, random_state=1), df[df.label == 0].sample(150, random_state=1)])


def test_model_separates_held_out_dataset_urls(predictor, test_sample):
    """On held-out test URLs the model must do far better than chance.

    Bound is loose on purpose: the documented test ROC-AUC is ~0.90 (docs/model_evaluation.md).
    """
    from sklearn.metrics import roc_auc_score
    probs = [predictor.predict(u)["phishing_probability"] for u in test_sample.URL]
    y = (test_sample.label == 0).astype(int)
    assert roc_auc_score(y, probs) > 0.8


def test_representative_urls(predictor):
    assert predictor.predict("https://www.wikipedia.org")["prediction"] == "Safe"
    assert predictor.predict("https://github.com/pallets/flask")["prediction"] == "Safe"
    assert predictor.predict("http://192.168.10.5:8080/secure/login.php")["prediction"] != "Safe"
    assert predictor.predict("https://paypal-login-secure-verify.account-update.xyz/signin")["prediction"] != "Safe"
