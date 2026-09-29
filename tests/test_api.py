"""REST API behaviour, error contract and leak checks."""
import copy
import json

import pytest

import ml.predictor
from ml.feature_schema import FEATURE_COUNT, FEATURE_NAMES

LEAK_MARKERS = (b"Traceback", b'File "', b"/Users/", b"site-packages", b".py", b"phishing_model.pkl",
                b"model_metadata.json", b"boom", b"secret")


def assert_error(response, status, code):
    assert response.status_code == status, response.data
    assert response.is_json
    body = response.get_json()
    assert body["success"] is False
    assert set(body["error"]) == {"code", "message"} and body["error"]["code"] == code
    assert isinstance(body["error"]["message"], str) and body["error"]["message"]
    for marker in LEAK_MARKERS:
        assert marker not in response.data, marker
    return body


# 1. health -------------------------------------------------------------------
def test_health(client):
    r = client.get("/api/health")
    assert r.status_code == 200 and r.get_json() == {"status": "ok", "model_loaded": True}


# 2. model info ---------------------------------------------------------------
def test_model_info_uses_real_metadata(client, real_predictor):
    r = client.get("/api/model-info")
    body = r.get_json()
    meta = real_predictor.metadata
    assert r.status_code == 200 and body["success"] is True
    assert body["model"] == meta["model_class"] and body["version"] == meta["model_version"]
    assert body["feature_count"] == FEATURE_COUNT and body["features"] == FEATURE_NAMES
    for k in ("accuracy", "precision", "recall", "f1", "roc_auc"):
        assert body["evaluation"][k] == meta["test_metrics"][k]
    assert body["thresholds"]["flag"] == meta["thresholds"]["flag"]
    assert body["prediction_labels"] == ["Safe", "Suspicious", "Phishing"]
    # legacy fields used by the web UI
    assert body["model_name"] == meta["model_name"] and body["model_version"] == meta["model_version"]
    for hidden in ("legitimate_reference", "candidates", "original_model", "threshold_analysis_validation"):
        assert hidden not in body
    assert b"/Users/" not in r.data and b".pkl" not in r.data


def test_features_endpoint(client):
    body = client.get("/api/features").get_json()
    assert [f["name"] for f in body["features"]] == FEATURE_NAMES
    assert "URLSimilarityIndex" in body["excluded_features"]


# 3. valid URL ----------------------------------------------------------------
def test_predict_valid_url(client, real_predictor):
    r = client.post("/api/predict", json={"url": "https://www.wikipedia.org"})
    body = r.get_json()
    assert r.status_code == 200 and body["success"] is True
    assert body["url"] == "https://www.wikipedia.org"
    assert body["prediction"] == "Safe" and body["risk_level"] == "Low"
    assert body["verdict"] == "Low-risk prediction"
    assert isinstance(body["confidence"], float) and 0.5 <= body["confidence"] <= 1
    assert list(body["features"]) == FEATURE_NAMES
    assert body["explanation"] and all(isinstance(m, str) for m in body["explanation"])
    assert body["explanations"] and body["scanned_at"] and body["history"]["saved"] is True
    # risk-signal wording, grounded in the metadata's measured recall
    recall = real_predictor.metadata["test_metrics"]["recall"]
    assert "risk signal" in body["disclaimer"] and f"{recall:.1%}" in body["disclaimer"]
    assert "does not mean a site is safe" in body["disclaimer"]
    assert "safe" not in body["summary"].lower()


def test_prediction_matches_direct_pipeline(client, real_predictor):
    url = "https://jhjhgfg-3176c.firebaseapp.com/"  # phishing URL from the held-out test split
    body = client.post("/api/predict", json={"url": url}).get_json()
    direct = real_predictor.predict(url)
    for key in ("prediction", "risk_level", "confidence", "phishing_probability", "features"):
        assert body[key] == direct[key]
    assert body["prediction"] == "Phishing" and body["verdict"] == "Phishing-risk prediction (high)"


def test_predict_normalises_url_without_scheme(client):
    body = client.post("/api/predict", json={"url": "Example.com/Login"}).get_json()
    assert body["url"] == "https://example.com/Login"
    assert any(e.get("check") == "scheme" for e in body["explanations"])


# 4-8. input validation ---------------------------------------------------------
def test_missing_url(client):
    assert_error(client.post("/api/predict", json={}), 400, "MISSING_URL")


@pytest.mark.parametrize("value", ["", "   "])
def test_empty_url(client, value):
    assert_error(client.post("/api/predict", json={"url": value}), 400, "MISSING_URL")


@pytest.mark.parametrize("value", [["https://a.com"], 42, {"u": 1}, True])
def test_non_string_url(client, value):
    assert_error(client.post("/api/predict", json={"url": value}), 400, "INVALID_TYPE")


@pytest.mark.parametrize("url", ["http://", "https://exa mple.com", "http://-bad-.com/", "http://a..b.com/",
                                 "https://example.com:99999/", "http://ex\x00ample.com", "not a url"])
def test_malformed_url(client, url):
    assert_error(client.post("/api/predict", json={"url": url}), 400, "INVALID_URL")


@pytest.mark.parametrize("url", ["javascript:alert(1)", "data:text/html,<b>x</b>", "file:///etc/passwd",
                                 "ftp://example.com/x", "mailto:a@b.com", "vbscript:msgbox(1)"])
def test_unsupported_scheme(client, url):
    assert_error(client.post("/api/predict", json={"url": url}), 400, "UNSUPPORTED_SCHEME")


def test_extremely_long_url(client):
    assert_error(client.post("/api/predict", json={"url": "https://example.com/" + "a" * 3000}), 400,
                 "URL_TOO_LONG")


# 9. suspicious URL -------------------------------------------------------------
def test_suspicious_url(client):
    r = client.post("/api/predict", json={"url": "http://paypal-login-secure-verify.account-update.xyz/signin"})
    body = r.get_json()
    assert r.status_code == 200
    assert body["prediction"] in {"Suspicious", "Phishing"} and body["risk_level"] in {"Medium", "High"}
    assert body["verdict"].startswith("Phishing-risk prediction")
    assert any(e["severity"] in ("risk", "caution") for e in body["explanations"])


def test_public_ip_url(client):
    body = client.post("/api/predict", json={"url": "http://45.77.10.3/secure/login.php"}).get_json()
    assert body["features"]["IsDomainIP"] == 1 and body["prediction"] != "Safe"


# 10. malformed JSON / payload ---------------------------------------------------
def test_malformed_json(client):
    assert_error(client.post("/api/predict", data="{not json", content_type="application/json"), 400,
                 "INVALID_JSON")


def test_invalid_utf8_body(client):
    assert_error(client.post("/api/predict", data=b"\xff\xfe", content_type="application/json"), 400,
                 "INVALID_JSON")


def test_json_array_body(client):
    assert_error(client.post("/api/predict", json=["https://a.com"]), 400, "INVALID_JSON")


def test_wrong_content_type(client):
    assert_error(client.post("/api/predict", data="url=https://a.com",
                             content_type="application/x-www-form-urlencoded"), 415, "UNSUPPORTED_MEDIA_TYPE")


def test_manual_feature_values_are_rejected(client):
    body = assert_error(client.post("/api/predict", json={"url": "https://a.com", "features": {"URLLength": 1}}),
                        400, "UNEXPECTED_FIELD")
    assert "features" in body["error"]["message"]


@pytest.mark.parametrize("payload,code", [({"url": "https://a.com", "source": "evil"}, "INVALID_FIELD"),
                                          ({"url": "https://a.com", "record": "no"}, "INVALID_TYPE")])
def test_optional_fields_are_type_checked(client, payload, code):
    assert_error(client.post("/api/predict", json=payload), 400, code)


def test_oversized_body_rejected(client):
    assert_error(client.post("/api/predict", data='{"url": "' + "a" * 20000 + '"}',
                             content_type="application/json"), 413, "PAYLOAD_TOO_LARGE")


def test_method_not_allowed_is_json(client):
    assert_error(client.get("/api/predict"), 405, "METHOD_NOT_ALLOWED")


def test_unknown_api_route_is_json(client):
    assert_error(client.get("/api/nope"), 404, "NOT_FOUND")


# 11. extractor failure ---------------------------------------------------------
def test_extractor_failure_returns_422(client, monkeypatch):
    def broken_extractor(*args, **kwargs):
        raise ZeroDivisionError("secret internal detail at /Users/x/ml/feature_extractor.py")
    monkeypatch.setattr(ml.predictor, "extract_features", broken_extractor)
    assert_error(client.post("/api/predict", json={"url": "https://www.example.com"}), 422,
                 "FEATURE_EXTRACTION_FAILED")


def test_invalid_feature_vector_returns_422(client, monkeypatch):
    real = ml.predictor.extract_features

    def bad_vector(*args, **kwargs):
        out = real(*args, **kwargs)
        out["vector"] = out["vector"][:-1]
        return out
    monkeypatch.setattr(ml.predictor, "extract_features", bad_vector)
    assert_error(client.post("/api/predict", json={"url": "https://www.example.com"}), 422,
                 "FEATURE_EXTRACTION_FAILED")


# 12. model failure -------------------------------------------------------------
class BrokenModel:
    classes_ = [0, 1]

    def predict_proba(self, X):
        raise RuntimeError("boom: secret internal detail in /Users/x/models/phishing_model.pkl")


def test_model_failure_returns_500_without_internals(make_app, real_predictor):
    broken = copy.copy(real_predictor)
    broken.model = BrokenModel()
    client = make_app(predictor=broken).test_client()
    assert_error(client.post("/api/predict", json={"url": "https://www.example.com"}), 500, "PREDICTION_FAILED")


def test_model_not_loaded_returns_503(make_app):
    client = make_app(predictor=None, MODEL_PATH="/nonexistent.pkl").test_client()
    assert client.get("/api/health").get_json()["model_loaded"] is False
    assert_error(client.post("/api/predict", json={"url": "https://example.com"}), 503, "MODEL_UNAVAILABLE")
    assert_error(client.get("/api/model-info"), 503, "MODEL_UNAVAILABLE")


def test_secrets_never_returned(make_app, monkeypatch):
    monkeypatch.setenv("GOOGLE_SAFE_BROWSING_API_KEY", "sk-test-SECRET-123")
    client = make_app().test_client()
    for r in (client.get("/api/model-info"), client.post("/api/predict", json={"url": "https://www.example.com"}),
              client.post("/api/predict", json={"url": "javascript:x"})):
        assert b"sk-test-SECRET-123" not in r.data
        json.loads(r.data)


def test_history_limit_error_uses_error_contract(client):
    assert_error(client.get("/api/history?limit=abc"), 400, "INVALID_PARAMETER")


def test_home_page_renders(client):
    r = client.get("/")
    assert r.status_code == 200 and b"<html" in r.data


def test_pages_render(client):
    for path in ("/", "/dashboard", "/inspect"):
        r = client.get(path)
        assert r.status_code == 200 and b"<html" in r.data


def test_model_is_loaded_once_at_startup_not_per_request(monkeypatch, tmp_path):
    from backend import create_app
    from config import Config
    import ml.predictor as predictor_module
    calls = []
    real = predictor_module.Predictor.from_paths.__func__

    def counting(cls, *args, **kwargs):
        calls.append(1)
        return real(cls, *args, **kwargs)
    monkeypatch.setattr(predictor_module.Predictor, "from_paths", classmethod(counting))
    cfg = type("C", (Config,), {"TESTING": True, "DATABASE_PATH": tmp_path / "h.db", "RATE_LIMIT_PER_MINUTE": 0})
    client = create_app(cfg).test_client()
    for i in range(10):
        assert client.post("/api/predict", json={"url": f"https://www.s{i}.example.com"}).status_code == 200
    client.get("/api/model-info")
    assert len(calls) == 1


def test_app_entry_point_limits_openmp_threads_in_request_threads():
    """app.py sets OMP_NUM_THREADS before scikit-learn loads, so new (request) threads use 1 thread."""
    import os
    import subprocess
    import sys
    code = ("import threading, app; from threadpoolctl import threadpool_info; out = [];"
            "t = threading.Thread(target=lambda: out.extend(p['num_threads'] for p in threadpool_info() "
            "if p['user_api'] == 'openmp')); t.start(); t.join(); print(out)")
    env = {k: v for k, v in os.environ.items() if k not in ("OMP_NUM_THREADS", "ML_THREADS")}
    out = subprocess.run([sys.executable, "-c", code], env=env, capture_output=True, text=True, timeout=120,
                         cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    assert out.returncode == 0, out.stderr
    counts = eval(out.stdout.strip().splitlines()[-1])
    assert counts and set(counts) == {1}
