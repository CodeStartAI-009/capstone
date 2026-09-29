"""REST API behaviour and error handling."""
from ml.feature_schema import FEATURE_COUNT, FEATURE_NAMES


def test_health(client):
    r = client.get("/api/health")
    assert r.status_code == 200 and r.get_json() == {"status": "ok", "model_loaded": True}


def test_predict_valid_url(client):
    r = client.post("/api/predict", json={"url": "https://www.example.com"})
    body = r.get_json()
    assert r.status_code == 200 and body["success"] is True
    assert body["url"] == "https://www.example.com"
    assert body["prediction"] in {"Safe", "Suspicious", "Phishing"}
    assert body["risk_level"] in {"Low", "Medium", "High"}
    assert isinstance(body["confidence"], float)
    assert list(body["features"]) == FEATURE_NAMES
    assert body["explanations"] and body["scanned_at"]


def test_predict_normalises_url_without_scheme(client):
    body = client.post("/api/predict", json={"url": "Example.com/Login"}).get_json()
    assert body["url"] == "https://example.com/Login"
    assert any(e.get("check") == "scheme" for e in body["explanations"])


def test_missing_url(client):
    r = client.post("/api/predict", json={})
    assert r.status_code == 400 and r.get_json() == {"success": False, "error": "Please enter a URL to scan."}


def test_empty_url(client):
    assert client.post("/api/predict", json={"url": "   "}).status_code == 400


def test_non_string_url(client):
    r = client.post("/api/predict", json={"url": ["https://a.com"]})
    assert r.status_code == 400 and "string" in r.get_json()["error"]


def test_invalid_url(client):
    r = client.post("/api/predict", json={"url": "javascript:alert(1)"})
    assert r.status_code == 400 and r.get_json()["error"].startswith("Please enter a valid URL")


def test_malformed_json(client):
    r = client.post("/api/predict", data="{not json", content_type="application/json")
    assert r.status_code == 400 and r.get_json()["success"] is False


def test_json_array_body(client):
    assert client.post("/api/predict", json=["https://a.com"]).status_code == 400


def test_wrong_content_type(client):
    r = client.post("/api/predict", data="url=https://a.com", content_type="application/x-www-form-urlencoded")
    assert r.status_code == 415


def test_very_long_url(client):
    r = client.post("/api/predict", json={"url": "https://example.com/" + "a" * 3000})
    assert r.status_code == 400


def test_oversized_body_rejected(client):
    r = client.post("/api/predict", data='{"url": "' + "a" * 20000 + '"}', content_type="application/json")
    assert r.status_code == 413 and r.get_json()["success"] is False


def test_method_not_allowed_is_json(client):
    r = client.get("/api/predict")
    assert r.status_code == 405 and r.get_json()["success"] is False


def test_unknown_api_route_is_json(client):
    r = client.get("/api/nope")
    assert r.status_code == 404 and r.get_json()["success"] is False


def test_model_not_loaded_returns_503(make_app):
    client = make_app(predictor=None, MODEL_PATH="/nonexistent.pkl").test_client()
    assert client.get("/api/health").get_json()["model_loaded"] is False
    r = client.post("/api/predict", json={"url": "https://example.com"})
    assert r.status_code == 503 and r.get_json()["success"] is False


class ExplodingPredictor:
    def predict(self, url):
        raise RuntimeError("boom: secret internal detail")


def test_model_failure_hides_internals(make_app):
    client = make_app(predictor=ExplodingPredictor()).test_client()
    r = client.post("/api/predict", json={"url": "https://example.com"})
    assert r.status_code == 500
    assert r.get_json() == {"success": False, "error": "Unable to analyze this URL right now."}
    assert b"boom" not in r.data and b"Traceback" not in r.data


def test_model_info(client):
    body = client.get("/api/model-info").get_json()
    assert body["success"] and body["feature_count"] == FEATURE_COUNT
    assert body["feature_names"] == FEATURE_NAMES
    assert body["model_input_view"] == "host"
    assert "legitimate_reference" not in body and "candidates" not in body


def test_features_endpoint(client):
    body = client.get("/api/features").get_json()
    assert [f["name"] for f in body["features"]] == FEATURE_NAMES
    assert "URLSimilarityIndex" in body["excluded_features"]


def test_pages_render(client):
    for path in ("/", "/dashboard", "/inspect"):
        r = client.get(path)
        assert r.status_code == 200 and b"<html" in r.data
