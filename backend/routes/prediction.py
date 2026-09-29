"""POST /api/predict"""
import logging

from flask import Blueprint, current_app, jsonify, request

from backend.utils.errors import json_error
from ml.feature_extractor import FeatureValidationError
from ml.url_utils import InvalidURLError

logger = logging.getLogger(__name__)
bp = Blueprint("prediction", __name__, url_prefix="/api")

ALLOWED_SOURCES = {"web", "extension", "api"}


@bp.post("/predict")
def predict():
    limiter = current_app.extensions["rate_limiter"]
    allowed, retry_after = limiter.check(request.remote_addr or "unknown")
    if not allowed:
        response, status = json_error("Too many requests. Please wait and try again.", 429)
        response.headers["Retry-After"] = str(retry_after)
        return response, status

    if not request.is_json:
        return json_error("Request body must be JSON (Content-Type: application/json)", 415)
    payload = request.get_json(silent=True)
    if payload is None:
        return json_error("Request body is not valid JSON", 400)
    if not isinstance(payload, dict):
        return json_error("Request body must be a JSON object", 400)

    url = payload.get("url")
    if url is None or (isinstance(url, str) and not url.strip()):
        return json_error("Please enter a URL to scan.", 400)
    if not isinstance(url, str):
        return json_error("Field 'url' must be a string", 400)
    if len(url) > current_app.config["MAX_URL_LENGTH"]:
        return json_error(f"URL is longer than {current_app.config['MAX_URL_LENGTH']} characters", 400)

    source = payload.get("source") if payload.get("source") in ALLOWED_SOURCES else "api"
    # Automatic background scans from the extension send record=false so the
    # user's browsing is not written to the history database.
    record = payload.get("record", True) is not False

    predictor = current_app.extensions.get("predictor")
    if predictor is None:
        return json_error("Unable to analyze this URL right now: the model is not loaded.", 503)

    try:
        result = predictor.predict(url)
    except InvalidURLError as exc:
        return json_error(f"Please enter a valid URL ({exc}).", 400)
    except FeatureValidationError:
        logger.exception("Feature vector failed schema validation for input of length %d", len(url))
        return json_error("Unable to analyze this URL right now.", 500)
    except Exception:
        logger.exception("Model failure")
        return json_error("Unable to analyze this URL right now.", 500)

    threat_intel = current_app.extensions.get("threat_intel")
    if threat_intel is not None and threat_intel.enabled:
        result["threat_intelligence"] = threat_intel.lookup(result["url"])

    result["scanned_at"] = None
    history = current_app.extensions.get("history")
    if record and history is not None:
        try:
            saved = history.add(url=url.strip(), normalized_url=result["url"], prediction=result["prediction"],
                                risk_level=result["risk_level"], confidence=result["confidence"], source=source)
            result["scanned_at"] = saved["scanned_at"]
        except Exception:  # history must never break a scan
            logger.exception("Could not save scan to history")

    return jsonify({"success": True, **result})
