"""POST /api/predict"""
from flask import Blueprint, current_app, jsonify, request

from backend.utils.errors import ApiError
from backend.utils.validation import parse_predict_payload, validate_url
from ml.feature_extractor import FeatureExtractionError
from ml.url_utils import InvalidURLError
from services.prediction_service import ModelUnavailableError, PredictionFailedError

bp = Blueprint("prediction", __name__, url_prefix="/api")


@bp.post("/predict")
def predict():
    allowed, retry_after = current_app.extensions["rate_limiter"].check(request.remote_addr or "unknown")
    if not allowed:
        raise ApiError("RATE_LIMITED", "Too many requests. Please wait and try again.", 429,
                       headers={"Retry-After": str(retry_after)})

    url, source, record = parse_predict_payload(request)
    validate_url(url, current_app.config["MAX_URL_LENGTH"], current_app.config["ALLOW_PRIVATE_HOSTS"])

    service = current_app.extensions["prediction_service"]
    try:
        result = service.predict(url)
    except ModelUnavailableError:
        raise ApiError("MODEL_UNAVAILABLE", "The phishing model is not loaded, so URLs cannot be analysed "
                                            "right now.", 503) from None
    except InvalidURLError:  # normally caught by validate_url; kept as a safety net
        raise ApiError("INVALID_URL", "The supplied URL is invalid.") from None
    except FeatureExtractionError:
        current_app.logger.exception("Feature extraction failed (input length %d)", len(url))
        raise ApiError("FEATURE_EXTRACTION_FAILED", "Features could not be extracted from this URL, so it "
                                                    "could not be analysed.", 422) from None
    except PredictionFailedError:
        raise ApiError("PREDICTION_FAILED", "The URL could not be analysed because of an internal error.",
                       500) from None

    # A history failure never changes the prediction: the scan is still returned
    # (200) and "history.saved" is false; the cause is logged server-side.
    result["history"] = (current_app.extensions["history"].record(url, result, source) if record
                         else {"saved": False, "reason": "not requested"})
    return jsonify({"success": True, **result})
