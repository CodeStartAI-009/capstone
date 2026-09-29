"""GET /api/model-info and GET /api/features"""
from flask import Blueprint, current_app, jsonify

from backend.utils.errors import ApiError
from ml.feature_schema import (EXCLUDED_FEATURES, FEATURE_COUNT, FEATURE_SCHEMA, MODEL_INPUT_VIEWS,
                               SCHEMA_VERSION)
from services.prediction_service import ModelUnavailableError

bp = Blueprint("model", __name__, url_prefix="/api")


@bp.get("/model-info")
def model_info():
    try:
        info = current_app.extensions["prediction_service"].model_info()
    except ModelUnavailableError:
        raise ApiError("MODEL_UNAVAILABLE", "The phishing model is not loaded.", 503) from None
    return jsonify({"success": True, **info})


@bp.get("/features")
def features():
    return jsonify({
        "success": True,
        "schema_version": SCHEMA_VERSION,
        "feature_count": FEATURE_COUNT,
        "features": [{**spec, "range": list(spec["range"])} for spec in FEATURE_SCHEMA],
        "excluded_features": EXCLUDED_FEATURES,
        "model_input_views": list(MODEL_INPUT_VIEWS),
    })
