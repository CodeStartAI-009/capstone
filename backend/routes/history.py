"""Scan history: GET/DELETE /api/history, GET/DELETE /api/history/<id>, GET /api/stats."""
from flask import Blueprint, current_app, jsonify, request

from backend.utils.errors import ApiError
from database.models import PREDICTIONS
from services.history_service import HistoryUnavailableError

bp = Blueprint("history", __name__, url_prefix="/api")
MAX_SEARCH_LENGTH = 200


def _service():
    return current_app.extensions["history"]


def _int_arg(name, default, minimum, maximum=None):
    raw = request.args.get(name, default)
    try:
        value = int(raw)
    except (TypeError, ValueError):
        raise ApiError("INVALID_PARAMETER", f"'{name}' must be an integer.") from None
    if value < minimum or (maximum is not None and value > maximum):
        bounds = f"between {minimum} and {maximum}" if maximum is not None else f"at least {minimum}"
        raise ApiError("INVALID_PARAMETER", f"'{name}' must be {bounds}.")
    return value


def _scan_id(raw):
    if not raw.isdigit() or len(raw) > 18 or int(raw) < 1:
        raise ApiError("INVALID_ID", "Scan id must be a positive integer.")
    return int(raw)


def _unavailable():
    return ApiError("HISTORY_UNAVAILABLE", "Scan history is temporarily unavailable.", 503)


@bp.get("/history")
def history_list():
    page = _int_arg("page", 1, 1, 1_000_000)
    limit = _int_arg("limit", 20, 1, current_app.config["HISTORY_LIMIT"])
    prediction = request.args.get("prediction") or None
    if prediction is not None and prediction not in PREDICTIONS:
        raise ApiError("INVALID_PARAMETER", f"'prediction' must be one of: {', '.join(PREDICTIONS)}.")
    search = (request.args.get("q") or "").strip() or None
    if search is not None and len(search) > MAX_SEARCH_LENGTH:
        raise ApiError("INVALID_PARAMETER", f"'q' must be at most {MAX_SEARCH_LENGTH} characters.")
    try:
        return jsonify({"success": True, **_service().page(page, limit, prediction, search)})
    except HistoryUnavailableError:
        raise _unavailable() from None


@bp.get("/history/<raw_id>")
def history_get(raw_id):
    scan_id = _scan_id(raw_id)
    try:
        scan = _service().get(scan_id)
    except HistoryUnavailableError:
        raise _unavailable() from None
    if scan is None:
        raise ApiError("SCAN_NOT_FOUND", "No scan with this id.", 404)
    return jsonify({"success": True, "item": scan})


@bp.delete("/history/<raw_id>")
def history_delete(raw_id):
    scan_id = _scan_id(raw_id)
    try:
        deleted = _service().delete(scan_id)
    except HistoryUnavailableError:
        raise _unavailable() from None
    if not deleted:
        raise ApiError("SCAN_NOT_FOUND", "No scan with this id.", 404)
    return jsonify({"success": True, "deleted": 1})


@bp.delete("/history")
def history_clear():
    try:
        deleted = _service().clear()
    except HistoryUnavailableError:
        raise _unavailable() from None
    return jsonify({"success": True, "deleted": deleted})


@bp.get("/stats")
def stats():
    days = _int_arg("days", 30, 1, 365)
    try:
        return jsonify({"success": True, **_service().stats(days)})
    except HistoryUnavailableError:
        raise _unavailable() from None
