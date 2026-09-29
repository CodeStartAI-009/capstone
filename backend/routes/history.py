"""GET/DELETE /api/history and GET /api/stats (dashboard)."""
from flask import Blueprint, current_app, jsonify, request

from backend.utils.errors import json_error

bp = Blueprint("history", __name__, url_prefix="/api")


@bp.get("/history")
def history_list():
    max_limit = current_app.config["HISTORY_LIMIT"]
    try:
        limit = int(request.args.get("limit", 20))
    except ValueError:
        return json_error("'limit' must be an integer", 400)
    limit = max(1, min(limit, max_limit))
    return jsonify({"success": True, "scans": current_app.extensions["history"].recent(limit)})


@bp.delete("/history")
def history_clear():
    deleted = current_app.extensions["history"].clear()
    return jsonify({"success": True, "deleted": deleted})


@bp.get("/stats")
def stats():
    return jsonify({"success": True, **current_app.extensions["history"].stats()})
