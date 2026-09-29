"""JSON error responses. Technical details are logged, never returned to clients."""
import logging

from flask import jsonify, request
from werkzeug.exceptions import HTTPException

logger = logging.getLogger(__name__)

FRIENDLY_HTTP_MESSAGES = {
    400: "Bad request",
    404: "Not found",
    405: "Method not allowed",
    413: "Request body too large",
    415: "Request body must be JSON (Content-Type: application/json)",
    429: "Too many requests. Please wait and try again.",
    500: "Internal server error",
}


def json_error(message, status, **extra):
    return jsonify({"success": False, "error": message, **extra}), status


def register_error_handlers(app):
    @app.errorhandler(HTTPException)
    def handle_http_error(exc):
        if request.path.startswith("/api/"):
            return json_error(FRIENDLY_HTTP_MESSAGES.get(exc.code, exc.name), exc.code)
        return exc

    @app.errorhandler(Exception)
    def handle_unexpected_error(exc):
        logger.exception("Unhandled error on %s %s", request.method, request.path)
        if request.path.startswith("/api/"):
            return json_error("Internal server error", 500)
        return "Internal server error", 500
