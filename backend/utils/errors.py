"""JSON error responses. Technical details are logged, never returned to clients.

Every API error has the same shape:

    {"success": false, "error": {"code": "INVALID_URL", "message": "The supplied URL is invalid."}}

`code` is stable and meant for programs; `message` is meant for people.
"""
import logging

from flask import jsonify, request
from werkzeug.exceptions import HTTPException

logger = logging.getLogger(__name__)

# Werkzeug/Flask HTTP errors on /api/ routes -> (code, message)
HTTP_ERRORS = {
    400: ("BAD_REQUEST", "The request could not be understood."),
    404: ("NOT_FOUND", "No such API endpoint."),
    405: ("METHOD_NOT_ALLOWED", "This HTTP method is not allowed for this endpoint."),
    413: ("PAYLOAD_TOO_LARGE", "The request body is too large."),
    415: ("UNSUPPORTED_MEDIA_TYPE", "The request body must be JSON (Content-Type: application/json)."),
    429: ("RATE_LIMITED", "Too many requests. Please wait and try again."),
    500: ("INTERNAL_ERROR", "An unexpected error occurred."),
}


class ApiError(Exception):
    """An expected, client-facing error. Raise it anywhere in a request; the handler renders it."""

    def __init__(self, code, message, status=400, headers=None):
        super().__init__(message)
        self.code, self.message, self.status, self.headers = code, message, status, headers or {}


def json_error(code, message, status, headers=None):
    response = jsonify({"success": False, "error": {"code": code, "message": message}})
    response.status_code = status
    for name, value in (headers or {}).items():
        response.headers[name] = value
    return response


def register_error_handlers(app):
    @app.errorhandler(ApiError)
    def handle_api_error(exc):
        return json_error(exc.code, exc.message, exc.status, exc.headers)

    @app.errorhandler(HTTPException)
    def handle_http_error(exc):
        if request.path.startswith("/api/"):
            code, message = HTTP_ERRORS.get(exc.code, ("HTTP_ERROR", exc.name))
            return json_error(code, message, exc.code)
        return exc

    @app.errorhandler(Exception)
    def handle_unexpected_error(exc):
        logger.exception("Unhandled error on %s %s", request.method, request.path)
        if request.path.startswith("/api/"):
            return json_error(*HTTP_ERRORS[500], 500)
        return "Internal server error", 500
