"""Configuration from environment variables with safe defaults. No secrets live in code."""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent


def _env_bool(name, default=False):
    value = os.environ.get(name)
    return default if value is None else value.strip().lower() in {"1", "true", "yes", "on"}


def _env_path(name, default):
    value = os.environ.get(name)
    if not value:
        return default
    path = Path(value)
    return path if path.is_absolute() else BASE_DIR / path


class Config:
    DEBUG = _env_bool("FLASK_DEBUG", False)
    API_HOST = os.environ.get("API_HOST", "127.0.0.1")
    API_PORT = int(os.environ.get("API_PORT", "5000"))

    MODEL_PATH = _env_path("MODEL_PATH", BASE_DIR / "models" / "phishing_model.pkl")
    MODEL_METADATA_PATH = _env_path("MODEL_METADATA_PATH", BASE_DIR / "models" / "model_metadata.json")
    TLD_TABLE_PATH = _env_path("TLD_TABLE_PATH", BASE_DIR / "models" / "tld_legitimate_prob.json")
    DATABASE_PATH = _env_path("DATABASE_PATH", BASE_DIR / "instance" / "scan_history.db")

    MAX_CONTENT_LENGTH = int(os.environ.get("MAX_CONTENT_LENGTH", 16 * 1024))  # bytes per request
    MAX_URL_LENGTH = int(os.environ.get("MAX_URL_LENGTH", "2048"))
    HISTORY_LIMIT = int(os.environ.get("HISTORY_LIMIT", "100"))
    RATE_LIMIT_PER_MINUTE = int(os.environ.get("RATE_LIMIT_PER_MINUTE", "60"))  # 0 disables

    # Extra origins allowed to call the API from a browser (comma-separated).
    # The bundled web UI is same-origin and the extension uses host_permissions,
    # so neither needs an entry here.
    CORS_ORIGINS = os.environ.get("CORS_ORIGINS", "")
