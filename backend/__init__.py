"""Flask application factory."""
import logging
from pathlib import Path

from flask import Flask, render_template, request

from backend.routes import BLUEPRINTS
from backend.utils.errors import register_error_handlers
from backend.utils.rate_limit import RateLimiter
from backend.utils.security import apply_security_headers, parse_origins
from config import Config
from database import Database, DatabaseError, ScanRepository
from ml.predictor import ModelNotAvailableError, Predictor
from services import threat_intelligence
from services.history_service import HistoryService
from services.prediction_service import PredictionService

logger = logging.getLogger(__name__)
ROOT = Path(__file__).resolve().parent.parent


def create_app(config_object=Config, predictor=None, threat_intel=None):
    app = Flask(__name__, template_folder=str(ROOT / "templates"), static_folder=str(ROOT / "static"))
    app.config.from_object(config_object)
    app.json.sort_keys = False  # keep feature dicts in schema order in API responses

    logging.basicConfig(level=logging.DEBUG if app.config.get("DEBUG") else logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    if predictor is None:
        try:
            predictor = Predictor.from_paths(app.config["MODEL_PATH"], app.config["MODEL_METADATA_PATH"],
                                             app.config["TLD_TABLE_PATH"])
        except ModelNotAvailableError as exc:
            # Keep serving so /api/health and the UI can report the problem.
            logger.error("Model unavailable: %s", exc)
    app.extensions["predictor"] = predictor
    app.extensions["prediction_service"] = PredictionService(
        predictor, threat_intel or threat_intelligence.from_environment())
    database = Database(app.config["DATABASE_PATH"])
    try:
        database.initialize()
    except DatabaseError:
        # Keep serving predictions; history endpoints return 503 and initialisation is retried per call.
        logger.exception("Scan history database unavailable at start-up")
    app.extensions["history"] = HistoryService(ScanRepository(database))
    app.extensions["rate_limiter"] = RateLimiter(app.config["RATE_LIMIT_PER_MINUTE"], 60)
    allowed_origins = parse_origins(app.config.get("CLIENT_ORIGIN"), app.config.get("CORS_ORIGINS"))

    for bp in BLUEPRINTS:
        app.register_blueprint(bp)
    register_error_handlers(app)

    @app.before_request
    def cors_preflight():
        if request.method == "OPTIONS" and request.path.startswith("/api/"):
            return app.response_class(status=204)
        return None

    @app.after_request
    def security_headers(response):
        return apply_security_headers(response, allowed_origins)

    @app.get("/")
    def index():
        return render_template("index.html")

    @app.get("/dashboard")
    def dashboard():
        return render_template("dashboard.html")

    @app.get("/inspect")
    def inspect():
        return render_template("inspect.html")

    return app
