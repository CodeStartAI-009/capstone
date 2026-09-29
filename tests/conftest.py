import pytest

from backend import create_app
from config import Config
from ml.predictor import Predictor
from services.threat_intelligence import DisabledThreatIntelligence


@pytest.fixture(scope="session")
def real_predictor():
    return Predictor.from_paths()


@pytest.fixture
def make_app(tmp_path, real_predictor):
    def _make(predictor="real", **overrides):
        attrs = {"TESTING": True, "DATABASE_PATH": tmp_path / "history.db", "RATE_LIMIT_PER_MINUTE": 1000,
                 **overrides}
        cfg = type("TestConfig", (Config,), attrs)
        return create_app(cfg, predictor=real_predictor if predictor == "real" else predictor,
                          threat_intel=DisabledThreatIntelligence())
    return _make


@pytest.fixture
def client(make_app):
    return make_app().test_client()
