"""Prediction engine: URL -> validated features -> model -> risk level -> explanations.

    from ml.predictor import predict_url
    predict_url("https://example.com")
"""
import json
import logging
import time
from functools import lru_cache
from pathlib import Path

import pandas as pd

from ml.feature_extractor import FeatureExtractionError, extract_features, load_tld_table, validate_vector
from ml.feature_schema import FEATURE_COUNT, FEATURE_NAMES, SCHEMA_VERSION
from ml.model_utils import load_model
from ml.url_utils import InvalidURLError, describe_url
from services.explanation_engine import explain

logger = logging.getLogger(__name__)

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_MODEL_PATH = ROOT / "models" / "phishing_model.pkl"
DEFAULT_METADATA_PATH = ROOT / "models" / "model_metadata.json"
DEFAULT_TLD_TABLE_PATH = ROOT / "models" / "tld_legitimate_prob.json"

RISK_LEVELS = {"Safe": "Low", "Suspicious": "Medium", "Phishing": "High"}


class ModelNotAvailableError(RuntimeError):
    """The model, its metadata or the TLD table is missing or inconsistent with the schema."""


class Predictor:
    def __init__(self, model, metadata, tld_table):
        if metadata.get("feature_names") != FEATURE_NAMES:
            raise ModelNotAvailableError(
                "Model metadata feature list does not match ml/feature_schema.py; retrain with "
                "`python -m ml.train_model`."
            )
        n_in = getattr(model, "n_features_in_", FEATURE_COUNT)
        if n_in != FEATURE_COUNT:
            raise ModelNotAvailableError(f"Model expects {n_in} features, schema defines {FEATURE_COUNT}")
        model_features = list(getattr(model, "feature_names_in_", FEATURE_NAMES))
        if model_features != FEATURE_NAMES:
            raise ModelNotAvailableError("Model was fitted with a different feature order than the schema")
        if hasattr(model, "n_jobs"):
            # One URL per request: thread start-up would dominate (measured ~13.5 ms vs ~4.2 ms per URL
            # for the random forest; identical probabilities).
            model.n_jobs = 1
        self.model = model
        self.metadata = metadata
        self.tld_table = tld_table
        self.view = metadata.get("model_input_view", "host")
        self.supports_probability = hasattr(model, "predict_proba")
        thresholds = metadata.get("thresholds", {})
        self.flag_threshold = thresholds.get("flag", 0.5)
        self.phishing_threshold = thresholds.get("high_confidence_phishing")

    @classmethod
    def from_paths(cls, model_path=DEFAULT_MODEL_PATH, metadata_path=DEFAULT_METADATA_PATH,
                   tld_table_path=DEFAULT_TLD_TABLE_PATH):
        for path in (model_path, metadata_path, tld_table_path):
            if not Path(path).exists():
                raise ModelNotAvailableError(f"Missing {path}; run `python -m ml.train_model`")
        try:
            model = load_model(model_path)
            metadata = json.loads(Path(metadata_path).read_text(encoding="utf-8"))
            tld_table = load_tld_table(Path(tld_table_path))
        except Exception as exc:  # corrupted/incompatible pickle, bad JSON
            raise ModelNotAvailableError(f"Could not load model artefacts: {exc}") from exc
        return cls(model, metadata, tld_table)

    def classify(self, p_phishing):
        """Map P(phishing) to (prediction, risk level). See metadata['thresholds']['definition']."""
        if p_phishing < self.flag_threshold:
            prediction = "Safe"
        elif self.phishing_threshold is not None and p_phishing >= self.phishing_threshold:
            prediction = "Phishing"
        else:
            prediction = "Suspicious"
        return prediction, RISK_LEVELS[prediction]

    def predict(self, raw_url):
        """Raises ml.url_utils.InvalidURLError for invalid input and
        ml.feature_extractor.FeatureExtractionError if features cannot be computed."""
        start = time.perf_counter()
        try:
            extracted = extract_features(raw_url, tld_table=self.tld_table, view=self.view)
            validate_vector(extracted["vector"])
        except (InvalidURLError, FeatureExtractionError):
            raise
        except Exception as exc:  # any other failure inside extraction is still an extraction failure
            raise FeatureExtractionError("feature extraction failed") from exc
        X = pd.DataFrame([extracted["vector"]], columns=FEATURE_NAMES)
        t_features = time.perf_counter()

        if self.supports_probability:
            classes = list(self.model.classes_)
            p_phishing = float(self.model.predict_proba(X)[0][classes.index(1)])
            prediction, risk_level = self.classify(p_phishing)
            confidence = p_phishing if p_phishing >= self.flag_threshold else 1.0 - p_phishing
            model_flag = int(p_phishing >= self.flag_threshold)
        else:  # never invent a confidence value
            model_flag = int(self.model.predict(X)[0])
            p_phishing = confidence = None
            prediction = "Phishing" if model_flag == 1 else "Safe"
            risk_level = RISK_LEVELS[prediction]
        t_model = time.perf_counter()

        url_facts = describe_url(extracted["url"])
        explanations = explain(extracted["features"], url_facts, self.metadata.get("legitimate_reference", {}),
                               scheme_assumed=extracted["scheme_assumed"], view=self.view)
        return {
            "url": extracted["url"],
            "prediction": prediction,
            # Dataset label convention: 0 = phishing, 1 = legitimate.
            "label": 0 if model_flag == 1 else 1,
            "risk_level": risk_level,
            "confidence": round(confidence, 4) if confidence is not None else None,
            "phishing_probability": round(p_phishing, 4) if p_phishing is not None else None,
            "model_input": extracted["model_input"],
            "feature_names": extracted["feature_names"],
            "features": extracted["features"],
            "url_facts": url_facts,
            "explanations": explanations,
            "timing_ms": {
                "feature_extraction": round((t_features - start) * 1000, 3),
                "model_inference": round((t_model - t_features) * 1000, 3),
                "total": round((time.perf_counter() - start) * 1000, 3),
            },
        }

    def public_info(self):
        m = self.metadata
        return {
            "model_name": m.get("model_name"),
            "model_class": m.get("model_class"),
            "model_version": m.get("model_version"),
            "schema_version": SCHEMA_VERSION,
            "model_input_view": self.view,
            "feature_count": FEATURE_COUNT,
            "feature_names": FEATURE_NAMES,
            "supports_probability": self.supports_probability,
            "thresholds": m.get("thresholds"),
            "trained_at": m.get("trained_at"),
            "sklearn_version": m.get("environment", {}).get("scikit_learn"),
            "test_metrics": m.get("test_metrics"),
            "dataset": {k: m.get("dataset", {}).get(k) for k in ("name", "split", "feature_source")},
        }


@lru_cache(maxsize=1)
def default_predictor():
    return Predictor.from_paths()


def predict_url(url):
    """Convenience wrapper around the default predictor (loads artefacts once)."""
    return {"success": True, **default_predictor().predict(url)}
