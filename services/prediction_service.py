"""Prediction service: the only place the API talks to the ML pipeline.

    URL -> ml.predictor.Predictor (validation, feature extraction, model, risk
    level, feature-based explanations) -> API result with risk-signal wording

No feature extraction or model logic lives here; it is all in ml/. This layer
only adds the client-facing wording, which is derived from the model output and
the model metadata (never invented), and optional threat intelligence.
"""
import logging
from datetime import datetime, timezone

from ml.feature_extractor import FeatureExtractionError
from ml.url_utils import InvalidURLError

logger = logging.getLogger(__name__)

# Human wording for the project's prediction labels (Safe / Suspicious / Phishing).
# The model has imperfect recall, so "Safe" is presented as a low-risk prediction, never as a guarantee.
VERDICTS = {
    "Safe": "Low-risk prediction",
    "Suspicious": "Phishing-risk prediction (moderate)",
    "Phishing": "Phishing-risk prediction (high)",
}


class ModelUnavailableError(RuntimeError):
    """No model is loaded."""


class PredictionFailedError(RuntimeError):
    """The model failed on a valid feature vector."""


class PredictionService:
    def __init__(self, predictor, threat_intel=None):
        self.predictor = predictor
        self.threat_intel = threat_intel

    @property
    def available(self):
        return self.predictor is not None

    # ------------------------------------------------------------------ predict
    def predict(self, url):
        """Score one URL.

        Raises: ModelUnavailableError, InvalidURLError, FeatureExtractionError, PredictionFailedError.
        """
        if self.predictor is None:
            raise ModelUnavailableError("model not loaded")
        try:
            result = self.predictor.predict(url)
        except (InvalidURLError, FeatureExtractionError):
            raise
        except Exception as exc:
            logger.exception("Model failure")
            raise PredictionFailedError("prediction failed") from exc

        result["scanned_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        result["model_version"] = self._metadata().get("model_version")
        result.update(self._risk_signal(result))
        if self.threat_intel is not None and self.threat_intel.enabled:
            result["threat_intelligence"] = self.threat_intel.lookup(result["url"])
        return result

    def _risk_signal(self, result):
        prediction = result["prediction"]
        p = result.get("phishing_probability")
        thresholds = self._metadata().get("thresholds", {})
        flag, high = thresholds.get("flag"), thresholds.get("high_confidence_phishing")
        if p is None or flag is None:
            summary = f"{VERDICTS[prediction]} from the model."
        elif prediction == "Safe":
            summary = (f"{VERDICTS[prediction]}: the model's phishing score ({p:.2f}) is below its decision "
                       f"threshold ({flag:.2f}). The assessed domain does not show the characteristics the "
                       "model associates with phishing.")
        elif prediction == "Suspicious":
            summary = (f"{VERDICTS[prediction]}: the model's phishing score ({p:.2f}) is above its decision "
                       f"threshold ({flag:.2f}) but below its high-confidence level ({high:.2f}). The assessed "
                       "domain has characteristics associated with higher phishing risk.")
        else:
            summary = (f"{VERDICTS[prediction]}: the model's phishing score ({p:.2f}) is at or above its "
                       f"high-confidence level ({high:.2f}). The assessed domain has "
                       "characteristics strongly associated with phishing in the training data.")
        return {
            "verdict": VERDICTS[prediction],
            "summary": summary,
            "explanation": [item["message"] for item in sorted(
                result.get("explanations", []), key=lambda i: ("risk", "caution", "info").index(i["severity"]))],
            "disclaimer": self.disclaimer(),
        }

    # --------------------------------------------------------------- metadata
    def _metadata(self):
        return getattr(self.predictor, "metadata", None) or {}

    def disclaimer(self):
        test = self._metadata().get("test_metrics", {})
        recall, fpr = test.get("recall"), test.get("false_positive_rate")
        part = ("the site's registrable domain name" if self._metadata().get("model_input_view") == "registrable"
                else "the URL's host name")
        text = f"This is a machine-learning risk signal computed from {part} only; the page itself is not visited or checked."
        if recall is not None and fpr is not None:
            text += (f" On held-out test data the model detected {recall:.1%} of phishing URLs (missing "
                     f"{1 - recall:.1%}) and flagged {fpr:.1%} of legitimate URLs, so a low-risk prediction does "
                     "not mean a site is safe.")
        return text

    def model_info(self):
        """Safe, client-facing model metadata (no file paths, training internals or per-row data)."""
        if self.predictor is None:
            raise ModelUnavailableError("model not loaded")
        info = self.predictor.public_info()
        meta = self._metadata()
        test = meta.get("test_metrics", {})
        dataset = meta.get("dataset", {})
        return {
            "model": info.get("model_class"),
            "version": info.get("model_version"),
            "feature_count": info.get("feature_count"),
            "features": info.get("feature_names"),
            "prediction_labels": list(VERDICTS),
            "verdicts": dict(VERDICTS),
            "risk_levels": {"Safe": "Low", "Suspicious": "Medium", "Phishing": "High"},
            "thresholds": {k: meta.get("thresholds", {}).get(k) for k in ("flag", "high_confidence_phishing")},
            "evaluation": {
                "split": "held-out test split (host-grouped, never used for training or tuning)",
                "rows": test.get("n"),
                "threshold": test.get("threshold"),
                **{k: test.get(k) for k in ("accuracy", "precision", "recall", "f1", "roc_auc",
                                            "false_positive_rate", "confusion_matrix")},
            },
            "training_data": {"name": dataset.get("name"), "split": dataset.get("split"),
                              "class_distribution": dataset.get("class_distribution")},
            "disclaimer": self.disclaimer(),
            # Fields kept for existing clients (web UI).
            "model_name": info.get("model_name"),
            "model_class": info.get("model_class"),
            "model_version": info.get("model_version"),
            "feature_names": info.get("feature_names"),
            "schema_version": info.get("schema_version"),
            "model_input_view": info.get("model_input_view"),
            "supports_probability": info.get("supports_probability"),
            "trained_at": info.get("trained_at"),
            "sklearn_version": info.get("sklearn_version"),
        }
