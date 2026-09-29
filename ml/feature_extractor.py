"""Automatic URL feature extraction.

The same code path produces features for training (ml/train_model.py computes
them from the dataset's URL column) and for live prediction, so the model never
sees differently-computed values at inference time.

Definitions follow ml/feature_schema.py; see that module for the terms
url/host/body/core.
"""
import json
import math
import re
from functools import lru_cache
from pathlib import Path

from ml.feature_schema import (DEFAULT_MODEL_INPUT_VIEW, FEATURE_COUNT, FEATURE_NAMES, FEATURE_RANGES,
                               FEATURE_TYPES)
from ml.url_utils import has_explicit_scheme, normalize_url

DEFAULT_TLD_TABLE_PATH = Path(__file__).resolve().parent.parent / "models" / "tld_legitimate_prob.json"
UNKNOWN_TLD_PROB = 0.0  # the dataset's own value for TLDs with no legitimate presence

_SCHEME_PREFIX_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")
_IPV4_PATTERN_RE = re.compile(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
_IPV6_LITERAL_RE = re.compile(r"^\[[0-9a-fA-F:.]+\]")
_LETTER_RUN_RE = re.compile(r"[A-Za-z]+")
_DIGIT_RUN_RE = re.compile(r"[0-9]+")
_SYMBOL_RUN_RE = re.compile(r"[^A-Za-z0-9]+")


class FeatureValidationError(ValueError):
    """The extracted vector does not match the schema (a programming error)."""


@lru_cache(maxsize=4)
def load_tld_table(path=DEFAULT_TLD_TABLE_PATH):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _host(url):
    rest = _SCHEME_PREFIX_RE.sub("", url, count=1)
    return re.split(r"[/?#]", rest, maxsplit=1)[0]


def model_input(url, view=DEFAULT_MODEL_INPUT_VIEW):
    """The string the model features are computed from (see feature_schema.MODEL_INPUT_VIEWS)."""
    if view == "full":
        return url
    if view != "host":
        raise ValueError(f"unknown model input view: {view!r}")
    host = _host(url).rpartition("@")[2]
    if host.startswith("www."):
        host = host[4:]
    return f"https://www.{host}"


def _longest(pattern, text):
    return max((len(m) for m in pattern.findall(text)), default=0)


def compute_features(url, tld_table):
    """Compute the schema features for an (already normalised) URL string.

    Returns a dict keyed by feature name. No validation is performed here.
    """
    host = _host(url)
    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    core = host[4:] if host.startswith("www.") else host
    core = core.rsplit(".", 1)[0] if "." in core else core
    body = url.replace("https://", "").replace("http://", "").replace("www.", "")
    n = len(url)

    letters = sum(1 for c in body if c.isascii() and c.isalpha())
    digits = sum(1 for c in body if c.isdigit())
    equals, qmarks, percents = body.count("="), body.count("?"), body.count("%")
    other_special = sum(1 for c in body if not c.isalnum() and c not in "=?%")

    if core:
        continuation = (
            _longest(_LETTER_RUN_RE, core) + _longest(_DIGIT_RUN_RE, core) + _longest(_SYMBOL_RUN_RE, core)
        ) / len(core)
    else:
        continuation = 0.0

    return {
        "URLLength": n,
        "DomainLength": len(host),
        "IsDomainIP": int(bool(_IPV4_PATTERN_RE.search(host) or _IPV6_LITERAL_RE.match(host.split("@")[-1]))),
        "CharContinuationRate": continuation,
        "TLDLegitimateProb": float(tld_table.get(tld.lower(), UNKNOWN_TLD_PROB)),
        "TLDLength": len(tld),
        "NoOfSubDomain": max(host.count(".") - 1, 0),
        "NoOfLettersInURL": letters,
        "LetterRatioInURL": round(letters / n, 3) if n else 0.0,
        "NoOfDegitsInURL": digits,
        "DegitRatioInURL": round(digits / n, 3) if n else 0.0,
        "NoOfEqualsInURL": equals,
        "NoOfQMarkInURL": qmarks,
        "NoOfAmpersandInURL": percents,  # dataset column counts '%' (see feature_schema)
        "NoOfOtherSpecialCharsInURL": other_special,
        "SpacialCharRatioInURL": round((other_special + equals + qmarks + percents) / n, 3) if n else 0.0,
        "IsHTTPS": int("https" in url.lower()),
    }


def validate_vector(vector):
    """Check count, type and range of a feature vector in schema order."""
    if len(vector) != FEATURE_COUNT:
        raise FeatureValidationError(f"expected {FEATURE_COUNT} features, got {len(vector)}")
    for name, value in zip(FEATURE_NAMES, vector):
        expected = FEATURE_TYPES[name]
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise FeatureValidationError(f"{name}: expected a number, got {type(value).__name__}")
        if expected == "int" and not isinstance(value, int):
            raise FeatureValidationError(f"{name}: expected int, got {type(value).__name__}")
        if not math.isfinite(value):
            raise FeatureValidationError(f"{name}: value is not finite")
        low, high = FEATURE_RANGES[name]
        if (low is not None and value < low) or (high is not None and value > high):
            raise FeatureValidationError(f"{name}: value {value} outside range {FEATURE_RANGES[name]}")


def extract_features(raw_url, tld_table=None, view=DEFAULT_MODEL_INPUT_VIEW):
    """Validate/normalise ``raw_url`` and return its model features in schema order.

    Returns:
        {
          "url": normalised URL,
          "scheme_assumed": True if the input had no scheme and https:// was assumed,
          "model_input": the string the features were computed from (see model_input()),
          "feature_names": FEATURE_NAMES,
          "vector": [values in FEATURE_NAMES order],
          "features": {name: value},
        }
    Raises ml.url_utils.InvalidURLError for unusable input.
    """
    url = normalize_url(raw_url)
    table = tld_table if tld_table is not None else load_tld_table()
    source = model_input(url, view)
    features = compute_features(source, table)
    vector = [features[name] for name in FEATURE_NAMES]
    validate_vector(vector)
    return {
        "url": url,
        "scheme_assumed": not has_explicit_scheme(raw_url),
        "model_input": source,
        "feature_names": list(FEATURE_NAMES),
        "vector": vector,
        "features": dict(zip(FEATURE_NAMES, vector)),
    }
