"""Single source of truth for the model's input features.

Training (ml/train_model.py), evaluation (ml/evaluate_model.py), extraction
(ml/feature_extractor.py), prediction (ml/predictor.py), the API and the tests
all take the feature order from FEATURE_NAMES below. Do not restate the order
anywhere else.

The definitions were reverse-engineered from the stored PhiUSIIL values and
checked against all 235,795 rows by scripts/feature_parity_audit.py
(results in docs/model_evaluation.md).

Terms used in the definitions:
    url    the normalised URL string
    host   text between "scheme://" and the first "/", "?" or "#"
           (includes any userinfo and port, as in the dataset)
    body   url with every "https://", "http://" and "www." removed
    core   host without a leading "www." and without its final ".label"
    n      len(url)
"""

SCHEMA_VERSION = "phiusiil-url-v1"

# Which string the model features are computed from (see docs/model_evaluation.md):
#   "host"  canonical "https://www.<host>" built from the URL's host (userinfo and a
#           leading "www." removed). Deployed default. Every legitimate URL in
#           PhiUSIIL is a bare https://www.<host> homepage, so with the full URL a
#           model learns "has a path / no www / http => phishing" and flags
#           essentially all real-world deep links. The host view removes that
#           shortcut and makes the model judge the host name itself.
#   "full"  the whole normalised URL (evaluated as an experiment only).
MODEL_INPUT_VIEWS = ("host", "full")
DEFAULT_MODEL_INPUT_VIEW = "host"

# Dataset label convention (PhiUSIIL): 0 = phishing, 1 = legitimate.
LABEL_COLUMN = "label"
LABEL_PHISHING = 0
LABEL_LEGITIMATE = 1
LABEL_NAMES = {LABEL_PHISHING: "phishing", LABEL_LEGITIMATE: "legitimate"}

FEATURE_SCHEMA = [
    {"name": "URLLength", "type": "int", "range": (1, None),
     "description": "Number of characters in the URL (n)."},
    {"name": "DomainLength", "type": "int", "range": (1, None),
     "description": "Number of characters in the host, including any port."},
    {"name": "IsDomainIP", "type": "int", "range": (0, 1),
     "description": "1 if the host contains a dotted IPv4 address or is an IP literal."},
    {"name": "CharContinuationRate", "type": "float", "range": (0.0, 1.0),
     "description": "(longest letter run + longest digit run + longest symbol run) / len(core)."},
    {"name": "TLDLegitimateProb", "type": "float", "range": (0.0, 1.0),
     "description": "Per-TLD legitimacy prior from the PhiUSIIL table; 0.0 for TLDs not in the table."},
    {"name": "TLDLength", "type": "int", "range": (0, None),
     "description": "Length of the last dot-separated label of the host."},
    {"name": "NoOfSubDomain", "type": "int", "range": (0, None),
     "description": "Number of dots in the host minus one (never below zero)."},
    {"name": "NoOfLettersInURL", "type": "int", "range": (0, None),
     "description": "ASCII letters in body."},
    {"name": "LetterRatioInURL", "type": "float", "range": (0.0, 1.0),
     "description": "NoOfLettersInURL / n, rounded to 3 decimals."},
    {"name": "NoOfDegitsInURL", "type": "int", "range": (0, None),
     "description": "Digits in body."},
    {"name": "DegitRatioInURL", "type": "float", "range": (0.0, 1.0),
     "description": "NoOfDegitsInURL / n, rounded to 3 decimals."},
    {"name": "NoOfEqualsInURL", "type": "int", "range": (0, None),
     "description": "'=' characters in body."},
    {"name": "NoOfQMarkInURL", "type": "int", "range": (0, None),
     "description": "'?' characters in body."},
    # The name is kept for compatibility with the dataset, but the stored values
    # count '%' characters (100% parity), not '&'.
    {"name": "NoOfAmpersandInURL", "type": "int", "range": (0, None),
     "description": "'%' characters in body (the dataset column is misnamed; it does not count '&')."},
    {"name": "NoOfOtherSpecialCharsInURL", "type": "int", "range": (0, None),
     "description": "Non-alphanumeric characters in body other than '=', '?' and '%'."},
    {"name": "SpacialCharRatioInURL", "type": "float", "range": (0.0, 1.0),
     "description": "(other special chars + '=' + '?' + '%') / n, rounded to 3 decimals."},
    {"name": "IsHTTPS", "type": "int", "range": (0, 1),
     "description": "1 if 'https' occurs anywhere in the URL."},
]

FEATURE_ORDER = tuple(spec["name"] for spec in FEATURE_SCHEMA)
FEATURE_NAMES = list(FEATURE_ORDER)
FEATURE_COUNT = len(FEATURE_NAMES)
FEATURE_TYPES = {spec["name"]: spec["type"] for spec in FEATURE_SCHEMA}
FEATURE_RANGES = {spec["name"]: spec["range"] for spec in FEATURE_SCHEMA}
FEATURE_DESCRIPTIONS = {spec["name"]: spec["description"] for spec in FEATURE_SCHEMA}

# Features of the original 22-feature URL model that are deliberately not used.
EXCLUDED_FEATURES = {
    "URLSimilarityIndex": (
        "Label leakage: similarity to the dataset authors' legitimate-URL list, which is where the "
        "legitimate samples came from (value 100.0 for 100% of legitimate rows). Cannot be computed "
        "without that list."
    ),
    "URLCharProb": (
        "Requires the authors' external character-probability corpus; the best reconstruction "
        "reached 0.22% exact parity."
    ),
    "HasObfuscation": (
        "Original rule not recoverable (99.79% parity, below the 99.9% bar): the original tool "
        "ignores some %XX codes. Percent-encoding is still captured by NoOfAmpersandInURL."
    ),
    "NoOfObfuscatedChar": "Same reason as HasObfuscation (99.79% parity).",
    "ObfuscationRatio": "Derived from NoOfObfuscatedChar; excluded with it.",
}

assert len(set(FEATURE_NAMES)) == FEATURE_COUNT, "duplicate feature name in schema"
