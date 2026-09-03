import json
from pathlib import Path

import joblib
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
)
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline


BASE = Path(__file__).resolve().parent

DATA = BASE / "data" / "clean_split"
MODELS = BASE / "models"
RESULTS = BASE / "results"

RESULTS.mkdir(exist_ok=True)

LABEL = "label"

# ------------------------------------------------------------
# Load data
# ------------------------------------------------------------

train = pd.read_csv(DATA / "train.csv", low_memory=False)
validation = pd.read_csv(DATA / "validation.csv", low_memory=False)
test = pd.read_csv(DATA / "test.csv", low_memory=False)

print("=" * 70)
print("FEATURE ABLATION EXPERIMENT")
print("=" * 70)

print("Train:", len(train))
print("Validation:", len(validation))
print("Test:", len(test))


# ------------------------------------------------------------
# Feature groups
# ------------------------------------------------------------

URL_FEATURES = [
    "URLLength",
    "DomainLength",
    "IsDomainIP",
    "TLDLength",
    "NoOfSubDomain",
    "HasObfuscation",
    "NoOfObfuscatedChar",
    "ObfuscationRatio",
    "NoOfLettersInURL",
    "LetterRatioInURL",
    "NoOfDegitsInURL",
    "DegitRatioInURL",
    "NoOfEqualsInURL",
    "NoOfQMarkInURL",
    "NoOfAmpersandInURL",
    "NoOfOtherSpecialCharsInURL",
    "SpacialCharRatioInURL",
    "IsHTTPS",
    "URLSimilarityIndex",
    "CharContinuationRate",
    "TLDLegitimateProb",
    "URLCharProb",
]

HTML_FEATURES = [
    "LineOfCode",
    "LargestLineLength",
    "HasTitle",
    "DomainTitleMatchScore",
    "URLTitleMatchScore",
    "HasFavicon",
    "Robots",
    "IsResponsive",
    "NoOfURLRedirect",
    "NoOfSelfRedirect",
    "HasDescription",
    "NoOfPopup",
    "NoOfiFrame",
    "HasExternalFormSubmit",
    "HasSocialNet",
    "HasSubmitButton",
    "HasHiddenFields",
    "HasPasswordField",
    "Bank",
    "Pay",
    "Crypto",
    "HasCopyrightInfo",
    "NoOfImage",
    "NoOfCSS",
    "NoOfJS",
    "NoOfSelfRef",
    "NoOfEmptyRef",
    "NoOfExternalRef",
]


# ------------------------------------------------------------
# Verify features
# ------------------------------------------------------------

ALL_NUMERIC = [
    c for c in train.columns
    if c not in {
        "label",
        "URL",
        "Domain",
        "TLD",
        "Title",
        "FILENAME",
    }
    and pd.api.types.is_numeric_dtype(train[c])
]

print("\nTotal numeric features:", len(ALL_NUMERIC))

print("\nURL features:", len(URL_FEATURES))
print("HTML features:", len(HTML_FEATURES))


# ------------------------------------------------------------
# Train/evaluate
# ------------------------------------------------------------

def run_experiment(name, features):

    print("\n" + "=" * 70)
    print(name)
    print("=" * 70)

    missing = [f for f in features if f not in train.columns]

    if missing:
        raise ValueError(
            f"Missing features for {name}: {missing}"
        )

    X_train = train[features]
    y_train = train[LABEL].astype(int)

    X_val = validation[features]
    y_val = validation[LABEL].astype(int)

    X_test = test[features]
    y_test = test[LABEL].astype(int)

    model = Pipeline([
        (
            "imputer",
            SimpleImputer(strategy="median")
        ),
        (
            "model",
            RandomForestClassifier(
                n_estimators=300,
                class_weight="balanced_subsample",
                n_jobs=-1,
                random_state=42
            )
        )
    ])

    print("Training...")
    model.fit(X_train, y_train)

    results = []

    for split_name, X, y in [
        ("validation", X_val, y_val),
        ("test", X_test, y_test),
    ]:

        pred = model.predict(X)

        tn, fp, fn, tp = confusion_matrix(
            y,
            pred
        ).ravel()

        metrics = {
            "experiment": name,
            "split": split_name,
            "accuracy": accuracy_score(y, pred),
            "precision": precision_score(
                y,
                pred,
                zero_division=0
            ),
            "recall": recall_score(
                y,
                pred,
                zero_division=0
            ),
            "f1": f1_score(
                y,
                pred,
                zero_division=0
            ),
            "TN": tn,
            "FP": fp,
            "FN": fn,
            "TP": tp,
            "feature_count": len(features),
        }

        results.append(metrics)

        print(
            f"{split_name}: "
            f"accuracy={metrics['accuracy']:.6f}, "
            f"precision={metrics['precision']:.6f}, "
            f"recall={metrics['recall']:.6f}, "
            f"f1={metrics['f1']:.6f}"
        )

    joblib.dump(
        model,
        MODELS / f"ablation_{name.lower().replace(' ', '_')}.joblib"
    )

    return results


# ------------------------------------------------------------
# Experiments
# ------------------------------------------------------------

all_results = []

all_results.extend(
    run_experiment(
        "URL_ONLY",
        URL_FEATURES
    )
)

all_results.extend(
    run_experiment(
        "HTML_ONLY",
        HTML_FEATURES
    )
)

all_results.extend(
    run_experiment(
        "URL_PLUS_HTML",
        URL_FEATURES + HTML_FEATURES
    )
)


# ------------------------------------------------------------
# Save
# ------------------------------------------------------------

results_df = pd.DataFrame(all_results)

output = RESULTS / "feature_ablation_metrics.csv"

results_df.to_csv(
    output,
    index=False
)

print("\n" + "=" * 70)
print("COMPLETE")
print("=" * 70)

print(results_df.to_string(index=False))

print("\nSaved:")
print(output)