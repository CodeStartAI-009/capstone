from pathlib import Path

import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
)


BASE = Path(__file__).resolve().parent

DATA = BASE / "data" / "clean_split"
RESULTS = BASE / "results"

train = pd.read_csv(DATA / "train.csv", low_memory=False)
validation = pd.read_csv(DATA / "validation.csv", low_memory=False)
test = pd.read_csv(DATA / "test.csv", low_memory=False)

LABEL = "label"

EXCLUDE = {
    "label",
    "URL",
    "Domain",
    "TLD",
    "Title",
    "FILENAME",
}

FEATURES = [
    c for c in train.columns
    if c not in EXCLUDE
    and pd.api.types.is_numeric_dtype(train[c])
]


TOP_FEATURES = [
    "URLSimilarityIndex",
    "NoOfExternalRef",
    "LineOfCode",
    "NoOfImage",
    "NoOfSelfRef",
    "NoOfJS",
    "HasSocialNet",
    "HasCopyrightInfo",
    "HasDescription",
    "NoOfCSS",
]


def evaluate(name, features):

    X_train = train[features]
    y_train = train[LABEL].astype(int)

    X_val = validation[features]
    y_val = validation[LABEL].astype(int)

    X_test = test[features]
    y_test = test[LABEL].astype(int)

    model = Pipeline([
        ("imputer", SimpleImputer(strategy="median")),
        (
            "model",
            RandomForestClassifier(
                n_estimators=300,
                class_weight="balanced_subsample",
                n_jobs=-1,
                random_state=42,
            ),
        ),
    ])

    print("\n" + "=" * 70)
    print(name)
    print("=" * 70)

    print("Features:", len(features))

    model.fit(X_train, y_train)

    results = []

    for split, X, y in [
        ("validation", X_val, y_val),
        ("test", X_test, y_test),
    ]:

        pred = model.predict(X)

        tn, fp, fn, tp = confusion_matrix(
            y,
            pred
        ).ravel()

        row = {
            "experiment": name,
            "split": split,
            "features": len(features),
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
        }

        results.append(row)

        print(
            f"{split}: "
            f"accuracy={row['accuracy']:.6f}, "
            f"precision={row['precision']:.6f}, "
            f"recall={row['recall']:.6f}, "
            f"f1={row['f1']:.6f}, "
            f"FP={fp}, FN={fn}"
        )

    return results


all_results = []


# ------------------------------------------------------------
# Baseline
# ------------------------------------------------------------

all_results.extend(
    evaluate(
        "ALL_FEATURES",
        FEATURES
    )
)


# ------------------------------------------------------------
# Remove each important feature individually
# ------------------------------------------------------------

for feature in TOP_FEATURES:

    remaining = [
        f for f in FEATURES
        if f != feature
    ]

    all_results.extend(
        evaluate(
            f"WITHOUT_{feature}",
            remaining
        )
    )


# ------------------------------------------------------------
# Remove top 5
# ------------------------------------------------------------

top5_removed = [
    f for f in FEATURES
    if f not in TOP_FEATURES[:5]
]

all_results.extend(
    evaluate(
        "WITHOUT_TOP_5",
        top5_removed
    )
)


# ------------------------------------------------------------
# Remove top 10
# ------------------------------------------------------------

top10_removed = [
    f for f in FEATURES
    if f not in TOP_FEATURES
]

all_results.extend(
    evaluate(
        "WITHOUT_TOP_10",
        top10_removed
    )
)


# ------------------------------------------------------------
# Save
# ------------------------------------------------------------

df = pd.DataFrame(all_results)

output = RESULTS / "top_feature_ablation_metrics.csv"

df.to_csv(
    output,
    index=False
)

print("\n" + "=" * 70)
print("FEATURE REMOVAL EXPERIMENT COMPLETE")
print("=" * 70)

print(df.to_string(index=False))

print("\nSaved:")
print(output)