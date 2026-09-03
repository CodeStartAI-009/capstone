import json
from pathlib import Path

import joblib
import pandas as pd

from sklearn.compose import ColumnTransformer
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.svm import LinearSVC
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
)
from xgboost import XGBClassifier


BASE = Path(__file__).resolve().parent
DATA = BASE / "data"
MODELS = BASE / "models"
RESULTS = BASE / "results"

MODELS.mkdir(exist_ok=True)
RESULTS.mkdir(exist_ok=True)

RANDOM_STATE = 42
LABEL = "label"


# Only features that can be derived from the URL itself.
URL_FEATURES = [
    "URLLength",
    "DomainLength",
    "IsDomainIP",
    "URLSimilarityIndex",
    "CharContinuationRate",
    "TLDLegitimateProb",
    "URLCharProb",
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
]


def load_split(filename):
    return pd.read_csv(DATA / filename, low_memory=False)


def prepare_xy(df):
    missing = [c for c in URL_FEATURES if c not in df.columns]

    if missing:
        raise ValueError(
            f"Missing URL features: {missing}"
        )

    X = df[URL_FEATURES].copy()
    y = df[LABEL].astype(int)

    return X, y


def make_preprocessor():
    return ColumnTransformer([
        (
            "numeric",
            Pipeline([
                ("imputer", SimpleImputer(strategy="median")),
                ("scaler", StandardScaler()),
            ]),
            URL_FEATURES,
        )
    ])


def make_models():

    return {

        "logistic_regression": Pipeline([
            ("preprocess", make_preprocessor()),
            (
                "model",
                LogisticRegression(
                    max_iter=2000,
                    class_weight="balanced",
                    random_state=RANDOM_STATE,
                ),
            ),
        ]),

        "svm": Pipeline([
            ("preprocess", make_preprocessor()),
            (
                "model",
                LinearSVC(
                    class_weight="balanced",
                    random_state=RANDOM_STATE,
                    max_iter=5000,
                ),
            ),
        ]),

        "random_forest": Pipeline([
            ("preprocess", make_preprocessor()),
            (
                "model",
                RandomForestClassifier(
                    n_estimators=300,
                    class_weight="balanced_subsample",
                    n_jobs=-1,
                    random_state=RANDOM_STATE,
                ),
            ),
        ]),

        "gradient_boosting": Pipeline([
            ("preprocess", make_preprocessor()),
            (
                "model",
                GradientBoostingClassifier(
                    n_estimators=150,
                    learning_rate=0.08,
                    max_depth=3,
                    random_state=RANDOM_STATE,
                ),
            ),
        ]),

        "xgboost": Pipeline([
            ("preprocess", make_preprocessor()),
            (
                "model",
                XGBClassifier(
                    n_estimators=300,
                    max_depth=6,
                    learning_rate=0.08,
                    subsample=0.85,
                    colsample_bytree=0.85,
                    objective="binary:logistic",
                    eval_metric="logloss",
                    tree_method="hist",
                    n_jobs=-1,
                    random_state=RANDOM_STATE,
                ),
            ),
        ]),

        "mlp": Pipeline([
            ("preprocess", make_preprocessor()),
            (
                "model",
                MLPClassifier(
                    hidden_layer_sizes=(128, 64),
                    activation="relu",
                    solver="adam",
                    batch_size=256,
                    learning_rate_init=0.001,
                    early_stopping=True,
                    validation_fraction=0.1,
                    max_iter=50,
                    random_state=RANDOM_STATE,
                    verbose=True,
                ),
            ),
        ]),
    }


def evaluate(model, X, y, split_name, model_name):

    predictions = model.predict(X)

    tn, fp, fn, tp = confusion_matrix(
        y,
        predictions,
        labels=[0, 1]
    ).ravel()

    return {
        "model": model_name,
        "split": split_name,
        "accuracy": accuracy_score(y, predictions),
        "precision": precision_score(
            y,
            predictions,
            zero_division=0
        ),
        "recall": recall_score(
            y,
            predictions,
            zero_division=0
        ),
        "f1": f1_score(
            y,
            predictions,
            zero_division=0
        ),
        "TN": tn,
        "FP": fp,
        "FN": fn,
        "TP": tp,
    }


def main():

    print("=" * 60)
    print("PHISHING URL - URL-ONLY MODEL TRAINING")
    print("=" * 60)

    print("\nLoading datasets...")

    train = load_split("train.csv")
    validation = load_split("validation.csv")
    test = load_split("test.csv")

    X_train, y_train = prepare_xy(train)
    X_val, y_val = prepare_xy(validation)
    X_test, y_test = prepare_xy(test)

    print(f"\nTraining samples:   {len(X_train):,}")
    print(f"Validation samples: {len(X_val):,}")
    print(f"Test samples:       {len(X_test):,}")

    print(f"\nURL features used: {len(URL_FEATURES)}")

    for feature in URL_FEATURES:
        print(f"  - {feature}")

    print("\nCreating models...")

    models = make_models()

    results = []

    for name, model in models.items():

        print("\n" + "=" * 60)
        print(f"TRAINING: {name.upper()}")
        print("=" * 60)

        model.fit(X_train, y_train)

        model_path = MODELS / f"{name}_url_only.joblib"

        joblib.dump(
            model,
            model_path
        )

        print(f"\nSaved model:")
        print(model_path)

        validation_result = evaluate(
            model,
            X_val,
            y_val,
            "validation",
            name,
        )

        test_result = evaluate(
            model,
            X_test,
            y_test,
            "test",
            name,
        )

        results.append(validation_result)
        results.append(test_result)

        print("\nValidation:")
        print(
            f"Accuracy : {validation_result['accuracy']:.6f}"
        )
        print(
            f"Precision: {validation_result['precision']:.6f}"
        )
        print(
            f"Recall   : {validation_result['recall']:.6f}"
        )
        print(
            f"F1       : {validation_result['f1']:.6f}"
        )

        print("\nTest:")
        print(
            f"Accuracy : {test_result['accuracy']:.6f}"
        )
        print(
            f"Precision: {test_result['precision']:.6f}"
        )
        print(
            f"Recall   : {test_result['recall']:.6f}"
        )
        print(
            f"F1       : {test_result['f1']:.6f}"
        )

    results_df = pd.DataFrame(results)

    output_file = RESULTS / "url_only_model_metrics.csv"

    results_df.to_csv(
        output_file,
        index=False
    )

    with open(
        RESULTS / "url_only_features.json",
        "w"
    ) as f:
        json.dump(
            URL_FEATURES,
            f,
            indent=2
        )

    print("\n" + "=" * 60)
    print("TRAINING COMPLETE")
    print("=" * 60)

    print("\nResults:")
    print(output_file)

    print("\nModels:")
    for name in models:
        print(
            f"  {MODELS / (name + '_url_only.joblib')}"
        )


if __name__ == "__main__":
    main()