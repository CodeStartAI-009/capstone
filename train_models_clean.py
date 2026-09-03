import json
from pathlib import Path

import joblib
import numpy as np
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


# ============================================================
# PATHS
# ============================================================

BASE = Path(__file__).resolve().parent

DATA = BASE / "data" / "clean_split"
MODELS = BASE / "models" / "clean"
RESULTS = BASE / "results"

MODELS.mkdir(parents=True, exist_ok=True)
RESULTS.mkdir(parents=True, exist_ok=True)

RANDOM_STATE = 42
LABEL = "label"


# ============================================================
# COLUMNS
# ============================================================

# Raw text/identifier columns are excluded.
#
# URL itself will be handled separately by DistilBERT.
#
# These traditional ML models use engineered numeric URL/page
# features.

EXCLUDE = {
    "label",
    "URL",
    "Domain",
    "TLD",
    "Title",
    "FILENAME",
}


# ============================================================
# LOAD DATA
# ============================================================

def load_split(filename):
    path = DATA / filename
    print(f"Loading: {path}")
    return pd.read_csv(path, low_memory=False)


# ============================================================
# PREPARE FEATURES
# ============================================================

def prepare_xy(df):
    feature_cols = [
        column
        for column in df.columns
        if (
            column not in EXCLUDE
            and pd.api.types.is_numeric_dtype(df[column])
        )
    ]

    X = df[feature_cols].copy()
    y = df[LABEL].astype(int)

    return X, y, feature_cols


# ============================================================
# PREPROCESSOR
# ============================================================

def make_preprocessor(feature_cols):

    return ColumnTransformer(
        transformers=[
            (
                "numeric",
                Pipeline([
                    (
                        "imputer",
                        SimpleImputer(strategy="median")
                    ),
                    (
                        "scaler",
                        StandardScaler()
                    ),
                ]),
                feature_cols,
            )
        ],
        remainder="drop",
    )


# ============================================================
# MODELS
# ============================================================

def make_models(feature_cols):

    return {

        # ----------------------------------------------------
        # LOGISTIC REGRESSION
        # ----------------------------------------------------

        "logistic_regression":

            Pipeline([
                (
                    "preprocess",
                    make_preprocessor(feature_cols)
                ),

                (
                    "model",
                    LogisticRegression(
                        max_iter=2000,
                        class_weight="balanced",
                        random_state=RANDOM_STATE,
                    )
                ),
            ]),


        # ----------------------------------------------------
        # SUPPORT VECTOR MACHINE
        # ----------------------------------------------------

        "svm":

            Pipeline([
                (
                    "preprocess",
                    make_preprocessor(feature_cols)
                ),

                (
                    "model",
                    LinearSVC(
                        class_weight="balanced",
                        max_iter=5000,
                        random_state=RANDOM_STATE,
                    )
                ),
            ]),


        # ----------------------------------------------------
        # RANDOM FOREST
        # ----------------------------------------------------

        "random_forest":

            Pipeline([
                (
                    "preprocess",
                    make_preprocessor(feature_cols)
                ),

                (
                    "model",
                    RandomForestClassifier(
                        n_estimators=300,
                        max_depth=None,
                        min_samples_leaf=1,
                        class_weight="balanced_subsample",
                        n_jobs=-1,
                        random_state=RANDOM_STATE,
                    )
                ),
            ]),


        # ----------------------------------------------------
        # GRADIENT BOOSTING
        # ----------------------------------------------------

        "gradient_boosting":

            Pipeline([
                (
                    "preprocess",
                    make_preprocessor(feature_cols)
                ),

                (
                    "model",
                    GradientBoostingClassifier(
                        n_estimators=150,
                        learning_rate=0.08,
                        max_depth=3,
                        random_state=RANDOM_STATE,
                    )
                ),
            ]),


        # ----------------------------------------------------
        # XGBOOST
        # ----------------------------------------------------

        "xgboost":

            Pipeline([
                (
                    "preprocess",
                    make_preprocessor(feature_cols)
                ),

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
                    )
                ),
            ]),


        # ----------------------------------------------------
        # MLP NEURAL NETWORK
        # ----------------------------------------------------

        "mlp":

            Pipeline([
                (
                    "preprocess",
                    make_preprocessor(feature_cols)
                ),

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
                    )
                ),
            ]),
    }


# ============================================================
# EVALUATION
# ============================================================

def evaluate(model, X, y, split_name, model_name):

    predictions = model.predict(X)

    tn, fp, fn, tp = confusion_matrix(
        y,
        predictions
    ).ravel()

    metrics = {
        "model": model_name,
        "split": split_name,

        "accuracy":
            accuracy_score(y, predictions),

        "precision":
            precision_score(
                y,
                predictions,
                zero_division=0
            ),

        "recall":
            recall_score(
                y,
                predictions,
                zero_division=0
            ),

        "f1":
            f1_score(
                y,
                predictions,
                zero_division=0
            ),

        "TN": int(tn),
        "FP": int(fp),
        "FN": int(fn),
        "TP": int(tp),
    }

    return metrics


# ============================================================
# MAIN
# ============================================================

def main():

    print("=" * 70)
    print("LEAKAGE-FREE PHISHING URL MODEL TRAINING")
    print("=" * 70)

    # --------------------------------------------------------
    # LOAD
    # --------------------------------------------------------

    train = load_split("train.csv")
    validation = load_split("validation.csv")
    test = load_split("test.csv")

    # --------------------------------------------------------
    # PREPARE
    # --------------------------------------------------------

    X_train, y_train, feature_cols = prepare_xy(train)

    X_val, y_val, _ = prepare_xy(validation)

    X_test, y_test, _ = prepare_xy(test)

    print()
    print(f"Training rows    : {len(X_train):,}")
    print(f"Validation rows  : {len(X_val):,}")
    print(f"Test rows        : {len(X_test):,}")
    print(f"Numeric features : {len(feature_cols)}")

    print()
    print("Features:")
    print(feature_cols)

    print()
    print("Training labels:")
    print(y_train.value_counts().to_dict())

    # --------------------------------------------------------
    # MODELS
    # --------------------------------------------------------

    models = make_models(feature_cols)

    all_metrics = []

    # --------------------------------------------------------
    # TRAIN
    # --------------------------------------------------------

    for name, model in models.items():

        print()
        print("=" * 70)
        print(f"TRAINING: {name.upper()}")
        print("=" * 70)

        model.fit(
            X_train,
            y_train
        )

        # ----------------------------------------------------
        # SAVE MODEL
        # ----------------------------------------------------

        model_path = MODELS / f"{name}.joblib"

        joblib.dump(
            model,
            model_path
        )

        print(f"Model saved: {model_path}")

        # ----------------------------------------------------
        # VALIDATION
        # ----------------------------------------------------

        validation_metrics = evaluate(
            model,
            X_val,
            y_val,
            "validation",
            name
        )

        # ----------------------------------------------------
        # TEST
        # ----------------------------------------------------

        test_metrics = evaluate(
            model,
            X_test,
            y_test,
            "test",
            name
        )

        all_metrics.append(validation_metrics)
        all_metrics.append(test_metrics)

        print()
        print("Validation:")
        print(json.dumps(
            validation_metrics,
            indent=2
        ))

        print()
        print("Test:")
        print(json.dumps(
            test_metrics,
            indent=2
        ))

    # --------------------------------------------------------
    # SAVE METRICS
    # --------------------------------------------------------

    metrics_df = pd.DataFrame(
        all_metrics
    )

    metrics_path = (
        RESULTS /
        "clean_model_metrics.csv"
    )

    metrics_df.to_csv(
        metrics_path,
        index=False
    )

    # --------------------------------------------------------
    # SAVE FEATURE LIST
    # --------------------------------------------------------

    feature_path = (
        RESULTS /
        "clean_feature_columns.json"
    )

    with open(
        feature_path,
        "w"
    ) as f:

        json.dump(
            feature_cols,
            f,
            indent=2
        )

    # --------------------------------------------------------
    # SUMMARY
    # --------------------------------------------------------

    print()
    print("=" * 70)
    print("TRAINING COMPLETE")
    print("=" * 70)

    print()
    print(f"Models saved to:")
    print(MODELS)

    print()
    print(f"Metrics saved to:")
    print(metrics_path)

    print()
    print("Final test results:")

    test_results = metrics_df[
        metrics_df["split"] == "test"
    ].copy()

    test_results = test_results.sort_values(
        "f1",
        ascending=False
    )

    print(
        test_results[
            [
                "model",
                "accuracy",
                "precision",
                "recall",
                "f1",
                "TN",
                "FP",
                "FN",
                "TP",
            ]
        ].to_string(index=False)
    )


if __name__ == "__main__":
    main()