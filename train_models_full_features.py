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
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report
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

# Text/identifier columns are intentionally excluded from the six
# traditional ML models. URL text will be used later by DistilBERT.
EXCLUDE = {"label", "URL", "Domain", "TLD", "Title", "FILENAME"}

def load_split(name):
    return pd.read_csv(DATA / name, low_memory=False)

def prepare_xy(df):
    feature_cols = [
        c for c in df.columns
        if c not in EXCLUDE and pd.api.types.is_numeric_dtype(df[c])
    ]
    X = df[feature_cols].copy()
    y = df[LABEL].astype(int)
    return X, y, feature_cols

def make_preprocessor(feature_cols):
    return ColumnTransformer([
        ("numeric", Pipeline([
            ("imputer", SimpleImputer(strategy="median")),
            ("scaler", StandardScaler())
        ]), feature_cols)
    ], remainder="drop")

def make_models(feature_cols):
    prep = make_preprocessor(feature_cols)

    return {
        "logistic_regression": Pipeline([
            ("preprocess", prep),
            ("model", LogisticRegression(
                max_iter=2000, class_weight="balanced",
                random_state=RANDOM_STATE
            ))
        ]),

        # LinearSVC is used because kernel SVC is generally impractical
        # for ~188k training rows. It is still a Support Vector Machine.
        "svm": Pipeline([
            ("preprocess", prep),
            ("model", LinearSVC(
                class_weight="balanced",
                random_state=RANDOM_STATE,
                max_iter=5000
            ))
        ]),

        "random_forest": Pipeline([
            ("preprocess", make_preprocessor(feature_cols)),
            ("model", RandomForestClassifier(
                n_estimators=300,
                max_depth=None,
                min_samples_leaf=1,
                class_weight="balanced_subsample",
                n_jobs=-1,
                random_state=RANDOM_STATE
            ))
        ]),

        "gradient_boosting": Pipeline([
            ("preprocess", make_preprocessor(feature_cols)),
            ("model", GradientBoostingClassifier(
                n_estimators=150,
                learning_rate=0.08,
                max_depth=3,
                random_state=RANDOM_STATE
            ))
        ]),

        "xgboost": Pipeline([
            ("preprocess", make_preprocessor(feature_cols)),
            ("model", XGBClassifier(
                n_estimators=300,
                max_depth=6,
                learning_rate=0.08,
                subsample=0.85,
                colsample_bytree=0.85,
                objective="binary:logistic",
                eval_metric="logloss",
                tree_method="hist",
                n_jobs=-1,
                random_state=RANDOM_STATE
            ))
        ]),

        "mlp": Pipeline([
            ("preprocess", make_preprocessor(feature_cols)),
            ("model", MLPClassifier(
                hidden_layer_sizes=(128, 64),
                activation="relu",
                solver="adam",
                batch_size=256,
                learning_rate_init=0.001,
                early_stopping=True,
                validation_fraction=0.1,
                max_iter=50,
                random_state=RANDOM_STATE,
                verbose=True
            ))
        ])
    }

def evaluate(model, X, y, split_name, model_name):
    pred = model.predict(X)
    metrics = {
        "model": model_name,
        "split": split_name,
        "accuracy": accuracy_score(y, pred),
        "precision": precision_score(y, pred, zero_division=0),
        "recall": recall_score(y, pred, zero_division=0),
        "f1": f1_score(y, pred, zero_division=0),
        "tn_fp_fn_tp": confusion_matrix(y, pred).ravel().tolist()
    }
    return metrics

def main():
    print("Loading data...")
    train = load_split("train.csv")
    validation = load_split("validation.csv")
    test = load_split("test.csv")

    X_train, y_train, feature_cols = prepare_xy(train)
    X_val, y_val, _ = prepare_xy(validation)
    X_test, y_test, _ = prepare_xy(test)

    print(f"Training rows: {len(X_train):,}")
    print(f"Validation rows: {len(X_val):,}")
    print(f"Test rows: {len(X_test):,}")
    print(f"Numeric features used: {len(feature_cols)}")
    print(feature_cols)

    models = make_models(feature_cols)
    all_metrics = []

    for name, model in models.items():
        print(f"\n===== TRAINING {name.upper()} =====")
        model.fit(X_train, y_train)

        joblib.dump(model, MODELS / f"{name}.joblib")

        val_metrics = evaluate(model, X_val, y_val, "validation", name)
        test_metrics = evaluate(model, X_test, y_test, "test", name)
        all_metrics.extend([val_metrics, test_metrics])

        print(json.dumps(val_metrics, indent=2))
        print(json.dumps(test_metrics, indent=2))

    metrics_df = pd.DataFrame(all_metrics)
    metrics_df.to_csv(RESULTS / "model_metrics.csv", index=False)

    with open(RESULTS / "feature_columns.json", "w") as f:
        json.dump(feature_cols, f, indent=2)

    print("\nFinished. Models are in models/ and metrics are in results/.")

if __name__ == "__main__":
    main()
