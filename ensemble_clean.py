import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
)


BASE = Path(__file__).resolve().parent

DATA = BASE / "data" / "clean_split"
MODELS = BASE / "models" / "clean"
RESULTS = BASE / "results"

RESULTS.mkdir(exist_ok=True)

MODEL_NAMES = [
    "logistic_regression",
    "svm",
    "random_forest",
    "gradient_boosting",
    "xgboost",
    "mlp",
]


def load_data(filename):
    return pd.read_csv(
        DATA / filename,
        low_memory=False
    )


def get_predictions(model, X):

    # Most sklearn classifiers support predict().
    # This gives the final class prediction.

    return model.predict(X)


def evaluate_ensemble(predictions, y, split_name):

    tn, fp, fn, tp = confusion_matrix(
        y,
        predictions
    ).ravel()

    return {
        "split": split_name,

        "accuracy": accuracy_score(
            y,
            predictions
        ),

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

        "TN": int(tn),
        "FP": int(fp),
        "FN": int(fn),
        "TP": int(tp),
    }


def majority_vote(prediction_matrix):

    # prediction_matrix shape:
    #
    # number_of_models x number_of_samples
    #
    # 0 = phishing
    # 1 = legitimate

    votes = np.sum(
        prediction_matrix,
        axis=0
    )

    # Six models are used.
    #
    # >= 3 legitimate votes => legitimate
    # < 3 legitimate votes  => phishing

    return (votes >= 3).astype(int)


def main():

    print("=" * 70)
    print("LEAKAGE-FREE ENSEMBLE")
    print("=" * 70)

    # --------------------------------------------------------
    # LOAD DATA
    # --------------------------------------------------------

    validation = load_data(
        "validation.csv"
    )

    test = load_data(
        "test.csv"
    )

    y_val = validation["label"].astype(int)
    y_test = test["label"].astype(int)

    # --------------------------------------------------------
    # LOAD MODELS
    # --------------------------------------------------------

    models = {}

    for name in MODEL_NAMES:

        path = (
            MODELS /
            f"{name}.joblib"
        )

        print(
            f"Loading model: {path}"
        )

        models[name] = joblib.load(
            path
        )

    # --------------------------------------------------------
    # GENERATE PREDICTIONS
    # --------------------------------------------------------

    validation_predictions = []
    test_predictions = []

    individual_results = []

    for name, model in models.items():

        print(
            f"Predicting with {name}..."
        )

        val_pred = get_predictions(
            model,
            validation
        )

        test_pred = get_predictions(
            model,
            test
        )

        validation_predictions.append(
            val_pred
        )

        test_predictions.append(
            test_pred
        )

    # --------------------------------------------------------
    # STACK PREDICTIONS
    # --------------------------------------------------------

    validation_matrix = np.array(
        validation_predictions
    )

    test_matrix = np.array(
        test_predictions
    )

    # --------------------------------------------------------
    # MAJORITY VOTE
    # --------------------------------------------------------

    ensemble_val = majority_vote(
        validation_matrix
    )

    ensemble_test = majority_vote(
        test_matrix
    )

    # --------------------------------------------------------
    # EVALUATE
    # --------------------------------------------------------

    val_metrics = evaluate_ensemble(
        ensemble_val,
        y_val,
        "validation"
    )

    test_metrics = evaluate_ensemble(
        ensemble_test,
        y_test,
        "test"
    )

    # --------------------------------------------------------
    # SAVE METRICS
    # --------------------------------------------------------

    metrics = pd.DataFrame([
        val_metrics,
        test_metrics
    ])

    metrics_path = (
        RESULTS /
        "clean_ensemble_metrics.csv"
    )

    metrics.to_csv(
        metrics_path,
        index=False
    )

    # --------------------------------------------------------
    # SAVE PREDICTIONS
    # --------------------------------------------------------

    validation_output = pd.DataFrame({
        "URL": validation["URL"],
        "actual_label": y_val,
        "ensemble_prediction": ensemble_val,
    })

    test_output = pd.DataFrame({
        "URL": test["URL"],
        "actual_label": y_test,
        "ensemble_prediction": ensemble_test,
    })

    validation_output.to_csv(
        RESULTS /
        "clean_ensemble_validation_predictions.csv",
        index=False
    )

    test_output.to_csv(
        RESULTS /
        "clean_ensemble_test_predictions.csv",
        index=False
    )

    # --------------------------------------------------------
    # SAVE CONFIG
    # --------------------------------------------------------

    configuration = {
        "models": MODEL_NAMES,
        "method": "majority_vote",
        "number_of_models": len(MODEL_NAMES),
        "decision_rule": (
            "3 or more legitimate predictions = legitimate"
        ),
        "label_mapping": {
            "0": "phishing",
            "1": "legitimate"
        }
    }

    with open(
        RESULTS /
        "clean_ensemble_configuration.json",
        "w"
    ) as f:

        json.dump(
            configuration,
            f,
            indent=2
        )

    # --------------------------------------------------------
    # PRINT RESULTS
    # --------------------------------------------------------

    print()
    print("=" * 70)
    print("ENSEMBLE VALIDATION")
    print("=" * 70)

    print(
        json.dumps(
            val_metrics,
            indent=2
        )
    )

    print()
    print("=" * 70)
    print("ENSEMBLE TEST")
    print("=" * 70)

    print(
        json.dumps(
            test_metrics,
            indent=2
        )
    )

    print()
    print(
        f"Metrics saved to: {metrics_path}"
    )


if __name__ == "__main__":
    main()