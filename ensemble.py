import json
from pathlib import Path

import joblib
import pandas as pd

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
)


# ============================================================
# PATHS
# ============================================================

BASE = Path(__file__).resolve().parent

DATA = BASE / "data"
MODELS = BASE / "models"
RESULTS = BASE / "results"

RESULTS.mkdir(exist_ok=True)


# ============================================================
# URL FEATURES
# ============================================================

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


# ============================================================
# MODELS
# ============================================================

MODEL_NAMES = [
    "logistic_regression",
    "svm",
    "random_forest",
    "gradient_boosting",
    "xgboost",
    "mlp",
]


# ============================================================
# LOAD DATA
# ============================================================

def load_dataset(filename):

    path = DATA / filename

    print(f"Loading {path}")

    return pd.read_csv(
        path,
        low_memory=False
    )


# ============================================================
# LOAD MODELS
# ============================================================

def load_models():

    models = {}

    for name in MODEL_NAMES:

        path = MODELS / f"{name}_url_only.joblib"

        print(f"Loading model: {path}")

        if not path.exists():

            raise FileNotFoundError(
                f"Model not found: {path}\n"
                f"Make sure you trained the URL-only models first."
            )

        models[name] = joblib.load(path)

    return models


# ============================================================
# ENSEMBLE PREDICTION
# ============================================================

def ensemble_predict(models, X):

    predictions = {}

    for name, model in models.items():

        print(f"Predicting with {name}...")

        predictions[name] = model.predict(X)

    prediction_df = pd.DataFrame(predictions)

    # --------------------------------------------------------
    # Majority voting
    #
    # 0 = phishing
    # 1 = legitimate
    #
    # If 4/6 models say phishing, final = phishing.
    # --------------------------------------------------------

    phishing_votes = (
        prediction_df == 0
    ).sum(axis=1)

    legitimate_votes = (
        prediction_df == 1
    ).sum(axis=1)

    final_prediction = (
        legitimate_votes >= phishing_votes
    ).astype(int)

    prediction_df["phishing_votes"] = phishing_votes

    prediction_df["legitimate_votes"] = legitimate_votes

    prediction_df["ensemble_prediction"] = final_prediction

    # --------------------------------------------------------
    # Confidence
    #
    # Example:
    # 6 legitimate votes = 100%
    # 5 legitimate votes = 83.33%
    # 4 legitimate votes = 66.67%
    # --------------------------------------------------------

    prediction_df["ensemble_confidence"] = (
        prediction_df[
            ["phishing_votes", "legitimate_votes"]
        ].max(axis=1)
        / len(models)
    )

    prediction_df["prediction_text"] = (
        prediction_df["ensemble_prediction"]
        .map({
            0: "phishing",
            1: "legitimate"
        })
    )

    return prediction_df


# ============================================================
# EVALUATION
# ============================================================

def evaluate(y_true, y_pred):

    tn, fp, fn, tp = confusion_matrix(
        y_true,
        y_pred,
        labels=[0, 1]
    ).ravel()

    return {
        "accuracy": accuracy_score(
            y_true,
            y_pred
        ),

        "precision": precision_score(
            y_true,
            y_pred,
            zero_division=0
        ),

        "recall": recall_score(
            y_true,
            y_pred,
            zero_division=0
        ),

        "f1": f1_score(
            y_true,
            y_pred,
            zero_division=0
        ),

        "TN": int(tn),
        "FP": int(fp),
        "FN": int(fn),
        "TP": int(tp),
    }


# ============================================================
# RUN ONE DATASET
# ============================================================

def evaluate_dataset(
    dataset_name,
    models
):

    print("\n" + "=" * 60)

    print(
        f"ENSEMBLE EVALUATION: {dataset_name.upper()}"
    )

    print("=" * 60)

    df = load_dataset(
        f"{dataset_name}.csv"
    )

    X = df[URL_FEATURES]

    y = df["label"].astype(int)

    predictions = ensemble_predict(
        models,
        X
    )

    metrics = evaluate(
        y,
        predictions["ensemble_prediction"]
    )

    print("\nRESULTS")

    print(
        f"Accuracy : {metrics['accuracy']:.6f}"
    )

    print(
        f"Precision: {metrics['precision']:.6f}"
    )

    print(
        f"Recall   : {metrics['recall']:.6f}"
    )

    print(
        f"F1       : {metrics['f1']:.6f}"
    )

    print(
        f"TN       : {metrics['TN']}"
    )

    print(
        f"FP       : {metrics['FP']}"
    )

    print(
        f"FN       : {metrics['FN']}"
    )

    print(
        f"TP       : {metrics['TP']}"
    )

    return metrics, predictions, df


# ============================================================
# MAIN
# ============================================================

def main():

    print("=" * 60)

    print(
        "PHISHING URL - 6 MODEL ENSEMBLE"
    )

    print("=" * 60)

    print(
        "\nVoting models:"
    )

    for name in MODEL_NAMES:

        print(
            f"  - {name}"
        )

    print(
        "\nLoading trained models..."
    )

    models = load_models()

    all_metrics = []

    # --------------------------------------------------------
    # VALIDATION
    # --------------------------------------------------------

    val_metrics, val_predictions, val_df = (
        evaluate_dataset(
            "validation",
            models
        )
    )

    val_metrics["split"] = "validation"

    all_metrics.append(
        val_metrics
    )

    # --------------------------------------------------------
    # TEST
    # --------------------------------------------------------

    test_metrics, test_predictions, test_df = (
        evaluate_dataset(
            "test",
            models
        )
    )

    test_metrics["split"] = "test"

    all_metrics.append(
        test_metrics
    )

    # --------------------------------------------------------
    # SAVE METRICS
    # --------------------------------------------------------

    metrics_df = pd.DataFrame(
        all_metrics
    )

    metrics_df = metrics_df[
        [
            "split",
            "accuracy",
            "precision",
            "recall",
            "f1",
            "TN",
            "FP",
            "FN",
            "TP",
        ]
    ]

    metrics_file = (
        RESULTS /
        "ensemble_metrics.csv"
    )

    metrics_df.to_csv(
        metrics_file,
        index=False
    )

    # --------------------------------------------------------
    # SAVE TEST PREDICTIONS
    # --------------------------------------------------------

    test_output = test_df.copy()

    for column in test_predictions.columns:

        test_output[
            column
        ] = test_predictions[column].values

    predictions_file = (
        RESULTS /
        "ensemble_test_predictions.csv"
    )

    test_output.to_csv(
        predictions_file,
        index=False
    )

    # --------------------------------------------------------
    # SAVE VALIDATION PREDICTIONS
    # --------------------------------------------------------

    validation_output = val_df.copy()

    for column in val_predictions.columns:

        validation_output[
            column
        ] = val_predictions[column].values

    validation_predictions_file = (
        RESULTS /
        "ensemble_validation_predictions.csv"
    )

    validation_output.to_csv(
        validation_predictions_file,
        index=False
    )

    # --------------------------------------------------------
    # SAVE CONFIGURATION
    # --------------------------------------------------------

    configuration = {
        "models": MODEL_NAMES,
        "number_of_models": len(MODEL_NAMES),
        "voting_method": "majority_vote",
        "phishing_label": 0,
        "legitimate_label": 1,
        "features": URL_FEATURES,
        "number_of_features": len(URL_FEATURES),
    }

    configuration_file = (
        RESULTS /
        "ensemble_configuration.json"
    )

    with open(
        configuration_file,
        "w"
    ) as f:

        json.dump(
            configuration,
            f,
            indent=2
        )

    # --------------------------------------------------------
    # FINISHED
    # --------------------------------------------------------

    print("\n" + "=" * 60)

    print(
        "ENSEMBLE TRAINING/EVALUATION COMPLETE"
    )

    print("=" * 60)

    print(
        f"\nMetrics:"
    )

    print(
        metrics_file
    )

    print(
        f"\nTest predictions:"
    )

    print(
        predictions_file
    )

    print(
        f"\nValidation predictions:"
    )

    print(
        validation_predictions_file
    )

    print(
        f"\nConfiguration:"
    )

    print(
        configuration_file
    )


if __name__ == "__main__":

    main()
