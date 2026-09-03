import pandas as pd
import numpy as np
import joblib
from pathlib import Path

BASE = Path(__file__).resolve().parent

DATA = BASE / "data" / "clean_split"
MODELS = BASE / "models"
RESULTS = BASE / "results"

RESULTS.mkdir(exist_ok=True)

print("=" * 70)
print("FEATURE IMPORTANCE ANALYSIS")
print("=" * 70)

# ------------------------------------------------------------
# LOAD DATA
# ------------------------------------------------------------

train = pd.read_csv(DATA / "train.csv", low_memory=False)

print(f"Training rows: {len(train):,}")

# Same feature exclusion used during training
EXCLUDE = {
    "label",
    "URL",
    "Domain",
    "TLD",
    "Title",
    "FILENAME",
}

feature_cols = [
    c for c in train.columns
    if c not in EXCLUDE
    and pd.api.types.is_numeric_dtype(train[c])
]

X = train[feature_cols]
y = train["label"].astype(int)

print(f"Features: {len(feature_cols)}")

# ------------------------------------------------------------
# RANDOM FOREST
# ------------------------------------------------------------

model_path = MODELS / "random_forest.joblib"

print("\nLoading Random Forest:")
print(model_path)

model = joblib.load(model_path)

# Pipeline -> actual RandomForest model
rf = model.named_steps["model"]

importance = rf.feature_importances_

importance_df = pd.DataFrame({
    "feature": feature_cols,
    "importance": importance,
})

importance_df = importance_df.sort_values(
    "importance",
    ascending=False
)

print("\nTop 30 features:")
print(
    importance_df.head(30).to_string(index=False)
)

importance_df.to_csv(
    RESULTS / "random_forest_feature_importance.csv",
    index=False
)

# ------------------------------------------------------------
# CLASS DISTRIBUTION BY TOP FEATURES
# ------------------------------------------------------------

top_features = importance_df.head(15)["feature"].tolist()

summary = []

for feature in top_features:

    grouped = train.groupby("label")[feature].mean()

    summary.append({
        "feature": feature,
        "phishing_mean_label_0": grouped.get(0, np.nan),
        "legitimate_mean_label_1": grouped.get(1, np.nan),
    })

summary_df = pd.DataFrame(summary)

summary_df.to_csv(
    RESULTS / "top_feature_class_means.csv",
    index=False
)

print("\nTop feature class means:")
print(summary_df.to_string(index=False))

print("\nSaved:")
print(
    RESULTS / "random_forest_feature_importance.csv"
)

print(
    RESULTS / "top_feature_class_means.csv"
)