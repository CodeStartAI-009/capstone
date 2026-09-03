import argparse
from pathlib import Path

import joblib
import pandas as pd

parser = argparse.ArgumentParser()
parser.add_argument("--input", required=True)
parser.add_argument("--model", required=True)
parser.add_argument("--output", required=True)
args = parser.parse_args()

df = pd.read_csv(args.input, low_memory=False)
model = joblib.load(args.model)

# The trained pipeline already knows the feature columns and preprocessing.
X = df.drop(columns=["label"], errors="ignore")

pred = model.predict(X)

out = df.copy()
out["prediction"] = pred

# 0 = phishing, 1 = legitimate
out["prediction_text"] = out["prediction"].map({
    0: "phishing",
    1: "legitimate"
})

Path(args.output).parent.mkdir(parents=True, exist_ok=True)
out.to_csv(args.output, index=False)

print(f"Saved predictions to {args.output}")
