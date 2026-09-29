"""Is the displayed "confidence" a calibrated probability? (validation split only)

    python scripts/calibration_report.py

For the deployed model (v2.0.0) and the archived v1.2.0, on each model's own validation split:
reliability table (10 equal-width score bins: mean score vs observed phishing rate), Brier score and
expected calibration error (ECE). Writes docs/data/calibration.json.
"""
import json
import sys
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from ml.dataset import (build_tld_table, featurize_prepared, load_host_grouped_split,  # noqa: E402
                        load_registrable_grouped_split)
from ml.model_utils import load_model, phishing_probability  # noqa: E402

OUT = ROOT / "docs" / "data" / "calibration.json"


def reliability(p, y, bins=10):
    edges = np.linspace(0, 1, bins + 1)
    idx = np.clip(np.digitize(p, edges[1:-1]), 0, bins - 1)
    table, ece = [], 0.0
    for b in range(bins):
        m = idx == b
        if not m.any():
            continue
        mean_p, rate = float(p[m].mean()), float(y[m].mean())
        ece += m.mean() * abs(mean_p - rate)
        table.append({"bin": f"{edges[b]:.1f}-{edges[b + 1]:.1f}", "n": int(m.sum()),
                      "mean_predicted": round(mean_p, 4), "observed_phishing_rate": round(rate, 4)})
    return table, float(ece), float(np.mean((p - y) ** 2))


def main():
    report = {}
    for name, loader, view, model_path in (
            ("v2.0.0 (deployed, registrable view)", load_registrable_grouped_split, "registrable",
             ROOT / "models" / "phishing_model.pkl"),
            ("v1.2.0 (archived, host view)", load_host_grouped_split, "host",
             ROOT / "models" / "previous_v1.2.0" / "phishing_model.pkl")):
        splits, _ = loader()
        table = build_tld_table(splits["train"])
        X, y = featurize_prepared(splits["validation"], table, view=view)
        p = phishing_probability(load_model(model_path), X)
        rel, ece, brier = reliability(p, y)
        report[name] = {"validation_rows": int(len(y)), "brier_score": round(brier, 4), "ece": round(ece, 4),
                        "reliability": rel}
        print(name, "Brier", round(brier, 4), "ECE", round(ece, 4))
        for r in rel:
            print("   ", r)
    OUT.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
