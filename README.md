# Phishing URL - 6 Model Training Project

This project trains the six traditional models from the Case-117 proposal:

1. Logistic Regression
2. Support Vector Machine (SVM)
3. Random Forest
4. Gradient Boosting
5. XGBoost
6. Multi-Layer Perceptron (MLP)

The supplied train/validation/test CSV files are expected in `data/`.

The raw `URL`, `Domain`, `TLD`, `Title`, and `FILENAME` text fields are not used by these six traditional models. The numeric engineered URL/web features are used instead. `URL` is reserved for the later DistilBERT model.

Label convention from the supplied dataset:
- 0 = phishing
- 1 = legitimate

## Folder structure

```text
phishing_ml_training/
├── data/
│   ├── phishing_urls.csv
│   ├── train.csv
│   ├── validation.csv
│   ├── test.csv
│   ├── features.csv
│   └── dataset_description.csv
├── models/
├── results/
├── train_models.py
├── predict.py
├── requirements.txt
└── README.md
```

## Install

```bash
pip install -r requirements.txt
```

## Train all six models

```bash
python train_models.py
```

This saves trained models in `models/` and validation/test metrics in `results/`.

## Predict a new CSV

```bash
python predict.py --input data/test.csv --model models/random_forest.joblib --output results/predictions.csv
```
