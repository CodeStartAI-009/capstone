import json
import os
from pathlib import Path

import numpy as np
import pandas as pd
import torch

from datasets import Dataset
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
)

from transformers import (
    AutoTokenizer,
    AutoModelForSequenceClassification,
    TrainingArguments,
    Trainer,
    DataCollatorWithPadding,
)


# ============================================================
# CONFIGURATION
# ============================================================

BASE = Path(__file__).resolve().parent

DATA = BASE / "data" / "clean_split"
OUTPUT = BASE / "distilbert_model_clean"
RESULTS = BASE / "results"
OUTPUT.mkdir(exist_ok=True)
RESULTS.mkdir(exist_ok=True)

MODEL_NAME = "distilbert-base-uncased"

URL_COLUMN = "URL"
LABEL_COLUMN = "label"

MAX_LENGTH = 128

RANDOM_SEED = 42


# ============================================================
# TRAINING CONFIGURATION
# ============================================================

# For a MacBook Air, start with these conservative values.
#
# If training is stable and memory is available, you can later
# increase NUM_EPOCHS or BATCH_SIZE.

NUM_EPOCHS = 1

BATCH_SIZE = 16

LEARNING_RATE = 2e-5

WEIGHT_DECAY = 0.01


# ============================================================
# DEVICE
# ============================================================

print("=" * 70)
print("DISTILBERT PHISHING URL CLASSIFIER")
print("=" * 70)

print("\nChecking device...")

if torch.cuda.is_available():

    DEVICE = "cuda"

elif torch.backends.mps.is_available():

    DEVICE = "mps"

else:

    DEVICE = "cpu"

print(f"Device: {DEVICE}")

print(f"PyTorch version: {torch.__version__}")

print(
    f"MPS available: {torch.backends.mps.is_available()}"
)


# ============================================================
# LOAD DATA
# ============================================================

def load_csv(filename):

    path = DATA / filename

    print(f"\nLoading: {path}")

    if not path.exists():

        raise FileNotFoundError(
            f"Dataset not found: {path}"
        )

    df = pd.read_csv(
        path,
        low_memory=False
    )

    print(
        f"Rows loaded: {len(df):,}"
    )

    return df


train_df = load_csv("train.csv")

validation_df = load_csv("validation.csv")

test_df = load_csv("test.csv")


# ============================================================
# VALIDATE COLUMNS
# ============================================================

required_columns = [
    URL_COLUMN,
    LABEL_COLUMN
]

for df_name, df in [
    ("train", train_df),
    ("validation", validation_df),
    ("test", test_df),
]:

    missing = [
        column
        for column in required_columns
        if column not in df.columns
    ]

    if missing:

        raise ValueError(
            f"{df_name}.csv is missing columns: {missing}"
        )


# ============================================================
# CLEAN DATA
# ============================================================

def prepare_dataframe(df):

    result = df[
        [
            URL_COLUMN,
            LABEL_COLUMN
        ]
    ].copy()

    # Remove missing URLs.

    result = result.dropna(
        subset=[URL_COLUMN]
    )

    # Convert URL to string.

    result[URL_COLUMN] = (
        result[URL_COLUMN]
        .astype(str)
        .str.strip()
    )

    # Remove empty URLs.

    result = result[
        result[URL_COLUMN] != ""
    ]

    # Ensure labels are integers.

    result[LABEL_COLUMN] = (
        result[LABEL_COLUMN]
        .astype(int)
    )

    # Validate labels.

    invalid_labels = set(
        result[LABEL_COLUMN].unique()
    ) - {0, 1}

    if invalid_labels:

        raise ValueError(
            f"Invalid labels found: {invalid_labels}"
        )

    return result


train_df = prepare_dataframe(train_df)

validation_df = prepare_dataframe(
    validation_df
)

test_df = prepare_dataframe(
    test_df
)


print("\nDataset sizes after cleaning:")

print(
    f"Train      : {len(train_df):,}"
)

print(
    f"Validation : {len(validation_df):,}"
)

print(
    f"Test       : {len(test_df):,}"
)


# ============================================================
# LABEL DISTRIBUTION
# ============================================================

print("\nTraining label distribution:")

print(
    train_df[LABEL_COLUMN]
    .value_counts()
    .sort_index()
)

print(
    "\nLabel mapping:"
)

print(
    "0 = phishing"
)

print(
    "1 = legitimate"
)


# ============================================================
# CONVERT TO HUGGING FACE DATASETS
# ============================================================

train_dataset = Dataset.from_pandas(
    train_df,
    preserve_index=False
)

validation_dataset = Dataset.from_pandas(
    validation_df,
    preserve_index=False
)

test_dataset = Dataset.from_pandas(
    test_df,
    preserve_index=False
)


# ============================================================
# LOAD TOKENIZER
# ============================================================

print("\nLoading tokenizer...")

tokenizer = AutoTokenizer.from_pretrained(
    MODEL_NAME
)


# ============================================================
# TOKENIZATION
# ============================================================

def tokenize_function(batch):

    return tokenizer(
        batch[URL_COLUMN],
        truncation=True,
        max_length=MAX_LENGTH,
        padding=False,
    )


print("\nTokenizing training dataset...")

tokenized_train = train_dataset.map(
    tokenize_function,
    batched=True,
    batch_size=1000,
    desc="Tokenizing train"
)


print("\nTokenizing validation dataset...")

tokenized_validation = validation_dataset.map(
    tokenize_function,
    batched=True,
    batch_size=1000,
    desc="Tokenizing validation"
)


print("\nTokenizing test dataset...")

tokenized_test = test_dataset.map(
    tokenize_function,
    batched=True,
    batch_size=1000,
    desc="Tokenizing test"
)


# ============================================================
# RENAME LABEL COLUMN
# ============================================================

tokenized_train = tokenized_train.rename_column(
    LABEL_COLUMN,
    "labels"
)

tokenized_validation = (
    tokenized_validation.rename_column(
        LABEL_COLUMN,
        "labels"
    )
)

tokenized_test = tokenized_test.rename_column(
    LABEL_COLUMN,
    "labels"
)


# ============================================================
# REMOVE ORIGINAL URL COLUMN
# ============================================================

tokenized_train = tokenized_train.remove_columns(
    [URL_COLUMN]
)

tokenized_validation = (
    tokenized_validation.remove_columns(
        [URL_COLUMN]
    )
)

tokenized_test = (
    tokenized_test.remove_columns(
        [URL_COLUMN]
    )
)


# ============================================================
# DATA COLLATOR
# ============================================================

data_collator = DataCollatorWithPadding(
    tokenizer=tokenizer
)


# ============================================================
# LOAD DISTILBERT
# ============================================================

print("\nLoading DistilBERT model...")

model = AutoModelForSequenceClassification.from_pretrained(
    MODEL_NAME,
    num_labels=2,
    id2label={
        0: "PHISHING",
        1: "LEGITIMATE",
    },
    label2id={
        "PHISHING": 0,
        "LEGITIMATE": 1,
    },
)


# ============================================================
# METRICS
# ============================================================

def compute_metrics(eval_prediction):

    logits, labels = eval_prediction

    predictions = np.argmax(
        logits,
        axis=-1
    )

    accuracy = accuracy_score(
        labels,
        predictions
    )

    precision = precision_score(
        labels,
        predictions,
        zero_division=0
    )

    recall = recall_score(
        labels,
        predictions,
        zero_division=0
    )

    f1 = f1_score(
        labels,
        predictions,
        zero_division=0
    )

    return {
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
    }


# ============================================================
# TRAINING ARGUMENTS
# ============================================================

print("\nPreparing training configuration...")

training_args = TrainingArguments(

    output_dir=str(
        OUTPUT / "checkpoints"
    ),

    overwrite_output_dir=True,

    num_train_epochs=NUM_EPOCHS,

    per_device_train_batch_size=BATCH_SIZE,

    per_device_eval_batch_size=BATCH_SIZE,

    learning_rate=LEARNING_RATE,

    weight_decay=WEIGHT_DECAY,

    warmup_ratio=0.1,

    logging_dir=str(
        OUTPUT / "logs"
    ),

    logging_steps=500,

    eval_strategy="epoch",

    save_strategy="epoch",

    load_best_model_at_end=True,

    metric_for_best_model="f1",

    greater_is_better=True,

    save_total_limit=2,

    report_to="none",

    seed=RANDOM_SEED,

    fp16=False,

    bf16=False,

    dataloader_num_workers=0,

)


# ============================================================
# TRAINER
# ============================================================

trainer = Trainer(

    model=model,

    args=training_args,

    train_dataset=tokenized_train,

    eval_dataset=tokenized_validation,

    processing_class=tokenizer,

    data_collator=data_collator,

    compute_metrics=compute_metrics,
)


# ============================================================
# TRAIN
# ============================================================

print("\n" + "=" * 70)

print("STARTING DISTILBERT TRAINING")

print("=" * 70)

print(
    f"\nModel: {MODEL_NAME}"
)

print(
    f"Device: {DEVICE}"
)

print(
    f"Epochs: {NUM_EPOCHS}"
)

print(
    f"Batch size: {BATCH_SIZE}"
)

print(
    f"Learning rate: {LEARNING_RATE}"
)

print(
    f"Maximum URL token length: {MAX_LENGTH}"
)

print(
    f"Training samples: {len(tokenized_train):,}"
)


train_result = trainer.train()


# ============================================================
# SAVE MODEL
# ============================================================

print("\nSaving final DistilBERT model...")

trainer.save_model(
    str(OUTPUT)
)

tokenizer.save_pretrained(
    str(OUTPUT)
)


# ============================================================
# SAVE TRAINING INFORMATION
# ============================================================

training_info = {

    "base_model": MODEL_NAME,

    "task": "phishing_url_classification",

    "input_column": URL_COLUMN,

    "label_column": LABEL_COLUMN,

    "label_mapping": {
        "0": "phishing",
        "1": "legitimate",
    },

    "max_length": MAX_LENGTH,

    "epochs": NUM_EPOCHS,

    "batch_size": BATCH_SIZE,

    "learning_rate": LEARNING_RATE,

    "weight_decay": WEIGHT_DECAY,

    "device": DEVICE,

    "train_samples": len(train_df),

    "validation_samples": len(
        validation_df
    ),

    "test_samples": len(test_df),
}


with open(
    OUTPUT / "training_config.json",
    "w"
) as file:

    json.dump(
        training_info,
        file,
        indent=2
    )


# ============================================================
# VALIDATION EVALUATION
# ============================================================

print("\n" + "=" * 70)

print("VALIDATION EVALUATION")

print("=" * 70)

validation_result = trainer.evaluate(
    tokenized_validation
)

print(
    json.dumps(
        validation_result,
        indent=2,
        default=float
    )
)


# ============================================================
# TEST PREDICTIONS
# ============================================================

print("\n" + "=" * 70)

print("TEST EVALUATION")

print("=" * 70)

test_output = trainer.predict(
    tokenized_test
)

test_logits = test_output.predictions

test_predictions = np.argmax(
    test_logits,
    axis=-1
)

test_labels = test_output.label_ids


# ============================================================
# TEST METRICS
# ============================================================

test_accuracy = accuracy_score(
    test_labels,
    test_predictions
)

test_precision = precision_score(
    test_labels,
    test_predictions,
    zero_division=0
)

test_recall = recall_score(
    test_labels,
    test_predictions,
    zero_division=0
)

test_f1 = f1_score(
    test_labels,
    test_predictions,
    zero_division=0
)


tn, fp, fn, tp = confusion_matrix(
    test_labels,
    test_predictions,
    labels=[0, 1]
).ravel()


test_metrics = {

    "model": "DistilBERT",

    "split": "test",

    "accuracy": test_accuracy,

    "precision": test_precision,

    "recall": test_recall,

    "f1": test_f1,

    "TN": int(tn),

    "FP": int(fp),

    "FN": int(fn),

    "TP": int(tp),
}


print(
    json.dumps(
        test_metrics,
        indent=2
    )
)


# ============================================================
# SAVE TEST METRICS
# ============================================================

distilbert_metrics_file = (
    RESULTS /
    "distilbert_metrics.csv"
)

pd.DataFrame(
    [test_metrics]
).to_csv(
    distilbert_metrics_file,
    index=False
)


# ============================================================
# SAVE TEST PREDICTIONS
# ============================================================

test_predictions_df = test_df.copy()

test_predictions_df[
    "distilbert_prediction"
] = test_predictions

test_predictions_df[
    "distilbert_prediction_text"
] = (
    test_predictions_df[
        "distilbert_prediction"
    ]
    .map({
        0: "phishing",
        1: "legitimate",
    })
)


# ------------------------------------------------------------
# Probabilities
# ------------------------------------------------------------

probabilities = torch.softmax(
    torch.tensor(test_logits),
    dim=-1
).numpy()


test_predictions_df[
    "phishing_probability"
] = probabilities[:, 0]

test_predictions_df[
    "legitimate_probability"
] = probabilities[:, 1]


predictions_file = (
    RESULTS /
    "distilbert_test_predictions.csv"
)

test_predictions_df.to_csv(
    predictions_file,
    index=False
)


# ============================================================
# SAVE VALIDATION PREDICTIONS
# ============================================================

validation_output = trainer.predict(
    tokenized_validation
)

validation_logits = (
    validation_output.predictions
)

validation_predictions = np.argmax(
    validation_logits,
    axis=-1
)

validation_probabilities = (
    torch.softmax(
        torch.tensor(validation_logits),
        dim=-1
    )
    .numpy()
)


validation_predictions_df = (
    validation_df.copy()
)


validation_predictions_df[
    "distilbert_prediction"
] = validation_predictions


validation_predictions_df[
    "distilbert_prediction_text"
] = (
    validation_predictions_df[
        "distilbert_prediction"
    ]
    .map({
        0: "phishing",
        1: "legitimate",
    })
)


validation_predictions_df[
    "phishing_probability"
] = (
    validation_probabilities[:, 0]
)


validation_predictions_df[
    "legitimate_probability"
] = (
    validation_probabilities[:, 1]
)


validation_predictions_file = (
    RESULTS /
    "distilbert_validation_predictions.csv"
)


validation_predictions_df.to_csv(
    validation_predictions_file,
    index=False
)


# ============================================================
# FINAL SUMMARY
# ============================================================

print("\n" + "=" * 70)

print("DISTILBERT TRAINING COMPLETE")

print("=" * 70)


print("\nModel saved to:")

print(
    OUTPUT
)


print("\nTest metrics saved to:")

print(
    distilbert_metrics_file
)


print("\nTest predictions saved to:")

print(
    predictions_file
)


print("\nValidation predictions saved to:")

print(
    validation_predictions_file
)


print("\nFinal Test Results:")

print(
    f"Accuracy : {test_accuracy:.6f}"
)

print(
    f"Precision: {test_precision:.6f}"
)

print(
    f"Recall   : {test_recall:.6f}"
)

print(
    f"F1       : {test_f1:.6f}"
)

print(
    f"TN       : {tn}"
)

print(
    f"FP       : {fp}"
)

print(
    f"FN       : {fn}"
)

print(
    f"TP       : {tp}"
)

print("\nDone.")