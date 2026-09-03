from pathlib import Path

import pandas as pd
from sklearn.model_selection import train_test_split


BASE = Path(__file__).resolve().parent
DATA = BASE / "data"
OUT = DATA / "clean_split"
OUT.mkdir(parents=True, exist_ok=True)

RANDOM_STATE = 42

print("=" * 70)
print("CREATING URL-GROUPED LEAKAGE-FREE DATASET")
print("=" * 70)

# Load the complete dataset from the three existing splits.
files = [
    DATA / "train.csv",
    DATA / "validation.csv",
    DATA / "test.csv",
]

frames = []

for path in files:
    print(f"Loading {path}")
    df = pd.read_csv(path, low_memory=False)
    frames.append(df)

df = pd.concat(frames, ignore_index=True)

print(f"\nTotal rows: {len(df):,}")
print(f"Unique URLs: {df['URL'].nunique():,}")

# Remove exact duplicate rows if any.
before = len(df)
df = df.drop_duplicates()
print(f"Exact duplicates removed: {before - len(df)}")

# Make sure every URL has only one label.
label_counts = df.groupby("URL")["label"].nunique()

conflicting = label_counts[label_counts > 1]

if len(conflicting) > 0:
    print("\nERROR: Some URLs have conflicting labels.")
    print(conflicting.head(20))
    raise ValueError("Conflicting labels found for identical URLs.")

print("No conflicting URL labels.")

# One row per unique URL for splitting.
# Because each URL has exactly one label, this prevents the same
# URL from appearing in multiple splits.
url_labels = (
    df[["URL", "label"]]
    .drop_duplicates("URL")
    .reset_index(drop=True)
)

print(f"\nURLs available for splitting: {len(url_labels):,}")

# First split:
# 80% train
# 20% temporary
train_urls, temp_urls = train_test_split(
    url_labels,
    test_size=0.20,
    random_state=RANDOM_STATE,
    stratify=url_labels["label"],
)

# Second split:
# temporary -> 10% validation / 10% test
val_urls, test_urls = train_test_split(
    temp_urls,
    test_size=0.50,
    random_state=RANDOM_STATE,
    stratify=temp_urls["label"],
)

train_url_set = set(train_urls["URL"])
val_url_set = set(val_urls["URL"])
test_url_set = set(test_urls["URL"])

print("\nSplit sizes:")
print(f"Train URLs      : {len(train_url_set):,}")
print(f"Validation URLs : {len(val_url_set):,}")
print(f"Test URLs       : {len(test_url_set):,}")

# Build actual row datasets.
train = df[df["URL"].isin(train_url_set)].copy()
validation = df[df["URL"].isin(val_url_set)].copy()
test = df[df["URL"].isin(test_url_set)].copy()

# Shuffle rows.
train = train.sample(frac=1, random_state=RANDOM_STATE).reset_index(drop=True)
validation = validation.sample(frac=1, random_state=RANDOM_STATE).reset_index(drop=True)
test = test.sample(frac=1, random_state=RANDOM_STATE).reset_index(drop=True)

# Save.
train.to_csv(OUT / "train.csv", index=False)
validation.to_csv(OUT / "validation.csv", index=False)
test.to_csv(OUT / "test.csv", index=False)

print("\nRow sizes:")
print(f"Train      : {len(train):,}")
print(f"Validation : {len(validation):,}")
print(f"Test       : {len(test):,}")

print("\nLabel distribution:")

print("\nTrain:")
print(train["label"].value_counts())

print("\nValidation:")
print(validation["label"].value_counts())

print("\nTest:")
print(test["label"].value_counts())

# Verify no URL leakage.
train_urls = set(train["URL"])
val_urls = set(validation["URL"])
test_urls = set(test["URL"])

print("\nLeakage verification:")
print("Train ∩ Validation:", len(train_urls & val_urls))
print("Train ∩ Test:", len(train_urls & test_urls))
print("Validation ∩ Test:", len(val_urls & test_urls))

assert len(train_urls & val_urls) == 0
assert len(train_urls & test_urls) == 0
assert len(val_urls & test_urls) == 0

print("\nSUCCESS: No URL appears in more than one split.")

print(f"\nFiles created in:")
print(OUT)
