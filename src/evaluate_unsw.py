
from pathlib import Path

import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import IsolationForest
from sklearn.impute import SimpleImputer
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler

# Project folders
PROJECT_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_DIR / "data"
RESULTS_DIR = PROJECT_DIR / "results"
RESULTS_DIR.mkdir(exist_ok=True)

TRAIN_FILE = DATA_DIR / "UNSW_NB15_training-set.csv"
TEST_FILE = DATA_DIR / "UNSW_NB15_testing-set.csv"

print("Loading UNSW-NB15 datasets...")

train = pd.read_csv(TRAIN_FILE, low_memory=False)
test = pd.read_csv(TEST_FILE, low_memory=False)

train.columns = train.columns.str.strip().str.lower()
test.columns = test.columns.str.strip().str.lower()

if "label" not in train.columns or "label" not in test.columns:
    raise ValueError("The required 'label' column is missing.")

# Exclude labels and the record ID from model features.
excluded = {"label", "attack_cat", "id"}
features = [
    col for col in train.columns
    if col in test.columns and col not in excluded
]

X_train = train[features].copy()
X_test = test[features].copy()

y_train = pd.to_numeric(train["label"], errors="raise").astype(int)
y_test = pd.to_numeric(test["label"], errors="raise").astype(int)

# Learn preprocessing from training data only.
numeric_features = X_train.select_dtypes(
    include=["number"]
).columns.tolist()

categorical_features = [
    col for col in features if col not in numeric_features
]

numeric_pipeline = Pipeline([
    ("imputer", SimpleImputer(strategy="median")),
    ("scaler", StandardScaler()),
])

categorical_pipeline = Pipeline([
    ("imputer", SimpleImputer(strategy="most_frequent")),
    ("encoder", OneHotEncoder(
        handle_unknown="ignore",
        sparse_output=True
    )),
])

preprocessor = ColumnTransformer([
    ("numeric", numeric_pipeline, numeric_features),
    ("categorical", categorical_pipeline, categorical_features),
])

# Train using normal records only.
normal_mask = y_train == 0

if not normal_mask.any():
    raise ValueError("No normal training records were found.")

print("Training rows:", len(train))
print("Testing rows:", len(test))
print("Normal training rows:", int(normal_mask.sum()))
print("Preparing features...")

X_train_normal = preprocessor.fit_transform(
    X_train.loc[normal_mask]
)
X_test_ready = preprocessor.transform(X_test)

print("Training Isolation Forest...")

model = IsolationForest(
    n_estimators=100,
    contamination="auto",
    random_state=42,
    n_jobs=-1,
)

model.fit(X_train_normal)

# -1 means anomaly; 1 means baseline.
predictions = model.predict(X_test_ready)
y_pred = (predictions == -1).astype(int)

print("\nEVALUATION RESULTS")
print("==================")
print("Test records:", len(test))
print("\nConfusion matrix (rows=actual, columns=predicted):")
print(confusion_matrix(y_test, y_pred, labels=[0, 1]))

print("\nClassification report:")
print(classification_report(
    y_test,
    y_pred,
    labels=[0, 1],
    target_names=["Normal", "Attack"],
    zero_division=0,
))

# Save the results separately from previous evaluations.
output = test.copy()
output["ActualLabel"] = y_test
output["PredictedLabel"] = y_pred
output["ReviewStatus"] = [
    "Review" if value == 1 else "Baseline"
    for value in y_pred
]

output_path = RESULTS_DIR / "unsw_evaluation_results_v2.csv"
output.to_csv(output_path, index=False)

print("\nSaved results to:", output_path)
print("Flags are anomaly candidates, not confirmed attacks.")
