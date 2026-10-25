
from pathlib import Path
from datetime import datetime
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline

# Project folders
PROJECT = Path(__file__).resolve().parent.parent
DATA = PROJECT / "data" / "network_data_detailed.csv"
RESULTS = PROJECT / "results"

RESULTS.mkdir(exist_ok=True)

print("=" * 55)
print(" DARKTRACE-INSPIRED NETWORK ANOMALY MONITOR")
print("=" * 55)

# 1. Load collected network connection data
if not DATA.exists():
    raise FileNotFoundError(f"Dataset not found: {DATA}")

df = pd.read_csv(DATA)
print(f"\nDataset loaded: {len(df)} records")

# 2. Check required columns
required = [
    "LocalPort", "RemotePort", "State",
    "ProcessId", "ProcessName"
]
missing = [col for col in required if col not in df.columns]

if missing:
    raise ValueError(f"Missing required columns: {missing}")

# 3. Prepare model features
numeric_features = ["LocalPort", "RemotePort", "ProcessId"]
categorical_features = ["State", "ProcessName"]

for col in numeric_features:
    df[col] = pd.to_numeric(df[col], errors="coerce")

numeric_pipeline = Pipeline([
    ("imputer", SimpleImputer(strategy="median"))
])

categorical_pipeline = Pipeline([
    ("imputer", SimpleImputer(strategy="most_frequent")),
    ("encoder", OneHotEncoder(handle_unknown="ignore"))
])

preprocessor = ColumnTransformer([
    ("numeric", numeric_pipeline, numeric_features),
    ("categorical", categorical_pipeline, categorical_features)
])

model = Pipeline([
    ("preprocessor", preprocessor),
    ("detector", IsolationForest(
        n_estimators=100,
        contamination=0.05,
        random_state=42
    ))
])

# 4. Learn patterns from the available dataset
features = df[numeric_features + categorical_features]
predictions = model.fit_predict(features)
scores = model.decision_function(features)

# 5. Generate review flags
results = df.copy()
results["AnomalyScore"] = scores
results["ReviewStatus"] = [
    "Review" if prediction == -1 else "Baseline"
    for prediction in predictions
]
results["Interpretation"] = [
    "Unusual pattern; requires investigation"
    if prediction == -1
    else "Not flagged by this model"
    for prediction in predictions
]

# 6. Save results
output_file = RESULTS / "demo_results.csv"
results.to_csv(output_file, index=False)

review_count = int((results["ReviewStatus"] == "Review").sum())
baseline_count = len(results) - review_count

# 7. Generate a readable alert report
alert_file = RESULTS / "demo_alert.txt"

with open(alert_file, "w", encoding="utf-8") as file:
    file.write("DARKTRACE-INSPIRED NETWORK MONITOR\n")
    file.write(f"Generated: {datetime.now()}\n")
    file.write("-" * 45 + "\n")
    file.write(f"Records analyzed: {len(results)}\n")
    file.write(f"Flagged for review: {review_count}\n")
    file.write(f"Baseline records: {baseline_count}\n\n")
    file.write(
        "IMPORTANT: A review flag is not proof of a cyberattack.\n"
    )
    file.write(
        "Investigate flagged records using additional evidence.\n"
    )

print("\nANALYSIS COMPLETE")
print("-" * 35)
print(f"Records analyzed : {len(results)}")
print(f"Flagged for review: {review_count}")
print(f"Baseline records : {baseline_count}")
print(f"\nCSV results: {output_file}")
print(f"Alert report: {alert_file}")
print("\nNote: Flags are anomaly candidates, not confirmed attacks.")
print("=" * 55)
