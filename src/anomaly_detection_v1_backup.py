
import os
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import OrdinalEncoder

PROJECT_DIR = r"D:\Users\HP\Documents\Desktop\Darktrace"
DATA_FILE = os.path.join(
    PROJECT_DIR, "data", "network_data_detailed.csv"
)
RESULTS_DIR = os.path.join(PROJECT_DIR, "results")

os.makedirs(RESULTS_DIR, exist_ok=True)

print("=" * 55)
print(" DARKTRACE - PRELIMINARY ANOMALY SCREENING")
print("=" * 55)

df = pd.read_csv(DATA_FILE)

# Select connection-related features available in our dataset.
feature_columns = [
    "LocalPort",
    "RemotePort",
    "State",
    "ProcessName"
]

X = df[feature_columns].copy()

# Convert numeric columns safely.
for col in ["LocalPort", "RemotePort"]:
    X[col] = pd.to_numeric(X[col], errors="coerce")

# Handle missing values.
X["LocalPort"] = X["LocalPort"].fillna(-1)
X["RemotePort"] = X["RemotePort"].fillna(-1)

for col in ["State", "ProcessName"]:
    X[col] = X[col].fillna("Unknown").astype(str)

# Encode categorical columns as numeric values.
encoder = OrdinalEncoder(
    handle_unknown="use_encoded_value",
    unknown_value=-1
)

X[["State", "ProcessName"]] = encoder.fit_transform(
    X[["State", "ProcessName"]]
)

# Fit an unsupervised anomaly detection model.
model = IsolationForest(
    n_estimators=100,
    contamination=0.05,
    random_state=42
)

predictions = model.fit_predict(X)
scores = model.decision_function(X)

# -1 means flagged as anomalous; 1 means not flagged.
results = df.copy()
results["AnomalyScore"] = scores
results["ModelFlag"] = [
    "Review" if prediction == -1 else "Baseline"
    for prediction in predictions
]

output_file = os.path.join(
    RESULTS_DIR, "anomaly_screening_results.csv"
)

results.to_csv(output_file, index=False)

print(f"\nRecords analyzed: {len(results)}")
print("\nModel screening summary:")
print(results["ModelFlag"].value_counts().to_string())

print("\nSample flagged records:")
flagged = results[results["ModelFlag"] == "Review"]

if flagged.empty:
    print("No records flagged.")
else:
    print(
        flagged[
            ["Timestamp", "RemotePort", "State",
             "ProcessName", "AnomalyScore", "ModelFlag"]
        ].head(10).to_string(index=False)
    )

print(f"\nResults saved to: {output_file}")
print("\nScreening complete.")
print("A Review flag is not proof of a cyberattack.")
