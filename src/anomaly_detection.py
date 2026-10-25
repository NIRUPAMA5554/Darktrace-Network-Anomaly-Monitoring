
import os
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.impute import SimpleImputer

PROJECT_DIR = r"D:\Users\HP\Documents\Desktop\Darktrace"
DATA_FILE = os.path.join(
    PROJECT_DIR, "data", "network_data_detailed.csv"
)
RESULTS_DIR = os.path.join(PROJECT_DIR, "results")
os.makedirs(RESULTS_DIR, exist_ok=True)

print("=" * 55)
print(" DARKTRACE - ANOMALY SCREENING V2")
print("=" * 55)

df = pd.read_csv(DATA_FILE)

numeric_features = ["LocalPort", "RemotePort"]
categorical_features = ["State", "ProcessName"]

# Prepare features without changing the original dataset.
X = df[numeric_features + categorical_features].copy()

for column in numeric_features:
    X[column] = pd.to_numeric(X[column], errors="coerce")

for column in categorical_features:
    X[column] = X[column].fillna("Unknown").astype(str)

# Numeric features: impute missing values and scale.
numeric_transformer = Pipeline([
    ("imputer", SimpleImputer(strategy="median")),
    ("scaler", StandardScaler())
])

# Categorical features: impute and one-hot encode.
categorical_transformer = Pipeline([
    ("imputer", SimpleImputer(strategy="most_frequent")),
    ("encoder", OneHotEncoder(handle_unknown="ignore"))
])

preprocessor = ColumnTransformer([
    ("numeric", numeric_transformer, numeric_features),
    ("categorical", categorical_transformer, categorical_features)
])

model = Pipeline([
    ("preprocessor", preprocessor),
    ("detector", IsolationForest(
        n_estimators=100,
        contamination=0.05,
        random_state=42
    ))
])

predictions = model.fit_predict(X)
scores = model.decision_function(X)

results = df.copy()
results["AnomalyScore"] = scores
results["ModelFlag"] = [
    "Review" if value == -1 else "Baseline"
    for value in predictions
]

output_file = os.path.join(
    RESULTS_DIR, "anomaly_screening_v2.csv"
)
results.to_csv(output_file, index=False)

print(f"\nRecords analyzed: {len(results)}")
print("\nScreening summary:")
print(results["ModelFlag"].value_counts().to_string())

print("\nFirst 10 records flagged for review:")
flagged = results[results["ModelFlag"] == "Review"]

if flagged.empty:
    print("No records flagged.")
else:
    print(flagged[
        ["Timestamp", "LocalPort", "RemotePort",
         "State", "ProcessName", "AnomalyScore"]
    ].head(10).to_string(index=False))

print(f"\nSaved results: {output_file}")
print("\nScreening complete.")
print("Review flags are not proof of cyberattacks.")
