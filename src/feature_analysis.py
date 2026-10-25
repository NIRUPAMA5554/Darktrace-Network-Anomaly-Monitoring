
import os
import pandas as pd

PROJECT_DIR = r"D:\Users\HP\Documents\Desktop\Darktrace"
DATA_FILE = os.path.join(
    PROJECT_DIR, "data", "network_data_detailed.csv"
)
RESULTS_DIR = os.path.join(PROJECT_DIR, "results")

df = pd.read_csv(DATA_FILE)

print("=" * 55)
print(" DARKTRACE - FEATURE ANALYSIS")
print("=" * 55)

# Examine the variety of values in each candidate feature.
features = ["LocalPort", "RemotePort", "State", "ProcessName"]

summary = []

for column in features:
    summary.append({
        "Feature": column,
        "UniqueValues": df[column].nunique(dropna=False),
        "MostCommonValue": str(df[column].mode(dropna=False).iloc[0]),
        "MostCommonCount": int(
            df[column].value_counts(dropna=False).iloc[0]
        )
    })

feature_summary = pd.DataFrame(summary)

print("\n--- Feature variety ---")
print(feature_summary.to_string(index=False))

print("\n--- State distribution ---")
print(df["State"].value_counts().to_string())

print("\n--- Remote port distribution ---")
print(df["RemotePort"].value_counts().head(10).to_string())

feature_summary.to_csv(
    os.path.join(RESULTS_DIR, "feature_analysis.csv"),
    index=False
)

print("\nSaved: results\\feature_analysis.csv")
