
import os
import pandas as pd

PROJECT_DIR = r"D:\Users\HP\Documents\Desktop\Darktrace"
RESULTS_DIR = os.path.join(PROJECT_DIR, "results")

v1_file = os.path.join(
    RESULTS_DIR, "anomaly_screening_results.csv"
)
v2_file = os.path.join(
    RESULTS_DIR, "anomaly_screening_v2.csv"
)

v1 = pd.read_csv(v1_file)
v2 = pd.read_csv(v2_file)

# Compare record identity using connection details and timestamp.
keys = [
    "Timestamp", "LocalAddress", "LocalPort",
    "RemoteAddress", "RemotePort", "State",
    "ProcessId", "ProcessName"
]

v1_keys = v1[keys].copy()
v2_keys = v2[keys].copy()

v1_keys["V1_Review"] = v1["ModelFlag"].eq("Review")
v2_keys["V2_Review"] = v2["ModelFlag"].eq("Review")

comparison = v1_keys.merge(
    v2_keys,
    on=keys,
    how="outer",
    suffixes=("_V1", "_V2"),
    indicator=True
)

both_review = (
    comparison["V1_Review"].fillna(False)
    & comparison["V2_Review"].fillna(False)
).sum()

v1_only = (
    comparison["V1_Review"].fillna(False)
    & ~comparison["V2_Review"].fillna(False)
).sum()

v2_only = (
    ~comparison["V1_Review"].fillna(False)
    & comparison["V2_Review"].fillna(False)
).sum()

print("=" * 50)
print(" MODEL FLAG COMPARISON")
print("=" * 50)
print(f"V1 review records: {int(v1['ModelFlag'].eq('Review').sum())}")
print(f"V2 review records: {int(v2['ModelFlag'].eq('Review').sum())}")
print(f"Flagged in both: {int(both_review)}")
print(f"Flagged only in V1: {int(v1_only)}")
print(f"Flagged only in V2: {int(v2_only)}")

print("\nThis compares model flags, not attack-detection accuracy.")
