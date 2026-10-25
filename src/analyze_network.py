
import os
import pandas as pd

# Project data file path
PROJECT_DIR = r"D:\Users\HP\Documents\Desktop\Darktrace"
DATA_FILE = os.path.join(
    PROJECT_DIR, "data", "network_data_detailed.csv"
)
RESULTS_DIR = os.path.join(PROJECT_DIR, "results")

os.makedirs(RESULTS_DIR, exist_ok=True)

print("=" * 55)
print(" DARKTRACE - NETWORK DATA ANALYSIS")
print("=" * 55)

# Load collected network data
if not os.path.exists(DATA_FILE):
    raise FileNotFoundError(f"Dataset not found: {DATA_FILE}")

df = pd.read_csv(DATA_FILE)

# Check required columns
required_columns = [
    "Timestamp", "LocalAddress", "LocalPort",
    "RemoteAddress", "RemotePort", "State",
    "ProcessId", "ProcessName"
]

missing_columns = [
    col for col in required_columns if col not in df.columns
]

if missing_columns:
    raise ValueError(f"Missing columns: {missing_columns}")

# Basic data preparation
df["Timestamp"] = pd.to_datetime(
    df["Timestamp"], errors="coerce"
)

for col in ["LocalPort", "RemotePort", "ProcessId"]:
    df[col] = pd.to_numeric(df[col], errors="coerce")

print(f"\nTotal records: {len(df)}")
print(f"Total columns: {len(df.columns)}")
print(f"Unique timestamps: {df['Timestamp'].nunique()}")
print(f"Missing values: {int(df.isna().sum().sum())}")

# Summarize connection states
state_summary = (
    df["State"]
    .fillna("Unknown")
    .value_counts()
    .rename_axis("State")
    .reset_index(name="Count")
)

# Summarize processes
process_summary = (
    df["ProcessName"]
    .fillna("Unknown")
    .value_counts()
    .head(10)
    .rename_axis("ProcessName")
    .reset_index(name="Count")
)

# Save reports
state_summary.to_csv(
    os.path.join(RESULTS_DIR, "python_state_summary.csv"),
    index=False
)

process_summary.to_csv(
    os.path.join(RESULTS_DIR, "python_process_summary.csv"),
    index=False
)

# Save a prepared copy without modifying the original
df.to_csv(
    os.path.join(RESULTS_DIR, "prepared_network_data.csv"),
    index=False
)

print("\n--- Connection states ---")
print(state_summary.to_string(index=False))

print("\n--- Top 10 processes ---")
print(process_summary.to_string(index=False))

print("\nAnalysis completed successfully.")
print(f"Results saved in: {RESULTS_DIR}")
