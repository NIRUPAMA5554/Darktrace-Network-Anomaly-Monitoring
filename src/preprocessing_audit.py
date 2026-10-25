
import os
import pandas as pd

PROJECT_DIR = r"D:\Users\HP\Documents\Desktop\Darktrace"
INPUT_FILE = os.path.join(
    PROJECT_DIR, "data", "network_data_detailed.csv"
)
RESULTS_DIR = os.path.join(PROJECT_DIR, "results")

os.makedirs(RESULTS_DIR, exist_ok=True)

# Load original data without modifying it
df = pd.read_csv(INPUT_FILE)
original_rows = len(df)

print("=" * 55)
print(" DARKTRACE - DATA PREPROCESSING AUDIT")
print("=" * 55)

# 1. Basic information
print(f"\nTotal rows: {original_rows}")
print(f"Total columns: {len(df.columns)}")

# 2. Missing values
print("\n--- Missing values by column ---")
print(df.isna().sum().to_string())

# 3. Exact duplicate rows (all columns, including timestamp)
exact_duplicates = int(df.duplicated().sum())
print(f"\nExact duplicate rows: {exact_duplicates}")

# 4. Repeated connection details, ignoring timestamp
connection_columns = [
    "LocalAddress", "LocalPort", "RemoteAddress",
    "RemotePort", "State", "ProcessId", "ProcessName"
]

unique_connections = df[connection_columns].drop_duplicates().shape[0]
print(f"Unique connection-detail combinations: {unique_connections}")
print(
    "Rows beyond unique combinations: "
    f"{original_rows - unique_connections}"
)

# 5. Validate timestamps and numeric fields
timestamps = pd.to_datetime(df["Timestamp"], errors="coerce")
print(f"Invalid timestamps: {int(timestamps.isna().sum())}")

for column in ["LocalPort", "RemotePort", "ProcessId"]:
    numeric = pd.to_numeric(df[column], errors="coerce")
    invalid = int(numeric.isna().sum())
    print(f"Invalid {column} values: {invalid}")

# Port values should normally be within 0-65535
for column in ["LocalPort", "RemotePort"]:
    numeric = pd.to_numeric(df[column], errors="coerce")
    out_of_range = int(
        ((numeric < 0) | (numeric > 65535)).fillna(False).sum()
    )
    print(f"Out-of-range {column} values: {out_of_range}")

# 6. State and process distributions
print("\n--- Connection states ---")
print(df["State"].value_counts(dropna=False).to_string())

print("\n--- Top 10 process names ---")
print(df["ProcessName"].value_counts(dropna=False).head(10).to_string())

# Save an audit report
report = pd.DataFrame({
    "Metric": [
        "Total rows",
        "Total columns",
        "Exact duplicate rows",
        "Unique connection-detail combinations",
        "Rows beyond unique combinations",
        "Invalid timestamps",
        "Missing cells"
    ],
    "Value": [
        original_rows,
        len(df.columns),
        exact_duplicates,
        unique_connections,
        original_rows - unique_connections,
        int(timestamps.isna().sum()),
        int(df.isna().sum().sum())
    ]
})

report.to_csv(
    os.path.join(RESULTS_DIR, "preprocessing_audit.csv"),
    index=False
)

print("\nAudit complete. Original data was not changed.")
print("Report saved to results\\preprocessing_audit.csv")
