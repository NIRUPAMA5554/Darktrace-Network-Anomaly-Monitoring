
from pathlib import Path

import pandas as pd

PROJECT = Path(__file__).resolve().parent
RESULTS = PROJECT / "results"
PUBLIC = PROJECT / "public_demo"
PUBLIC.mkdir(exist_ok=True)

# 1. Generate synthetic network records.
# These are examples, NOT records from your actual laptop.
demo = pd.DataFrame({
    "Timestamp": [
        "2026-01-01 10:00:00",
        "2026-01-01 10:00:10",
        "2026-01-01 10:00:20",
        "2026-01-01 10:00:30",
        "2026-01-01 10:00:40",
        "2026-01-01 10:00:50",
    ],
    "LocalAddress": ["DEMO-DEVICE"] * 6,
    "LocalPort": [443, 443, 80, 53, 8080, 443],
    "RemoteAddress": [
        "DEMO-ENDPOINT-1",
        "DEMO-ENDPOINT-2",
        "DEMO-ENDPOINT-1",
        "DEMO-ENDPOINT-3",
        "DEMO-ENDPOINT-4",
        "DEMO-ENDPOINT-2",
    ],
    "RemotePort": [443, 443, 80, 53, 8080, 443],
    "State": ["ESTABLISHED", "ESTABLISHED", "TIME_WAIT",
              "ESTABLISHED", "CLOSE_WAIT", "ESTABLISHED"],
    "ProcessId": [1001, 1002, 1003, 1004, 1005, 1006],
    "ProcessName": [
        "demo_browser", "demo_browser", "demo_web",
        "demo_dns", "demo_service", "demo_browser"
    ],
    "AnomalyScore": [-0.10, -0.08, -0.31, -0.05, -0.42, -0.12],
    "ReviewStatus": [
        "Baseline", "Baseline", "Review",
        "Baseline", "Review", "Baseline"
    ],
    "Interpretation": [
        "Synthetic baseline example",
        "Synthetic baseline example",
        "Synthetic unusual-pattern example",
        "Synthetic baseline example",
        "Synthetic unusual-pattern example",
        "Synthetic baseline example",
    ],
})
demo.to_csv(PUBLIC / "demo_results.csv", index=False)

# 2. Keep only fields used by the evaluation dashboard.
evaluation = pd.read_csv(
    RESULTS / "unsw_evaluation_results_v2.csv",
    usecols=["ActualLabel", "PredictedLabel"],
)
evaluation.to_csv(
    PUBLIC / "unsw_evaluation_results_v2.csv", index=False
)

# 3. Keep only model names and metrics needed for comparison.
comparison_columns = [
    "Version",
    "Accuracy",
    "Attack_Precision",
    "Attack_Recall",
    "Attack_F1_Score",
]
comparison = pd.read_csv(RESULTS / "evaluation_comparison.csv")

missing = set(comparison_columns) - set(comparison.columns)
if missing:
    raise ValueError(f"Missing comparison columns: {sorted(missing)}")

comparison[comparison_columns].to_csv(
    PUBLIC / "evaluation_comparison.csv", index=False
)

print("Created sanitized public demo files in public_demo/")
for file in sorted(PUBLIC.glob("*.csv")):
    print(f"{file.name}: {pd.read_csv(file).shape}")
