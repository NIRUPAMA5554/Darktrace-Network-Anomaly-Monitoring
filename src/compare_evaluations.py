
from pathlib import Path

import pandas as pd
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

PROJECT_DIR = Path(__file__).resolve().parent.parent
RESULTS_DIR = PROJECT_DIR / "results"

VERSION_FILES = {
    "Version 1": RESULTS_DIR / "unsw_evaluation_results.csv",
    "Version 2": RESULTS_DIR / "unsw_evaluation_results_v2.csv",
}

def evaluate_file(version, file_path):
    if not file_path.exists():
        raise FileNotFoundError(
            f"{version} results file not found: {file_path}"
        )

    df = pd.read_csv(file_path)

    required = {"ActualLabel", "PredictedLabel"}
    if not required.issubset(df.columns):
        raise ValueError(
            f"{version} file must contain {sorted(required)}"
        )

    actual = pd.to_numeric(df["ActualLabel"], errors="coerce")
    predicted = pd.to_numeric(df["PredictedLabel"], errors="coerce")

    valid = actual.isin([0, 1]) & predicted.isin([0, 1])
    actual = actual[valid].astype(int)
    predicted = predicted[valid].astype(int)

    if actual.empty:
        raise ValueError(f"No valid predictions found for {version}.")

    tp = int(((actual == 1) & (predicted == 1)).sum())
    fn = int(((actual == 1) & (predicted == 0)).sum())

    return {
        "Version": version,
        "Accuracy": accuracy_score(actual, predicted),
        "Attack_Precision": precision_score(
            actual, predicted, zero_division=0
        ),
        "Attack_Recall": recall_score(
            actual, predicted, zero_division=0
        ),
        "Attack_F1_Score": f1_score(
            actual, predicted, zero_division=0
        ),
        "Test_Records": len(actual),
        "Detected_Attacks": tp,
        "Missed_Attacks": fn,
    }

rows = [
    evaluate_file(version, path)
    for version, path in VERSION_FILES.items()
]

comparison = pd.DataFrame(rows)

output_file = RESULTS_DIR / "evaluation_comparison.csv"
comparison.to_csv(output_file, index=False)

print("\nVERSION 1 VS VERSION 2")
print("======================")
print(comparison.to_string(index=False, float_format=lambda x: f"{x:.4f}"))
print("\nComparison saved to:", output_file)
print("Metrics calculated directly from the saved prediction files.")
