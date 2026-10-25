
from pathlib import Path

import pandas as pd
import streamlit as st

PROJECT = Path(__file__).resolve().parent.parent
RESULTS_DIR = PROJECT / "results"

RESULTS_FILE = RESULTS_DIR / "demo_results.csv"
EVALUATION_FILE = RESULTS_DIR / "unsw_evaluation_results_v2.csv"
COMPARISON_FILE = RESULTS_DIR / "evaluation_comparison.csv"

st.set_page_config(
    page_title="Network Anomaly Monitor",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ Darktrace-Inspired Network Anomaly Monitor")
st.caption(
    "Network activity analysis • Anomaly screening • Review dashboard"
)

# ==================================================
# 1. LOCAL NETWORK MONITORING
# ==================================================

st.header("🌐 Local Network Activity")

if not RESULTS_FILE.exists():
    st.error(
        "Local network results were not found. "
        "Run src/demo.py first."
    )
    st.stop()

try:
    df = pd.read_csv(RESULTS_FILE)
except (OSError, pd.errors.ParserError, UnicodeDecodeError) as exc:
    st.error(f"Could not read local network results: {exc}")
    st.stop()

required = [
    "ReviewStatus",
    "AnomalyScore",
    "ProcessName",
    "State",
    "LocalPort",
    "RemotePort",
]

missing = [column for column in required if column not in df.columns]

if missing:
    st.error(f"Missing required columns: {missing}")
    st.stop()

df["ReviewStatus"] = df["ReviewStatus"].fillna("Unknown").astype(str)
df["ProcessName"] = df["ProcessName"].fillna("Unknown").astype(str)
df["State"] = df["State"].fillna("Unknown").astype(str)

total = len(df)
review_count = int((df["ReviewStatus"] == "Review").sum())
baseline_count = int((df["ReviewStatus"] == "Baseline").sum())

st.subheader("Network Activity Overview")

c1, c2, c3 = st.columns(3)
c1.metric("Total Records", f"{total:,}")
c2.metric("Flagged for Review", f"{review_count:,}")
c3.metric("Baseline Records", f"{baseline_count:,}")

if total:
    review_fraction = review_count / total
    st.progress(
        review_fraction,
        text=f"{review_fraction:.1%} of records flagged for review",
    )

st.info(
    "A review flag means that a record was identified as unusual by "
    "the prototype. It does not confirm a cyberattack."
)

st.divider()
st.subheader("🚩 Records Flagged for Review")

review_df = df[df["ReviewStatus"] == "Review"].copy()

if review_df.empty:
    st.success("No records are currently flagged.")
else:
    st.dataframe(review_df, use_container_width=True, hide_index=True)

st.divider()
st.subheader("🔎 Explore Network Records")

f1, f2 = st.columns(2)

with f1:
    processes = ["All Processes"] + sorted(df["ProcessName"].unique().tolist())
    chosen_process = st.selectbox("Filter by process", processes)

with f2:
    statuses = ["All Statuses"] + sorted(df["ReviewStatus"].unique().tolist())
    chosen_status = st.selectbox("Filter by review status", statuses)

filtered = df.copy()

if chosen_process != "All Processes":
    filtered = filtered[filtered["ProcessName"] == chosen_process]

if chosen_status != "All Statuses":
    filtered = filtered[filtered["ReviewStatus"] == chosen_status]

st.write(f"Showing **{len(filtered):,}** of {total:,} records")
st.dataframe(filtered, use_container_width=True, hide_index=True)

st.download_button(
    label="⬇️ Download Filtered Network Records",
    data=filtered.to_csv(index=False).encode("utf-8"),
    file_name="filtered_network_records.csv",
    mime="text/csv",
)

st.divider()
st.subheader("📈 Network Activity Charts")

left, right = st.columns(2)

with left:
    st.write("Records by review status")
    status_counts = (
        df["ReviewStatus"]
        .value_counts()
        .rename_axis("Review Status")
        .to_frame("Records")
    )
    st.bar_chart(status_counts, y="Records")

with right:
    st.write("Top 10 processes by record count")
    process_counts = (
        df["ProcessName"]
        .value_counts()
        .head(10)
        .sort_values(ascending=True)
        .rename_axis("Process")
        .to_frame("Records")
    )
    st.bar_chart(process_counts, y="Records")

st.divider()
st.subheader("ℹ️ How to Read the Anomaly Score")

st.markdown(
    """
    - **Review:** The model considers this record unusual relative to
      the patterns it learned.
    - **Baseline:** The model did not flag this record.
    - **Anomaly score:** In this prototype, a lower score indicates a
      record considered more unusual by Isolation Forest.
    - **Limitation:** These local network records do not have confirmed
      attack labels, so local review flags cannot be counted as verified attacks.
    """
)

st.caption(
    "Local monitoring prototype • No automatic blocking • "
    "Human investigation required"
)

# ==================================================
# 2. LABELLED UNSW-NB15 EVALUATION
# ==================================================

st.divider()
st.header("📊 Model Evaluation — UNSW-NB15")

st.caption(
    "This section evaluates saved predictions on the labelled UNSW-NB15 "
    "test dataset. It is separate from the local network records above."
)

if not EVALUATION_FILE.exists():
    st.warning(
        "Evaluation results not found. Run src/evaluate_unsw.py first."
    )
else:
    try:
        eval_df = pd.read_csv(EVALUATION_FILE)

        expected = {"ActualLabel", "PredictedLabel"}
        if not expected.issubset(eval_df.columns):
            st.error(
                "The evaluation file must contain ActualLabel "
                "and PredictedLabel columns."
            )
        else:
            actual = pd.to_numeric(
                eval_df["ActualLabel"], errors="coerce"
            )
            predicted = pd.to_numeric(
                eval_df["PredictedLabel"], errors="coerce"
            )

            valid = (
                actual.isin([0, 1])
                & predicted.isin([0, 1])
            )
            actual = actual[valid].astype(int)
            predicted = predicted[valid].astype(int)

            if actual.empty:
                st.error("No valid labelled predictions were found.")
            else:
                tn = int(((actual == 0) & (predicted == 0)).sum())
                fp = int(((actual == 0) & (predicted == 1)).sum())
                fn = int(((actual == 1) & (predicted == 0)).sum())
                tp = int(((actual == 1) & (predicted == 1)).sum())

                precision = tp / (tp + fp) if tp + fp else 0.0
                recall = tp / (tp + fn) if tp + fn else 0.0
                f1 = (
                    2 * precision * recall / (precision + recall)
                    if precision + recall else 0.0
                )
                accuracy = (tp + tn) / len(actual)

                st.subheader("Version 2 Evaluation Metrics")

                m1, m2, m3, m4 = st.columns(4)
                m1.metric("Accuracy", f"{accuracy:.1%}")
                m2.metric("Attack Precision", f"{precision:.1%}")
                m3.metric("Attack Recall", f"{recall:.1%}")
                m4.metric("Attack F1-score", f"{f1:.1%}")

                st.caption(
                    f"Evaluated {len(actual):,} valid test records."
                )

                st.subheader("Confusion Matrix")

                matrix = pd.DataFrame(
                    [[tn, fp], [fn, tp]],
                    index=["Actual Normal", "Actual Attack"],
                    columns=["Predicted Normal", "Predicted Attack"],
                )

                st.dataframe(
                    matrix.style.format("{:,.0f}"),
                    use_container_width=True,
                )

                outcomes = pd.DataFrame(
                    {
                        "Correct predictions": [tn, tp],
                        "Incorrect predictions": [fp, fn],
                    },
                    index=["Normal records", "Attack records"],
                )

                st.write("**Correct vs incorrect predictions**")
                st.bar_chart(outcomes, height=300)

                st.download_button(
                    label="⬇️ Download UNSW-NB15 Evaluation Results",
                    data=eval_df.to_csv(index=False).encode("utf-8"),
                    file_name="unsw_evaluation_results.csv",
                    mime="text/csv",
                )

                st.caption(
                    "Precision measures the proportion of flagged records "
                    "that were labelled attacks. Recall measures the "
                    "proportion of labelled attacks detected. These scores "
                    "describe this benchmark evaluation, not guaranteed "
                    "performance on live traffic."
                )

    except (OSError, pd.errors.ParserError, UnicodeDecodeError) as exc:
        st.error(f"Could not read evaluation results: {exc}")

# ==================================================
# 3. VERSION COMPARISON
# ==================================================

st.divider()
st.header("🆚 Version 1 vs Version 2")

st.caption(
    "Comparison based on the rounded metrics saved from the two experiments."
)

if not COMPARISON_FILE.exists():
    st.info(
        "Version comparison not found. Run src/compare_evaluations.py first."
    )
else:
    try:
        comparison_df = pd.read_csv(COMPARISON_FILE)

        comparison_columns = {
            "Version",
            "Accuracy",
            "Attack_Precision",
            "Attack_Recall",
            "Attack_F1_Score",
        }

        if not comparison_columns.issubset(comparison_df.columns):
            st.warning(
                "The comparison file is missing expected metric columns."
            )
        else:
            metric_columns = {
                "Accuracy": "Accuracy",
                "Attack_Precision": "Attack Precision",
                "Attack_Recall": "Attack Recall",
                "Attack_F1_Score": "Attack F1-score",
            }

            chart_df = comparison_df.set_index("Version")[
                list(metric_columns.keys())
            ].rename(columns=metric_columns)

            chart_df = chart_df.apply(pd.to_numeric, errors="coerce")

            if chart_df.isna().any().any():
                st.warning("Some comparison metrics are not numeric.")
            else:
                st.dataframe(
                    (chart_df * 100).round(1).astype(str) + "%",
                    use_container_width=True,
                )

                # Grouped bars: compare metrics without stacking them.
                st.bar_chart(
                    chart_df.T * 100,
                    stack=False,
                    height=380,
                    y_label="Score (%)",
                )

                st.caption(
                    "Higher scores are generally desirable. Recall is "
                    "especially important because missed attacks are a key "
                    "limitation of the current prototype."
                )

    except (OSError, pd.errors.ParserError, UnicodeDecodeError) as exc:
        st.error(f"Could not read the comparison file: {exc}")

# ==================================================
# 4. PROJECT LIMITATIONS
# ==================================================

st.divider()
st.subheader("🛡️ Project Scope and Limitations")

st.markdown(
    """
    - This is a research prototype inspired by adaptive network anomaly monitoring.
    - The UNSW-NB15 dataset provides labelled benchmark records for evaluation.
    - Benchmark metrics do not establish the same performance on this laptop's
      local network traffic.
    - Anomaly flags are candidates for investigation, not confirmed attacks.
    - The prototype does not automatically block connections or respond to threats.
    """
)
