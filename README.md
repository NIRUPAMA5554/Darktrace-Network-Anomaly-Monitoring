# Darktrace-Inspired Network Anomaly Monitoring Prototype

## 1. Project Overview

This project is a Python-based prototype for network activity analysis and anomaly screening. It uses machine learning to identify network records that differ from learned patterns and marks them for further review.

The project is inspired by adaptive network threat detection concepts. It is an independent prototype and is not an official Darktrace product.

## 2. Objectives

- Analyze network connection records.
- Perform data preprocessing and feature analysis.
- Identify potentially unusual network activity using Isolation Forest.
- Evaluate anomaly detection using the labelled UNSW-NB15 dataset.
- Compare two model versions using classification metrics.
- Display findings through an interactive Streamlit dashboard.

## 3. Technologies Used

- Python
- Pandas
- Scikit-learn
- Streamlit
- Isolation Forest
- UNSW-NB15 dataset

## 4. Project Structure

```text
Darktrace/
├── data/
│   ├── network_data_detailed.csv
│   ├── process_summary.csv
│   ├── state_summary.csv
│   ├── UNSW_NB15_training-set.csv
│   └── UNSW_NB15_testing-set.csv
├── results/
│   ├── anomaly_screening_results.csv
│   ├── anomaly_screening_v2.csv
│   ├── demo_results.csv
│   ├── demo_alert.txt
│   ├── evaluation_comparison.csv
│   ├── feature_analysis.csv
│   ├── preprocessing_audit.csv
│   ├── prepared_network_data.csv
│   ├── python_process_summary.csv
│   ├── python_state_summary.csv
│   ├── unsw_evaluation_results.csv
│   └── unsw_evaluation_results_v2.csv
├── src/
│   ├── analyze_network.py
│   ├── anomaly_detection.py
│   ├── anomaly_detection_v1_backup.py
│   ├── app.py
│   ├── compare_evaluations.py
│   ├── compare_models.py
│   ├── demo.py
│   ├── evaluate_unsw.py
│   ├── feature_analysis.py
│   └── preprocessing_audit.py
├── requirements.txt
└── README.md
```

## 5. Installation

Install Python 3.10 or a compatible version.

Open a terminal in the project directory and install the dependencies:

```bash
python -m pip install -r requirements.txt
```

## 6. Run the Dashboard

From the project directory, run:

```bash
python -m streamlit run src/app.py
```

Streamlit will provide a local URL to open the dashboard in your browser.

## 7. Model Evaluation

The project evaluates its anomaly detection approach using the labelled UNSW-NB15 training and testing datasets.

The current Version 2 evaluation reported:

| Metric | Result |
|---|---:|
| Accuracy | 66.15% |
| Attack Precision | 89.05% |
| Attack Recall | 43.92% |
| Attack F1-score | 58.83% |

The comparison script calculates metrics from the saved prediction files. In the current evaluation, both versions were checked against the same test record IDs and actual labels.

## 8. Understanding the Results

- **Accuracy:** Proportion of test records classified correctly.
- **Attack precision:** Proportion of records predicted as attacks that were actually labelled attacks.
- **Attack recall:** Proportion of labelled attack records detected by the model.
- **Attack F1-score:** Harmonic mean of attack precision and attack recall.
- **Review:** An anomaly candidate that deserves further investigation.
- **Baseline:** A record not flagged by the model.

## 9. Limitations

- An anomaly flag does not confirm that a cyberattack occurred.
- The local network CSV contains connection snapshots and is not a labelled attack dataset.
- Results on UNSW-NB15 do not guarantee equivalent performance on live networks.
- The prototype does not independently verify, block, or remediate cyberattacks.
- Further testing, threshold tuning, and validation on representative network traffic are needed.

## 10. Future Improvements

- Add more network traffic features.
- Evaluate additional anomaly detection algorithms.
- Improve recall while managing false-positive alerts.
- Add alert history and monitoring reports.
- Test on additional representative datasets.
- Investigate safe integrations with authorized network monitoring tools.

## 11. Responsible Use

Use this prototype only with network data you are authorized to access. Treat its output as decision-support information requiring further investigation, not as a definitive security verdict.
