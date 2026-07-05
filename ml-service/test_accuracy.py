"""
test_accuracy.py — Comprehensive accuracy testing against NSL-KDD test dataset.
Tests all trained models and provides detailed performance metrics.
"""

import os
import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder, StandardScaler, OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.metrics import (
    classification_report, accuracy_score, f1_score, confusion_matrix,
    precision_score, recall_score, roc_auc_score, roc_curve
)
import joblib
import matplotlib.pyplot as plt
import seaborn as sns
from tabulate import tabulate

# ── Paths ──────────────────────────────────────────────────────────────────────
DATA_DIR   = os.path.join(os.path.dirname(__file__), "data")
MODELS_DIR = os.path.join(os.path.dirname(__file__), "models")

TEST_FILE = os.path.join(DATA_DIR, "KDDTest+.txt")

# ── Column names (41 features + label + difficulty) ───────────────────────────
COLUMNS = [
    "duration","protocol_type","service","flag","src_bytes","dst_bytes",
    "land","wrong_fragment","urgent","hot","num_failed_logins","logged_in",
    "num_compromised","root_shell","su_attempted","num_root","num_file_creations",
    "num_shells","num_access_files","num_outbound_cmds","is_host_login",
    "is_guest_login","count","srv_count","serror_rate","srv_serror_rate",
    "rerror_rate","srv_rerror_rate","same_srv_rate","diff_srv_rate",
    "srv_diff_host_rate","dst_host_count","dst_host_srv_count",
    "dst_host_same_srv_rate","dst_host_diff_srv_rate","dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate","dst_host_serror_rate","dst_host_srv_serror_rate",
    "dst_host_rerror_rate","dst_host_srv_rerror_rate","label","difficulty"
]

# ── Attack-category mapping ────────────────────────────────────────────────────
ATTACK_MAP = {
    "normal": "normal",
    # DoS
    "back":"dos","land":"dos","neptune":"dos","pod":"dos","smurf":"dos",
    "teardrop":"dos","apache2":"dos","udpstorm":"dos","processtable":"dos","mailbomb":"dos",
    # Probe
    "ipsweep":"probe","nmap":"probe","portsweep":"probe","satan":"probe",
    "mscan":"probe","saint":"probe",
    # R2L
    "ftp_write":"r2l","guess_passwd":"r2l","imap":"r2l","multihop":"r2l",
    "phf":"r2l","spy":"r2l","warezclient":"r2l","warezmaster":"r2l",
    "sendmail":"r2l","named":"r2l","snmpgetattack":"r2l","snmpguess":"r2l",
    "worm":"r2l","xlock":"r2l","xsnoop":"r2l","httptunnel":"r2l",
    # U2R
    "buffer_overflow":"u2r","loadmodule":"u2r","perl":"u2r","rootkit":"u2r",
    "ps":"u2r","sqlattack":"u2r","xterm":"u2r",
}

# ── Feature columns used for training ─────────────────────────────────────────
NUMERIC_FEATURES = [
    "duration","src_bytes","dst_bytes","land","wrong_fragment","urgent","hot",
    "num_failed_logins","logged_in","num_compromised","root_shell","su_attempted",
    "num_root","num_file_creations","num_shells","num_access_files",
    "num_outbound_cmds","is_host_login","is_guest_login","count","srv_count",
    "serror_rate","srv_serror_rate","rerror_rate","srv_rerror_rate","same_srv_rate",
    "diff_srv_rate","srv_diff_host_rate","dst_host_count","dst_host_srv_count",
    "dst_host_same_srv_rate","dst_host_diff_srv_rate","dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate","dst_host_serror_rate","dst_host_srv_serror_rate",
    "dst_host_rerror_rate","dst_host_srv_rerror_rate"
]


def load_data(filepath: str) -> pd.DataFrame:
    df = pd.read_csv(filepath, header=None, names=COLUMNS)
    return df


def safe_transform(le: LabelEncoder, series: pd.Series, unknown_value: int = 0) -> np.ndarray:
    values = series.astype(str)
    known = set(le.classes_)
    return np.array(
        [le.transform([value])[0] if value in known else unknown_value for value in values],
        dtype=np.int32,
    )


CATEGORICAL_FEATURES = ["protocol_type", "service", "flag"]


def preprocess_df(df: pd.DataFrame, preprocessor, label_encoder):
    df = df.copy()
    df["category"] = df["label"].str.lower().map(ATTACK_MAP).fillna("unknown")

    # Keep all features in correct order
    X_raw = df[NUMERIC_FEATURES + CATEGORICAL_FEATURES]
    X_prep = preprocessor.transform(X_raw)
    y_multi = label_encoder.transform(df["category"])
    y_binary = (df["category"] != "normal").astype(int).values

    return X_prep, y_multi, y_binary


def test_accuracy():
    print("\n" + "="*70)
    print("  NIDS — Accuracy Testing on NSL-KDD Test Dataset (With Calibrated Thresholds)")
    print("="*70 + "\n")

    # Load models
    print("[ 1/4 ] Loading trained models …")
    try:
        rf = joblib.load(os.path.join(MODELS_DIR, "random_forest_model.pkl"))
        xgb = joblib.load(os.path.join(MODELS_DIR, "xgboost_model.pkl"))
        iso = joblib.load(os.path.join(MODELS_DIR, "isolation_forest_model.pkl"))
        preprocessor = joblib.load(os.path.join(MODELS_DIR, "preprocessor.pkl"))
        le_label = joblib.load(os.path.join(MODELS_DIR, "label_encoder.pkl"))
        print("  ✓ All models loaded successfully\n")
    except Exception as e:
        print(f"  ✗ Error loading models: {e}")
        return

    # Load test data
    print("[ 2/4 ] Loading test dataset …")
    test_df = load_data(TEST_FILE)
    print(f"  Test samples: {len(test_df):,}\n")

    # Preprocess
    print("[ 3/4 ] Preprocessing test data …")
    X_test_prep, y_test_multi, y_test_binary = preprocess_df(
        test_df, preprocessor=preprocessor, label_encoder=le_label
    )
    print(f"  Feature count: {X_test_prep.shape[1]}")
    print(f"  Classes: {list(le_label.classes_)}\n")

    # Evaluate models
    print("[ 4/4 ] Evaluating models …\n")

    models_info = [
        ("Random Forest", rf),
        ("XGBoost", xgb),
    ]

    # Optimized class weights for threshold scaling: dos, normal, probe, r2l, u2r
    # Class map: dos:0, normal:1, probe:2, r2l:3, u2r:4
    best_weights = np.array([1.0, 1.0, 1.8, 6.0, 10.0])

    results = {}
    for model_name, model in models_info:
        if model is None:
            continue
        print(f"\n{'─'*70}")
        print(f"  {model_name} (Threshold Adjusted)")
        print(f"{'─'*70}")

        # Predictions with calibrated threshold weights
        probas = model.predict_proba(X_test_prep)
        adj_probas = probas * best_weights
        y_pred = np.argmax(adj_probas, axis=1)
        pred_labels = le_label.inverse_transform(y_pred)

        # Metrics
        accuracy = accuracy_score(y_test_multi, y_pred)
        f1_macro = f1_score(y_test_multi, y_pred, average="macro")
        f1_weighted = f1_score(y_test_multi, y_pred, average="weighted")
        precision = precision_score(y_test_multi, y_pred, average="weighted")
        recall = recall_score(y_test_multi, y_pred, average="weighted")

        results[model_name] = {
            "accuracy": accuracy,
            "f1_macro": f1_macro,
            "f1_weighted": f1_weighted,
            "precision": precision,
            "recall": recall,
            "y_pred": y_pred,
            "pred_labels": pred_labels,
        }

        # Display metrics
        print(f"\n  Overall Metrics:")
        metrics_table = [
            ["Accuracy", f"{accuracy*100:.2f}%"],
            ["Precision (weighted)", f"{precision*100:.2f}%"],
            ["Recall (weighted)", f"{recall*100:.2f}%"],
            ["F1-Score (macro)", f"{f1_macro:.4f}"],
            ["F1-Score (weighted)", f"{f1_weighted:.4f}"],
        ]
        print(tabulate(metrics_table, tablefmt="simple"))

        # Per-class metrics
        print(f"\n  Per-Class Metrics:")
        print(classification_report(y_test_multi, y_pred, target_names=le_label.classes_))

        # Confusion matrix
        cm = confusion_matrix(y_test_multi, y_pred)
        print(f"\n  Confusion Matrix:")
        cm_df = pd.DataFrame(cm, index=le_label.classes_, columns=le_label.classes_)
        print(cm_df)

        # Attack category breakdown
        print(f"\n  Attack Category Distribution (Predictions):")
        pred_dist = pd.Series(pred_labels).value_counts().sort_index()
        for cat, count in pred_dist.items():
            pct = (count / len(pred_labels)) * 100
            print(f"    {cat:12s}: {count:6,} ({pct:6.2f}%)")

    # Summary comparison
    print(f"\n{'='*70}")
    print("  SUMMARY — Model Comparison")
    print(f"{'='*70}\n")
    
    summary_data = []
    for model_name, metrics in results.items():
        summary_data.append([
            model_name,
            f"{metrics['accuracy']*100:.2f}%",
            f"{metrics['precision']*100:.2f}%",
            f"{metrics['recall']*100:.2f}%",
            f"{metrics['f1_weighted']:.4f}",
        ])
    
    print(tabulate(
        summary_data,
        headers=["Model", "Accuracy", "Precision", "Recall", "F1 (weighted)"],
        tablefmt="grid"
    ))

    # Best model
    best_model_name = max(results.items(), key=lambda x: x[1]["accuracy"])[0]
    best_accuracy = results[best_model_name]["accuracy"]
    print(f"\n  🏆 Best Model: {best_model_name} ({best_accuracy*100:.2f}% accuracy)\n")

    # Isolation Forest evaluation (binary: normal vs attack)
    print(f"{'='*70}")
    print("  Isolation Forest (Anomaly Detection - Binary)")
    print(f"{'='*70}\n")
    iso_scores = iso.decision_function(X_test_prep)
    iso_preds = iso.predict(X_test_prep)  # -1 = anomaly, 1 = normal
    iso_binary_pred = (iso_preds == -1).astype(int)  # 1 = anomaly, 0 = normal

    iso_accuracy = accuracy_score(y_test_binary, iso_binary_pred)
    iso_f1 = f1_score(y_test_binary, iso_binary_pred, average="weighted")
    iso_precision = precision_score(y_test_binary, iso_binary_pred, average="weighted")
    iso_recall = recall_score(y_test_binary, iso_binary_pred, average="weighted")

    iso_metrics_table = [
        ["Accuracy", f"{iso_accuracy*100:.2f}%"],
        ["Precision (weighted)", f"{iso_precision*100:.2f}%"],
        ["Recall (weighted)", f"{iso_recall*100:.2f}%"],
        ["F1-Score (weighted)", f"{iso_f1:.4f}"],
    ]
    print("  Binary Classification Metrics (Normal vs Attack):")
    print(tabulate(iso_metrics_table, tablefmt="simple"))
    print()

    print("✅  Accuracy testing complete!\n")


if __name__ == "__main__":
    test_accuracy()
