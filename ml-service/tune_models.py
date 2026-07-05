"""
tune_models.py — Advanced model tuning with SMOTE, hyperparameter optimization,
and focus on improving rare attack detection (R2L, U2R).
"""

import os
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.metrics import (
    classification_report, accuracy_score, f1_score, precision_score, recall_score
)
from sklearn.utils.class_weight import compute_sample_weight
from sklearn.model_selection import GridSearchCV, StratifiedKFold
import joblib
import warnings
warnings.filterwarnings("ignore")

try:
    from imblearn.over_sampling import SMOTE
    HAS_IMBLEARN = True
except ImportError:
    HAS_IMBLEARN = False
    print("⚠️  imbalanced-learn not installed. Install with: pip install imbalanced-learn")

try:
    from xgboost import XGBClassifier
    HAS_XGBOOST = True
except ImportError:
    HAS_XGBOOST = False

# ── Paths ──────────────────────────────────────────────────────────────────────
DATA_DIR   = os.path.join(os.path.dirname(__file__), "data")
MODELS_DIR = os.path.join(os.path.dirname(__file__), "models")

TRAIN_FILE = os.path.join(DATA_DIR, "KDDTrain+.txt")
TEST_FILE  = os.path.join(DATA_DIR, "KDDTest+.txt")

# ── Column names ───────────────────────────────────────────────────────────────
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

# ── Attack mapping ─────────────────────────────────────────────────────────────
ATTACK_MAP = {
    "normal": "normal",
    "back":"dos","land":"dos","neptune":"dos","pod":"dos","smurf":"dos",
    "teardrop":"dos","apache2":"dos","udpstorm":"dos","processtable":"dos","mailbomb":"dos",
    "ipsweep":"probe","nmap":"probe","portsweep":"probe","satan":"probe",
    "mscan":"probe","saint":"probe",
    "ftp_write":"r2l","guess_passwd":"r2l","imap":"r2l","multihop":"r2l",
    "phf":"r2l","spy":"r2l","warezclient":"r2l","warezmaster":"r2l",
    "sendmail":"r2l","named":"r2l","snmpgetattack":"r2l","snmpguess":"r2l",
    "worm":"r2l","xlock":"r2l","xsnoop":"r2l","httptunnel":"r2l",
    "buffer_overflow":"u2r","loadmodule":"u2r","perl":"u2r","rootkit":"u2r",
    "ps":"u2r","sqlattack":"u2r","xterm":"u2r",
}

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
    return pd.read_csv(filepath, header=None, names=COLUMNS)


def safe_transform(le: LabelEncoder, series: pd.Series, unknown_value: int = 0) -> np.ndarray:
    values = series.astype(str)
    known = set(le.classes_)
    return np.array(
        [le.transform([value])[0] if value in known else unknown_value for value in values],
        dtype=np.int32,
    )


def preprocess(df: pd.DataFrame, encoders=None, label_encoder: LabelEncoder = None):
    df = df.copy()
    df["category"] = df["label"].str.lower().map(ATTACK_MAP).fillna("unknown")

    if encoders is None:
        le_proto   = LabelEncoder()
        le_service = LabelEncoder()
        le_flag    = LabelEncoder()
        df["protocol_type"] = le_proto.fit_transform(df["protocol_type"].astype(str))
        df["service"]       = le_service.fit_transform(df["service"].astype(str))
        df["flag"]          = le_flag.fit_transform(df["flag"].astype(str))
        encoders = (le_proto, le_service, le_flag)
    else:
        le_proto, le_service, le_flag = encoders
        df["protocol_type"] = safe_transform(le_proto, df["protocol_type"])
        df["service"]       = safe_transform(le_service, df["service"])
        df["flag"]          = safe_transform(le_flag, df["flag"])

    all_features = NUMERIC_FEATURES + ["protocol_type", "service", "flag"]
    X = df[all_features].values.astype(np.float32)

    if label_encoder is None:
        le_label = LabelEncoder()
        y_multi  = le_label.fit_transform(df["category"])
    else:
        le_label = label_encoder
        y_multi = le_label.transform(df["category"])

    y_binary = (df["category"] != "normal").astype(int).values
    return X, y_multi, y_binary, le_label, encoders


def apply_smote(X: np.ndarray, y: np.ndarray, random_state: int = 42):
    """Apply SMOTE to oversample minority classes."""
    if not HAS_IMBLEARN:
        print("  ! SMOTE skipped (imbalanced-learn not installed)")
        return X, y
    
    print("  Applying SMOTE for class balancing …", end=" ", flush=True)
    smote = SMOTE(random_state=random_state, k_neighbors=3)
    X_resampled, y_resampled = smote.fit_resample(X, y)
    print(f"done  ({len(X)} → {len(X_resampled)} samples)")
    return X_resampled, y_resampled


def tune_random_forest(X_train, y_train, X_test, y_test, le_label):
    """Tune Random Forest with GridSearchCV."""
    print("\n  ━━ Random Forest Tuning ━━")
    
    param_grid = {
        "n_estimators": [200, 300, 400],
        "max_depth": [15, 20, 25, 30],
        "min_samples_split": [2, 5, 10],
        "min_samples_leaf": [1, 2, 4],
        "max_features": ["sqrt", "log2"],
    }
    
    rf_base = RandomForestClassifier(
        class_weight="balanced_subsample",
        n_jobs=-1,
        random_state=42
    )
    
    print("  Running GridSearchCV (this may take a few minutes) …")
    cv = StratifiedKFold(n_splits=3, shuffle=True, random_state=42)
    
    # Focus on weighted F1 for imbalanced data
    grid_search = GridSearchCV(
        rf_base,
        param_grid,
        cv=cv,
        scoring="f1_weighted",
        n_jobs=-1,
        verbose=1
    )
    
    grid_search.fit(X_train, y_train)
    
    best_rf = grid_search.best_estimator_
    print(f"\n  ✓ Best params: {grid_search.best_params_}")
    
    # Evaluate
    y_pred = best_rf.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    f1_weighted = f1_score(y_test, y_pred, average="weighted")
    f1_macro = f1_score(y_test, y_pred, average="macro")
    
    print(f"  Test Accuracy: {accuracy*100:.2f}%")
    print(f"  Test F1 (weighted): {f1_weighted:.4f}")
    print(f"  Test F1 (macro): {f1_macro:.4f}")
    
    return best_rf, {"accuracy": accuracy, "f1_weighted": f1_weighted, "f1_macro": f1_macro}


def tune_xgboost(X_train, y_train, X_test, y_test, le_label):
    """Tune XGBoost with GridSearchCV."""
    if not HAS_XGBOOST:
        print("  ! XGBoost skipped (not installed)")
        return None, {}
    
    print("\n  ━━ XGBoost Tuning ━━")
    
    param_grid = {
        "n_estimators": [300, 400, 500],
        "max_depth": [5, 7, 9],
        "learning_rate": [0.01, 0.05, 0.1],
        "subsample": [0.7, 0.8, 0.9],
        "colsample_bytree": [0.7, 0.8, 0.9],
        "min_child_weight": [1, 3, 5],
    }
    
    xgb_base = XGBClassifier(
        eval_metric="mlogloss",
        n_jobs=-1,
        random_state=42,
        verbosity=0,
        use_label_encoder=False
    )
    
    print("  Running GridSearchCV (this may take a few minutes) …")
    cv = StratifiedKFold(n_splits=3, shuffle=True, random_state=42)
    
    grid_search = GridSearchCV(
        xgb_base,
        param_grid,
        cv=cv,
        scoring="f1_weighted",
        n_jobs=-1,
        verbose=1
    )
    
    grid_search.fit(X_train, y_train)
    
    best_xgb = grid_search.best_estimator_
    print(f"\n  ✓ Best params: {grid_search.best_params_}")
    
    # Evaluate
    y_pred = best_xgb.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    f1_weighted = f1_score(y_test, y_pred, average="weighted")
    f1_macro = f1_score(y_test, y_pred, average="macro")
    
    print(f"  Test Accuracy: {accuracy*100:.2f}%")
    print(f"  Test F1 (weighted): {f1_weighted:.4f}")
    print(f"  Test F1 (macro): {f1_macro:.4f}")
    
    return best_xgb, {"accuracy": accuracy, "f1_weighted": f1_weighted, "f1_macro": f1_macro}


def tune_models():
    print("\n" + "="*70)
    print("  NIDS — Advanced Model Tuning with SMOTE & Hyperparameter Optimization")
    print("="*70 + "\n")

    # Load data
    print("[ 1/5 ] Loading dataset …")
    train_df = load_data(TRAIN_FILE)
    test_df  = load_data(TEST_FILE)
    print(f"  Training: {len(train_df):,} samples")
    print(f"  Test:     {len(test_df):,} samples")

    # Preprocess
    print("\n[ 2/5 ] Preprocessing …")
    X_train, y_train, _, le_label, encoders = preprocess(train_df)
    X_test,  y_test,  _, *_ = preprocess(test_df, encoders=encoders, label_encoder=le_label)
    
    scaler = StandardScaler()
    X_train_s = scaler.fit_transform(X_train)
    X_test_s  = scaler.transform(X_test)
    
    print(f"  Classes: {list(le_label.classes_)}")
    
    # Class distribution
    unique, counts = np.unique(y_train, return_counts=True)
    print("\n  Class distribution (before SMOTE):")
    for idx, count in zip(unique, counts):
        pct = (count / len(y_train)) * 100
        print(f"    {le_label.classes_[idx]:8s}: {count:7,} ({pct:5.2f}%)")

    # Apply SMOTE
    print("\n[ 3/5 ] Applying SMOTE for class balancing …")
    X_train_balanced, y_train_balanced = apply_smote(X_train_s, y_train)
    
    unique, counts = np.unique(y_train_balanced, return_counts=True)
    print("\n  Class distribution (after SMOTE):")
    for idx, count in zip(unique, counts):
        pct = (count / len(y_train_balanced)) * 100
        print(f"    {le_label.classes_[idx]:8s}: {count:7,} ({pct:5.2f}%)")

    # Tune models
    print("\n[ 4/5 ] Hyperparameter tuning …")
    
    rf_tuned, rf_metrics = tune_random_forest(X_train_balanced, y_train_balanced, X_test_s, y_test, le_label)
    xgb_tuned, xgb_metrics = tune_xgboost(X_train_balanced, y_train_balanced, X_test_s, y_test, le_label)

    # Save tuned models
    print("\n[ 5/5 ] Saving tuned models …")
    joblib.dump(rf_tuned, os.path.join(MODELS_DIR, "random_forest_model_tuned.pkl"))
    if xgb_tuned:
        joblib.dump(xgb_tuned, os.path.join(MODELS_DIR, "xgboost_model_tuned.pkl"))
    joblib.dump(scaler, os.path.join(MODELS_DIR, "scaler.pkl"))
    joblib.dump(le_label, os.path.join(MODELS_DIR, "label_encoder.pkl"))
    joblib.dump(encoders, os.path.join(MODELS_DIR, "categorical_encoders.pkl"))
    print(f"  ✓ Models saved to {MODELS_DIR}")

    # Compare with original models
    print("\n" + "="*70)
    print("  Comparison: Original vs Tuned Models")
    print("="*70 + "\n")

    # Load original models for comparison
    try:
        rf_original = joblib.load(os.path.join(MODELS_DIR, "random_forest_model.pkl"))
        y_pred_rf_orig = rf_original.predict(X_test_s)
        rf_orig_acc = accuracy_score(y_test, y_pred_rf_orig)
        rf_orig_f1 = f1_score(y_test, y_pred_rf_orig, average="weighted")
    except:
        rf_orig_acc = rf_orig_f1 = None

    if xgb_tuned:
        try:
            xgb_original = joblib.load(os.path.join(MODELS_DIR, "xgboost_model.pkl"))
            y_pred_xgb_orig = xgb_original.predict(X_test_s)
            xgb_orig_acc = accuracy_score(y_test, y_pred_xgb_orig)
            xgb_orig_f1 = f1_score(y_test, y_pred_xgb_orig, average="weighted")
        except:
            xgb_orig_acc = xgb_orig_f1 = None

    # Display comparison
    print("Random Forest:")
    if rf_orig_acc:
        print(f"  Original Accuracy: {rf_orig_acc*100:.2f}%  →  Tuned: {rf_metrics['accuracy']*100:.2f}%  "
              f"(+{(rf_metrics['accuracy'] - rf_orig_acc)*100:.2f}%)")
        print(f"  Original F1: {rf_orig_f1:.4f}  →  Tuned: {rf_metrics['f1_weighted']:.4f}  "
              f"(+{rf_metrics['f1_weighted'] - rf_orig_f1:.4f})")
    else:
        print(f"  Tuned Accuracy: {rf_metrics['accuracy']*100:.2f}%")
        print(f"  Tuned F1: {rf_metrics['f1_weighted']:.4f}")

    if xgb_tuned:
        print("\nXGBoost:")
        if xgb_orig_acc:
            print(f"  Original Accuracy: {xgb_orig_acc*100:.2f}%  →  Tuned: {xgb_metrics['accuracy']*100:.2f}%  "
                  f"(+{(xgb_metrics['accuracy'] - xgb_orig_acc)*100:.2f}%)")
            print(f"  Original F1: {xgb_orig_f1:.4f}  →  Tuned: {xgb_metrics['f1_weighted']:.4f}  "
                  f"(+{xgb_metrics['f1_weighted'] - xgb_orig_f1:.4f})")
        else:
            print(f"  Tuned Accuracy: {xgb_metrics['accuracy']*100:.2f}%")
            print(f"  Tuned F1: {xgb_metrics['f1_weighted']:.4f}")

    print("\n" + "="*70)
    print("  Detailed Classification Report (Tuned XGBoost)")
    print("="*70 + "\n")
    y_pred = xgb_tuned.predict(X_test_s) if xgb_tuned else rf_tuned.predict(X_test_s)
    print(classification_report(y_test, y_pred, target_names=le_label.classes_))

    print("✅  Model tuning complete!")
    print("\nNext steps:")
    print("  1. Copy tuned models: mv *_tuned.pkl models/")
    print("  2. Or use tuned models directly in main.py")
    print("  3. Run test_accuracy.py again to verify improvements\n")


if __name__ == "__main__":
    tune_models()
