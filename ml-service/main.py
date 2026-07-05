"""
main.py — FastAPI ML service for NIDS.
Loads trained models and exposes /predict and /predict/batch endpoints.
"""

import os
import time
import logging
import numpy as np
import pandas as pd
from typing import Optional, List, Dict, Any, Union

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
import joblib

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(message)s")
log = logging.getLogger("nids-ml")

# ── Paths ─────────────────────────────────────────────────────────────────────
MODELS_DIR = os.path.join(os.path.dirname(__file__), "models")

# ── Attack category metadata ──────────────────────────────────────────────────
CATEGORY_META = {
    "normal":  {"display": "Normal",          "severity": "info",     "color": "#22c55e"},
    "dos":     {"display": "DoS Attack",      "severity": "critical", "color": "#ef4444"},
    "probe":   {"display": "Probe/Scan",      "severity": "high",     "color": "#f97316"},
    "r2l":     {"display": "Remote-to-Local", "severity": "high",     "color": "#eab308"},
    "u2r":     {"display": "User-to-Root",    "severity": "critical", "color": "#a855f7"},
    "anomaly": {"display": "Anomaly",         "severity": "medium",   "color": "#06b6d4"},
    "unknown": {"display": "Unknown",         "severity": "low",      "color": "#6b7280"},
}

# Rule-based heuristic labels when models are not available
KNOWN_ATTACK_NAMES = {
    "dos":   "Neptune",
    "probe": "Portsweep",
    "r2l":   "GuestPasswd",
    "u2r":   "BufferOverflow",
}

# ── FastAPI App ────────────────────────────────────────────────────────────────
app = FastAPI(
    title="NIDS ML Service",
    description="Real-time network intrusion detection using XGBoost + Isolation Forest",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Model state ───────────────────────────────────────────────────────────────
models: Dict[str, Any] = {}


def load_models():
    """Attempt to load all trained models from disk."""
    global models
    loaded = {}

    files = {
        "rf":           "random_forest_model.pkl",
        "xgb":          "xgboost_model.pkl",
        "iso":          "isolation_forest_model.pkl",
        "preprocessor": "preprocessor.pkl",
        "le":           "label_encoder.pkl",
    }

    for key, fname in files.items():
        path = os.path.join(MODELS_DIR, fname)
        if os.path.exists(path):
            try:
                loaded[key] = joblib.load(path)
                log.info(f"  Loaded {fname}")
            except Exception as e:
                log.warning(f"  Could not load {fname}: {e}")

    models = loaded
    if models:
        log.info(f"Models loaded: {list(models.keys())}")
    else:
        log.warning("No trained models found. Using rule-based fallback.")


@app.on_event("startup")
def startup_event():
    log.info("Starting NIDS ML Service …")
    load_models()


# ── Pydantic schemas ──────────────────────────────────────────────────────────
class PacketFeatures(BaseModel):
    # Core features — all optional so partial packets are accepted
    duration:                    float = Field(0,    ge=0)
    protocol_type:               Union[float, str] = Field("tcp")
    service:                     Union[float, str] = Field("private")
    flag:                        Union[float, str] = Field("SF")
    src_bytes:                   float = Field(0,    ge=0)
    dst_bytes:                   float = Field(0,    ge=0)
    land:                        float = Field(0,    ge=0, le=1)
    wrong_fragment:              float = Field(0,    ge=0)
    urgent:                      float = Field(0,    ge=0)
    hot:                         float = Field(0,    ge=0)
    num_failed_logins:           float = Field(0,    ge=0)
    logged_in:                   float = Field(0,    ge=0, le=1)
    num_compromised:             float = Field(0,    ge=0)
    root_shell:                  float = Field(0,    ge=0, le=1)
    su_attempted:                float = Field(0,    ge=0, le=1)
    num_root:                    float = Field(0,    ge=0)
    num_file_creations:          float = Field(0,    ge=0)
    num_shells:                  float = Field(0,    ge=0)
    num_access_files:            float = Field(0,    ge=0)
    num_outbound_cmds:           float = Field(0,    ge=0)
    is_host_login:               float = Field(0,    ge=0, le=1)
    is_guest_login:              float = Field(0,    ge=0, le=1)
    count:                       float = Field(1,    ge=0)
    srv_count:                   float = Field(1,    ge=0)
    serror_rate:                 float = Field(0.0,  ge=0, le=1)
    srv_serror_rate:             float = Field(0.0,  ge=0, le=1)
    rerror_rate:                 float = Field(0.0,  ge=0, le=1)
    srv_rerror_rate:             float = Field(0.0,  ge=0, le=1)
    same_srv_rate:               float = Field(1.0,  ge=0, le=1)
    diff_srv_rate:               float = Field(0.0,  ge=0, le=1)
    srv_diff_host_rate:          float = Field(0.0,  ge=0, le=1)
    dst_host_count:              float = Field(1,    ge=0)
    dst_host_srv_count:          float = Field(1,    ge=0)
    dst_host_same_srv_rate:      float = Field(1.0,  ge=0, le=1)
    dst_host_diff_srv_rate:      float = Field(0.0,  ge=0, le=1)
    dst_host_same_src_port_rate: float = Field(0.0,  ge=0, le=1)
    dst_host_srv_diff_host_rate: float = Field(0.0,  ge=0, le=1)
    dst_host_serror_rate:        float = Field(0.0,  ge=0, le=1)
    dst_host_srv_serror_rate:    float = Field(0.0,  ge=0, le=1)
    dst_host_rerror_rate:        float = Field(0.0,  ge=0, le=1)
    dst_host_srv_rerror_rate:    float = Field(0.0,  ge=0, le=1)

    class Config:
        extra = "allow"   # ignore extra fields like src_ip, dst_ip


class BatchRequest(BaseModel):
    packets: List[PacketFeatures]


# ── Feature extraction helper ─────────────────────────────────────────────────
FEATURE_ORDER = [
    "duration","src_bytes","dst_bytes","land","wrong_fragment","urgent","hot",
    "num_failed_logins","logged_in","num_compromised","root_shell","su_attempted",
    "num_root","num_file_creations","num_shells","num_access_files",
    "num_outbound_cmds","is_host_login","is_guest_login","count","srv_count",
    "serror_rate","srv_serror_rate","rerror_rate","srv_rerror_rate","same_srv_rate",
    "diff_srv_rate","srv_diff_host_rate","dst_host_count","dst_host_srv_count",
    "dst_host_same_srv_rate","dst_host_diff_srv_rate","dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate","dst_host_serror_rate","dst_host_srv_serror_rate",
    "dst_host_rerror_rate","dst_host_srv_rerror_rate",
    "protocol_type","service","flag"
]

CATEGORICAL_DEFAULTS = {
    "protocol_type": "tcp",
    "service": "private",
    "flag": "OTH",
}


def packet_to_prep_vector(pkt: PacketFeatures) -> np.ndarray:
    data = pkt.dict()
    # Create DataFrame with exact column ordering matching FEATURE_ORDER
    df = pd.DataFrame([{f: data.get(f, 0) for f in FEATURE_ORDER}])
    
    preprocessor = models.get("preprocessor")
    if preprocessor:
        try:
            return preprocessor.transform(df)
        except Exception as e:
            log.warning(f"Preprocessor transform failed: {e}. Falling back to zeros.")
    
    # Preprocessor fallback shape: StandardScaler (38) + OneHotEncoder output columns
    # If we don't have it, we return a shape of (1, 41) filled with zeros
    return np.zeros((1, 41))


# ── Rule-based fallback ───────────────────────────────────────────────────────
def rule_based_predict(pkt: PacketFeatures) -> Dict[str, Any]:
    d = pkt.dict()
    if d.get("serror_rate", 0) > 0.8 or d.get("srv_serror_rate", 0) > 0.8:
        cat = "dos"
    elif d.get("diff_srv_rate", 0) > 0.6 and d.get("same_srv_rate", 1) < 0.4:
        cat = "probe"
    elif d.get("num_failed_logins", 0) > 3 or d.get("is_guest_login", 0) == 1:
        cat = "r2l"
    elif d.get("root_shell", 0) == 1 or d.get("su_attempted", 0) == 1:
        cat = "u2r"
    else:
        cat = "normal"

    is_attack = cat != "normal"
    return {
        "prediction":      KNOWN_ATTACK_NAMES.get(cat, cat.capitalize()) if is_attack else "normal",
        "is_attack":       is_attack,
        "confidence":      75.0,
        "attack_category": cat,
        "model_used":      "Rule-Based Heuristic",
        "features_received": len(FEATURE_ORDER),
        "meta":            CATEGORY_META.get(cat, CATEGORY_META["unknown"]),
    }


# ── ML prediction ─────────────────────────────────────────────────────────────
def ml_predict(pkt: PacketFeatures) -> Dict[str, Any]:
    if not models or "preprocessor" not in models:
        return rule_based_predict(pkt)

    X_prep = packet_to_prep_vector(pkt)
    le = models.get("le")

    # Isolation Forest check first
    anomaly_flag = False
    if "iso" in models:
        try:
            iso_pred = models["iso"].predict(X_prep)[0]   # -1 = anomaly
            if iso_pred == -1:
                anomaly_flag = True
        except Exception as e:
            log.warning(f"Isolation Forest prediction error: {e}")

    # Primary classifier
    classifier = models.get("xgb") or models.get("rf")
    if classifier is None:
        return rule_based_predict(pkt)

    try:
        probas = classifier.predict_proba(X_prep)[0]
        # Calibrated weights: dos, normal, probe, r2l, u2r
        # Class map: dos:0, normal:1, probe:2, r2l:3, u2r:4
        best_weights = np.array([1.0, 1.0, 1.8, 6.0, 10.0])
        adj_probas = probas * best_weights
        pred_idx = int(np.argmax(adj_probas))
        confidence = float(probas[pred_idx]) * 100
        if le:
            category = le.inverse_transform([pred_idx])[0]
        else:
            category = str(pred_idx)
    except Exception as e:
        log.error(f"Prediction error: {e}")
        return rule_based_predict(pkt)

    # Override with anomaly if classifier says normal but ISO disagrees
    if category == "normal" and anomaly_flag:
        category = "anomaly"
        confidence = 60.0

    is_attack = category != "normal"
    model_name = "XGBoost + IsolationForest" if "xgb" in models else "RandomForest + IsolationForest"

    return {
        "prediction":        KNOWN_ATTACK_NAMES.get(category, category.capitalize()),
        "is_attack":         is_attack,
        "confidence":        round(confidence, 2),
        "attack_category":   category,
        "model_used":        model_name,
        "features_received": X_prep.shape[1],
        "anomaly_detected":  anomaly_flag,
        "meta":              CATEGORY_META.get(category, CATEGORY_META["unknown"]),
    }


# ── Endpoints ─────────────────────────────────────────────────────────────────
@app.get("/")
def root():
    return {
        "status":        "NIDS ML Service running",
        "models_loaded": list(models.keys()),
        "using_fallback": len(models) == 0,
    }


@app.get("/health")
def health():
    return {"status": "ok", "timestamp": time.time()}


@app.post("/predict")
def predict(pkt: PacketFeatures):
    t0 = time.perf_counter()
    result = ml_predict(pkt)
    result["latency_ms"] = round((time.perf_counter() - t0) * 1000, 3)
    return result


@app.post("/predict/batch")
def predict_batch(req: BatchRequest):
    if len(req.packets) > 500:
        raise HTTPException(status_code=400, detail="Batch size must be <= 500")
    t0 = time.perf_counter()
    results = [ml_predict(p) for p in req.packets]
    return {
        "results":      results,
        "count":        len(results),
        "latency_ms":   round((time.perf_counter() - t0) * 1000, 3),
    }


@app.post("/reload-models")
def reload_models():
    load_models()
    return {"status": "reloaded", "models": list(models.keys())}
