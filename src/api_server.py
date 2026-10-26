import os
import time
import json
import joblib
import numpy as np
from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(title="AI-Powered SDN Threat Protection API")

MODEL_DIR = "models"
LOG_DIR = "logs"
EVENTS_FILE = os.path.join(LOG_DIR, "security_events.json")
METRICS_FILE = os.path.join(MODEL_DIR, "evaluation_metrics.json")

os.makedirs(LOG_DIR, exist_ok=True)

scaler = joblib.load(os.path.join(MODEL_DIR, "scaler.pkl"))
rf_model = joblib.load(os.path.join(MODEL_DIR, "random_forest.pkl"))
iso_model = joblib.load(os.path.join(MODEL_DIR, "isolation_forest.pkl"))

WHITELIST_IPS = {"10.0.0.1", "10.0.0.4"}

if not os.path.exists(EVENTS_FILE):
    with open(EVENTS_FILE, "w") as f:
        json.dump([], f)


class FlowTelemetry(BaseModel):
    timestamp: float
    src_ip: str
    dst_ip: str
    flow_count: int
    pkt_rate: float
    byte_rate: float
    mean_pkt_size: float
    unique_dst_ports: int
    syn_ratio: float


def classify_attack_signature(telemetry: FlowTelemetry) -> str:
    if telemetry.unique_dst_ports >= 10:
        return "port_scan"
    if telemetry.pkt_rate > 80 and telemetry.syn_ratio >= 0.5:
        return "syn_flood"
    if telemetry.pkt_rate > 80:
        return "udp_dos_flood"
    return "suspicious_anomaly"


@app.get("/health")
def health_check():
    return {"status": "online", "model": "RandomForestClassifier"}


@app.get("/events")
def get_events():
    if os.path.exists(EVENTS_FILE):
        with open(EVENTS_FILE, "r") as f:
            return json.load(f)
    return []


@app.get("/metrics")
def get_metrics():
    if os.path.exists(METRICS_FILE):
        with open(METRICS_FILE, "r") as f:
            return json.load(f)
    return []


@app.post("/analyze")
def analyze_flow(telemetry: FlowTelemetry):
    t0 = time.perf_counter()

    features = np.array([[
        telemetry.flow_count,
        telemetry.pkt_rate,
        telemetry.byte_rate,
        telemetry.mean_pkt_size,
        telemetry.unique_dst_ports,
        telemetry.syn_ratio,
    ]])

    scaled = scaler.transform(features)
    rf_pred = int(rf_model.predict(scaled)[0])
    rf_conf = float(np.max(rf_model.predict_proba(scaled)[0]))
    iso_pred = 1 if int(iso_model.predict(scaled)[0]) == -1 else 0

    inference_ms = round((time.perf_counter() - t0) * 1000.0, 3)

    if rf_pred == 1 and telemetry.src_ip not in WHITELIST_IPS:
        action = "quarantine"
        threat_type = classify_attack_signature(telemetry)
    else:
        action = "allow"
        threat_type = "benign"

    event = {
        "time": time.strftime("%H:%M:%S", time.localtime()),
        "src_ip": telemetry.src_ip,
        "dst_ip": telemetry.dst_ip,
        "flow_count": telemetry.flow_count,
        "pkt_rate": telemetry.pkt_rate,
        "byte_rate": telemetry.byte_rate,
        "unique_dst_ports": telemetry.unique_dst_ports,
        "syn_ratio": telemetry.syn_ratio,
        "rf_prediction": rf_pred,
        "rf_confidence": round(rf_conf, 3),
        "iso_prediction": iso_pred,
        "threat_type": threat_type,
        "action": action,
        "inference_latency_ms": inference_ms,
    }

    try:
        with open(EVENTS_FILE, "r") as f:
            history = json.load(f)
    except Exception:
        history = []

    history.append(event)
    history = history[-300:]
    with open(EVENTS_FILE, "w") as f:
        json.dump(history, f, indent=2)

    return {
        "status": "processed",
        "src_ip": telemetry.src_ip,
        "prediction": rf_pred,
        "confidence": round(rf_conf, 3),
        "threat_type": threat_type,
        "action": action,
        "inference_latency_ms": inference_ms,
    }