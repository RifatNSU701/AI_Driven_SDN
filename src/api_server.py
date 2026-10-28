import os
import time
import json
import joblib
import numpy as np
import pandas as pd
from typing import Optional
from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from sqlalchemy.orm import Session

from src.database import (
    SessionLocal,
    User,
    SecurityEvent,
    PolicyRule,
    AuditLog,
    get_db,
    init_db,
)
from src.auth import (
    hash_password,
    verify_password,
    create_access_token,
    get_current_user,
     seed_default_accounts,
    log_audit,
)

app = FastAPI(
    title="AI-Powered SDN Threat Protection Enterprise API",
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

MODEL_DIR = "models"
LOG_DIR = "logs"
WEB_DIR = os.path.join("src", "web")
EVENTS_FILE = os.path.join(LOG_DIR, "security_events.json")
METRICS_FILE = os.path.join(MODEL_DIR, "evaluation_metrics.json")
IMPORTANCE_FILE = os.path.join(MODEL_DIR, "feature_importances.json")

os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(WEB_DIR, exist_ok=True)

seed_default_accounts()

scaler = joblib.load(os.path.join(MODEL_DIR, "scaler.pkl"))
iso_model = joblib.load(os.path.join(MODEL_DIR, "isolation_forest.pkl"))
rf_model = joblib.load(os.path.join(MODEL_DIR, "random_forest.pkl"))
gb_model = joblib.load(os.path.join(MODEL_DIR, "gradient_boosting.pkl"))
mlp_model = joblib.load(os.path.join(MODEL_DIR, "mlp_neural_net.pkl"))

AVAILABLE_MODELS = [
    "Ensemble Voting (All 5 Models)",
    "Random Forest",
    "Gradient Boosting",
    "Deep Neural Network (MLP)",
    "Isolation Forest",
    "Baseline Threshold",
]

RUNTIME_CONFIG = {
    "active_model": "Ensemble Voting (All 5 Models)",
    "auto_quarantine": True,
    "default_rate_limit_kbps": 512,
}

if not os.path.exists(EVENTS_FILE):
    with open(EVENTS_FILE, "w") as f:
        json.dump([], f)


class LoginRequest(BaseModel):
    username: str
    password: str


class RegisterRequest(BaseModel):
    username: str
    email: str
    full_name: str
    password: str
    role: str = "analyst"


class ModelSelectRequest(BaseModel):
    model_name: str


class PolicyActionRequest(BaseModel):
    target_ip: str
    rule_type: str  # 'quarantine', 'rate_limit', 'whitelist'
    rate_kbps: int = 0
    reason: str = "Manual SOC Operator Action"


class UnblockRequest(BaseModel):
    target_ip: str


class SimulationRequest(BaseModel):
    scenario: str  # 'benign', 'high_vol', 'port_scan', 'syn_flood', 'stealth_scan', 'kali_attack'


class FlowTelemetry(BaseModel):
    timestamp: Optional[float] = None
    src_ip: str
    dst_ip: str
    flow_count: int
    pkt_rate: float
    byte_rate: float
    mean_pkt_size: float
    unique_dst_ports: int
    syn_ratio: float


def classify_attack_signature(t: FlowTelemetry) -> str:
    if t.unique_dst_ports >= 10 and t.pkt_rate < 40:
        return "stealth_port_scan"
    if t.unique_dst_ports >= 10:
        return "port_scan"
    if t.pkt_rate > 80 and t.syn_ratio >= 0.5:
        return "syn_flood"
    if t.pkt_rate > 80:
        return "udp_dos_flood"
    return "suspicious_anomaly"


def generate_xai_explanation(t: FlowTelemetry, pred: int, votes: dict) -> str:
    if pred == 0:
        if t.pkt_rate > 100:
            return f"Allowed: High-volume transfer ({t.pkt_rate:.0f} pkts/s) with normal port count ({t.unique_dst_ports}) and low SYN ratio ({t.syn_ratio:.2f})."
        return f"Allowed: Normal baseline flow ({t.pkt_rate:.1f} pkts/s, {t.unique_dst_ports} port)."

    reasons = []
    if t.unique_dst_ports >= 10:
        reasons.append(f"abnormal destination port fan-out ({t.unique_dst_ports} ports)")
    if t.syn_ratio >= 0.5:
        reasons.append(f"elevated TCP SYN ratio ({t.syn_ratio * 100:.0f}%)")
    if t.pkt_rate > 80:
        reasons.append(f"flood-level packet rate ({t.pkt_rate:.0f} pkts/s)")
    if t.mean_pkt_size <= 64:
        reasons.append(f"small probe packet size ({t.mean_pkt_size:.0f} B)")

    flagged_by = [k for k, v in votes.items() if v == 1]
    reason_str = ", ".join(reasons) if reasons else "multi-feature statistical deviation"
    return f"Flagged due to {reason_str}. Confirmed by {len(flagged_by)}/5 detectors ({', '.join(flagged_by)})."


def run_all_models(telemetry: FlowTelemetry, scaled_features: np.ndarray):
    base_pred = 1 if (
        telemetry.unique_dst_ports > 10
        or telemetry.pkt_rate > 150
        or telemetry.syn_ratio > 0.6
    ) else 0

    iso_pred = 1 if int(iso_model.predict(scaled_features)[0]) == -1 else 0
    rf_pred = int(rf_model.predict(scaled_features)[0])
    rf_conf = float(np.max(rf_model.predict_proba(scaled_features)[0]))

    gb_pred = int(gb_model.predict(scaled_features)[0])
    gb_conf = float(np.max(gb_model.predict_proba(scaled_features)[0]))

    mlp_pred = int(mlp_model.predict(scaled_features)[0])
    mlp_conf = float(np.max(mlp_model.predict_proba(scaled_features)[0]))

    votes = {
        "Baseline Threshold": base_pred,
        "Isolation Forest": iso_pred,
        "Random Forest": rf_pred,
        "Gradient Boosting": gb_pred,
        "Deep Neural Network (MLP)": mlp_pred,
    }

    # Weighted ensemble vote (supervised models carry higher weight than unsupervised)
    weighted_score = (
        (rf_pred * 0.35)
        + (gb_pred * 0.30)
        + (mlp_pred * 0.20)
        + (base_pred * 0.10)
        + (iso_pred * 0.05)
    )
    ensemble_pred = 1 if weighted_score >= 0.45 else 0
    ensemble_conf = round(max(weighted_score, 1.0 - weighted_score), 3)

    active = RUNTIME_CONFIG["active_model"]
    if active == "Random Forest":
        final_pred, final_conf = rf_pred, rf_conf
    elif active == "Gradient Boosting":
        final_pred, final_conf = gb_pred, gb_conf
    elif active == "Deep Neural Network (MLP)":
        final_pred, final_conf = mlp_pred, mlp_conf
    elif active == "Isolation Forest":
        final_pred, final_conf = iso_pred, 0.85 if iso_pred == 1 else 0.90
    elif active == "Baseline Threshold":
        final_pred, final_conf = base_pred, 0.80 if base_pred == 1 else 0.90
    else:
        final_pred, final_conf = ensemble_pred, ensemble_conf

    return final_pred, round(final_conf, 3), votes


@app.get("/", response_class=HTMLResponse)
def serve_root():
    index_path = os.path.join(WEB_DIR, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return HTMLResponse(
        "<h2>AI-Powered SDN Threat Protection API v2.0 is Online.</h2>"
        "<p>Visit <a href='/docs'>/docs</a> for interactive API documentation.</p>"
    )


@app.get("/health")
def health_check():
    return {
        "status": "online",
        "active_model": RUNTIME_CONFIG["active_model"],
        "available_models": AVAILABLE_MODELS,
    }


@app.post("/api/auth/login")
def login(req: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == req.username, User.is_active == True).first()
    if not user or not verify_password(req.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid username or password")

    token = create_access_token({"sub": user.username, "role": user.role})
    log_audit(db, user.username, user.role, "USER_LOGIN", f"Logged in to SOC portal")
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "username": user.username,
            "full_name": user.full_name,
            "email": user.email,
            "role": user.role,
        },
    }


@app.post("/api/auth/register")
def register(req: RegisterRequest, db: Session = Depends(get_db)):
    if db.query(User).filter((User.username == req.username) | (User.email == req.email)).first():
        raise HTTPException(status_code=400, detail="Username or email already registered")

    role = req.role if req.role in ("admin", "analyst") else "analyst"
    new_user = User(
        username=req.username.strip(),
        email=req.email.strip(),
        full_name=req.full_name.strip(),
        password_hash=hash_password(req.password),
        role=role,
    )
    db.add(new_user)
    db.commit()
    log_audit(db, new_user.username, new_user.role, "USER_REGISTER", f"Registered new {role} account")
    token = create_access_token({"sub": new_user.username, "role": new_user.role})
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "username": new_user.username,
            "full_name": new_user.full_name,
            "email": new_user.email,
            "role": new_user.role,
        },
    }


@app.get("/api/auth/me")
def current_user_info(user: User = Depends(get_current_user)):
    return {
        "username": user.username,
        "full_name": user.full_name,
        "email": user.email,
        "role": user.role,
    }


@app.get("/metrics")
@app.get("/api/models")
def get_models_and_metrics():
    metrics = []
    importances = {}
    if os.path.exists(METRICS_FILE):
        with open(METRICS_FILE, "r") as f:
            metrics = json.load(f)
    if os.path.exists(IMPORTANCE_FILE):
        with open(IMPORTANCE_FILE, "r") as f:
            importances = json.load(f)
    return {
        "active_model": RUNTIME_CONFIG["active_model"],
        "available_models": AVAILABLE_MODELS,
        "benchmarks": metrics,
        "feature_importances": importances,
    }


@app.post("/api/models/select")
def select_active_model(req: ModelSelectRequest, db: Session = Depends(get_db)):
    if req.model_name not in AVAILABLE_MODELS:
        raise HTTPException(status_code=400, detail="Unsupported model name")
    RUNTIME_CONFIG["active_model"] = req.model_name
    log_audit(db, "admin", "admin", "SWITCH_MODEL", f"Switched active detector to {req.model_name}")
    return {"status": "updated", "active_model": RUNTIME_CONFIG["active_model"]}


@app.get("/events")
@app.get("/api/events")
def get_events(limit: int = 150, db: Session = Depends(get_db)):
    db_events = (
        db.query(SecurityEvent)
        .order_by(SecurityEvent.id.desc())
        .limit(limit)
        .all()
    )
    if db_events:
        return [
            {
                "id": e.id,
                "time": e.time_str,
                "src_ip": e.src_ip,
                "dst_ip": e.dst_ip,
                "flow_count": e.flow_count,
                "pkt_rate": e.pkt_rate,
                "byte_rate": e.byte_rate,
                "mean_pkt_size": e.mean_pkt_size,
                "unique_dst_ports": e.unique_dst_ports,
                "syn_ratio": e.syn_ratio,
                "active_model": e.active_model,
                "rf_prediction": e.rf_prediction,
                "rf_confidence": e.rf_confidence,
                "iso_prediction": e.iso_prediction,
                "threat_type": e.threat_type,
                "explanation": e.explanation,
                "action": e.action,
                "inference_latency_ms": e.inference_latency_ms,
            }
            for e in reversed(db_events)
        ]

    if os.path.exists(EVENTS_FILE):
        with open(EVENTS_FILE, "r") as f:
            return json.load(f)
    return []


@app.delete("/api/events/clear")
def clear_events(db: Session = Depends(get_db)):
    db.query(SecurityEvent).delete()
    db.query(PolicyRule).filter(PolicyRule.rule_type != "whitelist").delete()
    db.commit()
    with open(EVENTS_FILE, "w") as f:
        json.dump([], f)
    log_audit(db, "admin", "admin", "CLEAR_TELEMETRY", "Cleared live security event log and active blocks")
    return {"status": "cleared"}


@app.get("/api/policies")
def get_policies(db: Session = Depends(get_db)):
    rules = db.query(PolicyRule).filter(PolicyRule.status == "active").order_by(PolicyRule.id.desc()).all()
    return [
        {
            "id": r.id,
            "target_ip": r.target_ip,
            "rule_type": r.rule_type,
            "rate_kbps": r.rate_kbps,
            "priority": r.priority,
            "status": r.status,
            "reason": r.reason,
            "created_by": r.created_by,
            "created_at": r.created_at.strftime("%Y-%m-%d %H:%M:%S") if r.created_at else "",
        }
        for r in rules
    ]


@app.post("/api/policies/enforce")
def enforce_policy(req: PolicyActionRequest, db: Session = Depends(get_db)):
    existing = (
        db.query(PolicyRule)
        .filter(
            PolicyRule.target_ip == req.target_ip,
            PolicyRule.rule_type == req.rule_type,
            PolicyRule.status == "active",
        )
        .first()
    )
    if not existing:
        rule = PolicyRule(
            target_ip=req.target_ip,
            rule_type=req.rule_type,
            rate_kbps=req.rate_kbps,
            priority=200 if req.rule_type == "whitelist" else 100,
            status="active",
            reason=req.reason,
            created_by="soc_operator",
        )
        db.add(rule)
        db.commit()
    log_audit(db, "admin", "admin", f"POLICY_{req.rule_type.upper()}", f"Applied {req.rule_type} on {req.target_ip}")
    return {"status": "enforced", "target_ip": req.target_ip, "rule_type": req.rule_type}


@app.post("/api/policies/unblock")
def unblock_host(req: UnblockRequest, db: Session = Depends(get_db)):
    rules = (
        db.query(PolicyRule)
        .filter(
            PolicyRule.target_ip == req.target_ip,
            PolicyRule.rule_type.in_(["quarantine", "rate_limit"]),
            PolicyRule.status == "active",
        )
        .all()
    )
    for r in rules:
        r.status = "removed"
    db.commit()
    log_audit(db, "admin", "admin", "UNBLOCK_HOST", f"Removed quarantine/rate-limit on {req.target_ip}")
    return {"status": "unblocked", "target_ip": req.target_ip}


@app.get("/api/audit")
def get_audit_logs(limit: int = 50, db: Session = Depends(get_db)):
    logs = db.query(AuditLog).order_by(AuditLog.id.desc()).limit(limit).all()
    return [
        {
            "id": l.id,
            "timestamp": l.timestamp.strftime("%Y-%m-%d %H:%M:%S") if l.timestamp else "",
            "username": l.username,
            "role": l.role,
            "action": l.action,
            "details": l.details,
        }
        for l in logs
    ]


@app.get("/api/stats")
def get_soc_stats(db: Session = Depends(get_db)):
    total_events = db.query(SecurityEvent).count()
    quarantines = db.query(SecurityEvent).filter(SecurityEvent.action == "quarantine").count()
    rate_limits = db.query(SecurityEvent).filter(SecurityEvent.action == "rate_limit").count()
    active_blocks = (
        db.query(PolicyRule)
        .filter(PolicyRule.rule_type == "quarantine", PolicyRule.status == "active")
        .all()
    )
    blocked_ips = list({r.target_ip for r in active_blocks})

    recent = db.query(SecurityEvent).order_by(SecurityEvent.id.desc()).limit(30).all()
    avg_lat = (
        round(sum(e.inference_latency_ms for e in recent) / len(recent), 3)
        if recent
        else 0.111
    )

    return {
        "total_events": total_events,
        "quarantines": quarantines,
        "rate_limits": rate_limits,
        "active_model": RUNTIME_CONFIG["active_model"],
        "avg_latency_ms": avg_lat,
        "blocked_ips": blocked_ips,
        "system_status": "THREAT CONTAINED" if blocked_ips else "NETWORK HEALTHY",
    }


@app.post("/analyze")
@app.post("/api/analyze")
def analyze_flow(telemetry: FlowTelemetry, db: Session = Depends(get_db)):
    t0 = time.perf_counter()

    features_df = pd.DataFrame(
        [
            {
                "flow_count": telemetry.flow_count,
                "pkt_rate": telemetry.pkt_rate,
                "byte_rate": telemetry.byte_rate,
                "mean_pkt_size": telemetry.mean_pkt_size,
                "unique_dst_ports": telemetry.unique_dst_ports,
                "syn_ratio": telemetry.syn_ratio,
            }
        ]
    )

    scaled = scaler.transform(features_df)
    pred, conf, votes = run_all_models(telemetry, scaled)
    inference_ms = round((time.perf_counter() - t0) * 1000.0, 3)

    whitelist = {
        r.target_ip
        for r in db.query(PolicyRule)
        .filter(PolicyRule.rule_type == "whitelist", PolicyRule.status == "active")
        .all()
    }

    if pred == 1 and telemetry.src_ip not in whitelist:
        threat_type = classify_attack_signature(telemetry)
        if threat_type == "stealth_port_scan" and telemetry.pkt_rate < 25:
            action = "quarantine"
        else:
            action = "quarantine"

        existing_rule = (
            db.query(PolicyRule)
            .filter(
                PolicyRule.target_ip == telemetry.src_ip,
                PolicyRule.rule_type == action,
                PolicyRule.status == "active",
            )
            .first()
        )
        if not existing_rule:
            db.add(
                PolicyRule(
                    target_ip=telemetry.src_ip,
                    rule_type=action,
                    priority=100,
                    status="active",
                    reason=f"Auto-{action}: {threat_type} ({RUNTIME_CONFIG['active_model']})",
                    created_by="ml_engine",
                )
            )
    else:
        action = "allow"
        threat_type = "benign"

    explanation = generate_xai_explanation(telemetry, pred, votes)
    now_str = time.strftime("%H:%M:%S", time.localtime())

    db_event = SecurityEvent(
        timestamp=telemetry.timestamp or time.time(),
        time_str=now_str,
        src_ip=telemetry.src_ip,
        dst_ip=telemetry.dst_ip,
        flow_count=telemetry.flow_count,
        pkt_rate=telemetry.pkt_rate,
        byte_rate=telemetry.byte_rate,
        mean_pkt_size=telemetry.mean_pkt_size,
        unique_dst_ports=telemetry.unique_dst_ports,
        syn_ratio=telemetry.syn_ratio,
        active_model=RUNTIME_CONFIG["active_model"],
        rf_prediction=pred,
        rf_confidence=conf,
        iso_prediction=votes["Isolation Forest"],
        threat_type=threat_type,
        explanation=explanation,
        action=action,
        inference_latency_ms=inference_ms,
    )
    db.add(db_event)
    db.commit()

    event_dict = {
        "time": now_str,
        "src_ip": telemetry.src_ip,
        "dst_ip": telemetry.dst_ip,
        "flow_count": telemetry.flow_count,
        "pkt_rate": telemetry.pkt_rate,
        "byte_rate": telemetry.byte_rate,
        "mean_pkt_size": telemetry.mean_pkt_size,
        "unique_dst_ports": telemetry.unique_dst_ports,
        "syn_ratio": telemetry.syn_ratio,
        "active_model": RUNTIME_CONFIG["active_model"],
        "rf_prediction": pred,
        "rf_confidence": conf,
        "iso_prediction": votes["Isolation Forest"],
        "model_votes": votes,
        "threat_type": threat_type,
        "explanation": explanation,
        "action": action,
        "inference_latency_ms": inference_ms,
    }

    try:
        with open(EVENTS_FILE, "r") as f:
            history = json.load(f)
    except Exception:
        history = []

    history.append(event_dict)
    history = history[-300:]
    with open(EVENTS_FILE, "w") as f:
        json.dump(history, f, indent=2)

    return {
        "status": "processed",
        "src_ip": telemetry.src_ip,
        "active_model": RUNTIME_CONFIG["active_model"],
        "prediction": pred,
        "confidence": conf,
        "model_votes": votes,
        "threat_type": threat_type,
        "explanation": explanation,
        "action": action,
        "inference_latency_ms": inference_ms,
    }


@app.post("/api/simulate")
def simulate_traffic(req: SimulationRequest, db: Session = Depends(get_db)):
    scenarios = {
        "benign": FlowTelemetry(
            src_ip="10.0.0.2", dst_ip="10.0.0.1", flow_count=2, pkt_rate=5.0,
            byte_rate=490.0, mean_pkt_size=98.0, unique_dst_ports=1, syn_ratio=0.10
        ),
        "mint_benign": FlowTelemetry(
            src_ip="10.10.10.3", dst_ip="10.10.10.1", flow_count=3, pkt_rate=12.0,
            byte_rate=1176.0, mean_pkt_size=98.0, unique_dst_ports=2, syn_ratio=0.10
        ),
        "high_vol": FlowTelemetry(
            src_ip="10.0.0.2", dst_ip="10.0.0.4", flow_count=4, pkt_rate=420.0,
            byte_rate=609000.0, mean_pkt_size=1450.0, unique_dst_ports=2, syn_ratio=0.05
        ),
        "port_scan": FlowTelemetry(
            src_ip="10.0.0.3", dst_ip="10.0.0.1", flow_count=45, pkt_rate=62.0,
            byte_rate=3596.0, mean_pkt_size=58.0, unique_dst_ports=40, syn_ratio=0.95
        ),
        "syn_flood": FlowTelemetry(
            src_ip="10.0.0.3", dst_ip="10.0.0.1", flow_count=38, pkt_rate=285.0,
            byte_rate=11970.0, mean_pkt_size=42.0, unique_dst_ports=1, syn_ratio=0.98
        ),
        "kali_attack": FlowTelemetry(
            src_ip="10.10.10.2", dst_ip="10.10.10.1", flow_count=60, pkt_rate=340.0,
            byte_rate=14280.0, mean_pkt_size=42.0, unique_dst_ports=35, syn_ratio=0.96
        ),
    }
    flow = scenarios.get(req.scenario, scenarios["benign"])
    return analyze_flow(flow, db)
from fastapi.responses import PlainTextResponse
from src.observability import generate_prometheus_metrics, generate_executive_markdown_report
from src.robustness_suite import run_robustness_suite


@app.get("/metrics/prometheus", response_class=PlainTextResponse)
def prometheus_scrape_endpoint(db: Session = Depends(get_db)):
    return generate_prometheus_metrics(db, RUNTIME_CONFIG["active_model"])


@app.get("/api/robustness")
def get_robustness_report():
    report_path = os.path.join(MODEL_DIR, "robustness_report.json")
    if not os.path.exists(report_path):
        return run_robustness_suite()
    with open(report_path, "r") as f:
        return json.load(f)


@app.post("/api/robustness/run")
def trigger_robustness_suite(db: Session = Depends(get_db)):
    report = run_robustness_suite()
    log_audit(db, "admin", "admin", "RUN_ROBUSTNESS_SUITE", f"Pass rate: {report['pass_rate_pct']}% ({report['max_throughput_flows_per_sec']} flows/s)")
    return report


@app.get("/api/reports/executive", response_class=PlainTextResponse)
def download_executive_report(db: Session = Depends(get_db)):
    return generate_executive_markdown_report(db, RUNTIME_CONFIG["active_model"])