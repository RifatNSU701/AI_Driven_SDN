import os
import json
import time
from sqlalchemy.orm import Session
from src.database import SecurityEvent, PolicyRule, AuditLog

METRICS_FILE = os.path.join("models", "evaluation_metrics.json")
ROBUSTNESS_FILE = os.path.join("models", "robustness_report.json")


def generate_prometheus_metrics(db: Session, active_model: str) -> str:
    """Generates Prometheus-compatible plain-text scrape metrics for Grafana/Prometheus."""
    total_events = db.query(SecurityEvent).count()
    quarantines = db.query(SecurityEvent).filter(SecurityEvent.action == "quarantine").count()
    allowed = db.query(SecurityEvent).filter(SecurityEvent.action == "allow").count()
    active_blocks = (
        db.query(PolicyRule)
        .filter(PolicyRule.rule_type == "quarantine", PolicyRule.status == "active")
        .count()
    )

    recent = db.query(SecurityEvent).order_by(SecurityEvent.id.desc()).limit(50).all()
    avg_latency = (
        round(sum(e.inference_latency_ms for e in recent) / len(recent), 4)
        if recent
        else 0.111
    )

    lines = [
        "# HELP sdn_telemetry_windows_total Total OpenFlow 1.3 telemetry windows analyzed",
        "# TYPE sdn_telemetry_windows_total counter",
        f"sdn_telemetry_windows_total {total_events}",
        "# HELP sdn_quarantine_actions_total Total automated OpenFlow quarantine actions enforced",
        "# TYPE sdn_quarantine_actions_total counter",
        f"sdn_quarantine_actions_total {quarantines}",
        "# HELP sdn_allow_actions_total Total benign flows allowed",
        "# TYPE sdn_allow_actions_total counter",
        f"sdn_allow_actions_total {allowed}",
        "# HELP sdn_active_isolated_hosts Current number of hosts isolated on OVS switch s1",
        "# TYPE sdn_active_isolated_hosts gauge",
        f"sdn_active_isolated_hosts {active_blocks}",
        "# HELP sdn_ml_inference_latency_ms Mean ML anomaly detection latency in milliseconds",
        "# TYPE sdn_ml_inference_latency_ms gauge",
        f"sdn_ml_inference_latency_ms {avg_latency}",
    ]

    if os.path.exists(METRICS_FILE):
        try:
            with open(METRICS_FILE, "r") as f:
                benchmarks = json.load(f)
            lines.append("# HELP sdn_model_f1_score Verified F1 score per anomaly detection model")
            lines.append("# TYPE sdn_model_f1_score gauge")
            for b in benchmarks:
                model_label = b["model"].replace('"', "")
                lines.append(f'sdn_model_f1_score{{model="{model_label}"}} {b["f1_score"]}')
        except Exception:
            pass

    return "\n".join(lines) + "\n"


def generate_executive_markdown_report(db: Session, active_model: str) -> str:
    """Generates a downloadable Markdown/Audit Security Evaluation Report."""
    total_events = db.query(SecurityEvent).count()
    quarantines = db.query(SecurityEvent).filter(SecurityEvent.action == "quarantine").count()
    policies = db.query(PolicyRule).filter(PolicyRule.status == "active").all()
    audits = db.query(AuditLog).order_by(AuditLog.id.desc()).limit(15).all()

    benchmarks = []
    if os.path.exists(METRICS_FILE):
        with open(METRICS_FILE, "r") as f:
            benchmarks = json.load(f)

    robustness = {}
    if os.path.exists(ROBUSTNESS_FILE):
        with open(ROBUSTNESS_FILE, "r") as f:
            robustness = json.load(f)

    now_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    md = [
        "# AI-Powered SDN Threat Protection — Executive Security & Evaluation Report",
        f"**Generated At:** {now_str}  ",
        f"**Active Detection Engine:** {active_model}  ",
        f"**Total Telemetry Windows Analyzed:** {total_events}  ",
        f"**Total Automated Quarantines Enforced:** {quarantines}  ",
        "",
        "---",
        "",
        "## 1. Multi-Algorithm Benchmark Summary",
        "| Model | Precision | Recall | F1-Score | False-Positive Rate | Latency (ms) |",
        "| :--- | :---: | :---: | :---: | :---: | :---: |",
    ]

    for b in benchmarks:
        md.append(
            f"| **{b['model']}** | {b['precision']:.4f} | {b['recall']:.4f} | "
            f"{b['f1_score']:.4f} | {b['false_positive_rate']:.4f} | {b['latency_ms_per_sample']:.4f} ms |"
        )

    if robustness and "scenarios" in robustness:
        md.extend([
            "",
            "## 2. Phase 5 & 6 Robustness, Evasion & Unseen Traffic Stress-Test",
            "| Scenario | Category | Expected | Model Decision | Result | Latency (ms) |",
            "| :--- | :--- | :---: | :---: | :---: | :---: |",
        ])
        for s in robustness["scenarios"]:
            status = "PASS" if s["passed"] else "FAIL"
            md.append(
                f"| {s['name']} | {s['category']} | {s['expected']} | "
                f"{s['actual']} | **{status}** | {s['latency_ms']} ms |"
            )

    md.extend([
        "",
        "## 3. Active OpenFlow 1.3 Policy Rules",
        "| Rule ID | Target IP | Rule Type | Priority | Reason |",
        "| :---: | :--- | :--- | :---: | :--- |",
    ])
    for p in policies:
        md.append(f"| #{p.id} | `{p.target_ip}` | `{p.rule_type}` | {p.priority} | {p.reason} |")

    md.extend([
        "",
        "## 4. Recent SOC Operator Audit Trail",
        "| Timestamp | Operator | Role | Action | Details |",
        "| :--- | :--- | :--- | :--- | :--- |",
    ])
    for a in audits:
        ts = a.timestamp.strftime("%Y-%m-%d %H:%M:%S") if a.timestamp else ""
        md.append(f"| {ts} | `{a.username}` | `{a.role}` | `{a.action}` | {a.details} |")

    return "\n".join(md) + "\n"