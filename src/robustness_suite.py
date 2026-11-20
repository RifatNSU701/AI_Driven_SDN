import os
import sys
import json
import time
import numpy as np
import pandas as pd

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from src.ml_engine import ml_engine, FEATURES

IS_VERCEL = bool(os.getenv("VERCEL"))
IS_FROZEN = getattr(sys, "frozen", False)
BASE_DIR = (
    sys._MEIPASS
    if IS_FROZEN and hasattr(sys, "_MEIPASS")
    else os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
APP_DATA_DIR = os.path.join(os.path.expanduser("~"), ".ai_sdn_cybersoc")
MODEL_DIR = os.path.join(BASE_DIR, "models")


def run_robustness_suite() -> dict:
    scenarios = [
        {
            "name": "Normal Enterprise Web Flow (h2 -> h1)",
            "category": "Benign Baseline",
            "expected": "allow",
            "sample": {"flow_count": 3, "pkt_rate": 8.0, "byte_rate": 800.0, "mean_pkt_size": 100.0, "unique_dst_ports": 1, "syn_ratio": 0.10},
        },
        {
            "name": "Linux Mint Legitimate SSH/HTTP Session (10.10.10.3)",
            "category": "Benign Multi-Host",
            "expected": "allow",
            "sample": {"flow_count": 4, "pkt_rate": 12.0, "byte_rate": 1200.0, "mean_pkt_size": 100.0, "unique_dst_ports": 2, "syn_ratio": 0.08},
        },
        {
            "name": "High-Volume Legitimate iperf3 Bulk Transfer (610 KB/s)",
            "category": "False-Positive Stress",
            "expected": "allow",
            "sample": {"flow_count": 4, "pkt_rate": 420.0, "byte_rate": 610000.0, "mean_pkt_size": 1450.0, "unique_dst_ports": 2, "syn_ratio": 0.03},
        },
        {
            "name": "High-Rate Database Backup Burst (850 KB/s)",
            "category": "False-Positive Stress",
            "expected": "allow",
            "sample": {"flow_count": 6, "pkt_rate": 580.0, "byte_rate": 850000.0, "mean_pkt_size": 1465.0, "unique_dst_ports": 2, "syn_ratio": 0.02},
        },
        {
            "name": "Aggressive Nmap TCP SYN Port Scan (h3 -> h1)",
            "category": "Reconnaissance Attack",
            "expected": "quarantine",
            "sample": {"flow_count": 50, "pkt_rate": 65.0, "byte_rate": 3600.0, "mean_pkt_size": 55.0, "unique_dst_ports": 45, "syn_ratio": 0.96},
        },
        {
            "name": "High-Rate hping3 TCP SYN Flood (h3 -> h1)",
            "category": "Volumetric DoS",
            "expected": "quarantine",
            "sample": {"flow_count": 48, "pkt_rate": 350.0, "byte_rate": 15750.0, "mean_pkt_size": 45.0, "unique_dst_ports": 1, "syn_ratio": 0.99},
        },
        {
            "name": "Low-and-Slow Stealth Recon Scan (18 ports @ 19 pkts/s)",
            "category": "Unseen Evasion",
            "expected": "quarantine",
            "sample": {"flow_count": 20, "pkt_rate": 19.0, "byte_rate": 1140.0, "mean_pkt_size": 60.0, "unique_dst_ports": 18, "syn_ratio": 0.85},
        },
        {
            "name": "Adversarial Padded-Packet SYN Flood (512B Payload Padding)",
            "category": "Adversarial Evasion",
            "expected": "quarantine",
            "sample": {"flow_count": 55, "pkt_rate": 310.0, "byte_rate": 158720.0, "mean_pkt_size": 512.0, "unique_dst_ports": 1, "syn_ratio": 0.97},
        },
        {
            "name": "Kali Linux Multi-Vector Scan + Flood (10.10.10.2)",
            "category": "Multi-Vector Attack",
            "expected": "quarantine",
            "sample": {"flow_count": 62, "pkt_rate": 340.0, "byte_rate": 15300.0, "mean_pkt_size": 45.0, "unique_dst_ports": 38, "syn_ratio": 0.96},
        },
    ]

    results = []
    passed_count = 0

    for sc in scenarios:
        res = ml_engine.evaluate_window(sc["sample"], "Ensemble Voting (All 5 Models)")
        actual = "quarantine" if res["prediction"] == 1 else "allow"
        passed = actual == sc["expected"]
        if passed:
            passed_count += 1
        results.append({
            "name": sc["name"],
            "category": sc["category"],
            "expected": sc["expected"],
            "actual": actual,
            "threat_type": res["threat_type"],
            "latency_ms": res["inference_latency_ms"],
            "passed": passed,
        })

    batch_df = pd.DataFrame([scenarios[i % len(scenarios)]["sample"] for i in range(1000)])[FEATURES]
    t0 = time.perf_counter()
    scaled_batch = ml_engine.scaler.transform(batch_df)
    _ = ml_engine.gb_model.predict(scaled_batch)
    batch_sec = max(1e-6, time.perf_counter() - t0)
    batch_ms = round(batch_sec * 1000.0, 2)
    throughput = int(1000.0 / batch_sec)

    report = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
        "total_scenarios": len(scenarios),
        "passed_scenarios": passed_count,
        "pass_rate_pct": round((passed_count / len(scenarios)) * 100.0, 2),
        "batch_1000_latency_ms": batch_ms,
        "max_throughput_flows_per_sec": throughput,
        "scenarios": results,
    }

    if IS_VERCEL:
        out_path = "/tmp/robustness_report.json"
    elif IS_FROZEN:
        out_path = os.path.join(APP_DATA_DIR, "robustness_report.json")
    else:
        out_path = os.path.join(MODEL_DIR, "robustness_report.json")

    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(report, f, indent=2)

    return report


if __name__ == "__main__":
    print("=== PHASE 5 & 6 ROBUSTNESS, EVASION & SCALE BENCHMARK ===")
    rep = run_robustness_suite()
    for s in rep["scenarios"]:
        status = "PASS" if s["passed"] else "FAIL"
        print(f"[{status}] {s['name']:<58} | Expected={s['expected']:<10} | Actual={s['actual']:<10} | {s['latency_ms']} ms")
    print(f"\n[+] Verification Pass Rate      : {rep['passed_scenarios']}/{rep['total_scenarios']} ({rep['pass_rate_pct']}%)")
    print(f"[+] 1,000-Flow Batch Latency    : {rep['batch_1000_latency_ms']} ms ({rep['max_throughput_flows_per_sec']:,} flows/sec capacity)")