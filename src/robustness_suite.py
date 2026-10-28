import os
import time
import json
import joblib
import numpy as np
import pandas as pd

MODEL_DIR = "models"
REPORT_PATH = os.path.join(MODEL_DIR, "robustness_report.json")


def run_robustness_suite():
    scaler = joblib.load(os.path.join(MODEL_DIR, "scaler.pkl"))
    iso_model = joblib.load(os.path.join(MODEL_DIR, "isolation_forest.pkl"))
    rf_model = joblib.load(os.path.join(MODEL_DIR, "random_forest.pkl"))
    gb_model = joblib.load(os.path.join(MODEL_DIR, "gradient_boosting.pkl"))
    mlp_model = joblib.load(os.path.join(MODEL_DIR, "mlp_neural_net.pkl"))

    test_cases = [
        {
            "name": "Normal Enterprise Web Flow (h2 -> h1)",
            "category": "Baseline Benign",
            "expected": "allow",
            "features": {"flow_count": 2, "pkt_rate": 4.5, "byte_rate": 441.0, "mean_pkt_size": 98.0, "unique_dst_ports": 1, "syn_ratio": 0.10},
        },
        {
            "name": "Linux Mint Legitimate SSH/HTTP Session (10.10.10.3)",
            "category": "Multi-VM Benign",
            "expected": "allow",
            "features": {"flow_count": 3, "pkt_rate": 14.0, "byte_rate": 1372.0, "mean_pkt_size": 98.0, "unique_dst_ports": 2, "syn_ratio": 0.12},
        },
        {
            "name": "High-Volume Legitimate iperf3 Bulk Transfer (610 KB/s)",
            "category": "False-Positive Stress Test",
            "expected": "allow",
            "features": {"flow_count": 4, "pkt_rate": 420.0, "byte_rate": 609000.0, "mean_pkt_size": 1450.0, "unique_dst_ports": 2, "syn_ratio": 0.05},
        },
        {
            "name": "High-Rate Database Backup Burst (850 KB/s)",
            "category": "False-Positive Stress Test",
            "expected": "allow",
            "features": {"flow_count": 5, "pkt_rate": 580.0, "byte_rate": 841000.0, "mean_pkt_size": 1450.0, "unique_dst_ports": 1, "syn_ratio": 0.04},
        },
        {
            "name": "Aggressive Nmap TCP SYN Port Scan (h3 -> h1)",
            "category": "Known Recon Attack",
            "expected": "quarantine",
            "features": {"flow_count": 48, "pkt_rate": 64.0, "byte_rate": 3712.0, "mean_pkt_size": 58.0, "unique_dst_ports": 42, "syn_ratio": 0.95},
        },
        {
            "name": "High-Rate hping3 TCP SYN Flood (h3 -> h1)",
            "category": "Known DoS Attack",
            "expected": "quarantine",
            "features": {"flow_count": 38, "pkt_rate": 290.0, "byte_rate": 12180.0, "mean_pkt_size": 42.0, "unique_dst_ports": 1, "syn_ratio": 0.98},
        },
        {
            "name": "Low-and-Slow Stealth Recon Scan (18 ports @ 19 pkts/s)",
            "category": "Unseen / Evasion Attack",
            "expected": "quarantine",
            "features": {"flow_count": 22, "pkt_rate": 19.0, "byte_rate": 1140.0, "mean_pkt_size": 60.0, "unique_dst_ports": 18, "syn_ratio": 0.85},
        },
        {
            "name": "Adversarial Padded-Packet SYN Flood (512B Payload Padding)",
            "category": "Adversarial Evasion Test",
            "expected": "quarantine",
            "features": {"flow_count": 44, "pkt_rate": 240.0, "byte_rate": 122880.0, "mean_pkt_size": 512.0, "unique_dst_ports": 1, "syn_ratio": 0.96},
        },
        {
            "name": "Kali Linux Multi-Vector Scan + Flood (10.10.10.2)",
            "category": "Multi-VM Offensive Test",
            "expected": "quarantine",
            "features": {"flow_count": 60, "pkt_rate": 340.0, "byte_rate": 14280.0, "mean_pkt_size": 42.0, "unique_dst_ports": 35, "syn_ratio": 0.96},
        },
    ]

    scenario_results = []
    passed_count = 0

    for case in test_cases:
        f = case["features"]
        df = pd.DataFrame([f])
        t0 = time.perf_counter()
        scaled = scaler.transform(df)

        base_pred = 1 if (f["unique_dst_ports"] > 10 or f["pkt_rate"] > 150 or f["syn_ratio"] > 0.6) else 0
        iso_pred = 1 if int(iso_model.predict(scaled)[0]) == -1 else 0
        rf_pred = int(rf_model.predict(scaled)[0])
        gb_pred = int(gb_model.predict(scaled)[0])
        mlp_pred = int(mlp_model.predict(scaled)[0])

        weighted = (rf_pred * 0.35) + (gb_pred * 0.30) + (mlp_pred * 0.20) + (base_pred * 0.10) + (iso_pred * 0.05)
        pred = 1 if weighted >= 0.45 else 0
        latency_ms = round((time.perf_counter() - t0) * 1000.0, 3)

        actual = "quarantine" if pred == 1 else "allow"
        passed = actual == case["expected"]
        if passed:
            passed_count += 1

        scenario_results.append({
            "name": case["name"],
            "category": case["category"],
            "expected": case["expected"],
            "actual": actual,
            "passed": passed,
            "latency_ms": latency_ms,
            "votes": {
                "Random Forest": rf_pred,
                "Gradient Boosting": gb_pred,
                "DNN (MLP)": mlp_pred,
                "Isolation Forest": iso_pred,
                "Baseline": base_pred,
            },
        })

    # Batch Scale Benchmark: 1,000 concurrent flow windows
    batch_df = pd.DataFrame([test_cases[0]["features"]] * 1000)
    t_batch = time.perf_counter()
    scaled_batch = scaler.transform(batch_df)
    _ = rf_model.predict(scaled_batch)
    batch_total_ms = round((time.perf_counter() - t_batch) * 1000.0, 2)
    throughput_flows_per_sec = int(round(1000.0 / ((time.perf_counter() - t_batch) or 0.001)))

    report = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
        "total_scenarios": len(test_cases),
        "passed_scenarios": passed_count,
        "pass_rate_pct": round((passed_count / len(test_cases)) * 100.0, 2),
        "batch_1000_flows_ms": batch_total_ms,
        "max_throughput_flows_per_sec": throughput_flows_per_sec,
        "scenarios": scenario_results,
    }

    os.makedirs(MODEL_DIR, exist_ok=True)
    with open(REPORT_PATH, "w") as f:
        json.dump(report, f, indent=2)

    print("=== PHASE 5 & 6 ROBUSTNESS, EVASION & SCALE BENCHMARK ===")
    for s in scenario_results:
        badge = "PASS" if s["passed"] else "FAIL"
        print(f"[{badge}] {s['name']:<52} | Expected={s['expected']:<10} | Actual={s['actual']:<10} | {s['latency_ms']} ms")
    print(f"\n[+] Verification Pass Rate      : {passed_count}/{len(test_cases)} ({report['pass_rate_pct']}%)")
    print(f"[+] 1,000-Flow Batch Latency    : {batch_total_ms} ms ({throughput_flows_per_sec:,} flows/sec capacity)")
    print(f"[+] Saved robustness report to  : {REPORT_PATH}")
    return report


if __name__ == "__main__":
    run_robustness_suite()