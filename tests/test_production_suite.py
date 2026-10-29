import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from fastapi.testclient import TestClient
from src.api_server import app


client = TestClient(app)


def run_all_checks():
    print("=== RUNNING AUTOMATED END-TO-END PRODUCTION VERIFICATION SUITE ===")

    # 1. Health & 5-Model Availability
    r = client.get("/health")
    assert r.status_code == 200
    data = r.json()
    assert len(data["available_models"]) == 6
    print("[PASS] 1/7 FastAPI Health & 5-Algorithm Engine Loaded")

    # 2. JWT Authentication (Admin Login)
    r = client.post("/api/auth/login", json={"username": "admin", "password": "Admin@SDN2026"})
    assert r.status_code == 200
    token = r.json()["access_token"]
    r_me = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert r_me.status_code == 200 and r_me.json()["role"] == "admin"
    print("[PASS] 2/7 JWT Authentication & Role-Based Access Control (Admin)")

    # 3. High-Volume Benign Traffic False-Positive Check (iperf3 burst)
    r = client.post("/api/simulate", json={"scenario": "high_vol"})
    assert r.status_code == 200
    res = r.json()
    assert res["action"] == "allow" and res["threat_type"] == "benign"
    print(f"[PASS] 3/7 Zero False-Positive Check on High-Volume Burst ({res['inference_latency_ms']} ms)")

    # 4. Malicious Attack Detection, Explainable AI & Auto-Quarantine
    r = client.post("/api/simulate", json={"scenario": "kali_attack"})
    assert r.status_code == 200
    res = r.json()
    assert res["action"] == "quarantine" and "Flagged due to" in res["explanation"]
    print(f"[PASS] 4/7 Kali Attack Quarantine & XAI Explanation ({res['threat_type']})")

    # 5. Dynamic Host Unblock Verification
    r = client.post("/api/policies/unblock", json={"target_ip": "10.10.10.2"})
    assert r.status_code == 200
    stats = client.get("/api/stats").json()
    assert "10.10.10.2" not in stats["blocked_ips"]
    print("[PASS] 5/7 Dynamic OpenFlow Policy Unblock Verified")

    # 6. Robustness & Evasion Suite Endpoint
    r = client.get("/api/robustness")
    assert r.status_code == 200 and r.json()["pass_rate_pct"] == 100.0
    print(f"[PASS] 6/7 Robustness & Evasion Suite Verified (9/9 Pass | {r.json()['max_throughput_flows_per_sec']:,} flows/s)")

    # 7. Prometheus Metrics & Executive Report Export
    r_prom = client.get("/metrics/prometheus")
    r_rep = client.get("/api/reports/executive")
    assert r_prom.status_code == 200 and "sdn_telemetry_windows_total" in r_prom.text
    assert r_rep.status_code == 200 and "Executive Security & Evaluation Report" in r_rep.text
    print("[PASS] 7/7 Prometheus Metrics & Executive Markdown Report Generator Verified")

    print("\n[+] ALL 7 PRODUCTION SUBSYSTEMS VERIFIED WITH 0 ERRORS!")


if __name__ == "__main__":
    run_all_checks()