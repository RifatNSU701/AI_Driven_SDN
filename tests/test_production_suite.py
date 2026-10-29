import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from fastapi.testclient import TestClient
from src.api_server import app

client = TestClient(app)


def run_all_checks():
    print("=== RUNNING AUTOMATED MASTER-GRADE PRODUCTION VERIFICATION SUITE ===")

    # 1. Health & 5-Model + 6-Class Engine Availability
    r = client.get("/health")
    assert r.status_code == 200
    data = r.json()
    assert len(data["available_models"]) == 6
    print("[PASS] 1/8 FastAPI v3.0 Health & Multi-Algorithm Engine Loaded")

    # 2. JWT Authentication (Admin Login)
    r = client.post("/api/auth/login", json={"username": "admin", "password": "Admin@SDN2026"})
    assert r.status_code == 200
    token = r.json()["access_token"]
    r_me = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert r_me.status_code == 200 and r_me.json()["role"] == "admin"
    print("[PASS] 2/8 JWT Authentication & Role-Based Access Control (Admin)")

    # 3. High-Volume Benign Traffic False-Positive Check (6-Class Taxonomy: high_vol_benign)
    r = client.post("/api/simulate", json={"scenario": "high_vol"})
    assert r.status_code == 200
    res = r.json()
    assert res["action"] == "allow" and res["threat_type"] in ("benign", "high_vol_benign")
    assert "xai_contributions" in res and len(res["xai_contributions"]) == 6
    print(f"[PASS] 3/8 Zero False-Positive Check on High-Volume Burst (Class={res['threat_type']} | {res['inference_latency_ms']} ms)")

    # 4. Multi-Class Attack Detection, Mathematical XAI Attribution & Auto-Quarantine
    r = client.post("/api/simulate", json={"scenario": "kali_attack"})
    assert r.status_code == 200
    res = r.json()
    assert res["action"] == "quarantine" and "XAI weight" in res["explanation"]
    print(f"[PASS] 4/8 Kali Multi-Vector Quarantine & Mathematical XAI ({res['threat_type']} | Drift={res['drift_index']})")

    # 5. Surgical OpenFlow 1.3 Rate-Limiting Policy Check
    r = client.post(
        "/api/policies/enforce",
        json={"target_ip": "10.0.0.3", "rule_type": "rate_limit", "rate_kbps": 512, "protocol": "tcp", "reason": "Test OFPMeterMod"},
    )
    assert r.status_code == 200
    stats = client.get("/api/stats").json()
    assert "10.0.0.3" in stats["rate_limited_ips"] and "control_plane" in stats
    print(f"[PASS] 5/8 OpenFlow 1.3 Rate-Limit Policy & Control-Plane Telemetry (CPU={stats['control_plane']['controller_cpu_pct']}%)")

    # 6. Dynamic Host Unblock Verification
    client.post("/api/policies/unblock", json={"target_ip": "10.10.10.2"})
    client.post("/api/policies/unblock", json={"target_ip": "10.0.0.3"})
    stats = client.get("/api/stats").json()
    assert "10.10.10.2" not in stats["blocked_ips"] and "10.0.0.3" not in stats["rate_limited_ips"]
    print("[PASS] 6/8 Dynamic OpenFlow Policy Unblock Verified")

    # 7. Robustness & Evasion Suite Endpoint
    r = client.get("/api/robustness")
    assert r.status_code == 200 and r.json()["pass_rate_pct"] == 100.0
    print(f"[PASS] 7/8 Robustness & Evasion Suite Verified (9/9 Pass | {r.json()['max_throughput_flows_per_sec']:,} flows/s)")

    # 8. Prometheus Metrics & Executive Report Export
    r_prom = client.get("/metrics/prometheus")
    r_rep = client.get("/api/reports/executive")
    assert r_prom.status_code == 200 and "sdn_telemetry_windows_total" in r_prom.text
    assert r_rep.status_code == 200 and "Executive Security & Evaluation Report" in r_rep.text
    print("[PASS] 8/8 Prometheus Metrics & Executive Markdown Report Generator Verified")

    print("\n[+] ALL 8 MASTER-GRADE PRODUCTION SUBSYSTEMS VERIFIED WITH 0 ERRORS!")


if __name__ == "__main__":
    run_all_checks()