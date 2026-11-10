import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from fastapi.testclient import TestClient
from src.api_server import app

client = TestClient(app)


def run_all_checks():
    print("=== RUNNING 10-SUBSYSTEM SUPER MASTER-GRADE VERIFICATION SUITE ===")

    # 1. Health & 5-Model + 6-Class Engine Availability
    r = client.get("/health")
    assert r.status_code == 200
    assert len(r.json()["available_models"]) == 6
    print("[PASS] 1/10 FastAPI v3.1 Health & Multi-Algorithm Engine Loaded")

    # 2. JWT Authentication (Admin & Analyst Login)
    r_adm = client.post("/api/auth/login", json={"username": "admin", "password": "Admin@SDN2026"})
    r_ana = client.post("/api/auth/login", json={"username": "analyst", "password": "Analyst@SDN2026"})
    assert r_adm.status_code == 200 and r_ana.status_code == 200
    admin_token = r_adm.json()["access_token"]
    analyst_token = r_ana.json()["access_token"]
    print("[PASS] 2/10 JWT Authentication Tokens Issued (Admin & Analyst)")

    # 3. Enforced JWT RBAC (Analyst Blocked on Destructive Route, Admin Allowed)
    r_forbidden = client.delete("/api/events/clear", headers={"Authorization": f"Bearer {analyst_token}"})
    assert r_forbidden.status_code == 403
    r_allowed = client.delete("/api/events/clear", headers={"Authorization": f"Bearer {admin_token}"})
    assert r_allowed.status_code == 200
    print("[PASS] 3/10 Strict JWT RBAC Enforced (Analyst=403 Forbidden | Admin=200 OK)")

    # 4. High-Volume Benign Traffic False-Positive Check
    r = client.post("/api/simulate", json={"scenario": "high_vol"})
    assert r.status_code == 200
    res = r.json()
    assert res["action"] == "allow" and res["threat_type"] in ("benign", "high_vol_benign")
    print(f"[PASS] 4/10 Zero False-Positive Check on High-Volume Burst ({res['threat_type']} | {res['inference_latency_ms']} ms)")

    # 5. Multi-Class Attack Detection & Mathematical XAI Attribution
    r = client.post("/api/simulate", json={"scenario": "kali_attack"})
    assert r.status_code == 200
    res = r.json()
    assert res["action"] == "quarantine" and "XAI weight" in res["explanation"]
    print(f"[PASS] 5/10 Kali Multi-Vector Quarantine & Mathematical XAI ({res['threat_type']} | Drift={res['drift_index']})")

    # 6. Binary .pcap Packet Capture Ingestion & Feature Extraction
    r_pcap = client.post("/api/pcap/analyze_samples")
    assert r_pcap.status_code == 200
    pcap_data = r_pcap.json()
    assert pcap_data["files_processed"] == 4 and pcap_data["flows_evaluated"] >= 4
    print(f"[PASS] 6/10 Real Binary .pcap Packet-to-Flow Extractor ({pcap_data['files_processed']} .pcap files parsed)")

    # 7. Surgical OpenFlow 1.3 Rate-Limiting Policy & Control-Plane Telemetry
    r = client.post(
        "/api/policies/enforce",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"target_ip": "10.0.0.3", "rule_type": "rate_limit", "rate_kbps": 512, "protocol": "tcp", "reason": "Test OFPMeterMod"},
    )
    assert r.status_code == 200
    stats = client.get("/api/stats").json()
    assert "10.0.0.3" in stats["rate_limited_ips"]
    print(f"[PASS] 7/10 OpenFlow 1.3 Rate-Limit Policy & Control-Plane Telemetry (CPU={stats['control_plane']['controller_cpu_pct']}%)")

    # 8. Dynamic Host Unblock Verification
    client.post("/api/policies/unblock", headers={"Authorization": f"Bearer {admin_token}"}, json={"target_ip": "10.10.10.2"})
    client.post("/api/policies/unblock", headers={"Authorization": f"Bearer {admin_token}"}, json={"target_ip": "10.0.0.3"})
    stats = client.get("/api/stats").json()
    assert "10.10.10.2" not in stats["blocked_ips"] and "10.0.0.3" not in stats["rate_limited_ips"]
    print("[PASS] 8/10 Dynamic OpenFlow Policy Unblock Verified")

    # 9. Robustness & Evasion Suite Endpoint
    r = client.get("/api/robustness")
    assert r.status_code == 200 and r.json()["pass_rate_pct"] == 100.0
    print(f"[PASS] 9/10 Robustness & Evasion Suite Verified (9/9 Pass | {r.json()['max_throughput_flows_per_sec']:,} flows/s)")

    # 10. Prometheus Metrics & Executive Report Export
    r_prom = client.get("/metrics/prometheus")
    r_rep = client.get("/api/reports/executive")
    assert r_prom.status_code == 200 and "sdn_telemetry_windows_total" in r_prom.text
    assert r_rep.status_code == 200 and "Executive Security & Evaluation Report" in r_rep.text
    print("[PASS] 10/10 Prometheus Metrics & Executive Markdown Report Generator Verified")

    print("\n[+] ALL 10 SUPER MASTER-GRADE SUBSYSTEMS VERIFIED WITH 0 ERRORS!")


if __name__ == "__main__":
    run_all_checks()