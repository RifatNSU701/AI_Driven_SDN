#!/usr/bin/env python3
import time
import subprocess
import requests

API_BASE = "http://10.0.2.2:8000"
BRIDGE = "s1"


def run_cmd(cmd: str) -> str:
    res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return res.stdout.strip()


def ensure_ovs_bridge():
    bridges = run_cmd("ovs-vsctl list-br").splitlines()
    if BRIDGE not in bridges:
        run_cmd(f"ovs-vsctl add-br {BRIDGE}")
    run_cmd(f"ovs-vsctl set Bridge {BRIDGE} protocols=OpenFlow13")
    run_cmd(f"ovs-ofctl -O OpenFlow13 add-flow {BRIDGE} priority=1,actions=normal")


def enforce_ovs_quarantine(src_ip: str):
    run_cmd(
        f"ovs-ofctl -O OpenFlow13 add-flow {BRIDGE} "
        f"priority=100,dl_type=0x0800,nw_src={src_ip},hard_timeout=120,actions=drop"
    )


def remove_ovs_quarantine(src_ip: str):
    run_cmd(
        f"ovs-ofctl -O OpenFlow13 del-flows {BRIDGE} "
        f"dl_type=0x0800,nw_src={src_ip}"
    )


def sync_policies_with_ovs(enforced_ips: set):
    r = requests.get(f"{API_BASE}/api/policies", timeout=2.0)
    policies = r.json()
    active_quarantines = {
        p["target_ip"]
        for p in policies
        if p["rule_type"] == "quarantine" and p["status"] == "active"
    }

    for ip in active_quarantines - enforced_ips:
        enforce_ovs_quarantine(ip)
        print(f"[+] [OVS ENFORCED] Installed OpenFlow13 drop rule for {ip}")

    for ip in enforced_ips - active_quarantines:
        remove_ovs_quarantine(ip)
        print(f"[-] [OVS UNBLOCKED] Removed OpenFlow13 drop rule for {ip}")

    return active_quarantines


def stream_multi_vm_cycle():
    """Streams live 3-VM lab telemetry (Mint 10.10.10.3 benign + Kali 10.10.10.2 attack) and syncs OVS rules."""
    ensure_ovs_bridge()
    enforced_ips = set()
    print(f"[*] Live OVS Policy Guard active on bridge '{BRIDGE}' -> {API_BASE}")

    samples = [
        # Linux Mint (10.10.10.3) -> Ubuntu SDN-Core (10.10.10.1) Benign Traffic
        {
            "src_ip": "10.10.10.3",
            "dst_ip": "10.10.10.1",
            "flow_count": 3,
            "pkt_rate": 11.0,
            "byte_rate": 1078.0,
            "mean_pkt_size": 98.0,
            "unique_dst_ports": 2,
            "syn_ratio": 0.10,
        },
        # Kali Linux (10.10.10.2) -> Ubuntu SDN-Core (10.10.10.1) Authorized SYN Scan & Flood
        {
            "src_ip": "10.10.10.2",
            "dst_ip": "10.10.10.1",
            "flow_count": 58,
            "pkt_rate": 325.0,
            "byte_rate": 13650.0,
            "mean_pkt_size": 42.0,
            "unique_dst_ports": 38,
            "syn_ratio": 0.96,
        },
    ]

    for sample in samples:
        sample["timestamp"] = time.time()
        res = requests.post(f"{API_BASE}/api/analyze", json=sample, timeout=2.0).json()
        print(
            f"[*] Flow {sample['src_ip']} -> {sample['dst_ip']} | "
            f"Model={res['active_model']} | Threat={res['threat_type']} | "
            f"Decision={res['action'].upper()} ({res['inference_latency_ms']} ms)"
        )
        enforced_ips = sync_policies_with_ovs(enforced_ips)
        time.sleep(1)

    print("\n[*] Active OpenFlow 1.3 Rules on Switch s1:")
    print(run_cmd(f"ovs-ofctl -O OpenFlow13 dump-flows {BRIDGE}"))


if __name__ == "__main__":
    stream_multi_vm_cycle()