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
        f"priority=100,dl_type=0x0800,nw_src={src_ip},hard_timeout=180,actions=drop"
    )


def enforce_ovs_rate_limit(src_ip: str, rate_kbps: int = 512):
    """Applies OpenFlow 1.3 Meter Table (with OVS QoS fallback) to throttle suspicious host bandwidth."""
    meter_id = sum(int(x) for x in src_ip.split(".") if x.isdigit()) % 250 + 1
    meter_out = run_cmd(
        f"ovs-ofctl -O OpenFlow13 add-meter {BRIDGE} "
        f"meter={meter_id},kbps,burst,bands=type=drop,rate={rate_kbps},burst_size={rate_kbps * 2}"
    )
    if "OFPMMFC" not in meter_out and "error" not in meter_out.lower():
        run_cmd(
            f"ovs-ofctl -O OpenFlow13 add-flow {BRIDGE} "
            f"priority=80,dl_type=0x0800,nw_src={src_ip},instructions=meter:{meter_id},normal"
        )
    else:
        # Userspace/Kernel OVS fallback: apply port-level ingress policing and priority=80 monitoring flow
        ports = run_cmd(f"ovs-vsctl list-ports {BRIDGE}").splitlines()
        for p in ports:
            run_cmd(f"ovs-vsctl set interface {p} ingress_policing_rate={rate_kbps}")
            run_cmd(f"ovs-vsctl set interface {p} ingress_policing_burst={rate_kbps // 2}")
        run_cmd(
            f"ovs-ofctl -O OpenFlow13 add-flow {BRIDGE} "
            f"priority=80,dl_type=0x0800,nw_src={src_ip},actions=normal"
        )


def remove_ovs_rules(src_ip: str):
    run_cmd(
        f"ovs-ofctl -O OpenFlow13 del-flows {BRIDGE} "
        f"dl_type=0x0800,nw_src={src_ip}"
    )


def sync_policies_with_ovs(enforced_state: dict) -> dict:
    r = requests.get(f"{API_BASE}/api/policies", timeout=2.0)
    policies = r.json()

    desired_state = {}
    for p in policies:
        if p["status"] == "active" and p["rule_type"] in ("quarantine", "rate_limit"):
            desired_state[p["target_ip"]] = (p["rule_type"], p.get("rate_kbps", 512))

    for ip, (rtype, kbps) in desired_state.items():
        if enforced_state.get(ip) != (rtype, kbps):
            if rtype == "quarantine":
                enforce_ovs_quarantine(ip)
                print(f"[+] [OVS QUARANTINE] priority=100,nw_src={ip},actions=drop")
            elif rtype == "rate_limit":
                enforce_ovs_rate_limit(ip, kbps)
                print(f"[~] [OVS RATE-LIMIT] priority=80,nw_src={ip},rate={kbps}kbps")

    for ip in set(enforced_state.keys()) - set(desired_state.keys()):
        remove_ovs_rules(ip)
        print(f"[-] [OVS UNBLOCKED] Removed OpenFlow13 policy for {ip}")

    return desired_state


def stream_multi_vm_cycle():
    ensure_ovs_bridge()
    enforced_state = {}
    print(f"[*] Master OVS Policy Guard active on bridge '{BRIDGE}' -> {API_BASE}")

    samples = [
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
        {
            "src_ip": "10.10.10.2",
            "dst_ip": "10.10.10.1",
            "flow_count": 58,
            "pkt_rate": 325.0,
            "byte_rate": 14625.0,
            "mean_pkt_size": 45.0,
            "unique_dst_ports": 38,
            "syn_ratio": 0.96,
        },
    ]

    for sample in samples:
        sample["timestamp"] = time.time()
        res = requests.post(f"{API_BASE}/api/analyze", json=sample, timeout=2.0).json()
        print(
            f"[*] Flow {sample['src_ip']} -> {sample['dst_ip']} | "
            f"Threat={res['threat_type']} | Decision={res['action'].upper()} "
            f"| Drift={res.get('drift_index', 0)} ({res['inference_latency_ms']} ms)"
        )
        enforced_state = sync_policies_with_ovs(enforced_state)
        time.sleep(0.5)

    print("\n[*] Active OpenFlow 1.3 Rules on Switch s1:")
    print(run_cmd(f"ovs-ofctl -O OpenFlow13 dump-flows {BRIDGE}"))


if __name__ == "__main__":
    stream_multi_vm_cycle()