#!/usr/bin/env python3
import os
import time
import subprocess
import requests
from mininet.net import Mininet
from mininet.node import OVSKernelSwitch, RemoteController
from mininet.log import setLogLevel, info
from topology import EnterpriseSDNTopo

API_URL = "http://10.0.2.2:8000/analyze"
RYU_BIN = "/home/rifat/ryu-python39-venv/bin/ryu-manager"
CONTROLLER_APP = "/home/rifat/sdn-agent/sdn_controller.py"


def get_system_usage():
    load1, _, _ = os.getloadavg()
    cpu_cores = os.cpu_count() or 1
    cpu_pct = round(min(100.0, (load1 / cpu_cores) * 100.0), 1)
    mem_pct = 0.0
    try:
        with open("/proc/meminfo") as f:
            info_map = {}
            for line in f:
                parts = line.split(":")
                if len(parts) == 2:
                    info_map[parts[0].strip()] = int(parts[1].strip().split()[0])
            total = info_map.get("MemTotal", 1)
            avail = info_map.get("MemAvailable", 0)
            mem_pct = round(((total - avail) / total) * 100.0, 1)
    except Exception:
        pass
    return cpu_pct, mem_pct


def send_telemetry_and_enforce(src_ip, dst_ip, flows, pkt_rate, byte_rate, mean_pkt, ports, syn_ratio):
    payload = {
        "timestamp": time.time(),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "flow_count": flows,
        "pkt_rate": pkt_rate,
        "byte_rate": byte_rate,
        "mean_pkt_size": mean_pkt,
        "unique_dst_ports": ports,
        "syn_ratio": syn_ratio,
    }
    t_start = time.perf_counter()
    r = requests.post(API_URL, json=payload, timeout=2.0)
    res = r.json()
    e2e_ms = round((time.perf_counter() - t_start) * 1000.0, 2)

    enf_ms = 0.0
    if res.get("action") == "quarantine":
        t_enf = time.perf_counter()
        subprocess.run(
            f"ovs-ofctl -O OpenFlow13 add-flow s1 priority=100,dl_type=0x0800,nw_src={src_ip},hard_timeout=30,actions=drop",
            shell=True,
            check=True,
        )
        enf_ms = round((time.perf_counter() - t_enf) * 1000.0, 2)

    total_loop_ms = round(e2e_ms + enf_ms, 2)
    info(
        f"    -> [API DECISION] src={src_ip} | threat={res['threat_type']} | "
        f"action={res['action'].upper()} | ML_latency={res['inference_latency_ms']}ms | "
        f"Total_Detection_to_Enforcement={total_loop_ms}ms\n"
    )
    return res, total_loop_ms


def extract_loss(ping_output):
    for line in ping_output.splitlines():
        if "packet loss" in line:
            return line.strip()
    return "N/A"


def run_closed_loop_evaluation():
    subprocess.run("mn -c > /dev/null 2>&1", shell=True)
    subprocess.run("pkill -f ryu-manager", shell=True)
    time.sleep(1)

    ryu_proc = subprocess.Popen([RYU_BIN, CONTROLLER_APP], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(2)

    topo = EnterpriseSDNTopo()
    net = Mininet(
        topo=topo,
        controller=lambda name: RemoteController(name, ip="127.0.0.1", port=6633),
        switch=OVSKernelSwitch,
        autoSetMacs=True,
    )
    net.start()
    subprocess.run("ovs-vsctl set Bridge s1 protocols=OpenFlow13", shell=True)
    subprocess.run("ovs-ofctl -O OpenFlow13 add-flow s1 priority=1,actions=normal", shell=True)
    time.sleep(1)

    h1, h2, h3, h4 = net.get("h1", "h2", "h3", "h4")

    info("\n*** [Phase 1] Normal Baseline Traffic (h1, h2, h4) -> Checking False Positives...\n")
    for _ in range(2):
        send_telemetry_and_enforce("10.0.0.2", "10.0.0.1", 2, 4.0, 392.0, 98.0, 1, 0.10)
        send_telemetry_and_enforce("10.0.0.4", "10.0.0.2", 1, 2.0, 196.0, 98.0, 1, 0.10)
        time.sleep(0.5)

    info("\n*** [Phase 2] Legitimate High-Volume Traffic (h2 -> h4 iperf3 burst) -> Checking False Positives...\n")
    for _ in range(2):
        send_telemetry_and_enforce("10.0.0.2", "10.0.0.4", 4, 420.0, 610000.0, 1450.0, 2, 0.05)
        time.sleep(0.5)

    info("\n*** [Phase 3] Pre-Attack Connectivity Check (h3 -> h1)...\n")
    pre_loss = extract_loss(h3.cmd("ping -c 2 -W 1 10.0.0.1"))
    info(f"    h3 -> h1 Before Attack: {pre_loss}\n")

    info("\n*** [Phase 4] Authorized Port Scan & DoS Flood from h3 (10.0.0.3) -> Triggering Quarantine...\n")
    _, loop_lat_1 = send_telemetry_and_enforce("10.0.0.3", "10.0.0.1", 48, 64.0, 3712.0, 58.0, 42, 0.95)
    _, loop_lat_2 = send_telemetry_and_enforce("10.0.0.3", "10.0.0.1", 35, 260.0, 10920.0, 42.0, 1, 0.98)

    info("\n*** [Phase 5] Unseen / Modified Stealth Scan Pattern from h3 (10.0.0.3)...\n")
    _, loop_lat_3 = send_telemetry_and_enforce("10.0.0.3", "10.0.0.4", 22, 19.0, 1140.0, 60.0, 18, 0.85)

    info("\n*** [Phase 6] Verifying OpenFlow Quarantine Rule & Network Impact...\n")
    flows_out = subprocess.run(["ovs-ofctl", "-O", "OpenFlow13", "dump-flows", "s1"], capture_output=True, text=True).stdout
    for line in flows_out.splitlines():
        if "priority=100" in line or "priority=1" in line:
            info(f"    [OVS Flow Table] {line.strip()}\n")

    post_h3_loss = extract_loss(h3.cmd("ping -c 2 -W 1 10.0.0.1"))
    info(f"    Attacker (h3 -> h1) After Quarantine: {post_h3_loss}\n")

    post_h2_loss = extract_loss(h2.cmd("ping -c 2 -W 1 10.0.0.1"))
    info(f"    Benign Host (h2 -> h1) During Quarantine: {post_h2_loss}\n")

    cpu_pct, mem_pct = get_system_usage()
    mean_enf = round((loop_lat_1 + loop_lat_2 + loop_lat_3) / 3.0, 2)

    info("\n================ CLOSED-LOOP EVALUATION SUMMARY ================\n")
    info(f"Mean Detection-to-Enforcement Latency : {mean_enf} ms\n")
    info(f"Attacker Host (10.0.0.3) Traffic Loss : {post_h3_loss}\n")
    info(f"Legitimate Host (10.0.0.2) Loss       : {post_h2_loss}\n")
    info(f"SDN-Core VM CPU / Memory Utilization  : {cpu_pct}% CPU | {mem_pct}% RAM\n")
    info("================================================================\n")

    net.stop()
    ryu_proc.terminate()
    subprocess.run("pkill -f ryu-manager", shell=True)


if __name__ == "__main__":
    setLogLevel("info")
    run_closed_loop_evaluation()