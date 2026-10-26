#!/usr/bin/env python3
import os
import csv
import time
import subprocess
from mininet.net import Mininet
from mininet.node import OVSKernelSwitch, RemoteController
from mininet.log import setLogLevel, info
from topology import EnterpriseSDNTopo

RYU_BIN = "/home/rifat/ryu-python39-venv/bin/ryu-manager"
CONTROLLER_APP = "/home/rifat/sdn-agent/sdn_controller.py"
CSV_FILE = "/home/rifat/sdn-agent/flow_telemetry.csv"

HOST_MAP = {
    "s1-eth1": ("10.0.0.1", "10.0.0.2"),
    "s1-eth2": ("10.0.0.2", "10.0.0.1"),
    "s1-eth3": ("10.0.0.3", "10.0.0.1"),
    "s1-eth4": ("10.0.0.4", "10.0.0.2"),
}


def read_port_counters(iface):
    base = f"/sys/class/net/{iface}/statistics"
    try:
        with open(f"{base}/rx_packets") as fp:
            pkts = int(fp.read().strip())
        with open(f"{base}/rx_bytes") as fb:
            btes = int(fb.read().strip())
        return pkts, btes
    except Exception:
        return 0, 0


def parse_ovs_flows():
    """Read live OpenFlow 1.3 flow entries from OVS switch s1."""
    out = subprocess.run(
        ["ovs-ofctl", "-O", "OpenFlow13", "dump-flows", "s1"],
        capture_output=True, text=True
    ).stdout
    lines = [ln for ln in out.splitlines() if "n_packets=" in ln]
    return max(1, len(lines))


def collect_window(duration_sec, label, attack_type, prev_counters, default_dst, extra_ports, syn_ratio_base):
    steps = int(duration_sec)
    for _ in range(steps):
        time.sleep(1.0)
        now = round(time.time(), 3)
        active_flows = parse_ovs_flows()

        with open(CSV_FILE, "a", newline="") as f:
            writer = csv.writer(f)
            for iface, (src_ip, fallback_dst) in HOST_MAP.items():
                pkts, btes = read_port_counters(iface)
                prev_p, prev_b = prev_counters.get(iface, (pkts, btes))
                dpkts = max(0, pkts - prev_p)
                dbytes = max(0, btes - prev_b)
                prev_counters[iface] = (pkts, btes)

                if dpkts == 0:
                    continue

                # Only label the attacker host (h3 = 10.0.0.3) as malicious during attack phases
                row_label = label if (label == 1 and src_ip == "10.0.0.3") else 0
                row_type = attack_type if row_label == 1 else (
                    "benign_high_vol" if (attack_type == "benign_high_vol" and src_ip == "10.0.0.2") else "benign"
                )

                dst_ip = default_dst if row_label == 1 else fallback_dst
                pkt_rate = round(dpkts / 1.0, 2)
                byte_rate = round(dbytes / 1.0, 2)
                mean_pkt = round(dbytes / max(1, dpkts), 2)

                if row_type == "port_scan":
                    flow_cnt = max(active_flows, min(150, int(dpkts // 2) + 15))
                    uniq_ports = min(150, max(20, int(dpkts // 2)))
                    syn_ratio = 0.95
                elif row_type == "dos_flood":
                    flow_cnt = max(active_flows, min(80, int(dpkts // 10) + 10))
                    uniq_ports = extra_ports
                    syn_ratio = syn_ratio_base
                elif row_type == "benign_high_vol":
                    flow_cnt = max(2, min(8, active_flows))
                    uniq_ports = 2
                    syn_ratio = 0.05
                else:
                    flow_cnt = max(1, min(6, active_flows))
                    uniq_ports = 1 if dpkts < 10 else 2
                    syn_ratio = 0.10

                writer.writerow([
                    now, src_ip, dst_ip, flow_cnt,
                    pkt_rate, byte_rate, mean_pkt,
                    uniq_ports, syn_ratio, row_label, row_type
                ])


def build_dataset():
    subprocess.run("mn -c > /dev/null 2>&1", shell=True)
    subprocess.run("pkill -f ryu-manager", shell=True)
    time.sleep(1)

    with open(CSV_FILE, "w", newline="") as f:
        csv.writer(f).writerow([
            "timestamp", "src_ip", "dst_ip", "flow_count",
            "pkt_rate", "byte_rate", "mean_pkt_size",
            "unique_dst_ports", "syn_ratio", "label", "attack_type"
        ])

    ryu_proc = subprocess.Popen(
        [RYU_BIN, CONTROLLER_APP],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    time.sleep(2)

    topo = EnterpriseSDNTopo()
    net = Mininet(
        topo=topo,
        controller=lambda name: RemoteController(name, ip='127.0.0.1', port=6633),
        switch=OVSKernelSwitch,
        autoSetMacs=True
    )
    net.start()

    # Force OpenFlow 1.3 and connect s1 to Ryu
    subprocess.run("ovs-vsctl set Bridge s1 protocols=OpenFlow13", shell=True)
    subprocess.run("ovs-vsctl set-controller s1 tcp:127.0.0.1:6633", shell=True)
    time.sleep(2)

    h1, h2, h3, h4 = net.get('h1', 'h2', 'h3', 'h4')
    h1.cmd("python3 -m http.server 80 &")
    h4.cmd("iperf3 -s -D")
    subprocess.run("ovs-ofctl -O OpenFlow13 add-flow s1 priority=1,actions=normal", shell=True); net.pingAll()

    prev_counters = {iface: read_port_counters(iface) for iface in HOST_MAP}

    info("*** [1/4] Collecting Benign Baseline Traffic (20s)...\n")
    h2.cmd("ping -c 40 -i 0.5 10.0.0.1 > /dev/null 2>&1 &")
    h4.cmd("ping -c 40 -i 0.5 10.0.0.2 > /dev/null 2>&1 &")
    for _ in range(4):
        h2.cmd("curl -s http://10.0.0.1/ > /dev/null 2>&1 &")
        collect_window(5, 0, "benign", prev_counters, "10.0.0.1", 1, 0.10)

    info("*** [2/4] Collecting Legitimate High-Volume Traffic (15s)...\n")
    h2.cmd("iperf3 -c 10.0.0.4 -t 14 -b 20M > /dev/null 2>&1 &")
    collect_window(15, 0, "benign_high_vol", prev_counters, "10.0.0.4", 2, 0.05)

    info("*** [3/4] Collecting Authorized Port Scan Traffic from h3 (20s)...\n")
    for _ in range(4):
        h3.cmd("nmap -sS -p 1-120 --max-rate 80 10.0.0.1 > /dev/null 2>&1 &")
        h2.cmd("ping -c 5 -i 0.8 10.0.0.1 > /dev/null 2>&1 &")
        collect_window(5, 1, "port_scan", prev_counters, "10.0.0.1", 80, 0.95)

    info("*** [4/4] Collecting Authorized DoS SYN & UDP Flood Traffic from h3 (20s)...\n")
    h3.cmd("timeout 10 hping3 -S -p 80 -i u3000 10.0.0.1 > /dev/null 2>&1 &")
    collect_window(10, 1, "dos_flood", prev_counters, "10.0.0.1", 1, 0.98)

    h3.cmd("timeout 10 hping3 --udp -p 53 -i u3000 10.0.0.4 > /dev/null 2>&1 &")
    collect_window(10, 1, "dos_flood", prev_counters, "10.0.0.4", 1, 0.0)

    info("*** Stopping network and saving dataset...\n")
    net.stop()
    ryu_proc.terminate()
    subprocess.run("pkill -f ryu-manager", shell=True)
    subprocess.run("chown rifat:rifat " + CSV_FILE, shell=True)
    info(f"*** Dataset saved to {CSV_FILE}\n")


if __name__ == '__main__':
    setLogLevel('info')
    build_dataset()