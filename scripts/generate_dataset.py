#!/usr/bin/env python3
import os
import time
from mininet.net import Mininet
from mininet.node import OVSKernelSwitch, RemoteController
from mininet.log import setLogLevel, info
from topology import EnterpriseSDNTopo

CSV_FILE = "/home/rifat/sdn-agent/flow_telemetry.csv"
LABEL_FILE = "/home/rifat/sdn-agent/label_state.txt"

def set_label(label, attack_type):
    with open(LABEL_FILE, "w") as f:
        f.write(f"{label},{attack_type}\n")

def build_dataset():
    if os.path.exists(CSV_FILE):
        os.remove(CSV_FILE)

    set_label(0, "benign")

    topo = EnterpriseSDNTopo()
    net = Mininet(
        topo=topo,
        controller=lambda name: RemoteController(name, ip='127.0.0.1', port=6633),
        switch=OVSKernelSwitch,
        autoSetMacs=True
    )

    net.start()
    time.sleep(3)

    h1, h2, h3, h4 = net.get('h1', 'h2', 'h3', 'h4')
    h1.cmd("python3 -m http.server 80 &")
    h4.cmd("iperf3 -s -D")
    time.sleep(2)
    net.pingAll()

    info("*** [1/4] Collecting Benign Traffic (30s)...\n")
    set_label(0, "benign")
    for _ in range(15):
        h2.cmd("curl -s http://10.0.0.1/ > /dev/null &")
        h2.cmd("ping -c 2 -i 0.2 10.0.0.1 > /dev/null &")
        h4.cmd("ping -c 2 -i 0.2 10.0.0.2 > /dev/null &")
        time.sleep(2)

    info("*** [2/4] Collecting Legitimate High-Volume Traffic (20s)...\n")
    set_label(0, "benign_high_vol")
    h2.cmd("iperf3 -c 10.0.0.4 -t 18 -b 25M > /dev/null 2>&1 &")
    time.sleep(20)

    info("*** [3/4] Collecting Port Scan Traffic (25s)...\n")
    set_label(1, "port_scan")
    for _ in range(5):
        h3.cmd("nmap -sS -p 1-150 --max-rate 100 10.0.0.1 > /dev/null 2>&1")
        time.sleep(2)

    info("*** [4/4] Collecting DoS SYN & UDP Flood Traffic (25s)...\n")
    set_label(1, "dos_flood")
    h3.cmd("timeout 12 hping3 -S -p 80 -i u5000 10.0.0.1 > /dev/null 2>&1")
    h3.cmd("timeout 10 hping3 --udp -p 53 -i u5000 10.0.0.4 > /dev/null 2>&1")
    time.sleep(3)

    info("*** Dataset collection finished. Stopping network...\n")
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    build_dataset()