import os
import time
import struct
import socket
from collections import defaultdict

PCAP_GLOBAL_HDR_FMT = "<IHHiIII"
PCAP_PKT_HDR_FMT = "<IIII"
PCAP_MAGIC_LE = 0xA1B2C3D4
PCAP_MAGIC_BE = 0xD4C3B2A1


def _ip_to_bytes(ip_str: str) -> bytes:
    return socket.inet_aton(ip_str)


def _bytes_to_ip(raw: bytes) -> str:
    return socket.inet_ntoa(raw)


def build_raw_ipv4_tcp_packet(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    tcp_flags: int = 0x02,
    payload_size: int = 0,
) -> bytes:
    """Constructs a valid Ethernet + IPv4 + TCP frame for controlled lab PCAP synthesis."""
    eth_hdr = b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x02\x08\x00"
    total_len = 20 + 20 + payload_size
    ip_hdr = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_len,
        12345,
        0,
        64,
        socket.IPPROTO_TCP,
        0,
        _ip_to_bytes(src_ip),
        _ip_to_bytes(dst_ip),
    )
    tcp_hdr = struct.pack(
        "!HHIIBBHHH",
        src_port,
        dst_port,
        1000,
        0,
        (5 << 4),
        tcp_flags,
        8192,
        0,
        0,
    )
    payload = b"A" * max(0, payload_size)
    return eth_hdr + ip_hdr + tcp_hdr + payload


def write_pcap_file(filepath: str, packets: list[tuple[float, bytes]]):
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, "wb") as f:
        f.write(struct.pack(PCAP_GLOBAL_HDR_FMT, PCAP_MAGIC_LE, 2, 4, 0, 0, 65535, 1))
        for ts, raw_pkt in packets:
            sec = int(ts)
            usec = int((ts - sec) * 1_000_000)
            length = len(raw_pkt)
            f.write(struct.pack(PCAP_PKT_HDR_FMT, sec, usec, length, length))
            f.write(raw_pkt)


def generate_sample_pcap_files(output_dir: str = os.path.join("data", "pcaps")) -> dict:
    """Generates 4 standard Wireshark/libpcap (.pcap) capture files representing lab scenarios."""
    os.makedirs(output_dir, exist_ok=True)
    now = time.time()
    created = {}

    # 1. Benign Enterprise Web Traffic (h2 -> h1)
    benign_pkts = []
    for i in range(18):
        flags = 0x02 if i < 2 else 0x18  # SYN then PSH+ACK
        pkt = build_raw_ipv4_tcp_packet("10.0.0.2", "10.0.0.1", 51000 + (i % 2), 80, flags, payload_size=64)
        benign_pkts.append((now + (i * 0.15), pkt))
    p_benign = os.path.join(output_dir, "benign_web_h2.pcap")
    write_pcap_file(p_benign, benign_pkts)
    created["benign_web"] = p_benign

    # 2. High-Volume Benign iperf3 Bulk Transfer (h2 -> h4)
    iperf_pkts = []
    for i in range(420):
        flags = 0x02 if i < 4 else 0x10
        pkt = build_raw_ipv4_tcp_packet("10.0.0.2", "10.0.0.4", 52000 + (i % 3), 5201, flags, payload_size=1396)
        iperf_pkts.append((now + (i * 0.0023), pkt))
    p_iperf = os.path.join(output_dir, "high_vol_iperf3.pcap")
    write_pcap_file(p_iperf, iperf_pkts)
    created["high_vol_iperf"] = p_iperf

    # 3. Aggressive Nmap TCP SYN Port Scan (h3 -> h1)
    scan_pkts = []
    for i in range(65):
        pkt = build_raw_ipv4_tcp_packet("10.0.0.3", "10.0.0.1", 40000 + i, 20 + (i % 45), tcp_flags=0x02, payload_size=4)
        scan_pkts.append((now + (i * 0.015), pkt))
    p_scan = os.path.join(output_dir, "nmap_syn_scan_h3.pcap")
    write_pcap_file(p_scan, scan_pkts)
    created["nmap_syn_scan"] = p_scan

    # 4. Kali Linux Multi-Vector SYN Flood (10.10.10.2 -> 10.10.10.1)
    kali_pkts = []
    for i in range(340):
        pkt = build_raw_ipv4_tcp_packet("10.10.10.2", "10.10.10.1", 30000 + (i % 60), 80 + (i % 35), tcp_flags=0x02, payload_size=0)
        kali_pkts.append((now + (i * 0.0028), pkt))
    p_kali = os.path.join(output_dir, "kali_syn_flood.pcap")
    write_pcap_file(p_kali, kali_pkts)
    created["kali_syn_flood"] = p_kali

    return created


def parse_pcap_bytes(pcap_bytes: bytes, window_sec: float = 3.0) -> list[dict]:
    """Parses binary libpcap (.pcap) data and extracts the 6 SDN flow telemetry features."""
    if len(pcap_bytes) < 24:
        raise ValueError("Invalid PCAP: fewer than 24 bytes")

    magic = struct.unpack("<I", pcap_bytes[:4])[0]
    endian = "<" if magic == PCAP_MAGIC_LE else (">" if magic == PCAP_MAGIC_BE else "<")
    pkt_hdr_fmt = endian + "IIII"

    offset = 24
    buckets = defaultdict(lambda: {
        "pkt_count": 0,
        "byte_count": 0,
        "syn_count": 0,
        "dst_ports": set(),
        "flows": set(),
        "min_ts": None,
        "max_ts": None,
    })

    while offset + 16 <= len(pcap_bytes):
        sec, usec, incl_len, orig_len = struct.unpack(pkt_hdr_fmt, pcap_bytes[offset:offset + 16])
        offset += 16
        pkt = pcap_bytes[offset:offset + incl_len]
        offset += incl_len

        if len(pkt) < 34:
            continue

        eth_proto = struct.unpack("!H", pkt[12:14])[0]
        if eth_proto != 0x0800:
            continue

        ip_hdr_len = (pkt[14] & 0x0F) * 4
        proto = pkt[23]
        src_ip = _bytes_to_ip(pkt[26:30])
        dst_ip = _bytes_to_ip(pkt[30:34])

        l4_offset = 14 + ip_hdr_len
        src_port, dst_port, is_syn = 0, 0, False

        if proto == 6 and len(pkt) >= l4_offset + 14:  # TCP
            src_port, dst_port = struct.unpack("!HH", pkt[l4_offset:l4_offset + 4])
            flags = pkt[l4_offset + 13]
            if (flags & 0x02) and not (flags & 0x10):
                is_syn = True
        elif proto == 17 and len(pkt) >= l4_offset + 4:  # UDP
            src_port, dst_port = struct.unpack("!HH", pkt[l4_offset:l4_offset + 4])

        ts = float(sec) + (float(usec) / 1_000_000.0)
        win_idx = int(ts // max(1.0, window_sec))
        key = (src_ip, dst_ip, win_idx)

        b = buckets[key]
        b["pkt_count"] += 1
        b["byte_count"] += orig_len
        if is_syn:
            b["syn_count"] += 1
        if dst_port > 0:
            b["dst_ports"].add(dst_port)
        b["flows"].add((src_port, dst_port, proto))
        b["min_ts"] = ts if b["min_ts"] is None else min(b["min_ts"], ts)
        b["max_ts"] = ts if b["max_ts"] is None else max(b["max_ts"], ts)

    extracted = []
    for (src_ip, dst_ip, _), b in buckets.items():
        duration = max(1.0, (b["max_ts"] - b["min_ts"]) if (b["max_ts"] and b["min_ts"]) else window_sec)
        pkt_count = max(1, b["pkt_count"])
        extracted.append({
            "timestamp": b["max_ts"] or time.time(),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "flow_count": len(b["flows"]),
            "pkt_rate": round(pkt_count / duration, 2),
            "byte_rate": round(b["byte_count"] / duration, 2),
            "mean_pkt_size": round(b["byte_count"] / pkt_count, 2),
            "unique_dst_ports": max(1, len(b["dst_ports"])),
            "syn_ratio": round(b["syn_count"] / pkt_count, 4),
        })

    return extracted