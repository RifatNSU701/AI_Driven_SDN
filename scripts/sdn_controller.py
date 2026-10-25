import time
import csv
import os
import requests
from collections import defaultdict
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, tcp, udp, ether_types
from ryu.lib import hub

WINDOWS_API_URL = "http://10.0.2.2:8000/analyze"
CSV_FILE = "/home/rifat/sdn-agent/flow_telemetry.csv"
LABEL_FILE = "/home/rifat/sdn-agent/label_state.txt"
POLL_INTERVAL = 2.0


class SDNThreatProtectionController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SDNThreatProtectionController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}
        self.prev_stats = {}
        self.quarantined_ips = {}
        self.whitelist_ips = {"10.0.0.1", "10.0.0.4"}
        self.enable_ips = os.environ.get("ENABLE_IPS", "0") == "1"
        self._reset_window_cache()
        self._ensure_csv()
        self.monitor_thread = hub.spawn(self._monitor)

    def _reset_window_cache(self):
        self.pkt_in_cache = defaultdict(lambda: {
            "dst_ip": "0.0.0.0", "flows": 0, "pkts": 0,
            "bytes": 0, "ports": set(), "syn_pkts": 0
        })

    def _ensure_csv(self):
        if not os.path.exists(CSV_FILE):
            with open(CSV_FILE, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow([
                    "timestamp", "src_ip", "dst_ip", "flow_count",
                    "pkt_rate", "byte_rate", "mean_pkt_size",
                    "unique_dst_ports", "syn_ratio", "label", "attack_type"
                ])

    def _get_current_label(self):
        if os.path.exists(LABEL_FILE):
            try:
                with open(LABEL_FILE, "r") as f:
                    parts = f.read().strip().split(",")
                    if len(parts) == 2:
                        return parts[0], parts[1]
            except Exception:
                pass
        return "0", "benign"

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        dp = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.datapaths[dp.id] = dp
            self.logger.info("Switch s%s connected (OpenFlow 1.3)", dp.id)
        elif ev.state == DEAD_DISPATCHER:
            self.datapaths.pop(dp.id, None)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = ev.datapath
        ofproto = dp.ofproto
        parser = dp.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(dp, 0, match, actions)

    def add_flow(self, dp, priority, match, actions, idle_timeout=0, hard_timeout=0):
        ofproto = dp.ofproto
        parser = dp.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=dp, priority=priority,
            idle_timeout=idle_timeout, hard_timeout=hard_timeout,
            match=match, instructions=inst
        )
        dp.send_msg(mod)

    def quarantine_host(self, dp, src_ip, duration=30):
        if src_ip in self.whitelist_ips:
            return
        now = time.time()
        if src_ip in self.quarantined_ips and now < self.quarantined_ips[src_ip]:
            return
        parser = dp.ofproto_parser
        match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip)
        self.add_flow(dp, priority=100, match=match, actions=[], hard_timeout=duration)
        self.quarantined_ips[src_ip] = now + duration
        self.logger.warning("QUARANTINE ENFORCED: Blocked %s for %ds", src_ip, duration)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofproto = dp.ofproto
        parser = dp.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dpid = dp.id
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][eth.src] = in_port
        out_port = self.mac_to_port[dpid].get(eth.dst, ofproto.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]

        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt:
            t_pkt = pkt.get_protocol(tcp.tcp)
            u_pkt = pkt.get_protocol(udp.udp)
            dst_port = 0
            is_syn = False

            if t_pkt:
                dst_port = t_pkt.dst_port
                if (t_pkt.bits & 0x02) and not (t_pkt.bits & 0x10):
                    is_syn = True
            elif u_pkt:
                dst_port = u_pkt.dst_port

            c = self.pkt_in_cache[ip_pkt.src]
            c["dst_ip"] = ip_pkt.dst
            c["flows"] += 1
            c["pkts"] += 1
            c["bytes"] += len(msg.data)
            if dst_port:
                c["ports"].add(dst_port)
            if is_syn:
                c["syn_pkts"] += 1

            if out_port != ofproto.OFPP_FLOOD:
                if t_pkt:
                    match = parser.OFPMatch(
                        in_port=in_port, eth_type=0x0800,
                        ipv4_src=ip_pkt.src, ipv4_dst=ip_pkt.dst,
                        ip_proto=6, tcp_dst=t_pkt.dst_port
                    )
                elif u_pkt:
                    match = parser.OFPMatch(
                        in_port=in_port, eth_type=0x0800,
                        ipv4_src=ip_pkt.src, ipv4_dst=ip_pkt.dst,
                        ip_proto=17, udp_dst=u_pkt.dst_port
                    )
                else:
                    match = parser.OFPMatch(
                        in_port=in_port, eth_type=0x0800,
                        ipv4_src=ip_pkt.src, ipv4_dst=ip_pkt.dst,
                        ip_proto=ip_pkt.proto
                    )
                self.add_flow(dp, 10, match, actions, idle_timeout=10, hard_timeout=30)

        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        out = parser.OFPPacketOut(
            datapath=dp, buffer_id=msg.buffer_id,
            in_port=in_port, actions=actions, data=data
        )
        dp.send_msg(out)

    def _monitor(self):
        while True:
            for dp in list(self.datapaths.values()):
                parser = dp.ofproto_parser
                req = parser.OFPFlowStatsRequest(dp)
                dp.send_msg(req)
            hub.sleep(POLL_INTERVAL)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        t_arrival = time.time()
        dp = ev.msg.datapath
        label, attack_type = self._get_current_label()

        host_agg = defaultdict(lambda: {
            "dst_ip": "0.0.0.0", "flows": 0, "d_pkts": 0,
            "d_bytes": 0, "ports": set(), "syn_Indicators": 0
        })

        for src_ip, c in list(self.pkt_in_cache.items()):
            h = host_agg[src_ip]
            h["dst_ip"] = c["dst_ip"]
            h["flows"] += c["flows"]
            h["d_pkts"] += c["pkts"]
            h["d_bytes"] += c["bytes"]
            h["ports"].update(c["ports"])
            h["syn_Indicators"] += c["syn_pkts"]

        self._reset_window_cache()

        for stat in ev.msg.body:
            if stat.priority != 10:
                continue
            m = dict(stat.match.items())
            if 'ipv4_src' not in m:
                continue

            src = m['ipv4_src']
            dst = m.get('ipv4_dst', '0.0.0.0')
            dst_port = m.get('tcp_dst') or m.get('udp_dst') or 0
            proto = m.get('ip_proto', 0)
            key = (dp.id, src, dst, dst_port, proto)

            prev_p, prev_b = self.prev_stats.get(key, (0, 0))
            dpkts = max(0, stat.packet_count - prev_p)
            dbytes = max(0, stat.byte_count - prev_b)
            self.prev_stats[key] = (stat.packet_count, stat.byte_count)

            if dpkts == 0:
                continue

            h = host_agg[src]
            h["dst_ip"] = dst
            h["flows"] += 1
            h["d_pkts"] += dpkts
            h["d_bytes"] += dbytes
            if dst_port:
                h["ports"].add(dst_port)
            if proto == 6 and dpkts <= 3:
                h["syn_Indicators"] += 1

        self._ensure_csv()
        for src_ip, data in host_agg.items():
            if data["d_pkts"] == 0:
                continue
            pkt_rate = round(data["d_pkts"] / POLL_INTERVAL, 2)
            byte_rate = round(data["d_bytes"] / POLL_INTERVAL, 2)
            mean_pkt = round(data["d_bytes"] / max(1, data["d_pkts"]), 2)
            uniq_ports = len(data["ports"])
            syn_ratio = round(min(1.0, data["syn_Indicators"] / max(1, data["flows"])), 2)

            with open(CSV_FILE, "a", newline="") as f:
                csv.writer(f).writerow([
                    round(t_arrival, 3), src_ip, data["dst_ip"],
                    data["flows"], pkt_rate, byte_rate,
                    mean_pkt, uniq_ports, syn_ratio,
                    label, attack_type
                ])

            self.logger.info(
                "[TELEMETRY] src=%s dst=%s flows=%d pkt_rate=%.1f ports=%d label=%s(%s)",
                src_ip, data["dst_ip"], data["flows"], pkt_rate, uniq_ports, label, attack_type
            )

            if self.enable_ips:
                payload = {
                    "timestamp": t_arrival,
                    "src_ip": src_ip,
                    "dst_ip": data["dst_ip"],
                    "flow_count": data["flows"],
                    "pkt_rate": pkt_rate,
                    "byte_rate": byte_rate,
                    "mean_pkt_size": mean_pkt,
                    "unique_dst_ports": uniq_ports,
                    "syn_ratio": syn_ratio
                }
                try:
                    r = requests.post(WINDOWS_API_URL, json=payload, timeout=0.3)
                    if r.status_code == 200:
                        res = r.json()
                        if res.get("action") == "quarantine":
                            self.quarantine_host(dp, src_ip, duration=30)
                except Exception:
                    pass