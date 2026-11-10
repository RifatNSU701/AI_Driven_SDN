#!/usr/bin/env python3
"""
AI-Powered SDN Threat Protection — Native Ryu 4.34 OpenFlow 1.3 Controller
- Collects OpenFlow 1.3 packet/flow telemetry (OFPFlowStatsRequest / OFPPacketIn)
- Extracts the 6 flow-level security features every 3 seconds
- Queries the FastAPI ML/XAI engine (/api/analyze)
- Enforces native OpenFlow 1.3 Quarantine (OFPFlowMod priority=100, drop)
  and OpenFlow 1.3 Bandwidth Policing (OFPMeterMod + OFPInstructionMeter priority=80)
"""

import os
import time
from collections import defaultdict
import requests

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub
from ryu.lib.packet import packet, ethernet, ipv4, tcp, udp

API_ANALYZE_URL = os.getenv("SDN_ML_API_URL", "http://10.0.2.2:8000/api/analyze")
POLL_INTERVAL_SEC = 3.0


class AISdnThreatProtectionController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}
        self.enforced_hosts = {}
        self.window_stats = defaultdict(lambda: {
            "dst_ip": "10.0.0.1",
            "pkt_count": 0,
            "byte_count": 0,
            "syn_count": 0,
            "dst_ports": set(),
            "flows": set(),
        })
        self.monitor_thread = hub.spawn(self._telemetry_loop)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        dp = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.datapaths[dp.id] = dp
            self.logger.info("[+] OpenFlow 1.3 Switch connected: dpid=%016x", dp.id)
        elif ev.state == DEAD_DISPATCHER and dp.id in self.datapaths:
            del self.datapaths[dp.id]

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self._add_flow(datapath, priority=0, match=match, actions=actions)
        self.logger.info("[+] Installed Table-Miss Flow (priority=0) on dpid=%016x", datapath.id)

    def _add_flow(self, datapath, priority, match, actions, idle_timeout=0, hard_timeout=0, meter_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = []
        if meter_id is not None:
            inst.append(parser.OFPInstructionMeter(meter_id, ofproto.OFPIT_METER))
        if actions:
            inst.append(parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions))
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            idle_timeout=idle_timeout,
            hard_timeout=hard_timeout,
            match=match,
            instructions=inst,
        )
        datapath.send_msg(mod)

    def enforce_native_quarantine(self, datapath, src_ip: str):
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip)
        self._add_flow(datapath, priority=100, match=match, actions=[], hard_timeout=180)
        self.enforced_hosts[src_ip] = "quarantine"
        self.logger.warning("[!] [OFP13 QUARANTINE] Installed priority=100 DROP rule for nw_src=%s", src_ip)

    def enforce_native_rate_limit(self, datapath, src_ip: str, rate_kbps: int = 512):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        meter_id = sum(int(x) for x in src_ip.split(".") if x.isdigit()) % 250 + 1

        bands = [parser.OFPMeterBandDrop(rate=rate_kbps, burst_size=rate_kbps * 2)]
        meter_mod = parser.OFPMeterMod(
            datapath=datapath,
            command=ofproto.OFPMC_ADD,
            flags=ofproto.OFPMF_KBPS | ofproto.OFPMF_BURST,
            meter_id=meter_id,
            bands=bands,
        )
        datapath.send_msg(meter_mod)

        match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip)
        actions = [parser.OFPActionOutput(ofproto.OFPP_NORMAL)]
        self._add_flow(datapath, priority=80, match=match, actions=actions, hard_timeout=180, meter_id=meter_id)
        self.enforced_hosts[src_ip] = "rate_limit"
        self.logger.warning("[~] [OFP13 METER] Installed meter=%d (%d kbps) priority=80 for nw_src=%s", meter_id, rate_kbps, src_ip)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match["in_port"]

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        if eth.ethertype == 0x88CC:
            return

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][eth.src] = in_port
        out_port = self.mac_to_port[dpid].get(eth.dst, ofproto.OFPP_FLOOD)

        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt:
            src_ip = ip_pkt.src
            dst_ip = ip_pkt.dst
            w = self.window_stats[src_ip]
            w["dst_ip"] = dst_ip
            w["pkt_count"] += 1
            w["byte_count"] += len(msg.data)

            tcp_pkt = pkt.get_protocol(tcp.tcp)
            udp_pkt = pkt.get_protocol(udp.udp)
            if tcp_pkt:
                w["dst_ports"].add(tcp_pkt.dst_port)
                w["flows"].add((tcp_pkt.src_port, tcp_pkt.dst_port, 6))
                if (tcp_pkt.bits & tcp.TCP_SYN) and not (tcp_pkt.bits & tcp.TCP_ACK):
                    w["syn_count"] += 1
            elif udp_pkt:
                w["dst_ports"].add(udp_pkt.dst_port)
                w["flows"].add((udp_pkt.src_port, udp_pkt.dst_port, 17))

        actions = [parser.OFPActionOutput(out_port)]
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None,
        )
        datapath.send_msg(out)

    def _telemetry_loop(self):
        while True:
            hub.sleep(POLL_INTERVAL_SEC)
            for dp in list(self.datapaths.values()):
                parser = dp.ofproto_parser
                dp.send_msg(parser.OFPFlowStatsRequest(dp))

            snapshot = dict(self.window_stats)
            self.window_stats.clear()

            for src_ip, b in snapshot.items():
                if b["pkt_count"] == 0:
                    continue
                pkt_count = max(1, b["pkt_count"])
                payload = {
                    "timestamp": time.time(),
                    "src_ip": src_ip,
                    "dst_ip": b["dst_ip"],
                    "flow_count": max(1, len(b["flows"])),
                    "pkt_rate": round(pkt_count / POLL_INTERVAL_SEC, 2),
                    "byte_rate": round(b["byte_count"] / POLL_INTERVAL_SEC, 2),
                    "mean_pkt_size": round(b["byte_count"] / pkt_count, 2),
                    "unique_dst_ports": max(1, len(b["dst_ports"])),
                    "syn_ratio": round(b["syn_count"] / pkt_count, 4),
                }
                try:
                    resp = requests.post(API_ANALYZE_URL, json=payload, timeout=1.5)
                    if resp.status_code == 200:
                        decision = resp.json()
                        action = decision.get("action", "allow")
                        if action == "quarantine" and self.enforced_hosts.get(src_ip) != "quarantine":
                            for dp in self.datapaths.values():
                                self.enforce_native_quarantine(dp, src_ip)
                        elif action == "rate_limit" and self.enforced_hosts.get(src_ip) != "rate_limit":
                            for dp in self.datapaths.values():
                                self.enforce_native_rate_limit(dp, src_ip, 512)
                except Exception as exc:
                    self.logger.debug("ML API unreachable: %s", exc)