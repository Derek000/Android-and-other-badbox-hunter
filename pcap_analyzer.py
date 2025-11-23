#!/usr/bin/env python3
"""
PCAP / Wi-Fi traffic analyzer for BadBox Hunter.

Offline-only: parses PCAP files and correlates traffic with IoCs.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

import logging

import pyshark  # requires tshark installed

from ioc_store import IoCStore

LOG = logging.getLogger("pcap_analyzer")


@dataclass
class FlowSuspicion:
    src_ip: str
    dst_ip: str
    dst_port: Optional[int]
    proto: str
    reasons: List[str] = field(default_factory=list)
    matched_iocs: Dict[str, List[str]] = field(default_factory=dict)


class PcapAnalyzer:
    """Lightweight IoC-driven analysis on PCAPs.

    Heuristics:
      - DNS queries against suspicious domains
      - Connections to IoC IPs
      - HTTP Host headers / TLS SNI matching suspicious domains / patterns
    """

    def __init__(self, iocs: IoCStore):
        self.iocs = iocs

    def analyze_files(self, pcaps: List[Path]) -> List[FlowSuspicion]:
        results: Dict[str, FlowSuspicion] = {}
        for pcap in pcaps:
            if not pcap.exists():
                LOG.warning("PCAP %s not found, skipping", pcap)
                continue
            LOG.info("Analyzing PCAP %s ...", pcap)
            self._analyze_single(pcap, results)
        return list(results.values())

    def _analyze_single(self, pcap: Path, flows: Dict[str, FlowSuspicion]) -> None:
        cap = pyshark.FileCapture(str(pcap), use_json=True)
        for pkt in cap:
            try:
                self._handle_packet(pkt, flows)
            except Exception as e:  # noqa: BLE001
                LOG.debug("Error parsing packet: %s", e)
        cap.close()

    def _handle_packet(self, pkt, flows: Dict[str, FlowSuspicion]) -> None:
        ip_layer = getattr(pkt, "ip", None) or getattr(pkt, "ipv6", None)
        if not ip_layer:
            return

        src_ip = getattr(ip_layer, "src", None)
        dst_ip = getattr(ip_layer, "dst", None)
        if not src_ip or not dst_ip:
            return

        proto = pkt.highest_layer
        dst_port = None
        if hasattr(pkt, "tcp"):
            dst_port = int(pkt.tcp.dstport)
        elif hasattr(pkt, "udp"):
            dst_port = int(pkt.udp.dstport)

        key = f"{src_ip}>{dst_ip}:{dst_port or 0}"
        flow = flows.get(key)
        if not flow:
            flow = FlowSuspicion(
                src_ip=src_ip,
                dst_ip=dst_ip,
                dst_port=dst_port,
                proto=proto,
            )
            flows[key] = flow

        # DNS queries
        if hasattr(pkt, "dns") and hasattr(pkt.dns, "qry_name"):
            qname = str(pkt.dns.qry_name).lower()
            for dom in self.iocs.domains:
                if dom.lower() in qname:
                    flow.reasons.append(f"dns_query_to_suspicious_domain:{qname}")
                    flow.matched_iocs.setdefault("domains", []).append(dom)

        # IP-based IoCs
        for bad_ip in self.iocs.ips:
            if dst_ip == bad_ip or src_ip == bad_ip:
                flow.reasons.append(f"ip_contact_with_ioc:{bad_ip}")
                flow.matched_iocs.setdefault("ips", []).append(bad_ip)

        # HTTP Host header
        if hasattr(pkt, "http") and hasattr(pkt.http, "host"):
            host = str(pkt.http.host).lower()
            for dom in self.iocs.domains:
                if dom.lower() in host:
                    flow.reasons.append(f"http_host_matches_ioc:{host}")
                    flow.matched_iocs.setdefault("domains", []).append(dom)

        # TLS SNI
        tls = getattr(pkt, "tls", None) or getattr(pkt, "ssl", None)
        if tls and hasattr(tls, "handshake_extensions_server_name"):
            sni = str(tls.handshake_extensions_server_name).lower()
            for dom in self.iocs.domains:
                if dom.lower() in sni:
                    flow.reasons.append(f"tls_sni_matches_ioc:{sni}")
                    flow.matched_iocs.setdefault("domains", []).append(dom)

        # Deduplicate
        flow.reasons = sorted(set(flow.reasons))
        for k in list(flow.matched_iocs.keys()):
            flow.matched_iocs[k] = sorted(set(flow.matched_iocs[k]))
