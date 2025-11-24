#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""PCAP analysis for BadBox Hunter.

Uses tshark/pyshark to identify flows that touch IoC domains/IPs.
"""

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List

import pyshark  # type: ignore

from ioc_store import IoCStore

LOG = logging.getLogger("pcap_analyzer")


@dataclass
class PCAPAnalysisResult:
    flows: List[Dict[str, Any]] = field(default_factory=list)


def analyse_pcap(pcap_path: Path, iocs: IoCStore) -> PCAPAnalysisResult:
    """Scan a PCAP for basic IoC hits.

    This is intentionally simple and conservative.
    """
    result = PCAPAnalysisResult()
    if not pcap_path.exists():
        LOG.error("PCAP file %s does not exist", pcap_path)
        return result

    LOG.info("Analysing PCAP %s for IoC hits...", pcap_path)
    try:
        cap = pyshark.FileCapture(str(pcap_path), only_summaries=False)
    except Exception as e:  # pragma: no cover - environment specific
        LOG.error("Failed to open PCAP %s with pyshark: %s", pcap_path, e)
        return result

    # Limit packet count so we don't explode on very large files
    max_packets = 10000
    count = 0

    for pkt in cap:
        count += 1
        if count > max_packets:
            LOG.info("Stopping PCAP analysis after %d packets (limit).", max_packets)
            break

        flow: Dict[str, Any] = {}
        try:
            if "ip" in pkt:
                flow["src_ip"] = getattr(pkt.ip, "src", None)
                flow["dst_ip"] = getattr(pkt.ip, "dst", None)
            elif "ipv6" in pkt:
                flow["src_ip"] = getattr(pkt.ipv6, "src", None)
                flow["dst_ip"] = getattr(pkt.ipv6, "dst", None)
        except Exception:
            pass

        # Basic protocol markers
        proto = getattr(getattr(pkt, "highest_layer", None), "lower", lambda: "")()
        flow["proto"] = proto

        # Extract candidate domains: DNS, HTTP host, TLS SNI
        domains = set()
        try:
            if hasattr(pkt, "dns") and hasattr(pkt.dns, "qry_name"):
                domains.add(str(pkt.dns.qry_name))
        except Exception:
            pass
        try:
            if hasattr(pkt, "http") and hasattr(pkt.http, "host"):
                domains.add(str(pkt.http.host))
        except Exception:
            pass
        try:
            if hasattr(pkt, "tls") and hasattr(pkt.tls, "handshake_extensions_server_name"):
                domains.add(str(pkt.tls.handshake_extensions_server_name))
        except Exception:
            pass

        ioc_hits: List[str] = []

        for d in domains:
            if iocs.match_domain(d):
                ioc_hits.append(f"domain:{d}")

        for key in ("src_ip", "dst_ip"):
            ip = flow.get(key)
            if ip and iocs.match_ip(ip):
                ioc_hits.append(f"ip:{ip}")

        if not ioc_hits:
            continue

        flow["domains"] = list(domains)
        flow["ioc_hits"] = ioc_hits
        result.flows.append(flow)

    try:
        cap.close()
    except Exception:
        pass

    LOG.info("PCAP analysis complete, %d flows with IoC hits.", len(result.flows))
    return result
