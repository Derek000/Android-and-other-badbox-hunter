#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""BadBox Hunter v3 (with Web UI hooks)

Network- and PCAP-based triage tool to help detect compromised / backdoored
Android, IoT and other devices on small networks.
"""

import argparse
import ipaddress
import json
import logging
import subprocess
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from ioc_store import IoCStore
from pcap_analyzer import analyse_pcap, PCAPAnalysisResult

LOG = logging.getLogger("badbox_hunter")


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class ServiceInfo:
    port: int
    protocol: str
    name: str
    product: str = ""
    version: str = ""


@dataclass
class HostInfo:
    ip: str
    hostname: str = ""
    os_guess: str = ""
    services: List[ServiceInfo] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    risk_score: int = 0
    notes: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Nmap-based scanner
# ---------------------------------------------------------------------------


class NetworkScanner:
    """Wrapper around nmap.

    Default scan engine. Conservative and WSL/NAT friendly.
    """

    def __init__(
        self,
        cidrs: List[str],
        exclude_ips: Optional[List[str]] = None,
        max_retries: int = 1,
        host_timeout: str = "60s",
    ) -> None:
        self.cidrs = cidrs
        self.exclude_ips = exclude_ips or []
        self.max_retries = max_retries
        self.host_timeout = host_timeout

    def scan(self) -> List[HostInfo]:
        hosts: List[HostInfo] = []
        for cidr in self.cidrs:
            LOG.info("Scanning network %s with nmap, this may take a while...", cidr)
            cmd = [
                "nmap",
                "-sT",
                "-sV",
                "-Pn",
                "-T3",
                "--max-retries",
                str(self.max_retries),
                "--host-timeout",
                self.host_timeout,
                "-oX",
                "-",
                cidr,
            ]

            stop_event = threading.Event()

            def progress() -> None:
                dots = 0
                while not stop_event.is_set():
                    dots = (dots % 10) + 1
                    suffix = "." * dots
                    LOG.info("nmap still scanning %s%s", cidr, suffix)
                    time.sleep(10)

            t = threading.Thread(target=progress, daemon=True)
            t.start()

            try:
                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    check=True,
                )
            except FileNotFoundError:
                LOG.error("nmap not found. Please install nmap and try again.")
                stop_event.set()
                t.join(timeout=1)
                raise
            except subprocess.CalledProcessError as e:
                stop_event.set()
                t.join(timeout=1)
                stderr = e.stderr or ""
                LOG.error(
                    "nmap failed for %s (exit %s). stderr:\n%s",
                    cidr,
                    e.returncode,
                    stderr,
                )
                continue
            else:
                stop_event.set()
                t.join(timeout=1)
                xml_output = proc.stdout
                hosts.extend(self._parse_nmap_xml(xml_output))

        hosts = [h for h in hosts if h.ip not in self.exclude_ips]
        return hosts

    def _parse_nmap_xml(self, xml_output: str) -> List[HostInfo]:
        import xml.etree.ElementTree as ET

        hosts: List[HostInfo] = []
        try:
            root = ET.fromstring(xml_output)
        except ET.ParseError:
            LOG.error("Failed to parse nmap XML output.")
            return hosts

        for host_el in root.findall("host"):
            status = host_el.find("status")
            if status is not None and status.get("state") != "up":
                continue

            addr_el = host_el.find("address")
            if addr_el is None or addr_el.get("addrtype") != "ipv4":
                continue
            ip = addr_el.get("addr")
            if not ip:
                continue

            hostname = ""
            hostnames_el = host_el.find("hostnames")
            if hostnames_el is not None:
                hn_el = hostnames_el.find("hostname")
                if hn_el is not None:
                    hostname = hn_el.get("name") or ""

            os_guess = ""
            os_el = host_el.find("os")
            if os_el is not None:
                osmatch = os_el.find("osmatch")
                if osmatch is not None:
                    os_guess = osmatch.get("name") or ""

            services: List[ServiceInfo] = []
            ports_el = host_el.find("ports")
            if ports_el is not None:
                for port_el in ports_el.findall("port"):
                    state_el = port_el.find("state")
                    if state_el is None or state_el.get("state") != "open":
                        continue
                    portid = int(port_el.get("portid") or 0)
                    proto = port_el.get("protocol") or "tcp"
                    svc_el = port_el.find("service")
                    name = ""
                    product = ""
                    version = ""
                    if svc_el is not None:
                        name = svc_el.get("name") or ""
                        product = svc_el.get("product") or ""
                        version = svc_el.get("version") or ""
                    services.append(
                        ServiceInfo(
                            port=portid,
                            protocol=proto,
                            name=name,
                            product=product,
                            version=version,
                        )
                    )

            hosts.append(
                HostInfo(
                    ip=ip,
                    hostname=hostname,
                    os_guess=os_guess,
                    services=services,
                )
            )
        return hosts


# ---------------------------------------------------------------------------
# Masscan + parallel nmap scanner
# ---------------------------------------------------------------------------


class MasscanFastScanner(NetworkScanner):
    """Fast scanner using masscan for host discovery then parallel nmap."""

    def __init__(
        self,
        cidrs: List[str],
        exclude_ips: Optional[List[str]] = None,
        ports: Optional[List[int]] = None,
        rate: int = 5000,
        workers: int = 8,
        max_retries: int = 1,
        host_timeout: str = "60s",
    ) -> None:
        super().__init__(
            cidrs=cidrs,
            exclude_ips=exclude_ips,
            max_retries=max_retries,
            host_timeout=host_timeout,
        )
        self.ports = ports or [22, 23, 53, 80, 443, 8080, 8443, 5554, 5555]
        self.rate = rate
        self.workers = workers

    def _run_masscan(self, cidr: str) -> Set[str]:
        port_spec = ",".join(str(p) for p in self.ports)
        cmd = [
            "masscan",
            "-p",
            port_spec,
            "--rate",
            str(self.rate),
            "--wait",
            "5",
            "-oJ",
            "-",
            cidr,
        ]
        LOG.info("Running masscan on %s (ports %s, rate %s)...", cidr, port_spec, self.rate)
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=True,
            )
        except FileNotFoundError:
            LOG.error("masscan not found. Please install masscan and try again.")
            raise
        except subprocess.CalledProcessError as e:
            stderr = e.stderr or ""
            LOG.error(
                "masscan failed for %s (exit %s). stderr:\n%s",
                cidr,
                e.returncode,
                stderr,
            )
            return set()

        raw = proc.stdout.strip()
        if not raw:
            return set()

        discovered_ips: Set[str] = set()
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            LOG.error("Failed to decode masscan JSON output for %s", cidr)
            return set()

        for entry in data:
            ip = entry.get("ip")
            if not ip:
                continue
            discovered_ips.add(ip)

        LOG.info("masscan discovered %d candidate hosts in %s", len(discovered_ips), cidr)
        return discovered_ips

    def _scan_host_with_nmap(self, ip: str) -> List[HostInfo]:
        if ip in self.exclude_ips:
            return []
        LOG.info("nmap scanning host %s ...", ip)
        cmd = [
            "nmap",
            "-sT",
            "-sV",
            "-Pn",
            "-T3",
            "--max-retries",
            str(self.max_retries),
            "--host-timeout",
            self.host_timeout,
            "-oX",
            "-",
            ip,
        ]
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=True,
            )
        except subprocess.CalledProcessError as e:
            stderr = e.stderr or ""
            LOG.error(
                "nmap failed for host %s (exit %s). stderr:\n%s",
                ip,
                e.returncode,
                stderr,
            )
            return []
        except FileNotFoundError:
            LOG.error("nmap not found. Please install nmap and try again.")
            raise

        xml_output = proc.stdout
        return self._parse_nmap_xml(xml_output)

    def scan(self) -> List[HostInfo]:
        all_ips: Set[str] = set()
        for cidr in self.cidrs:
            ips = self._run_masscan(cidr)
            all_ips.update(ips)

        if not all_ips:
            LOG.info("No hosts discovered by masscan.")
            return []

        LOG.info(
            "Running nmap against %d discovered hosts with %d workers...",
            len(all_ips),
            self.workers,
        )
        hosts: List[HostInfo] = []

        from concurrent.futures import ThreadPoolExecutor, as_completed

        with ThreadPoolExecutor(max_workers=self.workers) as executor:
            future_to_ip = {
                executor.submit(self._scan_host_with_nmap, ip): ip
                for ip in sorted(all_ips)
            }
            for future in as_completed(future_to_ip):
                ip = future_to_ip[future]
                try:
                    host_infos = future.result()
                except Exception as e:
                    LOG.error("Error scanning host %s with nmap: %s", ip, e)
                    continue
                hosts.extend(host_infos)

        hosts = [h for h in hosts if h.ip not in self.exclude_ips]
        LOG.info("Completed fast scan, %d hosts total after exclusions.", len(hosts))
        return hosts


# ---------------------------------------------------------------------------
# Risk scoring, enrichment and PCAP integration
# ---------------------------------------------------------------------------


def enrich_hosts_with_iocs(hosts: List[HostInfo], iocs: IoCStore) -> None:
    """Add IoC-based tags and a simple risk score to each host."""
    for host in hosts:
        score = host.risk_score
        tags: List[str] = []

        if iocs.match_ip(host.ip):
            tags.append("ioc:ip")
            score += 50

        for svc in host.services:
            banner = f"{svc.name} {svc.product} {svc.version}".strip()
            if banner and iocs.match_banner(banner):
                tags.append(f"ioc:banner:{svc.port}")
                score += 20
            if svc.port in (5554, 5555):
                tags.append("suspicious:adb-tcp")
                score += 15
            if svc.name and svc.name.lower() == "telnet":
                tags.append("suspicious:telnet")
                score += 10

        if score >= 60:
            tags.append("priority:high")
        elif score >= 30:
            tags.append("priority:medium")
        elif score > 0:
            tags.append("priority:low")

        host.tags = sorted(set(host.tags + tags))
        host.risk_score = score

def integrate_pcap(hosts: List[HostInfo], pcap_result: PCAPAnalysisResult) -> None:
    if not pcap_result.flows:
        return

    host_by_ip: Dict[str, HostInfo] = {h.ip: h for h in hosts}

    for flow in pcap_result.flows:
        for key in ("src_ip", "dst_ip"):
            ip = flow.get(key)
            if not ip:
                continue
            host = host_by_ip.get(ip)
            if not host:
                continue
            host.notes.setdefault("pcap_ioc_flows", []).append(flow)
            if "ioc:pcap" not in host.tags:
                host.tags.append("ioc:pcap")
            host.risk_score = max(host.risk_score, host.risk_score + 10)


# ---------------------------------------------------------------------------
# Metrics helper
# ---------------------------------------------------------------------------


def compute_metrics(
    hosts: List[HostInfo],
    scan_engine: str,
    cidrs: List[str],
    max_retries: int,
    timeout_per_host: str,
    duration_seconds: float,
) -> Dict[str, Any]:
    num_hosts = len(hosts)
    num_ioc_hosts = sum(1 for h in hosts if any(t.startswith("ioc:") for t in h.tags))
    num_high = sum(1 for h in hosts if "priority:high" in h.tags)
    num_medium = sum(1 for h in hosts if "priority:medium" in h.tags)
    num_low = sum(1 for h in hosts if "priority:low" in h.tags)

    metrics: Dict[str, Any] = {
        "num_hosts": num_hosts,
        "num_ioc_hosts": num_ioc_hosts,
        "priority_counts": {
            "high": num_high,
            "medium": num_medium,
            "low": num_low,
        },
        "scan_engine": scan_engine,
        "cidrs": cidrs,
        "max_retries": max_retries,
        "timeout_per_host": timeout_per_host,
        "duration_seconds": duration_seconds,
    }
    return metrics


# ---------------------------------------------------------------------------
# CLI + orchestrator
# ---------------------------------------------------------------------------


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="BadBox Hunter v3")
    parser.add_argument(
        "--cidr",
        action="append",
        required=True,
        help="CIDR range to scan (can be specified multiple times).",
    )
    parser.add_argument(
        "--exclude-ip",
        action="append",
        default=[],
        help="IP address to exclude from results (can be specified multiple times).",
    )
    parser.add_argument(
        "--ioc-dir",
        type=Path,
        default=Path("iocs"),
        help="Directory containing IoC flat files (default: iocs).",
    )
    parser.add_argument(
        "--pcap",
        type=Path,
        help="Optional PCAP file to analyse and correlate with hosts.",
    )
    parser.add_argument(
        "--scan-engine",
        choices=["nmap", "masscan"],
        default="nmap",
        help="Scan engine to use. 'masscan' uses masscan for fast host discovery then parallel nmap.",
    )
    parser.add_argument(
        "--max-retries",
        type=int,
        default=1,
        help="Maximum nmap retries per port (default: 1).",
    )
    parser.add_argument(
        "--timeout-per-host",
        type=str,
        default="60s",
        help="Nmap host timeout per host, e.g. '30s', '2m' (default: 60s).",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("badbox_report.json"),
        help="Output JSON report path (default: badbox_report.json).",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose logging.",
    )
    return parser.parse_args()


def run_assessment(
    cidrs: List[str],
    exclude_ips: List[str],
    ioc_dir: Path,
    scan_engine: str,
    max_retries: int,
    timeout_per_host: str,
    pcap_path: Optional[Path] = None,
) -> List[HostInfo]:
    """Main orchestrator used by both CLI and web UI."""
    normalised_cidrs: List[str] = []
    for cidr in cidrs:
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except ValueError as e:
            LOG.error("Invalid CIDR %s: %s", cidr, e)
            continue
        normalised_cidrs.append(str(net))
    if not normalised_cidrs:
        LOG.error("No valid CIDRs to scan; aborting.")
        return []

    iocs = IoCStore(ioc_dir=ioc_dir)
    iocs.load()

    if scan_engine == "masscan":
        scanner = MasscanFastScanner(
            cidrs=normalised_cidrs,
            exclude_ips=exclude_ips,
            max_retries=max_retries,
            host_timeout=timeout_per_host,
        )
    else:
        scanner = NetworkScanner(
            cidrs=normalised_cidrs,
            exclude_ips=exclude_ips,
            max_retries=max_retries,
            host_timeout=timeout_per_host,
        )

    hosts = scanner.scan()

    if pcap_path is not None:
        pcap_result = analyse_pcap(pcap_path, iocs)
        integrate_pcap(hosts, pcap_result)

    enrich_hosts_with_iocs(hosts, iocs)
    return hosts


def hosts_to_json(hosts: List[HostInfo]) -> List[Dict[str, Any]]:
    data: List[Dict[str, Any]] = []
    for h in hosts:
        data.append(
            {
                "ip": h.ip,
                "hostname": h.hostname,
                "os_guess": h.os_guess,
                "services": [
                    {
                        "port": s.port,
                        "protocol": s.protocol,
                        "name": s.name,
                        "product": s.product,
                        "version": s.version,
                    }
                    for s in h.services
                ],
                "tags": h.tags,
                "risk_score": h.risk_score,
                "notes": h.notes,
            }
        )
    return data


def main() -> None:
    args = parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    LOG.info("Starting BadBox Hunter v3")

    start_ts = time.time()
    hosts = run_assessment(
        cidrs=args.cidr,
        exclude_ips=args.exclude_ip,
        ioc_dir=args.ioc_dir,
        scan_engine=args.scan_engine,
        max_retries=args.max_retries,
        timeout_per_host=args.timeout_per_host,
        pcap_path=args.pcap,
    )
    duration = time.time() - start_ts

    metrics = compute_metrics(
        hosts=hosts,
        scan_engine=args.scan_engine,
        cidrs=args.cidr,
        max_retries=args.max_retries,
        timeout_per_host=args.timeout_per_host,
        duration_seconds=duration,
    )

    report_data = {
        "hosts": hosts_to_json(hosts),
        "meta": metrics,
    }

    args.output.write_text(json.dumps(report_data, indent=2), encoding="utf-8")
    LOG.info(
        "Wrote report for %d hosts to %s (duration %.2fs)",
        len(hosts),
        args.output,
        duration,
    )


if __name__ == "__main__":
    main()
