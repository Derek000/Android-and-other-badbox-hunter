#!/usr/bin/env python3
"""
BadBox / Android IoT hunter – scans local networks and (optionally) packet
captures for suspicious devices and flows.

Defensive use only: only run against networks and devices you own or have
explicit permission to test.
"""

import argparse
import ipaddress
import json
import logging
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Any

try:
    import paramiko  # SSH client (optional)
except ImportError:  # pragma: no cover
    paramiko = None

from ioc_store import IoCStore

LOG = logging.getLogger("badbox_hunter")


# ------------------------------
# Data classes
# ------------------------------


@dataclass
class HostService:
    port: int
    protocol: str
    service: str
    banner: str = ""


@dataclass
class HostInfo:
    ip: str
    hostname: Optional[str] = None
    mac: Optional[str] = None
    os_guess: Optional[str] = None
    services: List[HostService] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    ioc_hits: Dict[str, Any] = field(default_factory=dict)


# ------------------------------
# Network scanning
# ------------------------------


class NetworkScanner:
    """Wrapper around nmap. Requires nmap installed."""

    def __init__(self, cidrs: List[str], exclude_ips: Optional[List[str]] = None):
        self.cidrs = cidrs
        self.exclude_ips = set(exclude_ips or [])

    def scan(self) -> List[HostInfo]:
        hosts: List[HostInfo] = []
        for cidr in self.cidrs:
            LOG.info("Scanning network %s with nmap, this may take a while...", cidr)
            cmd = ["nmap", "-sS", "-sV", "-O", "-oX", "-", cidr]
            try:
                proc = subprocess.run(
                    cmd, capture_output=True, text=True, check=True
                )
            except FileNotFoundError:
                LOG.error("nmap not found. Please install nmap and try again.")
                raise
            except subprocess.CalledProcessError as e:
                LOG.error("nmap failed: %s", e)
                continue

            xml_output = proc.stdout
            hosts.extend(self._parse_nmap_xml(xml_output))

        hosts = [h for h in hosts if h.ip not in self.exclude_ips]
        return hosts

    @staticmethod
    def _parse_nmap_xml(xml_output: str) -> List[HostInfo]:
        import xml.etree.ElementTree as ET

        host_infos: List[HostInfo] = []
        root = ET.fromstring(xml_output)
        for host in root.findall("host"):
            status_el = host.find("status")
            if status_el is not None and status_el.get("state") != "up":
                continue

            addr = host.find("address[@addrtype='ipv4']")
            if addr is None:
                continue
            ip = addr.get("addr")
            if not ip:
                continue

            hi = HostInfo(ip=ip)

            hostname_el = host.find("hostnames/hostname")
            if hostname_el is not None:
                hi.hostname = hostname_el.get("name")

            os_el = host.find("os/osmatch")
            if os_el is not None:
                hi.os_guess = os_el.get("name")

            for port_el in host.findall("ports/port"):
                portid = int(port_el.get("portid"))
                proto = port_el.get("protocol") or "tcp"

                state_el = port_el.find("state")
                if state_el is not None and state_el.get("state") != "open":
                    continue

                service_el = port_el.find("service")
                service_name = (
                    service_el.get("name") if service_el is not None else "unknown"
                )

                banner = ""
                if service_el is not None:
                    product = service_el.get("product") or ""
                    version = service_el.get("version") or ""
                    extrainfo = service_el.get("extrainfo") or ""
                    banner = " ".join(x for x in [product, version, extrainfo] if x)

                hi.services.append(
                    HostService(
                        port=portid,
                        protocol=proto,
                        service=service_name,
                        banner=banner,
                    )
                )

            host_infos.append(hi)
        return host_infos


# ------------------------------
# SSH enrichment
# ------------------------------


class SSHInspector:
    """Optional SSH enrichment.

    Inventory JSON format:
    [
      {"ip": "192.168.1.10", "user": "root", "auth": "key", "key_path": "~/.ssh/id_rsa"},
      {"ip": "192.168.1.11", "user": "pi", "auth": "password", "password": "s3cret"}
    ]
    """

    def __init__(self, inventory_path: Optional[Path]):
        self.inventory_path = inventory_path
        self.inventory = self._load_inventory() if inventory_path else []

    def _load_inventory(self) -> List[Dict[str, Any]]:
        if not self.inventory_path.exists():
            LOG.warning(
                "SSH inventory %s not found; SSH checks disabled", self.inventory_path
            )
            return []
        with self.inventory_path.open("r", encoding="utf-8") as f:
            data = json.load(f)
        return data

    def enrich_host(self, host: HostInfo) -> None:
        if paramiko is None:
            LOG.debug("paramiko not installed, skipping SSH for %s", host.ip)
            return

        entry = next((e for e in self.inventory if e.get("ip") == host.ip), None)
        if not entry:
            return

        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            if entry.get("auth") == "key":
                key_path = Path(entry["key_path"]).expanduser()
                ssh.connect(
                    host.ip,
                    username=entry["user"],
                    key_filename=str(key_path),
                    timeout=10,
                )
            else:
                ssh.connect(
                    host.ip,
                    username=entry["user"],
                    password=entry["password"],
                    timeout=10,
                )
        except Exception as e:  # noqa: BLE001
            LOG.warning("SSH connection to %s failed: %s", host.ip, e)
            return

        try:
            commands = {
                "uname": "uname -a",
                "ps": "ps auxw | head -n 25",
                "netstat": "netstat -tunp 2>/dev/null | head -n 25",
            }
            for key, cmd in commands.items():
                stdin, stdout, stderr = ssh.exec_command(cmd, timeout=10)
                output = stdout.read().decode("utf-8", errors="ignore")
                setattr(host, f"ssh_{key}", output)
        finally:
            ssh.close()


# ------------------------------
# Analysis
# ------------------------------


class Analyzer:
    """Applies tagging and IoC matching to hosts."""

    def __init__(self, iocs: IoCStore):
        self.iocs = iocs

    def analyse(self, hosts: List[HostInfo]) -> None:
        for host in hosts:
            self._tag_host(host)
            self._match_iocs(host)

    def _tag_host(self, host: HostInfo) -> None:
        ip = ipaddress.ip_address(host.ip)
        if ip.is_private:
            host.tags.append("private-net")

        for svc in host.services:
            if svc.port == 5555:
                host.tags.append("adb-exposed")
            if svc.port in (22, 2222):
                host.tags.append("ssh")
            if svc.port in (23, 2323):
                host.tags.append("telnet")
            if svc.service in ("http", "http-alt", "https"):
                host.tags.append("http-ui")

        if host.os_guess and "android" in host.os_guess.lower():
            host.tags.append("android-ish")

        host.tags = sorted(set(host.tags))

    def _match_iocs(self, host: HostInfo) -> None:
        banner_hits: List[str] = []
        for svc in host.services:
            if svc.banner:
                hits = self.iocs.match_banner(svc.banner)
                if hits:
                    banner_hits.extend(hits)

        if banner_hits:
            host.ioc_hits["banners"] = sorted(set(banner_hits))


# ------------------------------
# Reporting
# ------------------------------


class Reporter:
    def __init__(self, output_path: Path):
        self.output_path = output_path

    def to_dicts(self, hosts: List[HostInfo]) -> List[Dict[str, Any]]:
        data: List[Dict[str, Any]] = []
        for h in hosts:
            entry: Dict[str, Any] = {
                "ip": h.ip,
                "hostname": h.hostname,
                "os_guess": h.os_guess,
                "tags": h.tags,
                "ioc_hits": h.ioc_hits,
                "services": [
                    {
                        "port": s.port,
                        "protocol": s.protocol,
                        "service": s.service,
                        "banner": s.banner,
                    }
                    for s in h.services
                ],
            }
            for key in ("ssh_uname", "ssh_ps", "ssh_netstat"):
                if hasattr(h, key):
                    entry[key] = getattr(h, key)
            data.append(entry)
        return data

    def write(self, hosts: List[HostInfo]) -> None:
        data = self.to_dicts(hosts)
        self.output_path.write_text(
            json.dumps(data, indent=2), encoding="utf-8"
        )
        LOG.info("Wrote report for %d hosts to %s", len(hosts), self.output_path)


# ------------------------------
# Assessment helper (reusable from web UI)
# ------------------------------


def calculate_risk_score(host: HostInfo) -> Dict[str, Any]:
    """Simple heuristic scoring for hosts.

    Returns a dict with 'score' and 'level' (Low/Medium/High).
    """
    score = 0
    tags = set(host.tags)
    ioc_hits = host.ioc_hits or {}

    if "adb-exposed" in tags:
        score += 3
    if "telnet" in tags:
        score += 3
    if "pcap-suspicious-traffic" in tags:
        score += 2
    if "android-ish" in tags:
        score += 1
    if "http-ui" in tags:
        score += 1

    if "banners" in ioc_hits and ioc_hits["banners"]:
        score += 2
    if "pcap_flows" in ioc_hits and ioc_hits["pcap_flows"]:
        score += 3

    if score >= 7:
        level = "High"
    elif score >= 4:
        level = "Medium"
    else:
        level = "Low"

    return {"score": score, "level": level}


def run_assessment(
    cidrs: List[str],
    ioc_dir: Path,
    exclude_ips: Optional[List[str]] = None,
    ssh_inventory: Optional[Path] = None,
    pcaps: Optional[List[Path]] = None,
    capture_iface: Optional[str] = None,
    capture_seconds: int = 60,
) -> List[HostInfo]:
    """Programmatic assessment entry-point.

    Used by the CLI and the web UI.
    """
    iocs = IoCStore(ioc_dir)
    scanner = NetworkScanner(cidrs, exclude_ips=exclude_ips or [])
    ssh_inspector = SSHInspector(ssh_inventory)
    analyzer = Analyzer(iocs)

    final_pcaps: List[Path] = list(pcaps or [])
    if capture_iface:
        tmp_pcap = Path(f"capture_{capture_iface}.pcap")
        LOG.info(
            "Starting live capture on %s for %d seconds -> %s",
            capture_iface,
            capture_seconds,
            tmp_pcap,
        )
        cmd = [
            "tcpdump",
            "-i", capture_iface,
            "-w", str(tmp_pcap),
            "-s", "0",
            "-G", str(capture_seconds),
            "-W", "1",
        ]
        proc = subprocess.run(cmd)
        if proc.returncode != 0:
            LOG.error("tcpdump failed with code %s", proc.returncode)
        else:
            final_pcaps.append(tmp_pcap)

    hosts = scanner.scan()
    for host in hosts:
        ssh_inspector.enrich_host(host)
    analyzer.analyse(hosts)

    if final_pcaps:
        from pcap_analyzer import PcapAnalyzer

        p_analyzer = PcapAnalyzer(iocs)
        flows = p_analyzer.analyze_files(final_pcaps)

        ip_to_host = {h.ip: h for h in hosts}
        for flow in flows:
            h = ip_to_host.get(flow.src_ip) or ip_to_host.get(flow.dst_ip)
            if not h:
                continue
            h.tags.append("pcap-suspicious-traffic")
            h.tags = sorted(set(h.tags))
            h.ioc_hits.setdefault("pcap_flows", [])
            h.ioc_hits["pcap_flows"].append(
                {
                    "src_ip": flow.src_ip,
                    "dst_ip": flow.dst_ip,
                    "dst_port": flow.dst_port,
                    "proto": flow.proto,
                    "reasons": flow.reasons,
                    "matched_iocs": flow.matched_iocs,
                }
            )

    for h in hosts:
        risk = calculate_risk_score(h)
        h.ioc_hits.setdefault("risk", risk)

    return hosts


# ------------------------------
# CLI entrypoint
# ------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "BadBox / Android IoT hunter – scans local network and "
            "checks for suspicious devices (defensive use only)."
        )
    )
    parser.add_argument(
        "--cidr",
        action="append",
        required=True,
        help="CIDR(s) to scan, e.g. --cidr 192.168.1.0/24 (repeatable).",
    )
    parser.add_argument(
        "--exclude-ip",
        action="append",
        default=[],
        help="IP to exclude (can be repeated).",
    )
    parser.add_argument(
        "--ioc-dir",
        type=Path,
        default=Path("iocs"),
        help="Directory containing IoC text files.",
    )
    parser.add_argument(
        "--ssh-inventory",
        type=Path,
        default=None,
        help="Optional JSON inventory with SSH credentials.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("badbox_report.json"),
        help="Path for JSON output report.",
    )
    parser.add_argument(
        "--pcap",
        type=Path,
        action="append",
        default=[],
        help="PCAP file to analyze (repeatable).",
    )
    parser.add_argument(
        "--capture-iface",
        type=str,
        default=None,
        help="Optional interface for live tcpdump capture.",
    )
    parser.add_argument(
        "--capture-seconds",
        type=int,
        default=60,
        help="Duration for live capture in seconds (with --capture-iface).",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable verbose logging."
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    reporter = Reporter(args.output)

    hosts = run_assessment(
        cidrs=args.cidr,
        ioc_dir=args.ioc_dir,
        exclude_ips=args.exclude_ip,
        ssh_inventory=args.ssh_inventory,
        pcaps=args.pcap,
        capture_iface=args.capture_iface,
        capture_seconds=args.capture_seconds,
    )

    reporter.write(hosts)


if __name__ == "__main__":
    main()
