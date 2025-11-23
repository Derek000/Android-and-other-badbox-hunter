#!/usr/bin/env python3
"""
update_feeds.py

Fetches external threat intel feeds (as configured in feeds/feeds.yaml or
feeds/feeds.json) and normalises them into the local iocs/ directory so
that BadBox Hunter can use them during scans and PCAP analysis.

This script is intentionally separate from the main scanner so that you can
refresh feeds in an online environment and then operate offline/onsite.
"""

import argparse
import csv
import json
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Set, Any

import requests

try:
    import yaml  # type: ignore
except ImportError:  # pragma: no cover
    yaml = None

LOG = logging.getLogger("update_feeds")


@dataclass
class FeedResult:
    name: str
    type: str
    domains: Set[str] = field(default_factory=set)
    ips: Set[str] = field(default_factory=set)
    meta: Dict[str, Any] = field(default_factory=dict)


class FeedAggregator:
    def __init__(self, config: Dict[str, Dict[str, Any]]):
        self.config = config

    def run(self) -> List[FeedResult]:
        results: List[FeedResult] = []
        for name, cfg in self.config.items():
            if not cfg.get("enabled", True):
                LOG.info("Feed %s disabled, skipping", name)
                continue
            ftype = cfg.get("type")
            if not ftype:
                LOG.warning("Feed %s missing 'type', skipping", name)
                continue
            handler = getattr(self, f"_handle_{ftype}", None)
            if not handler:
                LOG.warning("Feed type %s (feed %s) not implemented, skipping", ftype, name)
                continue
            try:
                result = handler(name, cfg)
                results.append(result)
            except Exception as exc:  # noqa: BLE001
                LOG.error("Error processing feed %s (%s): %s", name, ftype, exc)
        return results

    # ---- URLhaus CSV ----

    def _handle_urlhaus(self, name: str, cfg: Dict[str, Any]) -> FeedResult:
        url = cfg["url"]
        LOG.info("Fetching URLhaus feed %s from %s", name, url)
        r = requests.get(url, timeout=60)
        r.raise_for_status()
        text = r.text
        domains: Set[str] = set()
        ips: Set[str] = set()

        reader = csv.reader(line for line in text.splitlines() if not line.startswith("#"))
        header = next(reader, None)
        if not header:
            LOG.warning("URLhaus feed %s appears empty", name)
            return FeedResult(name=name, type="urlhaus")

        header_map = {col: idx for idx, col in enumerate(header)}

        def idx(col: str) -> int:
            return header_map.get(col, -1)

        url_idx = idx("url")
        host_idx = idx("host")
        status_idx = idx("status")

        for row in reader:
            if not row:
                continue
            try:
                status = row[status_idx] if status_idx >= 0 else ""
            except IndexError:
                status = ""
            if status and status.lower() not in ("online", "active"):
                continue

            host = ""
            if host_idx >= 0 and host_idx < len(row):
                host = row[host_idx].strip()
            elif url_idx >= 0 and url_idx < len(row):
                url_value = row[url_idx].strip()
                if "://" in url_value:
                    host = url_value.split("://", 1)[1].split("/", 1)[0]
                else:
                    host = url_value.split("/", 1)[0]

            if host:
                host_only = host.split(":", 1)[0].lower()
                if self._looks_like_ip(host_only):
                    ips.add(host_only)
                else:
                    domains.add(host_only)

        return FeedResult(
            name=name,
            type="urlhaus",
            domains=domains,
            ips=ips,
            meta={"source_url": url, "entries": len(domains) + len(ips)},
        )

    # ---- SSLBL botnet C2 IP list ----

    def _handle_sslbl_ips(self, name: str, cfg: Dict[str, Any]) -> FeedResult:
        url = cfg["url"]
        LOG.info("Fetching SSLBL IP feed %s from %s", name, url)
        r = requests.get(url, timeout=60)
        r.raise_for_status()
        text = r.text
        ips: Set[str] = set()

        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(",")
            ip = parts[0].strip()
            if self._looks_like_ip(ip):
                ips.add(ip)

        return FeedResult(
            name=name,
            type="sslbl_ips",
            ips=ips,
            meta={"source_url": url, "entries": len(ips)},
        )

    # ---- OTX pulses ----

    def _handle_otx_pulses(self, name: str, cfg: Dict[str, Any]) -> FeedResult:
        api_url = cfg.get("api_url", "https://otx.alienvault.com/api/v1")
        api_key_env = cfg.get("api_key_env", "OTX_API_KEY")
        api_key = os.environ.get(api_key_env)
        if not api_key:
            raise RuntimeError(f"OTX feed {name} requires API key in env {api_key_env}")

        headers = {"X-OTX-API-KEY": api_key}
        pulses = cfg.get("pulses") or []
        if not pulses:
            LOG.warning(
                "OTX feed %s has no 'pulses' list configured; nothing will be fetched. "
                "You can either add pulse IDs in feeds.yaml or extend this handler to "
                "use /pulses/subscribed or other OTX endpoints.",
                name,
            )
            return FeedResult(name=name, type="otx_pulses")

        domains: Set[str] = set()
        ips: Set[str] = set()
        fetched_pulses: List[str] = []

        for pulse_id in pulses:
            url = f"{api_url.rstrip('/')}/pulses/{pulse_id}"
            LOG.info("Fetching OTX pulse %s (%s)", pulse_id, name)
            resp = requests.get(url, headers=headers, timeout=60)
            resp.raise_for_status()
            data = resp.json()
            fetched_pulses.append(pulse_id)
            indicators = data.get("indicators", [])
            for ind in indicators:
                itype = str(ind.get("type", "")).lower()
                value = (ind.get("indicator") or "").strip()
                if not value:
                    continue
                if itype in ("ipv4", "ipv4_addr"):
                    if self._looks_like_ip(value):
                        ips.add(value)
                elif itype in ("domain", "hostname"):
                    domains.add(value.lower())

        return FeedResult(
            name=name,
            type="otx_pulses",
            domains=domains,
            ips=ips,
            meta={"api_url": api_url, "pulses": fetched_pulses},
        )

    # ---- Shadowserver CSV (offline) ----

    def _handle_shadowserver_csv(self, name: str, cfg: Dict[str, Any]) -> FeedResult:
        paths = [Path(p) for p in cfg.get("paths", [])]
        ip_column = cfg.get("ip_column", "ip")
        ips: Set[str] = set()
        processed_files: List[str] = []

        for path in paths:
            if not path.exists():
                LOG.warning("Shadowserver CSV %s not found, skipping", path)
                continue
            LOG.info("Parsing Shadowserver CSV %s for IP column '%s'", path, ip_column)
            with path.open("r", encoding="utf-8", errors="ignore") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    ip = (row.get(ip_column) or "").strip()
                    if self._looks_like_ip(ip):
                        ips.add(ip)
            processed_files.append(str(path))

        return FeedResult(
            name=name,
            type="shadowserver_csv",
            ips=ips,
            meta={"files": processed_files, "entries": len(ips)},
        )

    @staticmethod
    def _looks_like_ip(value: str) -> bool:
        parts = value.split(".")
        if len(parts) != 4:
            return False
        try:
            nums = [int(p) for p in parts]
        except ValueError:
            return False
        return all(0 <= n <= 255 for n in nums)


def load_config(path: Path) -> Dict[str, Dict[str, Any]]:
    if not path.exists():
        raise FileNotFoundError(f"Config file {path} does not exist")
    if path.suffix.lower() in (".yaml", ".yml"):
        if yaml is None:
            raise RuntimeError(
                "PyYAML not installed but YAML config requested. "
                "Install PyYAML or use JSON config."
            )
        return yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if path.suffix.lower() == ".json":
        return json.loads(path.read_text(encoding="utf-8"))
    raise ValueError(f"Unsupported config type for {path}; use .yaml, .yml or .json")


def merge_and_write_iocs(
    ioc_dir: Path,
    feed_results: List[FeedResult],
    summary_path: Path,
) -> None:
    ioc_dir.mkdir(parents=True, exist_ok=True)

    domains_file = ioc_dir / "domains.txt"
    ips_file = ioc_dir / "ips.txt"

    existing_domains: Set[str] = set()
    existing_ips: Set[str] = set()

    if domains_file.exists():
        for line in domains_file.read_text(encoding="utf-8").splitlines():
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            existing_domains.add(s.lower())

    if ips_file.exists():
        for line in ips_file.read_text(encoding="utf-8").splitlines():
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            existing_ips.add(s)

    new_domains: Set[str] = set()
    new_ips: Set[str] = set()
    summary_feeds: List[Dict[str, Any]] = []

    for fr in feed_results:
        new_domains.update(fr.domains)
        new_ips.update(fr.ips)
        summary_feeds.append(
            {
                "name": fr.name,
                "type": fr.type,
                "domains": len(fr.domains),
                "ips": len(fr.ips),
                "meta": fr.meta,
            }
        )

    all_domains = sorted(existing_domains.union(new_domains))
    all_ips = sorted(existing_ips.union(new_ips))

    with domains_file.open("w", encoding="utf-8") as f:
        f.write("# Auto-generated by update_feeds.py\n")
        for d in all_domains:
            f.write(d + "\n")

    with ips_file.open("w", encoding="utf-8") as f:
        f.write("# Auto-generated by update_feeds.py\n")
        for ip in all_ips:
            f.write(ip + "\n")

    summary = {
        "domains_total": len(all_domains),
        "ips_total": len(all_ips),
        "feeds": summary_feeds,
    }
    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    LOG.info(
        "Updated IoCs: %d domains, %d IPs (from %d feeds)",
        len(all_domains),
        len(all_ips),
        len(feed_results),
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Fetch external threat intel feeds into iocs/ for BadBox Hunter"
        )
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=Path("feeds/feeds.yaml"),
        help="Path to feeds configuration (YAML or JSON).",
    )
    parser.add_argument(
        "--ioc-dir",
        type=Path,
        default=Path("iocs"),
        help="Directory containing IoC text files.",
    )
    parser.add_argument(
        "--summary",
        type=Path,
        default=Path("feeds/last_update.json"),
        help="Where to write a JSON summary of feed contents.",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable verbose logging.",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    config = load_config(args.config)
    if not isinstance(config, dict):
        raise RuntimeError(f"Unexpected config format in {args.config}; expected mapping")

    aggregator = FeedAggregator(config)
    feed_results = aggregator.run()
    merge_and_write_iocs(args.ioc_dir, feed_results, args.summary)


if __name__ == "__main__":
    main()
