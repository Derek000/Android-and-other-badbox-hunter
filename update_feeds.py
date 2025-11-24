#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Fetch external IoC feeds and normalise them into flat files.

This is intentionally minimal and focused on a few well-known sources.
"""

import logging
from pathlib import Path
from typing import Any, Dict, List

import requests
import yaml

LOG = logging.getLogger("update_feeds")


def load_config(path: Path) -> Dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    return data or {}


def fetch_text(url: str) -> str:
    resp = requests.get(url, timeout=30)
    resp.raise_for_status()
    return resp.text


def process_abusech_urlhaus(raw: str) -> List[str]:
    values: List[str] = []
    for line in raw.splitlines():
        if not line or line.startswith("#"):
            continue
        # format: url;status;threat;...
        parts = line.split(",")
        if not parts:
            continue
        url = parts[0].strip()
        if "://" in url:
            host = url.split("://", 1)[1].split("/", 1)[0]
            values.append(host.lower())
    return values


def process_abusech_ipblocklist(raw: str) -> List[str]:
    values: List[str] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        values.append(line)
    return values


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    import argparse

    parser = argparse.ArgumentParser(description="Update IoC flat files from external feeds")
    parser.add_argument("--config", type=Path, default=Path("feeds/feeds.yaml"))
    parser.add_argument("--ioc-dir", type=Path, default=Path("iocs"))
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    cfg = load_config(args.config)
    feeds = cfg.get("feeds", [])

    args.ioc_dir.mkdir(exist_ok=True)

    domains_out: List[str] = []
    ips_out: List[str] = []

    for feed in feeds:
        if not feed.get("enabled", True):
            continue
        name = feed.get("name")
        ftype = feed.get("type")
        url = feed.get("url")
        target = feed.get("target")
        LOG.info("Fetching feed %s (%s) from %s", name, ftype, url)
        try:
            raw = fetch_text(url)
        except Exception as e:
            LOG.error("Failed to fetch feed %s: %s", name, e)
            continue

        values: List[str]
        if ftype == "abusech_urlhaus":
            values = process_abusech_urlhaus(raw)
        elif ftype == "abusech_ipblocklist":
            values = process_abusech_ipblocklist(raw)
        else:
            LOG.warning("Unknown feed type %s for %s, skipping", ftype, name)
            continue

        LOG.info("Feed %s produced %d values targeting %s", name, len(values), target)
        if target == "domains":
            domains_out.extend(values)
        elif target == "ips":
            ips_out.extend(values)

    # De-duplicate and write out
    domains_out = sorted(set(domains_out))
    ips_out = sorted(set(ips_out))

    (args.ioc_dir / "domains.txt").write_text("\n".join(domains_out) + "\n", encoding="utf-8")
    (args.ioc_dir / "ips.txt").write_text("\n".join(ips_out) + "\n", encoding="utf-8")

    # Ensure other IoC files exist
    for name in ("banners.txt", "user_agents.txt"):
        path = args.ioc_dir / name
        if not path.exists():
            path.write_text("", encoding="utf-8")

    LOG.info(
        "Updated IoC files in %s (domains=%d, ips=%d)",
        args.ioc_dir,
        len(domains_out),
        len(ips_out),
    )


if __name__ == "__main__":
    main()
