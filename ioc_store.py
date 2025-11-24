#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Simple flat-file IoC store for BadBox Hunter."""

import logging
from pathlib import Path
from typing import List, Set

LOG = logging.getLogger("ioc_store")


class IoCStore:
    def __init__(self, ioc_dir: Path) -> None:
        self.ioc_dir = ioc_dir
        self.domains: Set[str] = set()
        self.ips: Set[str] = set()
        self.user_agents: Set[str] = set()
        self.banners: Set[str] = set()

    def load(self) -> None:
        self.domains = self._load_file("domains.txt")
        self.ips = self._load_file("ips.txt")
        self.user_agents = self._load_file("user_agents.txt")
        self.banners = self._load_file("banners.txt")

    def _load_file(self, name: str) -> Set[str]:
        path = self.ioc_dir / name
        if not path.exists():
            LOG.info("IoC file missing: %s (0 IoCs)", path)
            return set()
        values: Set[str] = set()
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            values.add(line.lower())
        LOG.info("Loaded %d IoCs from %s", len(values), path)
        return values

    # Matching helpers

    def match_domain(self, domain: str) -> bool:
        if not domain:
            return False
        d = domain.lower()
        return any(d == ioc or d.endswith("." + ioc) for ioc in self.domains)

    def match_ip(self, ip: str) -> bool:
        if not ip:
            return False
        return ip.strip() in self.ips

    def match_user_agent(self, ua: str) -> bool:
        if not ua:
            return False
        ua_l = ua.lower()
        return any(pattern in ua_l for pattern in self.user_agents)

    def match_banner(self, banner: str) -> bool:
        if not banner:
            return False
        b = banner.lower()
        return any(pattern in b for pattern in self.banners)
