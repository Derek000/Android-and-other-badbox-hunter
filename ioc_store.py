from pathlib import Path
from typing import List
import logging

LOG = logging.getLogger("ioc_store")


class IoCStore:
    """Simple IoC holder backed by flat files.

    Expected structure:

    iocs/
      domains.txt
      ips.txt
      banners.txt
      user_agents.txt
    """

    def __init__(self, base_dir: Path):
        self.base_dir = base_dir
        self.domains = self._load_list("domains.txt")
        self.ips = self._load_list("ips.txt")
        self.user_agents = self._load_list("user_agents.txt")
        self.banners = self._load_list("banners.txt")

    def _load_list(self, name: str) -> List[str]:
        path = self.base_dir / name
        if not path.exists():
            LOG.warning("IoC file %s not found, continuing with empty list", path)
            return []
        items: List[str] = []
        with path.open("r", encoding="utf-8") as f:
            for line in f:
                s = line.strip()
                if not s or s.startswith("#"):
                    continue
                items.append(s)
        LOG.info("Loaded %d IoCs from %s", len(items), path)
        return items

    def match_banner(self, banner: str) -> List[str]:
        hits: List[str] = []
        for pattern in self.banners:
            if pattern.lower() in banner.lower():
                hits.append(pattern)
        return hits
