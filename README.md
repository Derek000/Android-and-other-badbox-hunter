# BadBox Hunter v3 (Web UI enabled)

BadBox Hunter is a small, opinionated triage tool to help security
practitioners quickly identify potentially compromised or backdoored
Android, IoT and other devices on a network.

Features:

- `nmap`-based default scanner with bounded retries and host timeouts.
- Optional fast engine using `masscan` + parallel `nmap`.
- Flat-file IoC store (`iocs/`) enriched from external feeds (`update_feeds.py`).
- Optional PCAP correlation (`pcap_analyzer.py`).
- JSON report with per-host details and meta metrics.
- Lightweight Flask web UI (`web_app.py`) suitable for Docker.

See `docs/USAGE.md` for detailed instructions.
