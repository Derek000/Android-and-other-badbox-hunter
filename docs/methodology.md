# Methodology and threat model

This project is a **defensive helper** for security professionals and
technically minded practitioners. It combines:

- Network scanning (nmap)
- Service fingerprinting (banners / OS guesses)
- IoC correlation (domains, IPs, banners)
- Optional SSH enrichment on devices you own
- Optional PCAP analysis of wired / Wi-Fi traffic

Code layout:

- `badbox_hunter.py` focuses on network discovery and IoC matching.
- `pcap_analyzer.py` focuses on DNS/HTTP/TLS-based IoCs on PCAPs.
- `ioc_store.py` loads IoCs from flat files.
- `web_app.py` provides a lightweight UI and JSON export.
- `update_feeds.py` optionally pulls external threat intel into `iocs/`.
