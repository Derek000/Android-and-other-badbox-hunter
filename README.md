# BadBox Hunter

Network and traffic-based helper for spotting suspicious Android / IoT devices
(including pre-infected “BadBox”-style devices) on networks you own or are
explicitly authorised to test.

**Features**

- Discover devices on home / lab / small office networks via `nmap`.
- Fingerprint open services and flag exposed ADB, Telnet, SSH, HTTP UIs.
- Correlate banners and flows against Indicators of Compromise (IoCs).
- Optional SSH enrichment for devices you own.
- Optional PCAP analysis (wired and Wi-Fi) using `pyshark` / `tshark`.
- Lightweight web UI (Flask + gunicorn) with:
  - Risk scoring (Low/Medium/High) per host.
  - Per-host details page (services, IoC evidence, SSH enrichment).
  - JSON export endpoint for scripting.
- Docker image for easy deployment.
- `update_feeds.py` to pull external threat intel feeds into `iocs/`.

This project is **defensive/triage only** – it does **not** exploit, brute
force, or attempt rooting.

---

## Quick start (CLI)

```bash
git clone https://github.com/Derek000/Android-and-other-badbox-hunter.git
cd badbox-hunter

python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt

# Edit iocs/*.txt or run update_feeds.py to pull external feeds
python badbox_hunter.py       --cidr 192.168.0.0/24       --ioc-dir iocs       --output badbox_report.json       -v
```

---

## Web UI + Docker

Build the image:

```bash
docker build -t badbox-hunter-web .
```

Run it (Linux, scan-only):

```bash
docker run --rm -it       --network host       -e BADBOX_HUNTER_DEFAULT_CIDRS="192.168.0.0/24"       badbox-hunter-web
```

Then open `http://localhost:8000` in your browser.

If you also want live packet capture from inside the container:

```bash
docker run --rm -it       --network host       --cap-add=NET_RAW --cap-add=NET_ADMIN       -e BADBOX_HUNTER_DEFAULT_CIDRS="192.168.0.0/24"       badbox-hunter-web
```

The web UI lets you:

- Enter CIDR ranges to scan.
- Optionally upload PCAP files (e.g. from `tcpdump` / Wireshark).
- Optionally trigger a short `tcpdump` capture from inside the container.
- Optionally reference an SSH inventory for extra host context.
- See hosts sorted by risk (Low/Medium/High).
- Click hosts for detailed view (services, IoC hits, SSH output).
- Download the full JSON report via `/api/report.json`.

For more detail see `docs/methodology.md`, `docs/capture-howto.md` and
`docs/feeds.md`.

---

## Threat intel feeds

BadBox Hunter can optionally enrich its IoC lists using external feeds.

1. Review and edit `feeds/feeds.yaml` (or create a JSON variant).
2. Set any required API keys via environment variables (e.g. `OTX_API_KEY`).
3. Run:

   ```bash
   python update_feeds.py --config feeds/feeds.yaml --ioc-dir iocs -v
   ```

4. Then run either:

   ```bash
   python badbox_hunter.py --cidr 192.168.0.0/24 --ioc-dir iocs
   ```

   or the Docker/web UI.

The scanner itself never calls external services; it only consumes the IoCs
present in `iocs/` at the time of the run.
