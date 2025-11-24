# BadBox Hunter – Usage

## 1. Install prerequisites

On Debian/Ubuntu (including WSL2):

```bash
sudo apt update
sudo apt install -y nmap tcpdump tshark python3-venv
# Optional fast engine:
sudo apt install -y masscan
```

## 2. Python environment

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
```

## 3. Update IoCs (recommended)

```bash
python update_feeds.py --config feeds/feeds.yaml --ioc-dir iocs -v
```

## 4. CLI scan

```bash
python badbox_hunter.py       --cidr 192.168.1.0/24       --ioc-dir iocs       --output badbox_report.json       --max-retries 1       --timeout-per-host 60s       -v
```

Key flags:

- `--cidr`: CIDR range(s) to scan (repeatable).
- `--exclude-ip`: specific IPs to exclude (repeatable).
- `--scan-engine`: `nmap` (default) or `masscan` (masscan+parallel nmap).
- `--max-retries`: passed to `nmap --max-retries`.
- `--timeout-per-host`: passed to `nmap --host-timeout`.
- `--pcap`: optional PCAP for correlation.
- `--output`: JSON report file.

## 5. Web UI

```bash
python web_app.py
```

Then visit <http://localhost:5000/>. Use the form to:

- Enter CIDRs and optional exclude IPs.
- Choose scan engine, retries, and host timeout.
- Upload a PCAP file (optional).
- View metrics, hosts and tags, and download the JSON report.
```
