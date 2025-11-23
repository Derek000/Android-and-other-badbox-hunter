# External feeds integration

`update_feeds.py` lets you pull threat intelligence from external sources
into the local `iocs/` directory so that both the CLI and web UI runs have
up-to-date indicators.

## Design

- Configuration lives in `feeds/feeds.yaml` (or `feeds/feeds.json`).
- Each top-level key is a feed name; the value is a config dictionary.
- `update_feeds.py`:
  - Downloads and parses enabled feeds.
  - Normalises domains and IPs into Python sets.
  - Merges them into `iocs/domains.txt` and `iocs/ips.txt` (union with any
    existing entries).
  - Writes a summary to `feeds/last_update.json` with source counts and
    timestamps.

The runtime scanner (`badbox_hunter.py`) does **not** call any external
services. It reads whatever is present in `iocs/` at the time of the run,
so you can:

- Refresh feeds in an online environment, then
- Take the repo (or a container image) onsite into a constrained network.

## Supported feed types

The default sample `feeds.yaml` shows:

### `urlhaus` (abuse.ch URLhaus)

```yaml
abusech_urlhaus:
  enabled: true
  type: urlhaus
  url: "https://urlhaus.abuse.ch/downloads/csv/"
```

This pulls the URLhaus CSV and extracts hostnames and, where available,
IP addresses. Only active entries are used by default.

### `sslbl_ips` (abuse.ch SSLBL botnet C2 IPs)

```yaml
abusech_sslbl_c2_ips:
  enabled: true
  type: sslbl_ips
  url: "https://sslbl.abuse.ch/blacklist/sslipblacklist.csv"
```

This pulls the SSLBL IP blacklist and extracts the IP addresses.

### `otx_pulses` (AlienVault / LevelBlue OTX)

```yaml
otx_example:
  enabled: false
  type: otx_pulses
  api_url: "https://otx.alienvault.com/api/v1"
  api_key_env: "OTX_API_KEY"
  pulses:
    - "<pulse-id-1>"
    - "<pulse-id-2>"
```

- Set `OTX_API_KEY` in your environment (or adjust `api_key_env`).
- Add one or more pulse IDs that you want to pull indicators from.
- `update_feeds.py` will fetch each pulse and normalise indicators of type
  `IPv4`, `domain`, and `hostname` into the IoC lists.

This code path is provided as a reference implementation and may need
adjustments if OTX changes their API or field names.

### `shadowserver_csv` (client-specific CSVs)

```yaml
shadowserver_client_csv:
  enabled: false
  type: shadowserver_csv
  paths:
    - "feeds/shadowserver/sample_report.csv"
  ip_column: "ip"
```

- Assumes you have local CSV reports from Shadowserver (e.g. for a specific
  client netblock / ASN).
- `ip_column` is the name of the CSV column that holds IP addresses.
- All such IPs will be added to `iocs/ips.txt`.

## Usage

Online (to refresh feeds):

```bash
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt

python update_feeds.py --config feeds/feeds.yaml --ioc-dir iocs
```

Then run either the CLI or the web UI; both will automatically consume the
updated IoCs from `iocs/`.

Offline / onsite:

- Do **not** run `update_feeds.py`.
- Use the last set of IoCs that were baked into the repo/container before
  you entered the constrained environment.

## Safety notes

- Always respect each feed provider's terms and documented rate limits.
- Consider maintaining a separate "baseline" set of IoCs that you maintain
  by hand in addition to automated feed output.
- Be prepared for false positives; treat IoC hits as *signals* to be
  investigated, not final proof of compromise.
