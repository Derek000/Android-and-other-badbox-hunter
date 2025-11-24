# Scanning behaviour and tuning

- Default engine uses `nmap -sT -sV -Pn -T3` plus `--max-retries` and `--host-timeout`
  to avoid long stalls.
- The fast engine (`--scan-engine masscan`) uses `masscan` for host discovery
  on a curated port list and then runs `nmap` per host in parallel.
- Use smaller CIDR blocks and conservative timeouts for noisy/fragile networks.
