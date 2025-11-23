# Capture how-to (wired and Wi-Fi)

Use `tcpdump` or Wireshark to capture traffic on networks you own or are
authorised to monitor. Save PCAPs and upload them through the web UI, or
point the CLI at them with `--pcap`.

Examples:

```bash
# Capture from wlan0 for 120 seconds
sudo tcpdump -i wlan0 -w wifi.pcap -G 120 -W 1 -s 0

# Capture from eth0 until you stop it
sudo tcpdump -i eth0 -w wired.pcap -s 0
```

For live capture from inside the Docker container, run with
`--cap-add NET_ADMIN --cap-add NET_RAW` and specify an interface such as
`eth0` in the web form.

PCAPs are analysed by `pcap_analyzer.py`, which will look for:

- DNS queries to domains in `iocs/domains.txt`
- Traffic to IPs in `iocs/ips.txt`
- HTTP Host headers and TLS SNI values that contain IoC domains
