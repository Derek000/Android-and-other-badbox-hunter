# Manual checklist for Android / IoT devices

Use this as a complement to automated results. For each device flagged as
Medium or High risk in BadBox Hunter:

1. Confirm ownership and business purpose.
2. Identify vendor, model, and firmware version.
3. Check for exposed management interfaces:
   - Web UI on HTTP/HTTPS
   - ADB on TCP/5555
   - Telnet/SSH with default credentials
4. Review network behaviour:
   - Unexpected outbound connections (non-local addresses)
   - Repeated contacts to domains/IPs listed in `iocs/`
5. Apply vendor firmware updates where available.
6. If compromise is suspected:
   - Isolate the device from the network.
   - Capture additional PCAPs.
   - Consider full re-image / factory reset.
