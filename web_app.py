#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""BadBox Hunter Web UI."""

import json
import logging
import time
from pathlib import Path
from typing import List

from flask import Flask, render_template, request, redirect, url_for, Response

from badbox_hunter import (
    run_assessment,
    hosts_to_json,
    compute_metrics,
)

LOG = logging.getLogger("badbox_hunter.web")
app = Flask(__name__)

BASE_DIR = Path(__file__).resolve().parent
DEFAULT_IOC_DIR = BASE_DIR / "iocs"
UPLOAD_DIR = BASE_DIR / "uploads"
UPLOAD_DIR.mkdir(exist_ok=True)

LAST_REPORT_JSON: str = ""  # in-memory storage of last report


def _split_lines(value: str) -> List[str]:
    return [line.strip() for line in (value or "").splitlines() if line.strip()]


@app.route("/", methods=["GET", "POST"])
def index():
    global LAST_REPORT_JSON

    context = {
        "form": {
            "cidrs": "192.168.1.0/24",
            "exclude_ips": "",
            "scan_engine": "nmap",
            "max_retries": 1,
            "timeout_per_host": "60s",
        },
        "metrics": None,
        "hosts": [],
        "report_json": None,
    }

    if request.method == "POST":
        cidrs_raw = request.form.get("cidrs", "")
        exclude_raw = request.form.get("exclude_ips", "")
        scan_engine = request.form.get("scan_engine", "nmap")
        max_retries = int(request.form.get("max_retries", "1") or "1")
        timeout_per_host = request.form.get("timeout_per_host", "60s") or "60s"

        cidrs = _split_lines(cidrs_raw)
        exclude_ips = _split_lines(exclude_raw)

        pcap_file = request.files.get("pcap")
        pcap_path = None
        if pcap_file and pcap_file.filename:
            ts = int(time.time())
            safe_name = "".join(ch for ch in pcap_file.filename if ch.isalnum() or ch in (".", "_", "-"))
            if not safe_name:
                safe_name = f"pcap_{ts}.pcap"
            pcap_path = UPLOAD_DIR / f"{ts}_{safe_name}"
            pcap_file.save(pcap_path)

        logging.getLogger().setLevel(logging.INFO)
        LOG.info("Web UI starting assessment: cidrs=%s engine=%s", cidrs, scan_engine)

        start_ts = time.time()
        hosts = run_assessment(
            cidrs=cidrs,
            exclude_ips=exclude_ips,
            ioc_dir=DEFAULT_IOC_DIR,
            scan_engine=scan_engine,
            max_retries=max_retries,
            timeout_per_host=timeout_per_host,
            pcap_path=pcap_path,
        )
        duration = time.time() - start_ts

        metrics = compute_metrics(
            hosts=hosts,
            scan_engine=scan_engine,
            cidrs=cidrs,
            max_retries=max_retries,
            timeout_per_host=timeout_per_host,
            duration_seconds=duration,
        )

        hosts_json = hosts_to_json(hosts)
        report = {
            "hosts": hosts_json,
            "meta": metrics,
        }
        report_json = json.dumps(report, indent=2)
        LAST_REPORT_JSON = report_json

        context["form"] = {
            "cidrs": cidrs_raw,
            "exclude_ips": exclude_raw,
            "scan_engine": scan_engine,
            "max_retries": max_retries,
            "timeout_per_host": timeout_per_host,
        }
        context["metrics"] = metrics
        context["hosts"] = hosts_json
        context["report_json"] = report_json

    return render_template("index.html", **context)


@app.route("/download.json", methods=["GET"])
def download_json():
    global LAST_REPORT_JSON
    if not LAST_REPORT_JSON:
        return redirect(url_for("index"))
    return Response(
        LAST_REPORT_JSON,
        mimetype="application/json",
        headers={"Content-Disposition": "attachment; filename=badbox_web_report.json"},
    )


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    app.run(host="0.0.0.0", port=5000, debug=False)
