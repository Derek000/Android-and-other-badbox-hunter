import os
from pathlib import Path
from typing import List, Dict, Any

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify

from badbox_hunter import run_assessment, calculate_risk_score, HostInfo, Reporter

app = Flask(__name__)
app.secret_key = os.environ.get("BADBOX_HUNTER_SECRET_KEY", "change-me")

BASE_DIR = Path(__file__).resolve().parent
IOC_DIR = BASE_DIR / "iocs"
UPLOAD_DIR = BASE_DIR / "uploads"
UPLOAD_DIR.mkdir(exist_ok=True)

# In-memory cache of last run (per process)
LATEST_RESULTS: Dict[str, Any] = {
    "hosts": [],        # list of host dicts
    "hosts_by_ip": {},  # ip -> host dict
    "raw_json": [],     # JSON-ready list
}


def _parse_cidrs(text: str) -> List[str]:
    return [c.strip() for c in text.split(",") if c.strip()]


def host_to_dict(h: HostInfo) -> Dict[str, Any]:
    reporter = Reporter(Path("/dev/null"))
    base = reporter.to_dicts([h])[0]
    risk = h.ioc_hits.get("risk") or calculate_risk_score(h)
    base.setdefault("ioc_hits", {})
    base["ioc_hits"].setdefault("risk", risk)
    return base


@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        cidr_text = request.form.get("cidrs", "").strip()
        if not cidr_text:
            flash("Please provide at least one CIDR range.", "error")
            return redirect(url_for("index"))

        cidrs = _parse_cidrs(cidr_text)
        exclude_ips = [
            ip.strip()
            for ip in request.form.get("exclude_ips", "").split(",")
            if ip.strip()
        ]

        pcaps: List[Path] = []
        for f in request.files.getlist("pcaps"):
            if not f or not f.filename:
                continue
            dest = UPLOAD_DIR / f.filename
            f.save(dest)
            pcaps.append(dest)

        ssh_inventory_path = request.form.get("ssh_inventory_path", "").strip()
        ssh_inventory = Path(ssh_inventory_path) if ssh_inventory_path else None

        capture_iface = request.form.get("capture_iface", "").strip() or None
        capture_seconds = int(request.form.get("capture_seconds") or 60)

        try:
            hosts = run_assessment(
                cidrs=cidrs,
                ioc_dir=IOC_DIR,
                exclude_ips=exclude_ips,
                ssh_inventory=ssh_inventory,
                pcaps=pcaps,
                capture_iface=capture_iface,
                capture_seconds=capture_seconds,
            )
        except Exception as exc:  # noqa: BLE001
            flash(f"Assessment failed: {exc}", "error")
            hosts = []

        host_dicts = [host_to_dict(h) for h in hosts]
        hosts_by_ip = {h["ip"]: h for h in host_dicts}

        LATEST_RESULTS["hosts"] = host_dicts
        LATEST_RESULTS["hosts_by_ip"] = hosts_by_ip
        LATEST_RESULTS["raw_json"] = host_dicts

        host_summaries = []
        for h in host_dicts:
            risk = h.get("ioc_hits", {}).get("risk", {"score": 0, "level": "Low"})
            host_summaries.append(
                {
                    "ip": h["ip"],
                    "hostname": h.get("hostname"),
                    "os_guess": h.get("os_guess"),
                    "tags": h.get("tags", []),
                    "risk": risk,
                    "ioc_summary": list(h.get("ioc_hits", {}).keys()),
                }
            )

        host_summaries.sort(key=lambda x: x["risk"]["score"], reverse=True)

        return render_template("results.html", hosts=host_summaries)

    default_cidrs = os.environ.get("BADBOX_HUNTER_DEFAULT_CIDRS", "192.168.0.0/24")
    return render_template("index.html", default_cidrs=default_cidrs)


@app.route("/host/<ip>")
def host_detail(ip: str):
    host = LATEST_RESULTS["hosts_by_ip"].get(ip)
    if not host:
        flash("No details found for that host (run an assessment first).", "error")
        return redirect(url_for("index"))
    return render_template("host_detail.html", host=host)


@app.route("/api/report.json")
def api_report():
    return jsonify(LATEST_RESULTS.get("raw_json", []))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)
