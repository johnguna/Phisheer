from flask import Flask, render_template, request, jsonify
import yaml
from core.alert_store import AlertStore
from core.policy import should_propose_block
from detection.url_checker import check_url
from detection.file_scanner import scan_file
from detection.message_classifier import classify_message
from detection.network_monitor import SuricataEveMonitor
from firewall.router_controller import RouterController

with open("config.yaml", encoding="utf-8") as f:
    cfg = yaml.safe_load(f)

app = Flask(__name__)
app.secret_key = cfg["app"]["secret_key"]
store = AlertStore(cfg["storage"]["database"])
fw = cfg.get("firewall", {})
router = RouterController(fw.get("enabled", False), fw.get("dry_run", True))

def save_event(e):
    store.add(e.get("source", "system"), e.get("severity", "info"),
              e.get("title", "Event"), e.get("details", ""),
              e.get("source_ip"), e.get("destination_ip"))

net = cfg.get("network", {})
monitor = (SuricataEveMonitor(net["suricata_eve_path"], save_event, net.get("poll_seconds", 3))
           if net.get("enabled") else None)

@app.route("/")
def home():
    return render_template("index.html", alerts=store.latest(50), total=store.count())

@app.post("/api/check-url")
def url_api():
    d = request.get_json(silent=True) or {}
    r = check_url(d.get("url", ""))
    save_event({"source":"url_checker", "severity":r["risk"],
                "title":"URL check: " + r["risk"], "details":str(r)})
    return jsonify(r)

@app.post("/api/classify-message")
def message_api():
    d = request.get_json(silent=True) or {}
    text = str(d.get("text", ""))[:10000]
    if not text.strip(): return jsonify({"error":"Message text required"}), 400
    return jsonify(classify_message(text))

@app.post("/api/scan-file")
def file_api():
    d = request.get_json(silent=True) or {}
    # Local lab use only. Do not expose arbitrary server-side file scanning publicly.
    return jsonify(scan_file(d.get("path", ""), cfg["files"]["max_file_size_mb"],
                             cfg["files"]["clamav_command"]))

@app.post("/api/propose-block")
def block_api():
    d = request.get_json(silent=True) or {}
    ok, reason = should_propose_block(d.get("ip"), d.get("severity", "low"), fw.get("allowlist", []))
    if not ok: return jsonify({"proposed":False, "reason":reason}), 400
    result = router.propose_temporary_block(d["ip"], reason, int(d.get("ttl_seconds", 900)))
    save_event({"source":"firewall_policy", "severity":d.get("severity","high"),
                "title":"Temporary block proposal", "details":str(result), "source_ip":d["ip"]})
    return jsonify({"proposed":True, "reason":reason, "result":result})

if __name__ == "__main__":
    if monitor: monitor.start()
    app.run(host=cfg["app"]["host"], port=int(cfg["app"]["port"]), debug=False)
