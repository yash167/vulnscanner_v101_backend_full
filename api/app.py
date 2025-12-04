import os
import time
from threading import Thread
from flask import Flask, request, jsonify
from flask_socketio import SocketIO
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

NVD_API_KEY = os.getenv("NVD_API_KEY")
OTX_API_KEY = os.getenv("OTX_API_KEY")
ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_KEY")

# Import scanners
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), ".."))

from scanner.nmap_scanner import run_nmap_scan
from scanner.vuln_scanner import correlate

# Create Flask app
app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("APP_SECRET", "dev_secret_123")

# IMPORTANT FIX — Python 3.12 compatible mode:
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

sessions = {}

@app.route("/api/scan", methods=["POST"])
def api_scan():
    data = request.json or {}
    target = data.get("target")
    ports = data.get("ports") or [22, 80, 443, 3306, 8080]

    if not target:
        return {"error": "target required"}, 400

    sid = str(time.time()).replace(".", "")
    sessions[sid] = {"target": target, "status": "running"}

    def worker():
        socketio.emit("scan:update", {
            "sid": sid,
            "status": "started",
            "target": target
        })

        port_str = ",".join(str(x) for x in ports)
        nm = run_nmap_scan(target, port_str)

        if isinstance(nm, dict) and nm.get("error"):
            socketio.emit("scan:update", {
                "sid": sid,
                "status": "error",
                "error": nm["error"]
            })
            return

        open_ports = [x["port"] for x in nm]
        sessions[sid]["open_ports"] = open_ports

        socketio.emit("scan:update", {
            "sid": sid,
            "status": "ports_found",
            "open_ports": open_ports
        })

        for entry in nm:
            svc = {
                "name": entry["service"],
                "version": entry["version"]
            }

            socketio.emit("scan:update", {
                "sid": sid,
                "status": "service_identified",
                "port": entry["port"],
                "service": svc
            })

            vuln = correlate(entry["service"], entry["version"], NVD_API_KEY)

            socketio.emit("scan:update", {
                "sid": sid,
                "status": "vuln_correlated",
                "port": entry["port"],
                "service": svc,
                "vuln": vuln
            })

        socketio.emit("scan:update", {
            "sid": sid,
            "status": "finished"
        })

    Thread(target=worker, daemon=True).start()
    return {"sid": sid, "message": "scan started"}

@app.route("/api/status/<sid>", methods=["GET"])
def api_status(sid):
    return jsonify(sessions.get(sid, {"error": "unknown sid"}))

@socketio.on("connect")
def handle_connect():
    socketio.emit("connected", {"msg": "socket connected"})

if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=5000, debug=False)
