
import os, time
from threading import Thread
from flask import Flask, request, jsonify
from flask_socketio import SocketIO
from dotenv import load_dotenv
import eventlet
eventlet.monkey_patch()

load_dotenv()
KEY=os.getenv("NVD_API_KEY")

from scanner.nmap_scanner import run_nmap_scan
from scanner.vuln_scanner import correlate

app=Flask(__name__)
socketio=SocketIO(app,cors_allowed_origins="*",async_mode="eventlet")

sessions={}

@app.route("/api/scan",methods=["POST"])
def scan():
    d=request.json or {}
    t=d.get("target")
    ports=",".join(str(x) for x in d.get("ports",[22,80,443,3306,8080]))
    if not t: return {"error":"target required"},400
    sid=str(time.time()).replace(".","")
    sessions[sid]={"status":"running","target":t}

    def run():
        socketio.emit("scan:update",{"sid":sid,"status":"started","target":t})
        n=run_nmap_scan(t,ports)
        if isinstance(n,dict) and "error" in n:
            socketio.emit("scan:update",{"sid":sid,"status":"error","error":n["error"]})
            return
        open_ports=[x["port"] for x in n]
        socketio.emit("scan:update",{"sid":sid,"status":"ports_found","open_ports":open_ports})

        for s in n:
            socketio.emit("scan:update",{"sid":sid,"status":"service_identified","port":s["port"],"service":s})
            v=correlate(s["service"],s["version"],KEY)
            socketio.emit("scan:update",{"sid":sid,"status":"vuln_correlated","port":s["port"],"service":s,"vuln":v})

        socketio.emit("scan:update",{"sid":sid,"status":"finished"})

    Thread(target=run,daemon=True).start()
    return {"sid":sid,"message":"scan started"}

@app.route("/api/status/<sid>")
def status(sid): return jsonify(sessions.get(sid,{"error":"unknown sid"}))

if __name__=="__main__":
    socketio.run(app,host="0.0.0.0",port=5000)
