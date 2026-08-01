import sys
import os
import json
import glob
import threading
import time
from datetime import datetime
from flask import Flask, render_template, jsonify
from flask_socketio import SocketIO, emit
from flask_cors import CORS

app      = Flask(__name__)
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATE_FILE  = os.path.join(PROJECT_DIR, "cybersage_state.json")
FORENSIC_DIR= os.path.join(PROJECT_DIR, "dataset", "forensic")
ACTIONS_LOG = os.path.join(PROJECT_DIR, "cybersage_actions.log")


def read_state():
    try:
        if os.path.exists(STATE_FILE):
            with open(STATE_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
    except:
        pass
    return {
        "status"       : "MONITORING",
        "risk_score"   : 0,
        "threats_found": 0,
        "total_scanned": 0,
        "attacks"      : [],
        "all_logs"     : [],
        "last_scan"    : "Waiting...",
        "scan_count"   : 0,
    }


def push_updates():
    last_mod = 0
    while True:
        try:
            if os.path.exists(STATE_FILE):
                mod = os.path.getmtime(STATE_FILE)
                if mod != last_mod:
                    last_mod = mod
                    socketio.emit("update", read_state())
        except:
            pass
        time.sleep(4)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/state")
def api_state():
    return jsonify(read_state())


@app.route("/api/forensic")
def api_forensic():
    """Return list of all forensic evidence files"""
    os.makedirs(FORENSIC_DIR, exist_ok=True)
    files = []
    for filepath in sorted(
        glob.glob(os.path.join(FORENSIC_DIR, "*.json")),
        key=os.path.getmtime, reverse=True
    ):
        try:
            fname    = os.path.basename(filepath)
            fsize    = os.path.getsize(filepath)
            modified = datetime.fromtimestamp(
                os.path.getmtime(filepath)
            ).strftime("%Y-%m-%d %H:%M:%S")
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
            files.append({
                "filename" : fname,
                "attack"   : data.get("attack", "Unknown"),
                "captured" : data.get("captured", modified),
                "log_count": len(data.get("logs", [])),
                "filesize" : f"{fsize/1024:.1f} KB",
                "logs"     : data.get("logs", [])[:10],  # first 10 logs
            })
        except:
            pass
    return jsonify({"files": files, "total": len(files)})


@app.route("/api/actions")
def api_actions():
    """Return action log content"""
    try:
        if os.path.exists(ACTIONS_LOG):
            with open(ACTIONS_LOG, "r", encoding="utf-8",
                      errors="replace") as f:
                lines = f.readlines()
            # Return last 50 lines, newest first
            return jsonify({
                "lines": list(reversed(lines[-50:])),
                "total": len(lines)
            })
    except Exception as e:
        return jsonify({"lines": [], "total": 0, "error": str(e)})
    return jsonify({"lines": [], "total": 0})


@socketio.on("connect")
def on_connect():
    emit("update", read_state())


@socketio.on("manual_scan")
def on_manual_scan():
    emit("scanning", {})
    emit("update", read_state())


@socketio.on("user_feedback")
def on_feedback(data):
    print(f"User feedback: {data}")
    emit("feedback_received", {"status": "ok"})


if __name__ == "__main__":
    threading.Thread(target=push_updates, daemon=True).start()
    print("\n" + "="*50)
    print("  📊 CyberSage 2.0 — Security Dashboard")
    print("="*50)
    print("  URL : http://localhost:5000")
    print("="*50 + "\n")
    socketio.run(app, debug=False, port=5000, use_reloader=False)