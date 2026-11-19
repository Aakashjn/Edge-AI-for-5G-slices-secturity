"""
api_server.py
=============
Flask backend for the SliceShield dashboard.

  GET  /api/logs?since=N   audit events from line N onwards (incremental polling)
  GET  /api/status         current state of every slice (normal / isolated)
  GET  /api/rca/<slice>    latest RCA report for a slice
  POST /api/attack         inject traffic through the real pipeline (needs API key)

Security:
  * binds to 127.0.0.1 by default (SLICESHIELD_API_HOST to change)
  * POST /api/attack requires header X-API-Key == $SLICESHIELD_API_KEY
    (a random key is generated and printed at start-up if unset)
  * CORS limited to local origins (and file:// for the bundled dashboard)
"""

import json
import os
import secrets
import subprocess
import sys

from flask import Flask, abort, jsonify, request
from flask_cors import CORS

from features import SLICE_NAMES

LOG_PATH = "logs/response_audit.jsonl"
REPORT_DIR = "reports"
API_KEY = os.getenv("SLICESHIELD_API_KEY") or secrets.token_urlsafe(16)
ALLOWED_ATTACKS = {"nosql", "benign"}

app = Flask(__name__)
CORS(app, origins=[r"^null$", r"^http://(localhost|127\.0\.0\.1)(:\d+)?$"])


def read_events(since: int = 0):
    """Return (events from line `since` onwards, total line count)."""
    events, n = [], 0
    if not os.path.exists(LOG_PATH):
        return events, n
    with open(LOG_PATH) as f:
        for n, line in enumerate(f, 1):
            if n <= since or not line.strip():
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return events, n


@app.route("/api/logs")
def get_logs():
    since = max(request.args.get("since", 0, type=int), 0)
    events, n = read_events(since)
    return jsonify({"events": events, "next": max(n, since)})


@app.route("/api/status")
def get_status():
    state = {sid: {"slice_id": sid, "name": name, "state": "normal", "since": None}
             for sid, name in SLICE_NAMES.items()}
    for e in read_events()[0]:
        sid = e.get("slice_id")
        if sid not in state:
            continue
        if e.get("event") == "slice_isolated":
            state[sid].update(state="isolated", since=e.get("timestamp"),
                              attack_type=e.get("attack_type"))
        elif e.get("event") == "slice_readmitted":
            state[sid].update(state="normal", since=e.get("timestamp"), attack_type=None)
    return jsonify(list(state.values()))


@app.route("/api/rca/<int:slice_id>")
def get_rca(slice_id):
    if slice_id not in SLICE_NAMES:
        abort(404)
    prefix = f"RCA_Report_Slice{slice_id}_"
    reports = sorted(f for f in os.listdir(REPORT_DIR) if f.startswith(prefix)) \
        if os.path.isdir(REPORT_DIR) else []
    if not reports:
        return jsonify({"report": "No RCA report available yet."})
    with open(os.path.join(REPORT_DIR, reports[-1])) as f:
        return jsonify({"report": f.read(), "file": reports[-1]})


@app.route("/api/attack", methods=["POST"])
def trigger_attack():
    if not secrets.compare_digest(request.headers.get("X-API-Key", ""), API_KEY):
        abort(401)
    data = request.get_json(silent=True) or {}
    try:
        slice_id = int(data.get("slice", 1))
    except (TypeError, ValueError):
        abort(400)
    attack = str(data.get("attack", "nosql"))
    if slice_id not in SLICE_NAMES or attack not in ALLOWED_ATTACKS:
        abort(400)
    subprocess.Popen([sys.executable, "attack_simulation.py",
                      "--slice", str(slice_id), "--attack", attack])
    return jsonify({"status": "injected", "slice": slice_id, "attack": attack})


if __name__ == "__main__":
    host = os.getenv("SLICESHIELD_API_HOST", "127.0.0.1")
    if not os.getenv("SLICESHIELD_API_KEY"):
        print(f"[API] SLICESHIELD_API_KEY not set — generated key for this run: {API_KEY}")
    app.run(host=host, port=5002)
