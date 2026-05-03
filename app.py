#!/usr/bin/env python3
"""
Challenge 6 — Log Analysis
Players browse realistic server logs, find the one anomalous entry,
and decode it to get the flag.
"""

import re
from flask import Flask, request, jsonify, Response

app = Flask(__name__)
FLAG = open("flag.txt").read().strip()

# Pre-built realistic web server log (2000 lines would be too much for static str,
# so we generate it programmatically and cache it)

import random, base64, hashlib
from datetime import datetime, timedelta

random.seed(42)  # deterministic

NORMAL_IPS = [
    "10.0.1.12", "10.0.1.45", "10.0.2.7", "10.0.2.88",
    "192.168.1.5", "192.168.1.99", "172.16.0.3", "172.16.0.44"
]

NORMAL_PATHS = [
    "/api/health", "/api/version", "/api/deploy", "/api/users",
    "/dashboard", "/login", "/logout", "/static/main.css",
    "/static/app.js", "/api/profile/1", "/api/profile/2", "/api/profile/3",
]

NORMAL_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    "nullgrids-monitor/1.0",
    "python-requests/2.31.0",
    "curl/7.88.1",
]

METHODS = ["GET", "GET", "GET", "GET", "POST", "POST", "GET"]
STATUS_CODES = [200, 200, 200, 200, 200, 200, 301, 304, 404, 500]

def make_log():
    lines = []
    base_time = datetime(2026, 3, 15, 0, 0, 0)
    anomaly_line = random.randint(180, 220)  # hide anomaly in middle-ish

    for i in range(300):
        ts = base_time + timedelta(seconds=i * 4 + random.randint(0, 3))
        ts_str = ts.strftime("%d/%b/%Y:%H:%M:%S +0000")
        ip = random.choice(NORMAL_IPS)
        method = random.choice(METHODS)
        path = random.choice(NORMAL_PATHS)
        status = random.choice(STATUS_CODES)
        size = random.randint(180, 8200)
        agent = random.choice(NORMAL_AGENTS)
        line = f'{ip} - - [{ts_str}] "{method} {path} HTTP/1.1" {status} {size} "-" "{agent}"'
        lines.append(line)

        if i == anomaly_line:
            # THE ANOMALY: unusual IP, unusual path, unusual agent carrying base64 flag
            anomaly_ts = ts + timedelta(seconds=1)
            anomaly_ts_str = anomaly_ts.strftime("%d/%b/%Y:%H:%M:%S +0000")
            # The user-agent contains a base64-encoded exfiltrated value
            encoded_flag = base64.b64encode(FLAG.encode()).decode()
            anomaly_ua = f"nullgrids-internal-probe/0.1 (exfil={encoded_flag})"
            anomaly_line_str = (
                f'185.220.101.47 - - [{anomaly_ts_str}] '
                f'"POST /api/internal/metrics HTTP/1.1" 200 42 "-" "{anomaly_ua}"'
            )
            lines.append(anomaly_line_str)

    return "\n".join(lines)

LOG_CONTENT = make_log()

@app.route("/")
def index():
    return """
    <html><head><title>NullGrids Log Viewer</title></head>
    <body style='font-family:monospace;background:#0a0a0a;color:#88ff88;padding:40px'>
    <h1>NullGrids SIEM — Log Viewer</h1>
    <p>Incident Report: Possible data exfiltration on 2026-03-15.</p>
    <p>Analyze the server logs and find the anomaly.</p>
    <br>
    <p>Endpoints:</p>
    <ul>
      <li><a style='color:#88ff88' href='/logs'>GET /logs</a> — full access log</li>
      <li><a style='color:#88ff88' href='/logs/search?q=POST'>GET /logs/search?q=TERM</a> — search logs</li>
      <li>GET /logs/line/{n} — get specific line</li>
    </ul>
    </body></html>
    """

@app.route("/logs")
def logs():
    return Response(LOG_CONTENT, mimetype="text/plain")

@app.route("/logs/search")
def search_logs():
    q = request.args.get("q", "")
    if not q or len(q) > 100:
        return jsonify({"error": "Provide a search query ?q=TERM"}), 400
    matches = []
    for i, line in enumerate(LOG_CONTENT.split("\n"), 1):
        if q.lower() in line.lower():
            matches.append({"line": i, "content": line})
    return jsonify({"query": q, "matches": len(matches), "results": matches})

@app.route("/logs/line/<int:n>")
def log_line(n):
    lines = LOG_CONTENT.split("\n")
    if n < 1 or n > len(lines):
        return jsonify({"error": f"Line must be 1–{len(lines)}"}), 404
    return jsonify({"line": n, "content": lines[n-1]})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
