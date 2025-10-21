from flask import Flask, request, jsonify
import subprocess
import sqlite3
import logging
import re
from logging.handlers import RotatingFileHandler
import shared.common as common

app = Flask(__name__)
handler = RotatingFileHandler("fixed.log", maxBytes=2000000, backupCount=2)
logging.basicConfig(level=logging.INFO, handlers=[handler])

HOST_RE = re.compile(
    r"^[A-Za-z0-9\.\-]+$"
)  # simple whitelist: letters, digits, dot, dash


@app.before_request
def log_request_info():
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    endpoint = request.path
    params = dict(request.args)
    ua = request.headers.get("User-Agent", "")
    logging.info("REQ ip=%s endpoint=%s params=%s ua=%s", ip, endpoint, params, ua)


@app.route("/ping")
def ping():
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    if common.is_blocked(ip):
        logging.warning("Blocked request from %s to /ping", ip)
        return "Temporarily blocked", 403

    host = request.args.get("host", "127.0.0.1")
    ua = request.headers.get("User-Agent", "")
    suspicious, key, val = common.check_params_for_suspicious({"host": host, "ua": ua})
    if suspicious:
        logging.warning("Suspicious token in /ping param %s=%s from=%s", key, val, ip)
        common.record_suspicious(ip, f"/ping param {key}={val}")

    logging.info("PING request host=%s from=%s", host, ip)
    # Validate host (whitelist) and use list args to avoid shell
    if not HOST_RE.match(host) or len(host) > 100:
        return "Invalid host", 400
    try:
        # use list form: no shell
        proc = subprocess.run(
            ["ping", "-c", "1", host], capture_output=True, text=True, timeout=5
        )
        return "<pre>" + proc.stdout + proc.stderr + "</pre>"
    except Exception as e:
        logging.exception("Ping failed: %s", e)
        return "Error", 500


@app.route("/user")
def user():
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    if common.is_blocked(ip):
        logging.warning("Blocked request from %s to /user", ip)
        return "Temporarily blocked", 403

    username = request.args.get("username", "")
    ua = request.headers.get("User-Agent", "")
    suspicious, key, val = common.check_params_for_suspicious(
        {"username": username, "ua": ua}
    )
    if suspicious:
        logging.warning("Suspicious token in /user param %s=%s from=%s", key, val, ip)
        common.record_suspicious(ip, f"/user param {key}={val}")

    logging.info("USER request username=%s from=%s", username, ip)
    if not username or len(username) > 50:
        return "Invalid username", 400
    # Parameterized query to prevent SQL injection
    conn = sqlite3.connect("users.db")
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    query = "SELECT id,username,fullname FROM users WHERE username = ?"
    try:
        rows = c.execute(query, (username,)).fetchall()
        return jsonify([dict(r) for r in rows])
    except Exception as e:
        logging.exception("SQL error for ip=%s query=%s: %s", ip, query, e)
        common.record_sql_error(ip, f"query={query} params={username} exc={e}")
        return "Error", 500
    finally:
        conn.close()


if __name__ == "__main__":
    common.init_db()
    app.run(host="0.0.0.0", port=5001)
