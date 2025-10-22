from flask import Flask, request, jsonify
import subprocess
import sqlite3
import logging
from logging.handlers import RotatingFileHandler
import shared.common as common

app = Flask(__name__)
handler = RotatingFileHandler("vuln.log", maxBytes=2000000, backupCount=2)
logging.basicConfig(level=logging.INFO, handlers=[handler])


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

    # NOTE: Vulnerable: shell interpolation allows command injection
    out = subprocess.getoutput(f"ping -c 1 {host}")

    return "<pre>" + out + "</pre>"


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

    # NOTE: Vulnerable: Concatenated query vulnerable to SQLi
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    query = "SELECT id,username,fullname FROM users WHERE username = '%s'" % username

    try:
        rows = c.execute(query).fetchall()
        return jsonify([dict(id=r[0], username=r[1], fullname=r[2]) for r in rows])
    except Exception as e:
        logging.exception("SQL error for ip=%s query=%s: %s", ip, query, e)
        common.record_sql_error(ip, f"query={query} exc={e}")
        return "Error", 500
    finally:
        conn.close()


if __name__ == "__main__":
    common.init_db()
    app.run(host="0.0.0.0", port=5000)
