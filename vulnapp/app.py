from flask import Flask, request, jsonify
import subprocess, sqlite3, logging, time, re, threading
from logging.handlers import RotatingFileHandler

app = Flask(__name__)
handler = RotatingFileHandler("vuln.log", maxBytes=2000000, backupCount=2)
logging.basicConfig(level=logging.INFO, handlers=[handler])

# --- Simple in-memory IDS / rate blocking ---
SUSPICIOUS_RE = re.compile(r"['\";]|--|/\*|\*/|&&|\|")
SUSPICIOUS_THRESHOLD = 5      # number of suspicious hits to trigger block
SUSPICIOUS_WINDOW = 60        # seconds window to count suspicious hits
BLOCK_TIME = 300              # seconds to block offending IP

_lock = threading.Lock()
_suspicious_hits = {}   # ip -> list of timestamps
_blocked = {}           # ip -> unblock_timestamp

def _now():
    return time.time()

def is_blocked(ip):
    with _lock:
        unblock = _blocked.get(ip)
        if unblock and unblock > _now():
            return True
        if unblock and unblock <= _now():
            del _blocked[ip]
        return False

def record_suspicious(ip, details=""):
    ts = _now()
    with _lock:
        lst = _suspicious_hits.setdefault(ip, [])
        lst.append(ts)
        # purge old
        cutoff = ts - SUSPICIOUS_WINDOW
        lst[:] = [t for t in lst if t >= cutoff]
        if len(lst) >= SUSPICIOUS_THRESHOLD:
            _blocked[ip] = ts + BLOCK_TIME
            logging.warning("IDS: blocking ip=%s for %d seconds; reason=%s", ip, BLOCK_TIME, details)
            # reset the hit list
            _suspicious_hits[ip] = []

def check_params_for_suspicious(params):
    for k, v in params.items():
        if v and SUSPICIOUS_RE.search(v):
            return True, k, v
    return False, None, None
# --- end IDS ---

def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, fullname TEXT)')
    c.executemany('INSERT INTO users(username,fullname) VALUES(?,?)',
                  [('alice','Alice A'),('bob','Bob B')])
    conn.commit(); conn.close()

@app.before_request
def log_request_info():
    ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    endpoint = request.path
    params = dict(request.args)
    ua = request.headers.get('User-Agent', '')
    logging.info("REQ ip=%s endpoint=%s params=%s ua=%s", ip, endpoint, params, ua)

@app.route('/ping')
def ping():
    ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    if is_blocked(ip):
        logging.warning("Blocked request from %s to /ping", ip)
        return "Temporarily blocked", 403

    host = request.args.get('host','127.0.0.1')
    ua = request.headers.get('User-Agent', '')
    suspicious, key, val = check_params_for_suspicious({'host': host, 'ua': ua})
    if suspicious:
        logging.warning("Suspicious token in /ping param %s=%s from=%s", key, val, ip)
        record_suspicious(ip, f"/ping param {key}={val}")

    logging.info("PING request host=%s from=%s", host, ip)
    # Vulnerable: shell interpolation allows command injection
    out = subprocess.getoutput(f"ping -c 1 {host}")
    return "<pre>"+out+"</pre>"

@app.route('/user')
def user():
    ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    if is_blocked(ip):
        logging.warning("Blocked request from %s to /user", ip)
        return "Temporarily blocked", 403

    username = request.args.get('username','')
    ua = request.headers.get('User-Agent', '')
    suspicious, key, val = check_params_for_suspicious({'username': username, 'ua': ua})
    if suspicious:
        logging.warning("Suspicious token in /user param %s=%s from=%s", key, val, ip)
        record_suspicious(ip, f"/user param {key}={val}")

    logging.info("USER request username=%s from=%s", username, ip)
    # Vulnerable: SQL built by concatenation -> SQLi
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    query = "SELECT id,username,fullname FROM users WHERE username = '%s'" % username
    try:
        rows = c.execute(query).fetchall()
        return jsonify([dict(id=r[0],username=r[1],fullname=r[2]) for r in rows])
    except Exception as e:
        logging.exception("SQL error: %s", e)
        return "Error", 500
    finally:
        conn.close()

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000)
