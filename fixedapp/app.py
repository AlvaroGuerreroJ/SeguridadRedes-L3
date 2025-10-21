from flask import Flask, request, jsonify
import subprocess, sqlite3, logging, re, time, threading
from logging.handlers import RotatingFileHandler

app = Flask(__name__)
handler = RotatingFileHandler("fixed.log", maxBytes=2000000, backupCount=2)
logging.basicConfig(level=logging.INFO, handlers=[handler])

HOST_RE = re.compile(r'^[A-Za-z0-9\.\-]+$')  # simple whitelist: letters, digits, dot, dash

# --- Simple in-memory IDS / rate blocking (same logic as vulnapp) ---
SUSPICIOUS_RE = re.compile(r"['\";]|--|/\*|\*/|&&|\|")
SUSPICIOUS_THRESHOLD = 5
SUSPICIOUS_WINDOW = 60
BLOCK_TIME = 300

_lock = threading.Lock()
_suspicious_hits = {}
_blocked = {}

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
        cutoff = ts - SUSPICIOUS_WINDOW
        lst[:] = [t for t in lst if t >= cutoff]
        if len(lst) >= SUSPICIOUS_THRESHOLD:
            _blocked[ip] = ts + BLOCK_TIME
            logging.warning("IDS: blocking ip=%s for %d seconds; reason=%s", ip, BLOCK_TIME, details)
            _suspicious_hits[ip] = []

def check_params_for_suspicious(params):
    for k, v in params.items():
        if v and SUSPICIOUS_RE.search(v):
            return True, k, v
    return False, None, None
# --- end IDS ---

# --- SQL error detection / counting (per-IP) ---
SQL_ERROR_THRESHOLD = 5      # number of SQL errors to trigger block
SQL_ERROR_WINDOW = 60        # seconds window to count SQL errors

_sql_error_hits = {}         # ip -> list of timestamps for SQL errors

def record_sql_error(ip, details=""):
    ts = _now()
    with _lock:
        lst = _sql_error_hits.setdefault(ip, [])
        lst.append(ts)
        cutoff = ts - SQL_ERROR_WINDOW
        lst[:] = [t for t in lst if t >= cutoff]
        if len(lst) >= SQL_ERROR_THRESHOLD:
            _blocked[ip] = ts + BLOCK_TIME
            logging.warning("SQL-IDS: blocking ip=%s for %d seconds; sql_error_count=%d; details=%s",
                            ip, BLOCK_TIME, len(lst), details)
            _sql_error_hits[ip] = []

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
    # Validate host (whitelist) and use list args to avoid shell
    if not HOST_RE.match(host) or len(host) > 100:
        return "Invalid host", 400
    try:
        # use list form: no shell
        proc = subprocess.run(["ping","-c","1", host], capture_output=True, text=True, timeout=5)
        return "<pre>"+proc.stdout+proc.stderr+"</pre>"
    except Exception as e:
        logging.exception("Ping failed: %s", e)
        return "Error", 500

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
    if not username or len(username) > 50:
        return "Invalid username", 400
    # Parameterized query to prevent SQL injection
    conn = sqlite3.connect('users.db')
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    query = "SELECT id,username,fullname FROM users WHERE username = ?"
    try:
        rows = c.execute(query, (username,)).fetchall()
        return jsonify([dict(r) for r in rows])
    except Exception as e:
        # Log exception (stacktrace) and record a SQL error for the requesting IP.
        logging.exception("SQL error for ip=%s query=%s: %s", ip, query, e)
        record_sql_error(ip, f"query={query} params={username} exc={e}")
        return "Error", 500
    finally:
        conn.close()

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5001)
