import time
import threading
import re
import sqlite3
import logging

# IDS / blocking config
SUSPICIOUS_RE = re.compile(r"['\";]|--|/\*|\*/|&&|\|")
SUSPICIOUS_THRESHOLD = 5
SUSPICIOUS_WINDOW = 60
BLOCK_TIME = 300

# SQL error detection
SQL_ERROR_THRESHOLD = 5
SQL_ERROR_WINDOW = 60

# shared state
_lock = threading.Lock()
_suspicious_hits = {}   # ip -> list of timestamps
_blocked = {}           # ip -> unblock_timestamp
_sql_error_hits = {}    # ip -> list of timestamps for SQL errors

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

def init_db(db_path='users.db', seed_users=None):
    if seed_users is None:
        seed_users = [('alice','Alice A'), ('bob','Bob B')]
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, fullname TEXT)')
    # insert only if table empty
    c.execute('SELECT COUNT(*) FROM users')
    if c.fetchone()[0] == 0:
        c.executemany('INSERT INTO users(username,fullname) VALUES(?,?)', seed_users)
    conn.commit()
    conn.close()
