from flask import Flask, request, jsonify
import subprocess, sqlite3, logging, re
from logging.handlers import RotatingFileHandler

app = Flask(__name__)
handler = RotatingFileHandler("fixed.log", maxBytes=2000000, backupCount=2)
logging.basicConfig(level=logging.INFO, handlers=[handler])

HOST_RE = re.compile(r'^[A-Za-z0-9\.\-]+$')  # simple whitelist: letters, digits, dot, dash

def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, fullname TEXT)')
    c.executemany('INSERT INTO users(username,fullname) VALUES(?,?)',
                  [('alice','Alice A'),('bob','Bob B')])
    conn.commit(); conn.close()

@app.route('/ping')
def ping():
    host = request.args.get('host','127.0.0.1')
    logging.info("PING request host=%s from=%s", host, request.remote_addr)
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
    username = request.args.get('username','')
    logging.info("USER request username=%s from=%s", username, request.remote_addr)
    if not username or len(username) > 50:
        return "Invalid username", 400
    # Parameterized query to prevent SQL injection
    conn = sqlite3.connect('users.db')
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    try:
        rows = c.execute("SELECT id,username,fullname FROM users WHERE username = ?", (username,)).fetchall()
        return jsonify([dict(r) for r in rows])
    except Exception as e:
        logging.exception("SQL error: %s", e)
        return "Error", 500
    finally:
        conn.close()

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5001)
