from flask import Flask, request, jsonify
import subprocess, sqlite3, logging
from logging.handlers import RotatingFileHandler

app = Flask(__name__)
handler = RotatingFileHandler("vuln.log", maxBytes=2000000, backupCount=2)
logging.basicConfig(level=logging.INFO, handlers=[handler])

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
    # Vulnerable: shell interpolation allows command injection
    out = subprocess.getoutput(f"ping -c 1 {host}")
    return "<pre>"+out+"</pre>"

@app.route('/user')
def user():
    username = request.args.get('username','')
    logging.info("USER request username=%s from=%s", username, request.remote_addr)
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
