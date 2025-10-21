# optional: duplicates init code in app.py; you can run this to recreate DB
import sqlite3

conn = sqlite3.connect("users.db")
c = conn.cursor()
c.execute("DROP TABLE IF EXISTS users")
c.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, fullname TEXT)")
c.executemany(
    "INSERT INTO users(username,fullname) VALUES(?,?)",
    [("alice", "Alice A"), ("bob", "Bob B")],
)
conn.commit()
conn.close()
