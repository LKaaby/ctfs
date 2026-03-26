from flask import Flask, request, session, abort, redirect
import os
import sqlite3
import tempfile
import base64

app = Flask(__name__)
app.secret_key = os.urandom(8)

class TemporaryDB:
    def __init__(self):
        self.db_file = tempfile.NamedTemporaryFile(delete=False, suffix=".db")

    def execute(self, sql, parameters=()):
        con = sqlite3.connect(self.db_file.name)
        con.row_factory = sqlite3.Row
        cur = con.cursor()
        res = cur.execute(sql, parameters)
        con.commit()
        return res

@app.route("/debug/sql")
def debug_sql():
    query = request.args.get("q")
    if not query:
        return "missing ?q= parameter"

    try:
        rows = db.execute(query).fetchall()
        return "<br>".join(str(dict(r)) for r in rows) or "no results"
    except Exception as e:
        encoded = base64.b64encode(str(e).encode()).decode()
        return f"error(b64): {encoded}"

db = TemporaryDB()

# Database
db.execute("""CREATE TABLE users(username VARCHAR(30), password varchar(200))""")
db.execute("""INSERT INTO users VALUES('admin','Securinets{ev3n_sql_c4n_b3_bl1nd}')""")
db.execute("""INSERT INTO users VALUES('test1','test2')""")


@app.route("/", methods=["POST"])
def challenge_post():

    # -----------------------------
    # Decode username coming in
    # -----------------------------
    raw_username = request.form.get("username")
    try:
        username = base64.b64decode(raw_username).decode()
    except:
        abort(400, "Invalid base64")

    password = request.form.get("password")
    if not username or not password:
        abort(400, "Missing form parameter")

    # -----------------------------
    # Vulnerable SQL
    # -----------------------------
    query = f"SELECT rowid,* FROM users WHERE username='{username}' AND password='{password}'"
    print("[DEBUG SQL] =>", query)

    try:
        user = db.execute(query).fetchone()
    except sqlite3.Error as e:
        encoded = base64.b64encode(str(e).encode()).decode()
        abort(500, f"SQL(b64): {encoded}")

    # -----------------------------
    # Login FAIL → encode SQL query
    # -----------------------------
    if not user:
        encoded_query = base64.b64encode(query.encode()).decode()
        return f"Invalid login <!-- SQL_b64={encoded_query} -->", 403

    # -----------------------------
    # Login SUCCESS → encode username
    # -----------------------------
    session["user"] = base64.b64encode(username.encode()).decode()

    return redirect("/")


@app.route("/")
def challenge_get():
    encoded_user = session.get("user")

    if not encoded_user:
        return """
        <html><body>
        Welcome! Log in as admin to get the flag.<hr>
        <form method=post>
        User:<input name=username>
        Password:<input name=password>
        <input type=submit>
        </form></body></html>
        """

    # Display encoded username
    return f"<html><body>Hello, {encoded_user}!</body></html>"


if __name__ == "__main__":
    app.run("127.0.0.1", 5000)
