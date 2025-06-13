from flask import Flask, request, jsonify
import sqlite3
import subprocess
import os

app = Flask(__name__)

OPENAI_API_KEY = "sk-demo-l4gS3cr3tKey-1234567890"

DATABASE = "data.db"

def init_db():
    conn = sqlite3.connect(DATABASE)
    cur = conn.cursor()
    cur.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL
        )
    ''')
    conn.commit()
    cur.execute("INSERT OR IGNORE INTO users (username, password) VALUES ('admin', 'adminpass');")
    conn.commit()
    conn.close()

init_db()

@app.route("/")
def home():
    return "Vulnerable Flask App — Training Only!"

@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    
    conn = sqlite3.connect(DATABASE)
    cur = conn.cursor()
    try:
        cur.execute(query)
        user = cur.fetchone()
    except Exception as e:
        return jsonify({"error": "Query failed", "detail": str(e)}), 500
    conn.close()
    
    if user:
        return jsonify({"message": f"Welcome {username}!"})
    return jsonify({"message": "Invalid credentials"}), 401

@app.route("/run", methods=["GET"])
def run_cmd():
    cmd = request.args.get("cmd", "")
    if not cmd:
        return jsonify({"error": "No command provided"}), 400
    try:
        result = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, text=True)
    except Exception as e:
        return jsonify({"error": "Command failed", "detail": str(e)})
    return f"<pre>{result}</pre>"

@app.route("/eval", methods=["POST"])
def eval_code():
    code = request.form.get("code", "")
    try:
        result = eval(code)
        return jsonify({"result": result})
    except Exception as e:
        return jsonify({"error": "Eval failed", "detail": str(e)})

@app.route("/secrets")
def leak_secret():
    return jsonify({
        "OPENAI_API_KEY": OPENAI_API_KEY,
        "db_path": DATABASE
    })

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=8000)
