from flask import Flask, request, jsonify
import os
import sqlite3
import bcrypt
import subprocess
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
app.config['API'] = os.getenv('API', 'super-api')
csrf = CSRFProtect(app)

DB_PATH = 'users.db'

def init_db():
    first_time = not os.path.exists(DB_PATH)
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL
    );
    ''')
    conn.commit()

    if first_time:
        hashed_pw = bcrypt.hashpw("password123".encode('utf-8'), bcrypt.gensalt())
        cur.execute("INSERT INTO users (username, password) VALUES (?, ?);", ('admin', hashed_pw))
        conn.commit()
    conn.close()

init_db()

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

@app.route("/")
def index():
    return "Hello from SATNUSA secure app!"

@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")

    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cur.fetchone()
    except Exception as e:
        conn.close()
        return jsonify({"error": "Database error", "detail": str(e)}), 500

    conn.close()

    if user and bcrypt.checkpw(password.encode('utf-8'), user['password']):
        return jsonify({"message": f"Welcome, {user['username']}!"})
    else:
        return jsonify({"message": "Invalid credentials"}), 401

@app.route("/exec", methods=["POST"])
def exec_cmd():
    """
    Eksekusi command yang diizinkan saja (whitelist)
    """
    allowed_commands = {
        "list_files": ["ls", "-la"],
        "disk_usage": ["df", "-h"]
    }
    cmd_key = request.json.get("cmd")
    if cmd_key not in allowed_commands:
        return jsonify({"error": "Command not allowed"}), 403

    try:
        result = subprocess.check_output(allowed_commands[cmd_key], stderr=subprocess.STDOUT, text=True)
        return f"<pre>{result}</pre>"
    except subprocess.CalledProcessError as e:
        return jsonify({"error": "Execution error", "detail": e.output}), 500

@app.route("/show_key", methods=["GET"])
def show_key():
    if not GROQ_API_KEY:
        return jsonify({"error": "API Key not set"}), 404
    return jsonify({"message": "API Key is configured but not exposed for security reasons"})

if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=5000)
