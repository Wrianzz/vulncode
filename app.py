from flask import Flask, request, jsonify
import os
import sqlite3

app = Flask(__name__)

DB_PATH = 'users.db'
def init_db():
    first_time = not os.path.exists(DB_PATH)
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    # Buat tabel jika belum ada
    cur.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL
    );
    ''')
    conn.commit()
    if first_time:
        cur.execute("INSERT INTO users (username, password) VALUES ('admin', 'password123');")
        conn.commit()
    conn.close()
init_db()


def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

@app.route("/")
def index():
    return "Hello from SATNUSA vulnerable app!"

@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")

    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}';"
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute(query)
        user = cur.fetchone()
    except Exception as e:
        conn.close()
        return jsonify({"error": "Database error", "detail": str(e)}), 500

    conn.close()
    if user:
        return jsonify({"message": f"Welcome, {user['username']}!"})
    else:
        return jsonify({"message": "Invalid credentials"}), 401

@app.route("/exec")
def exec_cmd():
    """
    Contoh eksploit:
      /exec?cmd=ls
      /exec?cmd=ls%20-la
      /exec?cmd=cat%20users.db
      /exec?cmd=rm%20temp.txt
    """
    cmd = request.args.get("cmd", "")
    if not cmd:
        return jsonify({"error": "No cmd provided"}), 400
    try:
        result = os.popen(cmd).read()
    except Exception as e:
        return jsonify({"error": "Execution error", "detail": str(e)}), 500
    return f"<pre>{result}</pre>"

@app.route("/show_key")
def show_key():
    return jsonify({"GROQ_API_KEY": GROQ_API_KEY})

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
