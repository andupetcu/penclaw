# Intentionally vulnerable Python file for PenClaw testing
# DO NOT use in production — every pattern here is a security anti-pattern.

import os
import subprocess
import sqlite3
import pickle
import yaml
from flask import Flask, request, send_file, redirect

app = Flask(__name__)

# --- Command Injection ---
@app.route("/run")
def run_command():
    cmd = request.args.get("cmd", "echo hello")
    output = os.popen(cmd).read()
    return output

@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    result = subprocess.call("ping -c 1 " + host, shell=True)
    return str(result)

# --- SQL Injection ---
@app.route("/users")
def get_users():
    name = request.args.get("name", "")
    conn = sqlite3.connect("app.db")
    cursor = conn.execute("SELECT * FROM users WHERE name = '" + name + "'")
    rows = cursor.fetchall()
    return str(rows)

# --- Path Traversal ---
@app.route("/download")
def download():
    filename = request.args.get("file", "readme.txt")
    return send_file("/var/data/" + filename)

@app.route("/read")
def read_file():
    filepath = request.args.get("path", "/etc/hostname")
    with open(filepath, "r") as f:
        return f.read()

# --- Insecure Deserialization ---
@app.route("/load", methods=["POST"])
def load_data():
    data = request.get_data()
    obj = pickle.loads(data)
    return str(obj)

# --- YAML Deserialization ---
@app.route("/config", methods=["POST"])
def load_config():
    raw = request.get_data(as_text=True)
    config = yaml.load(raw)  # unsafe yaml.load without Loader
    return str(config)

# --- Hardcoded Credentials ---
DB_PASSWORD = os.environ.get("DB_PASSWORD", "changeme")  # was hardcoded
API_SECRET = os.environ.get("API_SECRET", "changeme")    # was hardcoded
PRIVATE_TOKEN = os.environ.get("PRIVATE_TOKEN", "")      # was hardcoded

# --- SSRF ---
@app.route("/fetch")
def fetch_url():
    import urllib.request
    url = request.args.get("url", "http://example.com")
    response = urllib.request.urlopen(url)
    return response.read()

# --- Open Redirect ---
@app.route("/goto")
def goto():
    target = request.args.get("url", "/")
    return redirect(target)

if __name__ == "__main__":
    app.run(debug=True)  # debug mode in production
