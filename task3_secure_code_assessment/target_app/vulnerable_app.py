"""Deliberately Vulnerable Flask Web Application.

File: target_app/vulnerable_app.py
Purpose: Educational target application designed for security code auditing,
static analysis vulnerability detection (SAST), and manual security reviews.
Contains 10 distinct, labeled security flaws (VULN-01 through VULN-10).
Author: CodSoft Cyber Security Intern
License: Educational Use Only

WARNING:
THIS CODE CONTAINS DELIBERATE VULNERABILITIES FOR TEACHING AND ASSESSMENT ONLY.
NEVER DEPLOY THIS APPLICATION TO PRODUCTION OR EXPOSE IT TO UNTRUSTED NETWORKS.
"""

import os
import sqlite3
import subprocess
from flask import Flask, request, jsonify, render_template_string

app = Flask(__name__)

# ============================================================================
# VULN-02: Hardcoded Secret Key and Hardcoded Admin Credentials
# CWE-798: Use of Hard-coded Credentials
# OWASP: A07:2021-Identification and Authentication Failures
# LEARNING NOTE:
# Hardcoding session signing keys or passwords directly into source code means anyone
# with repository read access (including contractors, interns, or public GitHub visitors)
# can forge authentication session cookies or access administrative functions.
# ============================================================================
app.secret_key = "hardcoded_insecure_development_secret_key_98765"
STATIC_ADMIN_USER = "admin"
STATIC_ADMIN_PASS = "admin123"

DATABASE_FILE = os.path.join(os.path.dirname(__file__), "vulnerable_notes.db")
UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


def init_db():
    """Initialize test SQLite database with deliberate plaintext passwords."""
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            role TEXT
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            title TEXT,
            content TEXT
        )
    """)
    # ============================================================================
    # VULN-03: Plaintext / Insecure Password Storage
    # CWE-256: Unprotected Storage of Credentials
    # OWASP: A02:2021-Cryptographic Failures
    # LEARNING NOTE:
    # Storing passwords in plaintext (or with unsalted fast hashes like MD5) ensures that
    # any SQL injection or database backup compromise immediately reveals all user credentials.
    # ============================================================================
    cursor.execute("INSERT OR IGNORE INTO users (id, username, password, role) VALUES (1, 'admin', 'admin123', 'admin')")
    cursor.execute("INSERT OR IGNORE INTO users (id, username, password, role) VALUES (2, 'alice', 'alicepass', 'user')")
    cursor.execute("INSERT OR IGNORE INTO notes (id, username, title, content) VALUES (1, 'admin', 'System Secrets', 'Master API key: sk-secret-999')")
    cursor.execute("INSERT OR IGNORE INTO notes (id, username, title, content) VALUES (2, 'alice', 'Shopping', 'Milk, eggs, apples')")
    conn.commit()
    conn.close()


init_db()


# ============================================================================
# VULN-01: SQL Injection (String Formatting in Queries)
# CWE-89: Improper Neutralization of Special Elements used in an SQL Command
# OWASP: A03:2021-Injection
# LEARNING NOTE:
# Concatenating raw user strings into SQL queries allows attackers to break out of
# data syntax and execute arbitrary database commands (e.g., ' OR '1'='1' --).
# ============================================================================
@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or request.form
    username = data.get("username", "")
    password = data.get("password", "")

    # VULN-09: No rate limiting on login endpoint (allows brute-forcing)
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()

    # VULN-01: Raw string formatting directly into SQL query
    query = f"SELECT id, username, role FROM users WHERE username = '{username}' AND password = '{password}'"
    try:
        cursor.execute(query)
        user = cursor.fetchone()
        conn.close()
        if user:
            return jsonify({"status": "success", "user": {"id": user[0], "username": user[1], "role": user[2]}})
        return jsonify({"status": "error", "message": "Invalid username or password"}), 401
    except Exception as e:
        # ============================================================================
        # VULN-10: Verbose Error Messages Leaking Internal State
        # CWE-209: Generation of Error Message Containing Sensitive Information
        # OWASP: A05:2021-Security Misconfiguration
        # ============================================================================
        return jsonify({"status": "error", "exception": str(e), "executed_query": query}), 500


# ============================================================================
# VULN-04: Reflected Cross-Site Scripting (XSS)
# CWE-79: Improper Neutralization of Input During Web Page Generation
# OWASP: A03:2021-Injection
# LEARNING NOTE:
# Embedding unescaped user input directly into HTML output allows an attacker to
# inject malicious JavaScript (<script>alert(1)</script>) executed in the victim's browser.
# ============================================================================
@app.route("/search")
def search_notes():
    query = request.args.get("q", "")
    # Unescaped user string rendered directly into HTML response
    html = f"""
    <!DOCTYPE html>
    <html>
      <body>
        <h1>Search Notes</h1>
        <p>Results for query: <b>{query}</b></p>
      </body>
    </html>
    """
    return html


# ============================================================================
# VULN-05: Path Traversal (Arbitrary File Read)
# CWE-22: Improper Limitation of a Pathname to a Restricted Directory
# OWASP: A01:2021-Broken Access Control
# LEARNING NOTE:
# Trusting a user-supplied filename parameter and joining it without validating
# canonical paths allows path traversal sequences (../) to read sensitive system files.
# ============================================================================
@app.route("/api/view_attachment")
def view_attachment():
    filename = request.args.get("file", "")
    # Vulnerable path join without canonicalization
    filepath = os.path.join(UPLOAD_FOLDER, filename)
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()
        return jsonify({"file": filename, "content": content})
    except Exception as e:
        return jsonify({"error": str(e)}), 404


# ============================================================================
# VULN-07: Missing Authentication & Authorization Check
# CWE-306: Missing Authentication for Critical Function
# OWASP: A01:2021-Broken Access Control
# LEARNING NOTE:
# Exposing administrative actions without validating session identity or role
# permits any unauthenticated user to trigger privileged operations.
# ============================================================================
@app.route("/api/admin/delete_user", methods=["POST"])
def delete_user():
    data = request.get_json(silent=True) or request.form
    target_id = data.get("id")
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute(f"DELETE FROM users WHERE id = {target_id}")
    conn.commit()
    conn.close()
    return jsonify({"status": "deleted", "user_id": target_id})


# ============================================================================
# VULN-08: Command Injection via Subprocess with shell=True
# CWE-78: Improper Neutralization of Special Elements used in an OS Command
# OWASP: A03:2021-Injection
# LEARNING NOTE:
# Executing system shell commands by concatenating unsanitized user input with
# shell=True allows command chaining (e.g., 127.0.0.1; cat /etc/passwd or & whoami).
# ============================================================================
@app.route("/api/network/diagnostics")
def network_diagnostics():
    host = request.args.get("host", "127.0.0.1")
    # Command injection vulnerability: shell=True with user concatenation
    cmd = f"ping -n 1 {host}" if os.name == "nt" else f"ping -c 1 {host}"
    try:
        output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, text=True)
        return jsonify({"host": host, "output": output})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ============================================================================
# VULN-09: Missing CSRF Protection on State-Changing Endpoint
# CWE-352: Cross-Site Request Forgery (CSRF)
# OWASP: A01:2021-Broken Access Control
# ============================================================================
@app.route("/api/user/update_bio", methods=["POST"])
def update_bio():
    data = request.get_json(silent=True) or request.form
    bio = data.get("bio", "")
    # Modifies user state without checking CSRF token
    return jsonify({"status": "bio updated", "bio": bio})


# ============================================================================
# VULN-06: Debug Mode Enabled in Production
# CWE-489: Active Debug Code in Production
# OWASP: A05:2021-Security Misconfiguration
# LEARNING NOTE:
# Running Flask with debug=True enables interactive Werkzeug web consoles on errors,
# which can allow arbitrary Python code execution if exposed to an attacker.
# ============================================================================
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
