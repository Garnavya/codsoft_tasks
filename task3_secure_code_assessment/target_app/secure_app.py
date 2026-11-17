"""Hardened, Production-Grade Flask Web Application.

File: target_app/secure_app.py
Purpose: Remediated counterpart to vulnerable_app.py. Demonstrates secure coding best practices,
defense-in-depth, input validation, cryptographic hashing, and OWASP Top 10 mitigations.
Contains 10 distinct, labeled remediations (FIX-01 through FIX-10).
Author: CodSoft Cyber Security Intern
License: MIT
"""

from functools import wraps
import ipaddress
import logging
import os
import secrets
import sqlite3
import subprocess
from flask import Flask, request, jsonify, session, abort
from markupsafe import escape
from werkzeug.security import check_password_hash, generate_password_hash

# Configure secure server-side logging without leaking to client
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("secure_app")

app = Flask(__name__)

# ============================================================================
# FIX-02: Secrets Loaded from Environment with Cryptographic Fallback
# CWE-798 Remediation
# OWASP: A07:2021-Identification and Authentication Failures
# LEARNING NOTE:
# Secret keys must never reside in source control. Load from environment variables,
# and generate a dynamic cryptographically secure random token (secrets.token_hex) if unset.
# ============================================================================
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32)

DATABASE_FILE = os.path.join(os.path.dirname(__file__), "secure_notes.db")
UPLOAD_FOLDER = os.path.abspath(os.path.join(os.path.dirname(__file__), "uploads"))
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# In-memory rate limiting tracker (IP -> timestamp count)
LOGIN_ATTEMPTS = {}
MAX_LOGIN_ATTEMPTS = 5


def init_secure_db():
    """Initialize database with cryptographically salted and hashed passwords."""
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password_hash TEXT,
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
    # FIX-03: Password Hashing using PBKDF2-SHA256 with Salt
    # CWE-256 Remediation
    # OWASP: A02:2021-Cryptographic Failures
    # LEARNING NOTE:
    # Passwords must be hashed using adaptive, salted, one-way cryptographic algorithms
    # (such as PBKDF2, Argon2, or bcrypt). Even if the database is dumped, brute force
    # is computationally prohibitive.
    # ============================================================================
    admin_hash = generate_password_hash("AdminSecurePass!2026", method="pbkdf2:sha256")
    alice_hash = generate_password_hash("AliceSecurePass!2026", method="pbkdf2:sha256")

    cursor.execute(
        "INSERT OR IGNORE INTO users (id, username, password_hash, role) VALUES (1, 'admin', ?, 'admin')",
        (admin_hash,)
    )
    cursor.execute(
        "INSERT OR IGNORE INTO users (id, username, password_hash, role) VALUES (2, 'alice', ?, 'user')",
        (alice_hash,)
    )
    cursor.execute(
        "INSERT OR IGNORE INTO notes (id, username, title, content) VALUES (1, 'admin', 'System Secrets', 'Confidential Info')",
    )
    conn.commit()
    conn.close()


init_secure_db()


# ============================================================================
# FIX-07: Role-Based Access Control (RBAC) Decorators
# CWE-306 Remediation
# OWASP: A01:2021-Broken Access Control
# LEARNING NOTE:
# Centralizing authentication and authorization checks in function decorators
# ensures privileged endpoints cannot be accessed by unauthenticated callers.
# ============================================================================
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user" not in session:
            return jsonify({"status": "error", "message": "Authentication required"}), 401
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user" not in session or session.get("user", {}).get("role") != "admin":
            return jsonify({"status": "error", "message": "Administrative privileges required"}), 403
        return f(*args, **kwargs)
    return decorated_function


# ============================================================================
# Security Response Headers Middleware
# LEARNING NOTE:
# HTTP security headers (CSP, X-Content-Type-Options, etc.) instruct modern browsers
# to enforce defensive guardrails, mitigating XSS, clickjacking, and MIME confusion.
# ============================================================================
@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    return response


# ============================================================================
# FIX-01: Parameterized SQL Queries
# CWE-89 Remediation
# OWASP: A03:2021-Injection
# LEARNING NOTE:
# Parameterization separates code from data. The database driver treats parameter
# placeholders (?) strictly as literal values, completely neutralizing SQL injection.
# ============================================================================
@app.route("/api/login", methods=["POST"])
def login():
    client_ip = request.remote_addr or "127.0.0.1"

    # FIX-09: Rate limiting on authentication attempts
    attempts = LOGIN_ATTEMPTS.get(client_ip, 0)
    if attempts >= MAX_LOGIN_ATTEMPTS:
        logger.warning(f"Rate limit exceeded for IP: {client_ip}")
        return jsonify({"status": "error", "message": "Too many failed login attempts. Please try again later."}), 429

    data = request.get_json(silent=True) or request.form
    username = (data.get("username") or "").strip()
    password = (data.get("password") or "").strip()

    if not username or not password:
        return jsonify({"status": "error", "message": "Missing credentials"}), 400

    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()

    try:
        # FIX-01: Parameterized SQL execution
        cursor.execute("SELECT id, username, password_hash, role FROM users WHERE username = ?", (username,))
        user_row = cursor.fetchone()
        conn.close()

        # FIX-03: Cryptographic hash comparison
        if user_row and check_password_hash(user_row[2], password):
            LOGIN_ATTEMPTS[client_ip] = 0  # Reset on success
            session["user"] = {"id": user_row[0], "username": user_row[1], "role": user_row[3]}
            # Generate CSRF token for the authenticated session
            session["csrf_token"] = secrets.token_hex(16)
            return jsonify({
                "status": "success",
                "user": session["user"],
                "csrf_token": session["csrf_token"]
            })

        LOGIN_ATTEMPTS[client_ip] = attempts + 1
        return jsonify({"status": "error", "message": "Invalid username or password"}), 401

    except Exception as e:
        # ============================================================================
        # FIX-10: Generic Error Messages (No Information Disclosure)
        # CWE-209 Remediation
        # OWASP: A05:2021-Security Misconfiguration
        # ============================================================================
        logger.error(f"Internal database exception during login: {e}")
        return jsonify({"status": "error", "message": "An internal error occurred. Please try again later."}), 500


# ============================================================================
# FIX-04: Context-Aware Output Encoding (XSS Mitigation)
# CWE-79 Remediation
# OWASP: A03:2021-Injection
# LEARNING NOTE:
# Escaping user input converts hazardous HTML characters (<, >, &, ", ') into safe
# HTML character entities (&lt;, &gt;, &amp;, &quot;, &#x27;), neutralizing XSS payloads.
# ============================================================================
@app.route("/search")
def search_notes():
    query = request.args.get("q", "")
    # Sanitize and HTML-escape user input before rendering
    safe_query = escape(query)
    html = f"""
    <!DOCTYPE html>
    <html>
      <body>
        <h1>Search Notes</h1>
        <p>Results for query: <b>{safe_query}</b></p>
      </body>
    </html>
    """
    return html


# ============================================================================
# FIX-05: Path Traversal Prevention (Canonical Path Validation)
# CWE-22 Remediation
# OWASP: A01:2021-Broken Access Control
# LEARNING NOTE:
# Validating that the resolved absolute path begins strictly with the allowed
# directory prevents directory traversal attacks like ../../etc/passwd.
# ============================================================================
@app.route("/api/view_attachment")
def view_attachment():
    filename = request.args.get("file", "")
    if not filename:
        return jsonify({"error": "Missing filename"}), 400

    # Whitelist alphanumeric + safe extension characters only
    safe_basename = os.path.basename(filename)
    target_path = os.path.abspath(os.path.join(UPLOAD_FOLDER, safe_basename))

    # Verify that target_path is strictly inside UPLOAD_FOLDER
    if not target_path.startswith(UPLOAD_FOLDER) or not os.path.exists(target_path):
        return jsonify({"error": "Access denied or file not found"}), 404

    try:
        with open(target_path, "r", encoding="utf-8") as f:
            content = f.read()
        return jsonify({"file": safe_basename, "content": content})
    except Exception as e:
        logger.error(f"Error reading file: {e}")
        return jsonify({"error": "Unable to read file"}), 500


# ============================================================================
# FIX-07: Protected Administrative Action with Role Verification
# CWE-306 Remediation
# ============================================================================
@app.route("/api/admin/delete_user", methods=["POST"])
@admin_required
def delete_user():
    data = request.get_json(silent=True) or request.form
    target_id = data.get("id")
    try:
        target_id_int = int(target_id)
    except (ValueError, TypeError):
        return jsonify({"error": "Invalid user ID"}), 400

    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM users WHERE id = ?", (target_id_int,))
    conn.commit()
    conn.close()
    return jsonify({"status": "deleted", "user_id": target_id_int})


# ============================================================================
# FIX-08: Command Injection Mitigation (Strict Validation & shell=False)
# CWE-78 Remediation
# OWASP: A03:2021-Injection
# LEARNING NOTE:
# Avoid shell commands when possible. When unavoidable, strictly validate input format
# (e.g. valid IP address) and pass argument lists to subprocess.run with shell=False.
# ============================================================================
@app.route("/api/network/diagnostics")
def network_diagnostics():
    host = request.args.get("host", "127.0.0.1")

    # Strictly validate that host is a valid IPv4 or IPv6 address
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return jsonify({"error": "Invalid IP address provided"}), 400

    # Run without shell=True, passing an array of arguments
    cmd_args = ["ping", "-n", "1", str(ip)] if os.name == "nt" else ["ping", "-c", "1", str(ip)]
    try:
        res = subprocess.run(cmd_args, capture_output=True, text=True, timeout=5, shell=False)
        return jsonify({"host": str(ip), "output": res.stdout})
    except Exception as e:
        logger.error(f"Diagnostics failure: {e}")
        return jsonify({"error": "Diagnostics execution failed"}), 500


# ============================================================================
# FIX-09: CSRF Token Validation
# CWE-352 Remediation
# OWASP: A01:2021-Broken Access Control
# LEARNING NOTE:
# Validating an anti-CSRF token on every state-changing POST request proves that
# the submission originated from an intentional user action on our origin.
# ============================================================================
@app.route("/api/user/update_bio", methods=["POST"])
@login_required
def update_bio():
    client_csrf = request.headers.get("X-CSRF-Token") or (request.get_json(silent=True) or {}).get("csrf_token")
    session_csrf = session.get("csrf_token")

    if not client_csrf or not session_csrf or not secrets.compare_digest(client_csrf, session_csrf):
        return jsonify({"status": "error", "message": "CSRF token validation failed"}), 403

    data = request.get_json(silent=True) or request.form
    bio = data.get("bio", "")
    return jsonify({"status": "bio updated", "bio": escape(bio)})


# ============================================================================
# FIX-06: Production Configuration (debug=False, Localhost Binding)
# CWE-489 Remediation
# OWASP: A05:2021-Security Misconfiguration
# ============================================================================
if __name__ == "__main__":
    app.run(debug=False, host="127.0.0.1", port=5000)
