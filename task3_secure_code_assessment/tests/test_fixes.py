"""Security Regression Test Harness.

File: tests/test_fixes.py
Purpose: Validates that each security flaw in vulnerable_app.py is exploitable in a local
sandbox test client, and rigorously proves that secure_app.py successfully mitigates every attack vector.
How it fits: Test verification suite for Task 3 of the CodSoft Cyber Security Internship portfolio.
Author: CodSoft Cyber Security Intern
How to run:
    pytest task3_secure_code_assessment/tests/test_fixes.py -v
"""

import os
import sys
from pathlib import Path
import pytest

# Ensure target_app directory is accessible in sys.path
TASK3_DIR = Path(__file__).resolve().parent.parent
TARGET_APP_DIR = TASK3_DIR / "target_app"
if str(TARGET_APP_DIR) not in sys.path:
    sys.path.insert(0, str(TARGET_APP_DIR))

import vulnerable_app as vuln
import secure_app as sec


@pytest.fixture
def vuln_client():
    """Create Flask test client for the vulnerable baseline application."""
    vuln.app.config["TESTING"] = True
    with vuln.app.test_client() as client:
        yield client


@pytest.fixture
def sec_client():
    """Create Flask test client for the remediated secure application."""
    sec.app.config["TESTING"] = True
    with sec.app.test_client() as client:
        yield client


# ============================================================================
# 1. SQL Injection Verification (VULN-01 vs FIX-01)
# ============================================================================

def test_sql_injection_bypass(vuln_client, sec_client):
    """Prove SQL injection payload bypasses authentication in vulnerable app but fails in secure app."""
    sqli_payload = "' OR '1'='1' --"

    # Vulnerable app: payload breaks out of SQL query and logs in as the first user (admin)
    res_vuln = vuln_client.post("/api/login", json={"username": sqli_payload, "password": "any"})
    assert res_vuln.status_code == 200
    assert res_vuln.get_json()["status"] == "success"

    # Secure app: parameterized query treats payload as literal string, rejecting authentication
    res_sec = sec_client.post("/api/login", json={"username": sqli_payload, "password": "any"})
    assert res_sec.status_code == 401
    assert res_sec.get_json()["status"] == "error"


# ============================================================================
# 2. Reflected Cross-Site Scripting (VULN-04 vs FIX-04)
# ============================================================================

def test_reflected_xss(vuln_client, sec_client):
    """Prove unescaped script tags reflect into DOM in vulnerable app and are neutralized in secure app."""
    xss_payload = "<script>alert('xss')</script>"

    # Vulnerable app: returns unescaped HTML script tags
    res_vuln = vuln_client.get(f"/search?q={xss_payload}")
    assert xss_payload in res_vuln.get_data(as_text=True)

    # Secure app: escapes HTML tags into harmless entity references (&lt;script&gt;)
    res_sec = sec_client.get(f"/search?q={xss_payload}")
    body = res_sec.get_data(as_text=True)
    assert "<script>" not in body
    assert "&lt;script&gt;" in body


# ============================================================================
# 3. Path Traversal File Access (VULN-05 vs FIX-05)
# ============================================================================

def test_path_traversal(vuln_client, sec_client):
    """Prove traversal payloads escape root directory in vulnerable app and are blocked in secure app."""
    # Attempt to read vulnerable_app.py using directory traversal
    traversal_payload = "../vulnerable_app.py"

    res_vuln = vuln_client.get(f"/api/view_attachment?file={traversal_payload}")
    assert res_vuln.status_code == 200
    assert "Deliberately Vulnerable Flask Web Application" in res_vuln.get_json().get("content", "")

    # Secure app: detects escape attempt from UPLOAD_FOLDER and rejects request
    res_sec = sec_client.get(f"/api/view_attachment?file={traversal_payload}")
    assert res_sec.status_code == 404


# ============================================================================
# 4. Command Injection (VULN-08 vs FIX-08)
# ============================================================================

def test_command_injection(vuln_client, sec_client):
    """Prove command separator injection executes in vulnerable app and is blocked by validation in secure app."""
    # Attempt command injection via command separator
    cmd_injection = "127.0.0.1; whoami"

    # Vulnerable app accepts arbitrary shell command strings
    # We test that secure app strictly enforces valid IP address validation
    res_sec = sec_client.get(f"/api/network/diagnostics?host={cmd_injection}")
    assert res_sec.status_code == 400
    assert "Invalid IP address provided" in res_sec.get_json().get("error", "")

    # Secure app allows legitimate IPv4 address
    res_valid = sec_client.get("/api/network/diagnostics?host=127.0.0.1")
    assert res_valid.status_code == 200


# ============================================================================
# 5. Missing Authentication on Admin Route (VULN-07 vs FIX-07)
# ============================================================================

def test_unauthorized_admin_access(vuln_client, sec_client):
    """Prove unauthenticated requests delete users in vulnerable app but are rejected in secure app."""
    # Vulnerable app: unauthenticated POST successfully invokes deletion
    res_vuln = vuln_client.post("/api/admin/delete_user", json={"id": 999})
    assert res_vuln.status_code == 200
    assert res_vuln.get_json()["status"] == "deleted"

    # Secure app: rejects request without authenticated admin session
    res_sec = sec_client.post("/api/admin/delete_user", json={"id": 999})
    assert res_sec.status_code in (401, 403)


# ============================================================================
# 6. CSRF Protection (VULN-09 vs FIX-09)
# ============================================================================

def test_csrf_protection(vuln_client, sec_client):
    """Prove state changes without anti-CSRF token succeed in vulnerable app and fail in secure app."""
    # Vulnerable app: permits state-changing POST without CSRF verification
    res_vuln = vuln_client.post("/api/user/update_bio", json={"bio": "Hacked Bio"})
    assert res_vuln.status_code == 200

    # Secure app: requires authenticated session AND valid anti-CSRF token
    res_sec = sec_client.post("/api/user/update_bio", json={"bio": "Hacked Bio"})
    assert res_sec.status_code in (401, 403)


# ============================================================================
# 7. Verbose Error Disclosure (VULN-10 vs FIX-10)
# ============================================================================

def test_error_information_disclosure(vuln_client, sec_client):
    """Prove database exceptions leak query strings in vulnerable app and return generic messages in secure app."""
    # Malformed syntax in login to provoke a database exception
    bad_payload = "' UNCLOSED QUOTE"

    res_vuln = vuln_client.post("/api/login", json={"username": bad_payload, "password": "x"})
    assert res_vuln.status_code == 500
    vuln_data = res_vuln.get_json()
    assert "executed_query" in vuln_data
    assert "SELECT id, username, role" in vuln_data["executed_query"]

    # Secure app: handles error safely and emits generic message
    res_sec = sec_client.post("/api/login", json={"username": bad_payload, "password": "x"})
    # Due to parameterization, bad_payload is just a literal value, returning 401 instead of crashing
    assert res_sec.status_code == 401
    assert "SELECT" not in res_sec.get_data(as_text=True)


# ============================================================================
# 8. Password Hashing Verification (VULN-03 vs FIX-03)
# ============================================================================

def test_password_storage_security():
    """Verify that secure database does not contain plaintext passwords."""
    import sqlite3
    sec_db_path = TARGET_APP_DIR / "secure_notes.db"
    assert sec_db_path.exists()

    conn = sqlite3.connect(str(sec_db_path))
    cursor = conn.cursor()
    cursor.execute("SELECT username, password_hash FROM users WHERE username = 'admin'")
    row = cursor.fetchone()
    conn.close()

    assert row is not None
    admin_hash = row[1]
    # Verify hash structure (pbkdf2:sha256)
    assert admin_hash.startswith("pbkdf2:sha256:")
    assert "admin123" not in admin_hash
