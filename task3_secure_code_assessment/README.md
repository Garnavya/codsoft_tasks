# Task 3: Secure Code Assessment

A comprehensive source code vulnerability audit, static application security testing (SAST), and remediation project covering the OWASP Top 10 and Common Weakness Enumeration (CWE) standards.

---

## 1. Project Objective

To demonstrate practical software security auditing by examining an application for security flaws, evaluating it with automated static analysis tools (Bandit), identifying architectural weaknesses through manual code review, refactoring the application to implement industry-standard secure coding practices, and proving the fixes with automated regression test fixtures.

---

## 2. Directory Structure

```
task3_secure_code_assessment/
├── README.md                      # Architecture, methodology, usage, student guide
├── REPORT.md                      # Comprehensive formal vulnerability audit report
├── target_app/
│   ├── vulnerable_app.py          # Deliberately flawed Flask baseline (VULN-01 to VULN-10)
│   ├── secure_app.py              # Remediated, hardened production counterpart (FIX-01 to FIX-10)
│   ├── requirements.txt           # Target application dependencies
│   ├── uploads/                   # Test directory for attachment path traversal evaluation
│   ├── vulnerable_notes.db        # SQLite database for vulnerable baseline
│   └── secure_notes.db            # SQLite database with hashed credentials for secure app
├── analysis/
│   ├── run_bandit.ps1             # PowerShell script executing Bandit SAST scans
│   ├── bandit_report_before.txt   # Real baseline Bandit scan report (text format)
│   ├── bandit_report_before.json  # Real baseline Bandit scan report (JSON format)
│   ├── bandit_report_after.txt    # Real post-remediation Bandit report (text format)
│   └── bandit_report_after.json   # Real post-remediation Bandit report (JSON format)
└── tests/
    └── test_fixes.py              # Pytest harness proving exploit execution & mitigation
```

---

## 3. Vulnerability Inventory & Mapping

| ID | Weakness Title | CWE ID | OWASP (2021) | Vulnerable Baseline | Secure Remediation |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **01** | SQL Injection | CWE-89 | A03: Injection | Raw f-string queries | Parameterized queries (`?`) |
| **02** | Hardcoded Secrets | CWE-798 | A07: Auth Failures | Hardcoded key & admin pass | `os.environ.get()` + token fallback |
| **03** | Plaintext Passwords | CWE-256 | A02: Crypto Failures | Stored in raw plaintext | PBKDF2-SHA256 salted hashes |
| **04** | Reflected XSS | CWE-79 | A03: Injection | Unescaped HTML string | `markupsafe.escape()` sanitization |
| **05** | Path Traversal | CWE-22 | A01: Broken Access | Unvalidated file paths | `os.path.basename` + boundary check |
| **06** | Debug Mode in Prod | CWE-489 | A05: Misconfiguration | `debug=True`, bind `0.0.0.0` | `debug=False`, bind `127.0.0.1` |
| **07** | Missing Auth / RBAC | CWE-306 | A01: Broken Access | Unprotected delete route | `@admin_required` session decorator |
| **08** | Command Injection | CWE-78 | A03: Injection | String concat + `shell=True` | `ipaddress` validation + `shell=False` |
| **09** | Missing CSRF & Rate Limit | CWE-352 | A01: Broken Access | No token / infinite login | Anti-CSRF token + IP rate limiter |
| **10** | Verbose Error Leaks | CWE-209 | A05: Misconfiguration | Query & tracebacks returned | Server-side logs + generic error messages |

---

## 4. Mapping to CodSoft Requirements

| CodSoft Specification | Implementation in Repository | Relevant Files |
| :--- | :--- | :--- |
| **Choose an application in a language of choice** | Python Flask notes and authentication microservice. | `target_app/vulnerable_app.py` |
| **Examine source code for common weaknesses and flaws** | Audited for 10 distinct CWE vulnerabilities across authentication, crypto, and injection. | `REPORT.md`, `target_app/vulnerable_app.py` |
| **Use static analysis tools or manual review** | Bandit SAST scanner executed via PowerShell + comprehensive manual forensic review. | `analysis/run_bandit.ps1`, `REPORT.md` |
| **Suggest secure coding practices** | Complete code refactoring demonstrating parameterized queries, hashing, and defense-in-depth. | `target_app/secure_app.py` |
| **Prepare a report documenting vulnerabilities and fixes** | Formal vulnerability assessment report featuring findings matrix, CVSS, CWE, and diffs. | `REPORT.md` |

---

## 5. How to Run the Assessment & Verify Fixes

### Step 1: Run Automated Static Analysis (Bandit SAST)
Execute the automated PowerShell analysis script to scan both the baseline and remediated applications:
```powershell
powershell -ExecutionPolicy Bypass -File task3_secure_code_assessment/analysis/run_bandit.ps1
```
This generates:
- `analysis/bandit_report_before.txt` & `.json` (Showing 8 detected security issues)
- `analysis/bandit_report_after.txt` & `.json` (Showing 0 High, 0 Medium issues)

### Step 2: Run the Exploit & Remediation Test Suite (Pytest)
Execute the automated test harness using Flask's `test_client()` to verify that exploits succeed on the vulnerable app and are blocked on the secure app:
```powershell
pytest task3_secure_code_assessment/tests/test_fixes.py -v
```

### Step 3: Run the Applications Locally (Optional)
```powershell
# Run the vulnerable baseline (Port 5000)
python task3_secure_code_assessment/target_app/vulnerable_app.py

# Run the hardened application (Port 5000)
python task3_secure_code_assessment/target_app/secure_app.py
```

---

## 6. How to Apply This Assessment Process to Your Own Project

You can follow this exact four-step methodology to conduct a professional secure code assessment on your personal repositories:

1. **Install and Run Bandit on Your Codebase:**
   ```powershell
   pip install bandit
   bandit -r path/to/your/project -f txt -o my_audit_report.txt
   ```
2. **Perform Manual Business Logic Review:**
   - Check where user data enters SQL statements, shell commands, or HTML templates.
   - Verify whether authentication and authorization decorators guard all mutating endpoints.
   - Search for hardcoded API keys, passwords, or test tokens using regex or `git-secrets`.
3. **Refactor Insecure Patterns:**
   - Replace raw queries with parameter bindings (`?` or ORM models).
   - Sanitize file paths using canonical absolute path boundary checks.
   - Hash passwords with `werkzeug.security` or `bcrypt`.
4. **Author a Findings Report:**
   - Use the template in Section 7 below to document your findings, business impact, and remediation steps.

---

## 7. Appendix: Template for Reviewing Your Own Project

```markdown
# Security Assessment Report: [Your Project Name]

## 1. Executive Summary
Briefly describe the purpose of your application and summarize the results of your security audit.

## 2. Tools & Methodology
- Automated SAST: Bandit vX.X / Semgrep
- Dependency Check: pip-audit / safety
- Manual Review: OWASP Top 10 checklist

## 3. Findings Summary
| Finding | Severity | CWE | File & Line | Status |
| :--- | :--- | :--- | :--- | :--- |
| e.g. SQL Injection in search | High | CWE-89 | routes.py:42 | Fixed |
| e.g. Debug mode enabled | Medium | CWE-489 | app.py:110 | Fixed |

## 4. Remediation Evidence
Show the before/after code snippets demonstrating the secure fix.
```

---

## 8. What I Learned

1. **SAST vs. Human Intelligence:** Static analysis tools like Bandit are fast and reliable for finding syntactic anti-patterns (like `shell=True` or hardcoded tokens), but they cannot evaluate business logic, access controls, or CSRF protections. Manual code review is irreplaceable.
2. **The Power of Parameterization:** Understanding how prepared statements instruct database engines to separate executable SQL code from literal data inputs, rendering SQL injection impossible.
3. **Defense-in-Depth:** Security is not achieved through a single control; combining input validation, canonicalization, role-based authorization, rate limiting, and defensive response headers creates resilient systems.
