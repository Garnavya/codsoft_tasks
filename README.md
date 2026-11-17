# CodSoft Cyber Security Internship Portfolio

![Python Version](https://img.shields.io/badge/Python-3.10%2B-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Security Testing](https://img.shields.io/badge/Security_Testing-Bandit%20%7C%20Pytest-orange.svg)
![Status](https://img.shields.io/badge/Status-Submission%20Ready-success.svg)

A complete, production-grade cybersecurity engineering portfolio developed for the **CodSoft Cyber Security Internship**. This repository contains three independent, fully documented, and verified projects designed to demonstrate practical technical competency across network defense, social engineering awareness, and secure application development.

---

## 📌 Internship Task Index

| Task # | Project Title | Primary Technologies | Directory | Status |
| :---: | :--- | :--- | :--- | :---: |
| **01** | **Network Packet Analyzer** | Python, Scapy, Rich, Pytest | [`task1_network_packet_analyzer/`](task1_network_packet_analyzer/) | **Complete** |
| **02** | **Phishing Awareness Platform** | HTML5, CSS3, ES6 JavaScript | [`task2_phishing_awareness_program/`](task2_phishing_awareness_program/) | **Complete** |
| **03** | **Secure Code Assessment** | Python, Flask, Bandit SAST, SQLite3 | [`task3_secure_code_assessment/`](task3_secure_code_assessment/) | **Complete** |

---

## 🎯 CodSoft Requirements Mapping Matrix

| CodSoft Specification | Satisfying Project Implementation | Key Files |
| :--- | :--- | :--- |
| **Task 1: Capture packets using Python** | Implemented Scapy packet sniffer supporting BPF filters, packet counts, interface binding, and timeout limits. | `task1_.../packet_analyzer.py`<br>`task1_.../analyzer/capture.py` |
| **Task 1: Inspect packets for protocol behavior** | Full layered protocol dissection (Ethernet, ARP, IPv4, TCP flags, UDP, ICMP, DNS, HTTP, TLS). | `task1_.../analyzer/parser.py`<br>`task1_.../analyzer/protocols.py` |
| **Task 1: Extract IP, protocol, payload** | Structured parsing extracting endpoints, ports, protocol names, TTL, and 64-byte dual hex/ASCII payload dumps. | `task1_.../analyzer/parser.py` |
| **Task 1: Present output in clear format** | Color-coded Rich terminal tables, verbose inspector views, session telemetry panels, JSON & CSV exports. | `task1_.../analyzer/formatter.py`<br>`task1_.../analyzer/stats.py` |
| **Task 2: Educational phishing module** | Responsive, zero-dependency web training application with dark/light themes and persistent progress tracking. | `task2_.../index.html`<br>`task2_.../css/styles.css` |
| **Task 2: Identify suspicious emails** | Interactive webmail simulator with 6 clickable red-flag indicators (typosquatting, urgency, link mismatches). | `task2_.../modules/lesson2-spotting-emails.html` |
| **Task 2: Fake logins & websites** | Dissects URL anatomy, typosquatting, the HTTPS padlock misconception, and includes a non-functional training mockup. | `task2_.../modules/lesson3-fake-logins-websites.html` |
| **Task 2: Social engineering techniques** | Explains urgency, authority, fear, greed, curiosity, pretexting, baiting, tailgating, and impersonation. | `task2_.../modules/lesson4-social-engineering.html` |
| **Task 2: Practical security tips** | FIDO2 MFA, password managers, incident response checklist, India-specific safety (UPI PIN rules, 1930 Helpline). | `task2_.../modules/lesson5-defense-and-response.html` |
| **Task 2: Case studies & quizzes** | 4 documented breach case studies (Twitter, DNC, BEC, RSA), 5 lesson quizzes, 6-scenario lab, and 15-question exam. | `task2_.../modules/case-studies.html`<br>`task2_.../final-assessment.html` |
| **Task 3: Examine app for weaknesses** | Created deliberately flawed Flask notes app featuring 10 distinct OWASP Top 10 / CWE vulnerabilities. | `task3_.../target_app/vulnerable_app.py` |
| **Task 3: Static analysis & manual review** | Automated Bandit SAST scan via PowerShell script + manual architectural and business-logic code review. | `task3_.../analysis/run_bandit.ps1`<br>`task3_.../REPORT.md` |
| **Task 3: Suggest secure practices** | Engineered hardened production application remediating all 10 flaws with parameterized queries, hashing, and RBAC. | `task3_.../target_app/secure_app.py` |
| **Task 3: Prepare vulnerability report** | Formal security audit report with executive summary, CVSS scoring, CWE mapping, tool comparisons, and code diffs. | `task3_.../REPORT.md` |

---

## 💻 Technology Stack

| Layer | Technology | Version | Purpose |
| :--- | :--- | :--- | :--- |
| **Language** | Python | 3.10+ (tested on 3.11) | Core development language for Tasks 1 & 3 |
| **Packet Inspection** | Scapy | 2.5.0 | Low-level packet capture, PCAP reading, frame dissection |
| **Terminal UI** | Rich | 13.7.1 | Color-coded terminal tables, banners, summary telemetry |
| **Web Frontend** | Vanilla HTML5 / CSS3 / ES6 | Modern Standards | Zero-dependency, accessible training portal for Task 2 |
| **Target Web App** | Flask / Werkzeug | 3.0.3 | Web service under security review for Task 3 |
| **Static Analysis** | Bandit | 1.7.8 | Automated security linter and AST security scanner |
| **Testing Harness** | Pytest | 8.2.0 | Automated unit, functional, and security regression testing |

---

## 📁 Repository Directory Structure

```text
CODSOFT_TASKS/
├── README.md                          # Master portfolio overview and index
├── LICENSE                            # MIT License
├── .gitignore                         # Python, venv, PCAP outputs, IDE artifacts
├── requirements.txt                   # Shared pinned Python dependencies
├── docs/
│   ├── LINKEDIN_VIDEO_SCRIPTS.md      # 60-90s demo scripts, captions, hashtags for each task
│   └── SUBMISSION_CHECKLIST.md        # Comprehensive CodSoft submission verification
├── task1_network_packet_analyzer/
│   ├── README.md                      # Task 1 architecture, usage, and ethics guide
│   ├── packet_analyzer.py             # Main CLI entrypoint
│   ├── analyzer/                      # Core analysis modules
│   │   ├── __init__.py
│   │   ├── capture.py                 # Live sniffing & offline PCAP ingestion with Scapy
│   │   ├── parser.py                  # Packet dissection to normalized dictionaries
│   │   ├── protocols.py               # Port/protocol lookup tables & TCP flag decoding
│   │   ├── formatter.py               # Rich terminal tables, CSV, and JSON exporters
│   │   └── stats.py                   # Session metrics & top talker statistics
│   ├── samples/
│   │   ├── generate_sample_pcap.py    # Synthetic PCAP generator (TCP, HTTP, DNS, ICMP)
│   │   └── sample_traffic.pcap        # Ready-to-demo synthetic traffic capture
│   ├── output/                        # Default export destination (.gitkeep)
│   └── tests/
│       └── test_parser.py             # 11 automated pytest tests on synthetic packets
├── task2_phishing_awareness_program/
│   ├── README.md                      # Task 2 instructional design & deployment guide
│   ├── index.html                     # Central training portal & progress dashboard
│   ├── css/
│   │   └── styles.css                 # Responsive stylesheet with dark/light theme support
│   ├── js/
│   │   ├── app.js                     # State management & localStorage progress engine
│   │   ├── quiz.js                    # Reusable quiz engine & certificate generator
│   │   └── data/
│   │       ├── quizzes.js             # Data-driven lesson quizzes, 15-question exam, scenarios
│   │       └── cases.js               # Documented case studies (Twitter, DNC, RSA, BEC)
│   └── modules/
│       ├── lesson1-what-is-phishing.html
│       ├── lesson2-spotting-emails.html      # Interactive annotated email inspector
│       ├── lesson3-fake-logins-websites.html # URL anatomy & safe non-functional mockup
│       ├── lesson4-social-engineering.html
│       ├── lesson5-defense-and-response.html # FIDO2, "what to do if clicked", India 1930
│       ├── case-studies.html                 # Historical breach analyses
│       ├── scenario-quiz.html                # "Spot the Phish" 6 workplace scenario challenges
│       └── final-assessment.html             # 15-question exam & certificate generator
└── task3_secure_code_assessment/
    ├── README.md                      # Task 3 audit methodology, OWASP guide, student template
    ├── REPORT.md                      # Formal security audit & vulnerability report
    ├── target_app/
    │   ├── vulnerable_app.py          # Deliberately flawed Flask app (VULN-01 to VULN-10)
    │   ├── secure_app.py              # Hardened production counterpart (FIX-01 to FIX-10)
    │   ├── requirements.txt           # Flask dependencies
    │   └── uploads/                   # Test directory for attachment traversal evaluation
    ├── analysis/
    │   ├── run_bandit.ps1             # PowerShell script executing Bandit SAST
    │   ├── bandit_report_before.txt   # Real baseline Bandit scan report (text)
    │   ├── bandit_report_before.json  # Real baseline Bandit scan report (JSON)
    │   ├── bandit_report_after.txt    # Real post-remediation Bandit report (text)
    │   └── bandit_report_after.json   # Real post-remediation Bandit report (JSON)
    └── tests/
        └── test_fixes.py              # 8 automated pytest tests verifying exploit mitigations
```

---

## 🚀 Quick Start Guide

### Prerequisites
- **Target OS:** Windows 10/11 (PowerShell primary; cross-platform compatible with Linux/macOS)
- **Python:** Version 3.10 or newer

### 1. Environment Setup (PowerShell)
```powershell
# Clone or navigate to the repository directory
cd c:\Users\garna\Desktop\codsoft_tasks

# Create Python virtual environment
python -m venv .venv

# Activate virtual environment
.\.venv\Scripts\Activate.ps1

# Install pinned dependencies
pip install -r requirements.txt
```

---

### 2. Task 1: Network Packet Analyzer Quick Start
```powershell
# Run the analyzer on the included synthetic multi-protocol capture (No admin required!)
python task1_network_packet_analyzer/packet_analyzer.py --read-pcap task1_network_packet_analyzer/samples/sample_traffic.pcap

# Verbose mode showing Hex/ASCII payload previews
python task1_network_packet_analyzer/packet_analyzer.py --read-pcap task1_network_packet_analyzer/samples/sample_traffic.pcap --verbose

# Run unit tests
pytest task1_network_packet_analyzer/tests/test_parser.py -v
```

---

### 3. Task 2: Phishing Awareness Training Platform Quick Start
- **Option 1 (Direct Launch):** Double-click `task2_phishing_awareness_program/index.html` in Windows Explorer to open it in any modern browser.
- **Option 2 (Local Server):**
  ```powershell
  python -m http.server 8000 --directory task2_phishing_awareness_program
  ```
  Open `http://localhost:8000` in your web browser.

---

### 4. Task 3: Secure Code Assessment Quick Start
```powershell
# Execute the automated Bandit SAST security scan
powershell -ExecutionPolicy Bypass -File task3_secure_code_assessment/analysis/run_bandit.ps1

# Execute the exploit & defense verification test harness
pytest task3_secure_code_assessment/tests/test_fixes.py -v
```

---

## ⚖️ Ethics, Safety, and Legal Notice

> [!CAUTION]
> **Strictly Defensive and Educational Purpose**
> All tools, code samples, training materials, and vulnerability assessments in this repository are developed strictly for authorized educational research, diagnostic monitoring, defensive engineering, and academic assessment.
> 
> - **Task 1 (Packet Analyzer):** Packet capture should only ever be conducted on private local loops, isolated laboratory networks, or networks where explicit, documented authorization has been granted by the infrastructure owner. Capturing third-party traffic without consent is illegal under the Computer Fraud and Abuse Act (CFAA) and the Indian Information Technology Act, 2000.
> - **Task 2 (Phishing Awareness):** Contains zero malicious code, credential harvesting scripts, or proprietary brand infringements. All simulated mockups are strictly non-functional training visualizers clearly marked with warning ribbons.
> - **Task 3 (Secure Code Assessment):** Vulnerabilities in `vulnerable_app.py` exist solely to teach secure code review and remediation. Never deploy flawed code to public environments.

---

## 📄 License

This repository is licensed under the [MIT License](LICENSE).
