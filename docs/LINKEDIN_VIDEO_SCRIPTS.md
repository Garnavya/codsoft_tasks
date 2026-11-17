# LinkedIn Video Demonstration Scripts & Social Captions

This guide provides timestamped 60–90 second screen recording demonstration scripts and ready-to-paste LinkedIn post captions for each of the three completed CodSoft internship tasks.

---

## Task 1: Network Packet Analyzer

### 📹 Screen Recording Script (60–90 Seconds)

| Timestamp | Visual Action (What to Show on Screen) | Spoken Narration (What to Say) |
| :--- | :--- | :--- |
| **00:00 - 00:15** | Open VS Code showing `packet_analyzer.py` and the project structure. Show the CLI banner with the ethics and legal notice. | *"Hi everyone! As part of my CodSoft Cyber Security Internship, I developed a modular Network Packet Analyzer in Python using Scapy and Rich. Packet analysis is fundamental for network defenders to inspect protocols and detect intrusions."* |
| **00:15 - 00:35** | Run `python packet_analyzer.py --read-pcap samples/sample_traffic.pcap` in terminal. Scroll through the color-coded Rich table showing ARP, DNS, TCP handshakes, and ICMP pings. | *"Here, I'm analyzing a synthetic multi-protocol packet capture. The tool automatically decodes Layer 2 through 7 headers: extracting IP addresses, ports, TTL, and decoding TCP control flags like SYN and ACK to trace connection states."* |
| **00:35 - 00:55** | Run `python packet_analyzer.py --read-pcap samples/sample_traffic.pcap --verbose`. Highlight the Hex & ASCII payload dump and HTTP header detection. | *"In verbose mode, the analyzer performs deep packet inspection. It extracts unencrypted HTTP request methods, highlights DNS queries, and provides a 64-byte hex and ASCII payload preview to inspect raw byte signatures."* |
| **00:55 - 01:15** | Show the end-of-run Session Summary table (top talkers, protocol distribution percentages) and run `pytest tests/test_parser.py -v` showing 11 passed tests. | *"At the end of each session, it aggregates traffic metrics—calculating protocol distributions, throughput, and top talker IPs. All parser logic is backed by an automated 11-test pytest suite. Check out the GitHub repository below!"* |

### 📱 Ready-to-Paste LinkedIn Post Caption (Task 1)

```text
🚀 Excited to share Task 1 of my Cyber Security Internship with CodSoft: A Network Packet Analyzer built with Python and Scapy!

Understanding network protocol behavior at the byte and packet level is essential for any aspiring security analyst. For this project, I engineered a modular packet inspection engine with features including:

🔹 Multi-Protocol Dissection (Ethernet, ARP, IPv4, TCP, UDP, ICMP, DNS, HTTP)
🔹 TCP Control Flag Decoding (SYN, ACK, FIN, RST, PSH tracking connection states)
🔹 Forensic Payload Previews (Dual Hex and printable ASCII inspection)
🔹 Traffic Intelligence Telemetry (Bandwidth, protocol distributions, and top talkers)
🔹 Automated Testing (11 passing pytest test fixtures on synthetic packet captures)
🔹 Windows Privilege Resilience (Gracefully detects missing Npcap/admin rights)

💻 GitHub Repository: https://github.com/[YOUR_USERNAME]/CODSOFT_TASKSNO

Special thanks to CodSoft for this hands-on cybersecurity learning experience!

#codsoft #internship #cybersecurity #python #infosec #networking #scapy #blueteam #packetanalysis
```

---

## Task 2: Phishing Awareness Platform

### 📹 Screen Recording Script (60–90 Seconds)

| Timestamp | Visual Action (What to Show on Screen) | Spoken Narration (What to Say) |
| :--- | :--- | :--- |
| **00:00 - 00:15** | Open `index.html` in browser. Toggle Dark/Light mode and showcase the curriculum progress bar. | *"Hello everyone! For Task 2 of my CodSoft Cyber Security Internship, I created 'PhishAware'—a responsive, web-based phishing awareness training platform built with vanilla HTML, CSS, and JavaScript with zero external frameworks."* |
| **00:15 - 00:35** | Navigate to Lesson 2 (`lesson2-spotting-emails.html`). Click on the interactive highlighted red markers in the simulated email client. | *"In Lesson 2, learners use an interactive forensic email inspector. Clicking on highlighted red flags reveals technical breakdowns of typosquatting domains, artificial urgency, mismatched hyperlink destinations, and dangerous double file extensions."* |
| **00:35 - 00:55** | Navigate to Lesson 3 (Mockup Login) and Lesson 5 (Indian Cyber Safety). Highlight Helpline 1930 and the UPI PIN rule. | *"Lesson 3 dismantles the misconception that the HTTPS padlock means a site is safe, using a strictly non-functional training mockup. In Lesson 5, I included domestic cyber defense: the golden UPI rule and reporting via the 1930 National Helpline."* |
| **00:55 - 01:20** | Navigate to Final Exam (`final-assessment.html`). Submit answers, type name, and display the personalized Certificate of Completion. | *"The platform features 4 historical breach case studies, a 6-scenario practical lab, and a 15-question certification exam that generates a personalized completion certificate. The full source code is on GitHub!"* |

### 📱 Ready-to-Paste LinkedIn Post Caption (Task 2)

```text
🛡️ Excited to share Task 2 of my Cyber Security Internship with CodSoft: A Web-Based Phishing Awareness Training Platform!

Over 80% of cybersecurity incidents originate with human manipulation. To bridge the gap between technical defense and human intuition, I built a zero-dependency web application to educate users on recognizing social engineering attacks:

🔹 Interactive Email Forensic Inspector (Clickable red flags revealing typosquatting & payload tactics)
🔹 URL Anatomy & Padlock Misconception (Explaining why HTTPS encryption does NOT mean a site is safe)
🔹 Psychological Manipulation Breakdown (Urgency, authority, fear, pretexting, and baiting)
🔹 Indian Digital Safety Module (UPI PIN rules, KYC SMS scams, and the National 1930 Helpline)
🔹 Landmark Case Studies (Twitter 2020, DNC 2016, $120M BEC Invoice Fraud, RSA SecurID)
🔹 Certification Exam & Generator (15-question quiz unlocking a personalized Certificate of Completion)

Built entirely with pure HTML5, CSS3, and ES6 JavaScript!

💻 GitHub Repository: https://github.com/[YOUR_USERNAME]/CODSOFT_TASKSNO

#codsoft #internship #cybersecurity #python #infosec #phishingawareness #socialengineering #websecurity #cyberawareness
```

---

## Task 3: Secure Code Assessment

### 📹 Screen Recording Script (60–90 Seconds)

| Timestamp | Visual Action (What to Show on Screen) | Spoken Narration (What to Say) |
| :--- | :--- | :--- |
| **00:00 - 00:15** | Open VS Code showing side-by-side comparison of `vulnerable_app.py` and `secure_app.py`. | *"Hello everyone! For Task 3 of my CodSoft Cyber Security Internship, I conducted a Secure Code Assessment on a Flask web application, auditing common flaws against the OWASP Top 10 and CWE standards."* |
| **00:15 - 00:40** | Run `powershell -ExecutionPolicy Bypass -File analysis/run_bandit.ps1`. Open `bandit_report_before.txt` and `bandit_report_after.txt`. | *"I executed automated SAST scanning using Bandit. The baseline scan flagged 8 issues including command injection with shell=True, SQL query formatting, and debug=True. In the remediated version, all high and medium severity vulnerabilities were completely eliminated."* |
| **00:40 - 01:00** | Open `REPORT.md` and show the 10-finding vulnerability matrix and code diffs. | *"My formal vulnerability report covers 10 weaknesses, comparing automated SAST findings against manual code review. While Bandit caught syntactic issues, manual review was required to detect business logic flaws like missing authorization and path traversal."* |
| **01:00 - 01:20** | Run `pytest tests/test_fixes.py -v` showing all 8 tests passing. | *"Finally, I developed an automated test harness using Flask's test client, proving that exploit payloads succeed on the vulnerable baseline but are strictly blocked by our remediated defenses. Check out the report on GitHub!"* |

### 📱 Ready-to-Paste LinkedIn Post Caption (Task 3)

```text
🔍 Excited to present Task 3 of my Cyber Security Internship with CodSoft: Secure Code Assessment & Vulnerability Audit!

Writing functional code is not enough—software must be secure by design. For this assessment, I audited a Flask microservice, identified 10 critical security weaknesses, refactored the application using defense-in-depth engineering, and authored a formal vulnerability report:

🔹 Automated SAST (Executed Bandit scanning before and after remediation)
🔹 10 Remediated CWE Flaws (SQL injection, XSS, Path Traversal, Command Injection, Insecure Deserialization, Hardcoded Secrets, Missing RBAC, CSRF, and Verbose Errors)
🔹 Defense-in-Depth Fixes (Parameterized queries, PBKDF2-SHA256 password hashing, strict path boundary validation, and security headers)
🔹 Exploit vs. Defense Test Harness (8 automated pytest tests verifying exploit execution on vulnerable code and complete blockage on secure code)
🔹 Comprehensive Vulnerability Report (Formal audit report with CVSS scoring, CWE mappings, and tool vs. manual comparisons)

💻 GitHub Repository: https://github.com/[YOUR_USERNAME]/CODSOFT_TASKSNO

#codsoft #internship #cybersecurity #python #infosec #securecoding #appsec #sast #owasp #flask
```
