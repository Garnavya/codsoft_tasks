# Task 2: Phishing Awareness Training Platform

An interactive, responsive, web-based educational training program designed for employees, developers, and students to recognize, analyze, and defend against phishing attacks and social engineering deception.

---

## 1. Project Objective

To address the human layer of cybersecurity vulnerability through education. According to global industry threat reports, over 80% of security breaches involve a human element (phishing, stolen credentials, or social engineering). This modular web platform provides learners with hands-on forensic intuition: dissecting deceptive email headers, analyzing fraudulent domain structures, experiencing safe non-functional mockups, examining landmark real-world breach case studies, and assessing knowledge through quizzes and certification.

---

## 2. Key Features

- **Zero-Dependency Architecture:** Built strictly with vanilla HTML5, modern CSS3, and ES6 JavaScript. No Node.js, npm, build steps, or external framework dependencies required.
- **Local Progress Persistence:** Curriculum progress is automatically tracked across modules and saved in browser `localStorage` (safely wrapped in defensive error handling).
- **Interactive Email Inspector (Lesson 2):** A webmail simulator allowing learners to click highlighted email zones (sender mismatches, artificial urgency, lookalike links, double file extensions) to reveal detailed threat intelligence analysis.
- **Safe Fraudulent Website Lab (Lesson 3):** An educational mockup of a fake single sign-on portal clearly labeled with prominent `TRAINING LAB MOCKUP - NON-FUNCTIONAL` warnings to teach URL anatomy and dismantle the dangerous myth that the HTTPS padlock means a website is safe.
- **Social Engineering Psychology (Lesson 4):** Breaks down the 6 primary emotional triggers (urgency, authority, fear, greed, curiosity, likability) and tactical vectors (pretexting, baiting, tailgating, impersonation).
- **Practical Defense & Indian Cyber Safety (Lesson 5):** Features phishing-resistant MFA (FIDO2), password manager domain matching, emergency incident response checklists ("What to do if you clicked"), and India-specific scam awareness (UPI PIN rules, KYC SMS scams, the **1930 Cyber Fraud Helpline**, and **cybercrime.gov.in** reporting).
- **Historical Case Studies:** In-depth technical breakdowns of landmark public breaches: the **2020 Twitter Internal Tools Breach**, the **2016 DNC Spear-Phishing Campaign**, the **Google/Facebook $120M BEC Invoice Fraud**, and the **2011 RSA SecurID APT Compromise**.
- **Interactive Scenario Lab ("Spot the Phish"):** Evaluates 6 realistic simulated workplace communications where learners judge messages as legitimate or phishing, receiving instant feedback and indicator breakdowns.
- **Certification Exam & Generator:** A 15-question randomized final exam requiring an 80% passing grade to unlock a personalized, printable Certificate of Completion (rendered securely via DOM `textContent` without XSS risks).
- **Accessibility & Theming:** High-contrast design, keyboard-navigable controls, responsive mobile support, and automatic dark/light theme switching with manual toggle.

---

## 3. Platform Architecture & File Organization

```
task2_phishing_awareness_program/
├── README.md                      # Instructional design, architecture, deployment guide
├── index.html                     # Central landing page & curriculum progress dashboard
├── css/
│   └── styles.css                 # CSS variables, dark/light themes, card grids, certificate styles
├── js/
│   ├── app.js                     # State management, localStorage persistence, theme manager
│   ├── quiz.js                    # Reusable QuizEngine class & CertificateService
│   └── data/
│       ├── quizzes.js             # Data-driven quiz questions, 15-question final exam, 6 scenarios
│       └── cases.js               # Historical case studies data (Twitter, DNC, RSA, Rimasauskas)
└── modules/
    ├── lesson1-what-is-phishing.html          # Taxonomy: spear phishing, whaling, smishing, vishing, quishing
    ├── lesson2-spotting-emails.html           # Interactive annotated email inspector simulator
    ├── lesson3-fake-logins-websites.html      # URL anatomy, HTTPS padlock misconception & non-functional lab
    ├── lesson4-social-engineering.html        # Cognitive biases, pretexting, baiting, tailgating
    ├── lesson5-defense-and-response.html      # FIDO2, "what to do if clicked", India 1930 & cybercrime.gov.in
    ├── case-studies.html                      # Historical breach root-cause and defensive analysis
    ├── scenario-quiz.html                     # "Spot the Phish" 6 workplace scenario evaluations
    └── final-assessment.html                  # 15-question certification exam & certificate generator
```

---

## 4. Mapping to CodSoft Requirements

| CodSoft Specification | Implementation in Repository | Relevant Files |
| :--- | :--- | :--- |
| **Educational presentation / web-based training module** | Multi-page, responsive, accessible web curriculum with progress tracking. | `index.html`, `modules/` |
| **Explain how to identify suspicious emails** | Lesson 2 with interactive 6-point forensic email inspector. | `modules/lesson2-spotting-emails.html` |
| **Explain fake login pages and fraudulent websites** | Lesson 3 dissecting URL anatomy, lookalike domains, and the HTTPS misconception. | `modules/lesson3-fake-logins-websites.html` |
| **Describe common social engineering techniques** | Lesson 4 explaining urgency, authority, fear, pretexting, baiting, tailgating. | `modules/lesson4-social-engineering.html` |
| **Share practical security tips** | Lesson 5 covering FIDO2 MFA, password managers, incident response checklist, and Indian helpline 1930. | `modules/lesson5-defense-and-response.html` |
| **Include case studies, real-life examples, and quizzes** | Dedicated case studies page (Twitter, DNC, RSA, BEC), 5 lesson quizzes, 6-scenario lab, and 15-question exam. | `modules/case-studies.html`, `modules/scenario-quiz.html`, `final-assessment.html` |

---

## 5. How to Run the Training Program

Because this project is built entirely on vanilla web standards with no build step, you can run it immediately in two ways:

### Option A: Direct Browser Launch (Simplest)
1. Navigate to `task2_phishing_awareness_program` in Windows File Explorer.
2. Double-click `index.html` to open it in Microsoft Edge, Google Chrome, or Mozilla Firefox.

### Option B: Local Python Web Server (PowerShell)
```powershell
# Navigate to the task directory
cd c:\Users\garna\Desktop\codsoft_tasks\task2_phishing_awareness_program

# Start lightweight local server on port 8000
python -m http.server 8000
```
Open your browser and navigate to: [http://localhost:8000](http://localhost:8000).

---

## 6. Safety, Ethics, and Scope Declaration

> [!IMPORTANT]
> **Defensive and Educational Integrity**
> - **Zero Malicious Code:** This project does not contain phishing kits, credential harvesters, keyloggers, or exploitation tools.
> - **Non-Functional Mockups:** All simulated login forms are strictly visual mockups (`disabled` attributes, non-submitting form handlers) clearly watermarked with high-visibility warning ribbons.
> - **No Brand Copyright Infringement:** Visual examples use generic corporate placeholders and SVG vector icons without infringing on trademarked commercial logos.
> - **Secure JavaScript:** All dynamic text rendering (including user-entered names on certificates) utilizes `textContent` rather than `innerHTML` to prevent Cross-Site Scripting (XSS).

---

## 7. What I Learned

1. **Human Psychology in Security:** Understanding why attackers prioritize emotional pressure (fear and urgency) over software exploits—because manipulating human cognitive biases bypasses multi-million dollar perimeter firewalls.
2. **The HTTPS Myth:** Learning that TLS only protects data confidentiality in transit between client and server; cybercriminals can and do obtain free, automated SSL certificates for fraudulent domains.
3. **URL Parsing Nuances:** Dissecting how attackers exploit subdomains and lookalike character glyphs (typosquatting and homograph attacks) to mislead casual users.
4. **Resilient Vanilla Web Development:** Structuring modular data-driven JavaScript applications with zero external dependencies or build tools.
