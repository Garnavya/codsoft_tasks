/**
 * @file quizzes.js
 * @description Curated educational questions and scenarios for Phishing Awareness Program.
 * Author: CodSoft Cyber Security Intern
 */

/**
 * Educational quiz questions organized by module.
 */
const QUIZ_DATA = {
  // Lesson 1: What is Phishing?
  lesson1: [
    {
      id: "l1_q1",
      question: "Which term describes a targeted phishing attack aimed specifically at high-profile corporate executives (such as C-level officers)?",
      options: [
        "Smishing",
        "Whaling",
        "Vishing",
        "Clone Phishing"
      ],
      correctAnswer: 1,
      explanation: "Whaling specifically targets high-ranking executives (CEOs, CFOs) to authorize fraudulent wire transfers or disclose sensitive corporate trade secrets."
    },
    {
      id: "l1_q2",
      question: "What is 'Quishing' in modern social engineering?",
      options: [
        "Phishing conducted through encrypted instant messaging",
        "Using malicious QR codes that redirect mobile victims to phishing login portals",
        "Targeting quantum computing algorithms",
        "Brute-forcing database queries"
      ],
      correctAnswer: 1,
      explanation: "Quishing (QR Code Phishing) embeds malicious URLs into QR codes, evading traditional email security gateways and tricking users who scan them on personal mobile devices."
    },
    {
      id: "l1_q3",
      question: "How does Clone Phishing differ from generic bulk phishing?",
      options: [
        "It uses automated voice calls instead of email",
        "It intercepts a legitimate, previously delivered email, duplicates its content, and replaces links/attachments with malicious versions",
        "It attacks web servers rather than human users",
        "It only targets Android operating systems"
      ],
      correctAnswer: 1,
      explanation: "Clone phishing takes an authentic email that was previously received, copies its exact layout, and claims to be a 'resend' or 'updated version' with malicious links substituted."
    }
  ],

  // Lesson 2: Spotting Suspicious Emails
  lesson2: [
    {
      id: "l2_q1",
      question: "An email claims to be from 'support@paypa1.com'. What defensive concept is being observed here?",
      options: [
        "Cross-Site Scripting",
        "Typosquatting / Lookalike Domain Impersonation",
        "SQL Injection",
        "Buffer Overflow"
      ],
      correctAnswer: 1,
      explanation: "Typosquatting replaces subtle characters (such as digit '1' for letter 'l' in paypa1.com) to visually impersonate legitimate domain names."
    },
    {
      id: "l2_q2",
      question: "Before clicking any hyperlink in an email, what safe practice should you always perform?",
      options: [
        "Immediately forward the email to all coworkers",
        "Hover your cursor over the link to verify the true destination URL in your mail client's status bar",
        "Disable your operating system firewall",
        "Double-click the link as quickly as possible"
      ],
      correctAnswer: 1,
      explanation: "Hovering over anchor text reveals the actual destination URL, which frequently points to a malicious third-party server rather than the benign text displayed."
    },
    {
      id: "l2_q3",
      question: "Why do phishers frequently demand urgent action (e.g., 'Account suspended in 24 hours!')?",
      options: [
        "To bypass network intrusion detection systems",
        "To induce psychological panic, overriding logical scrutiny and careful verification",
        "Because email servers discard messages after 24 hours",
        "To comply with corporate privacy guidelines"
      ],
      correctAnswer: 1,
      explanation: "Artificial urgency induces fear and haste, prompting victims to act impulsively without verifying the communication through official out-of-band channels."
    }
  ],

  // Lesson 3: Fake Login Pages & Websites
  lesson3: [
    {
      id: "l3_q1",
      question: "Does the presence of a padlock icon (HTTPS) guarantee that a website is legitimate and safe?",
      options: [
        "Yes, HTTPS certificates are only issued to verified banks and government organizations",
        "No, HTTPS only encrypts the connection between browser and server; threat actors routinely obtain free SSL certificates for fraudulent domains",
        "Yes, browsers automatically block all malicious HTTPS traffic",
        "No, HTTPS means the website is running on a local intranet"
      ],
      correctAnswer: 1,
      explanation: "HTTPS encrypts data in transit to prevent eavesdropping, but modern automated certificate authorities (such as Let's Encrypt) provide certificates to any domain owner—including cybercriminals."
    },
    {
      id: "l3_q2",
      question: "In the URL 'https://secure-login.bank.com.attacker-portal.net/auth', what is the actual apex domain you are connecting to?",
      options: [
        "bank.com",
        "secure-login.bank.com",
        "attacker-portal.net",
        "auth.net"
      ],
      correctAnswer: 2,
      explanation: "The actual registered domain is the segment immediately preceding the top-level domain (/auth is a path). Here, 'attacker-portal.net' is the true destination, while 'bank.com' is merely a misleading subdomain prefix."
    },
    {
      id: "l3_q3",
      question: "What is an IDN Homograph Attack?",
      options: [
        "Cracking passwords using identical hash dictionaries",
        "Registering domain names using non-Latin Unicode characters (e.g., Cyrillic 'а') that appear visually identical to standard ASCII characters",
        "Sending identical phishing emails to an entire department",
        "Using machine learning to synthesize fraudulent audio"
      ],
      correctAnswer: 1,
      explanation: "Homograph attacks abuse internationalized domain names (IDN) by swapping standard Latin letters with visually indistinguishable Cyrillic or Greek glyphs."
    }
  ],

  // Lesson 4: Social Engineering Techniques
  lesson4: [
    {
      id: "l4_q1",
      question: "An attacker calls an employee pretending to be the corporate IT helpdesk diagnosing a network outage to extract login credentials. What technique is this?",
      options: [
        "Pretexting",
        "Watering Hole Attack",
        "Ransomware Encryption",
        "Denial of Service"
      ],
      correctAnswer: 0,
      explanation: "Pretexting involves creating an invented scenario (a pretext) where the attacker assumes a fabricated persona (such as internal IT support) to persuade the victim to surrender privileged information."
    },
    {
      id: "l4_q2",
      question: "Leaving malware-infected USB flash drives labeled 'Confidential Executive Salaries' in an office parking lot is an example of which attack vector?",
      options: [
        "Baiting",
        "Tailgating",
        "Spear Phishing",
        "Typosquatting"
      ],
      correctAnswer: 0,
      explanation: "Baiting exploits human curiosity and greed by offering an enticing item (like a labeled USB drive or free software download) that carries a malicious payload."
    },
    {
      id: "l4_q3",
      question: "Following closely behind an authorized employee through a secure badge-access turnstile without swiping a badge is known as:",
      options: [
        "Shoulder Surfing",
        "Tailgating (Piggybacking)",
        "Bluejacking",
        "War Driving"
      ],
      correctAnswer: 1,
      explanation: "Tailgating or piggybacking is a physical social engineering tactic where an unauthorized person slips through secure doors right behind an authorized badge holder."
    }
  ],

  // Lesson 5: Practical Defense Tips & Indian Cyber Safety
  lesson5: [
    {
      id: "l5_q1",
      question: "Which form of Multi-Factor Authentication (MFA) is most resilient against real-time adversary-in-the-middle (AiTM) phishing proxies?",
      options: [
        "SMS-based OTP verification",
        "Email verification links",
        "FIDO2 / WebAuthn Hardware Security Keys (e.g. YubiKey)",
        "Voice call passcodes"
      ],
      correctAnswer: 2,
      explanation: "FIDO2 / WebAuthn security keys cryptographically bind authentication credentials to the specific origin URL in the browser, rendering reverse-proxy phishing attacks ineffective."
    },
    {
      id: "l5_q2",
      question: "In India, what is the official national toll-free helpline number for reporting active financial cyber fraud?",
      options: [
        "100",
        "108",
        "1930",
        "1800"
      ],
      correctAnswer: 2,
      explanation: "Helpline 1930 is the national citizen financial cyber fraud reporting helpline operated by the Ministry of Home Affairs (MHA) under the Indian Cyber Crime Coordination Centre (I4C)."
    },
    {
      id: "l5_q3",
      question: "If you accidentally entered your corporate credentials into a suspected phishing portal, what is the critical first step to take?",
      options: [
        "Delete your web browser history and shut down your computer",
        "Immediately change your password from a known-clean device and notify your security/IT team",
        "Wait 48 hours to see if any unauthorized transactions occur",
        "Reply to the phisher demanding your data be removed"
      ],
      correctAnswer: 1,
      explanation: "Time is crucial: changing the compromised credentials from a safe device revokes attacker access, and alerting internal SOC/IT teams allows rapid session token invalidation."
    }
  ],

  // Spot the Phishing Email Scenario Challenge (6 scenarios)
  scenarios: [
    {
      id: "sc_1",
      title: "Scenario 1: HR Department Policy Update",
      sender: "human-resources@company-updates-portal.co",
      subject: "ACTION REQUIRED: Mandatory Updated Severance & Leave Policy",
      bodyText: "All employees must download and review the attached PDF document 'Leave_Policy_2026.pdf.exe' and sign acknowledgment within 4 hours to avoid salary delay.",
      isPhishing: true,
      indicators: [
        "External domain ('company-updates-portal.co') rather than legitimate internal domain",
        "High urgency threatening salary disruption within 4 hours",
        "Dangerous double file extension: .pdf.exe indicating an executable disguised as a document"
      ]
    },
    {
      id: "sc_2",
      title: "Scenario 2: Software License Renewal Notification",
      sender: "notifications@github.com",
      subject: "[GitHub] Your personal access token will expire in 7 days",
      bodyText: "Your personal access token 'ci-runner' will expire on May 24, 2026. You can review your tokens by navigating to https://github.com/settings/tokens.",
      isPhishing: false,
      indicators: [
        "Sender header originates from authentic registered domain (github.com)",
        "Does not demand emergency action or threaten immediate punishment",
        "Directs the user to an official, authenticated destination with no obfuscated redirects"
      ]
    },
    {
      id: "sc_3",
      title: "Scenario 3: Banking Security Alert (India SMS/Email)",
      sender: "alerts@sbi-kyc-verification-desk.in",
      subject: "URGENT: SBI YONO Account Blocked - Update PAN Immediately",
      bodyText: "Dear Customer, Your SBI NetBanking access is frozen due to pending KYC. Click http://bit.ly/sbi-pan-updt to upload Aadhaar and PAN immediately to unblock.",
      isPhishing: true,
      indicators: [
        "Legitimate banks never request PAN/Aadhaar updates over shortened bit.ly links",
        "Impersonation domain ('sbi-kyc-verification-desk.in') is not the official onlinesbi.sbi portal",
        "Classic panic-inducing pretext threatening account freezing"
      ]
    },
    {
      id: "sc_4",
      title: "Scenario 4: Cloud Storage Share Link",
      sender: "share-point-service@external-share-docs.cc",
      subject: "Vendor Invoice #4892 shared via Microsoft SharePoint",
      bodyText: "A confidential invoice has been shared with you. Click 'View Document' to log in with your corporate email credentials to decrypt this spreadsheet.",
      isPhishing: true,
      indicators: [
        "Generic external domain masquerading as Microsoft SharePoint",
        "Unsolicited vendor invoice with no known business relationship",
        "Requests corporate login credentials to view a supposed document"
      ]
    },
    {
      id: "sc_5",
      title: "Scenario 5: Corporate IT Calendar Invitation",
      sender: "alex.sharma@internal-corp.com",
      subject: "Quarterly Townhall & Roadmap Review",
      bodyText: "Hi team, please find the meeting invitation attached for our all-hands townhall this Thursday at 3 PM IST on our corporate Google Meet room.",
      isPhishing: false,
      indicators: [
        "Originates from verified internal organizational domain",
        "Matches expected recurring organizational schedule",
        "Contains standard meeting metadata with no credential harvesting links"
      ]
    },
    {
      id: "sc_6",
      title: "Scenario 6: Package Delivery Notification (Smishing/Email)",
      sender: "tracking@indiapost-tracking-services.live",
      subject: "India Post: Undelivered parcel due to incomplete address",
      bodyText: "Your package #IN8931201 is held at the regional terminal. Pay re-delivery fee of ₹25 via UPI link http://indiapost-terminal.xyz/pay within 12 hours.",
      isPhishing: true,
      indicators: [
        "India Post official portal is indiapost.gov.in, never .live or .xyz",
        "Demanding nominal ₹25 fee via unverified link to capture UPI PIN/card details",
        "Unsolicited delivery alert with false urgency"
      ]
    }
  ],

  // Comprehensive 15-Question Final Assessment
  finalExam: [
    {
      id: "fe_01",
      question: "Which of the following describes the primary objective of a 'Spear Phishing' attack?",
      options: [
        "Broadcasting millions of generic emails hoping a small percentage of recipients click",
        "Sending highly personalized communications using researched details to target a specific individual or organization",
        "Disrupting an organization's network bandwidth via Distributed Denial of Service (DDoS)",
        "Interpreting unencrypted radio signals from wireless access points"
      ],
      correctAnswer: 1,
      explanation: "Spear phishing is highly targeted and customized using victim reconnaissance (names, roles, projects) to increase the likelihood of deception."
    },
    {
      id: "fe_02",
      question: "What is 'Vishing'?",
      options: [
        "Voice-based phishing where attackers use phone calls to manipulate victims into revealing information",
        "Video-based deepfake video attacks",
        "Virtual reality phishing environments",
        "Vulnerability scanning against web firewalls"
      ],
      correctAnswer: 0,
      explanation: "Vishing (Voice Phishing) leverages telephonic social engineering, often spoofing caller IDs to masquerade as banks, law enforcement, or tech support."
    },
    {
      id: "fe_03",
      question: "In the context of email headers, what does the Sender Policy Framework (SPF) record authenticate?",
      options: [
        "It encrypts the entire email payload using RSA public keys",
        "It publishes a list of authorized IP addresses permitted to send emails on behalf of a specific domain",
        "It verifies the recipient's password before delivery",
        "It guarantees that an email contains no executable attachments"
      ],
      correctAnswer: 1,
      explanation: "SPF is a DNS TXT record that specifies which mail servers and IP addresses are authorized to transmit email on behalf of that domain name."
    },
    {
      id: "fe_04",
      question: "What is DKIM (DomainKeys Identified Mail) primarily designed to prevent?",
      options: [
        "Unauthorized physical access to server rooms",
        "Email tampering and spoofing by attaching a cryptographic digital signature to outbound messages",
        "Excessive network packet loss",
        "Malicious SQL query injection in web forms"
      ],
      correctAnswer: 1,
      explanation: "DKIM uses public-key cryptography to digitally sign email headers and bodies, ensuring the message was not altered in transit."
    },
    {
      id: "fe_05",
      question: "How does DMARC build upon SPF and DKIM protocols?",
      options: [
        "It tells receiving email servers what policy action to take (none, quarantine, or reject) if SPF or DKIM checks fail",
        "It forces all emails to be converted into PDF documents",
        "It replaces HTTPS certificates with DNS records",
        "It automatically unblocks quarantined spam messages"
      ],
      correctAnswer: 0,
      explanation: "DMARC (Domain-based Message Authentication, Reporting, and Conformance) specifies policy enforcement (e.g., reject fraudulent emails) and generates delivery reports."
    },
    {
      id: "fe_06",
      question: "Which of the following domain names is an example of a lookalike 'typosquatting' attack targeting google.com?",
      options: [
        "mail.google.com",
        "support.google.com",
        "g00gle.com",
        "workspace.google.com"
      ],
      correctAnswer: 2,
      explanation: "'g00gle.com' replaces the lowercase letter 'o' with the digit '0' to mimic the legitimate domain name."
    },
    {
      id: "fe_07",
      question: "Why is an adversary-in-the-middle (AiTM) reverse proxy phishing attack particularly dangerous?",
      options: [
        "It immediately crashes the victim's operating system",
        "It intercepts both login credentials AND real-time MFA session cookies, bypassing traditional SMS/Authenticator OTPs",
        "It permanently deletes the victim's cloud data within seconds",
        "It requires physical proximity to the victim's keyboard"
      ],
      correctAnswer: 1,
      explanation: "AiTM proxies (such as Evilginx) proxy live web sessions between the victim and the legitimate service, allowing the attacker to steal the authenticated session cookie upon MFA completion."
    },
    {
      id: "fe_08",
      question: "What makes hardware security keys (FIDO2 / WebAuthn) resistant to AiTM proxy attacks?",
      options: [
        "They require typing an 8-digit randomized code",
        "They bind the authentication signature to the exact TLS domain origin (URL) loaded in the browser address bar",
        "They work without any cryptographic handshakes",
        "They disable JavaScript in the web browser"
      ],
      correctAnswer: 1,
      explanation: "The browser passes its origin to the security key, which signs only the genuine domain. If the victim is on a fake proxy domain, the signature will not match the real server's challenge."
    },
    {
      id: "fe_09",
      question: "An attacker calls an employee claiming to be a courier driver who needs an urgent ₹10 address confirmation fee over UPI to deliver a high-priority parcel. Which psychological trigger is being exploited?",
      options: [
        "Artificial urgency combined with curiosity and a trivial financial obstacle",
        "Quantum superposition",
        "Cryptographic diffusion",
        "Hardware buffer overflow"
      ],
      correctAnswer: 0,
      explanation: "Social engineers use minimal payment requests to capture payment credentials or trick users into entering their UPI PIN on fraudulent collect-request screens."
    },
    {
      id: "fe_10",
      question: "What is the critical rule regarding your UPI PIN in India?",
      options: [
        "You must enter your UPI PIN whenever receiving money into your bank account",
        "UPI PIN is required ONLY for SENDING money or debiting your account; receiving money NEVER requires entering your PIN",
        "UPI PIN should be shared with bank officials over SMS for KYC validation",
        "UPI PIN changes automatically every 24 hours"
      ],
      correctAnswer: 1,
      explanation: "A cornerstone of digital banking security: UPI PIN is strictly for authorizing debits. Receiving incoming money requires zero PIN entry."
    },
    {
      id: "fe_11",
      question: "Which Indian government portal allows citizens to formally lodge complaints regarding cybercrimes, including online financial fraud and identity theft?",
      options: [
        "cybercrime.gov.in",
        "incometaxindia.gov.in",
        "epfindia.gov.in",
        "passportindia.gov.in"
      ],
      correctAnswer: 0,
      explanation: "The National Cyber Crime Reporting Portal (cybercrime.gov.in) is the official central portal managed by the Indian Government for reporting cyber incidents."
    },
    {
      id: "fe_12",
      question: "What is 'Pretexting' in social engineering?",
      options: [
        "Encrypting hard drives before sending ransom demands",
        "Creating a detailed fabricated story and persona to manipulate a target into providing sensitive information",
        "Scanning network ports prior to launching a denial of service attack",
        "Writing clean documentation for open-source software"
      ],
      correctAnswer: 1,
      explanation: "Pretexting is the act of establishing an invented backstory or scenario to convince the target of the attacker's legitimacy."
    },
    {
      id: "fe_13",
      question: "When evaluating an email containing a link, what is 'out-of-band verification'?",
      options: [
        "Replying directly to the suspicious email to ask if it was legitimate",
        "Contacting the supposed sender through a known, trusted, independent channel (such as a verified phone number or internal chat) rather than using links or phone numbers provided in the email",
        "Running a packet sniffer on your local wireless adapter",
        "Forwarding the email to personal Gmail accounts"
      ],
      correctAnswer: 1,
      explanation: "Out-of-band verification relies on a completely separate, trusted communication pathway to validate the request without trusting the sender's unverified email channel."
    },
    {
      id: "fe_14",
      question: "Why should organizations implement dedicated password managers across their workforce?",
      options: [
        "Password managers generate unique, complex passwords for every service and inherently resist phishing because they will not autofill credentials into lookalike domains",
        "Password managers make passwords publicly accessible to coworkers",
        "Password managers completely eliminate the need for firewalls",
        "Password managers only function when connected to a VPN"
      ],
      correctAnswer: 0,
      explanation: "Password managers match the browser's exact domain before offering autofill; on fraudulent domains (e.g., paypa1.com), autofill will refuse to trigger, alerting the user."
    },
    {
      id: "fe_15",
      question: "In the 2020 Twitter breach, how did threat actors gain access to internal administrative customer support tools?",
      options: [
        "By cracking high-grade RSA 4096-bit encryption keys",
        "By conducting a targeted vishing campaign against remote Twitter employees to harvest VPN credentials",
        "By intercepting unencrypted Wi-Fi at a public cafe",
        "By deploying physical keyloggers inside Twitter headquarters"
      ],
      correctAnswer: 1,
      explanation: "Attackers called remote employees masquerading as Twitter IT support, directing them to a fake VPN login portal to harvest their credentials and access internal admin panels."
    }
  ]
};
