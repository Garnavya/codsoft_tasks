/**
 * @file cases.js
 * @description Documented historical cybersecurity case studies for Phishing Awareness Program.
 * Author: CodSoft Cyber Security Intern
 */

const CASE_STUDIES = [
  {
    id: "twitter_2020",
    title: "The 2020 Twitter Administrative Tools Social Engineering Breach",
    year: "July 2020",
    target: "Twitter, Inc. (Internal Support Infrastructure)",
    threatActor: "Teenage social engineers and online conspirators",
    primaryTechnique: "Targeted Phone Vishing & Credential Harvesting via Fake VPN Portal",
    summary: "Attackers phoned remote Twitter customer service and IT employees, posing as legitimate Twitter helpdesk representatives troubleshooting remote work issues. Victims were instructed to enter their credentials into a lookalike VPN portal, allowing attackers to bypass two-factor authentication and hijack internal admin customer support tools.",
    impact: "130 high-profile accounts (including Barack Obama, Elon Musk, Bill Gates, and Apple) were commandeered to broadcast a Bitcoin doubling scam. Over $110,000 in cryptocurrency was collected before Twitter temporarily disabled posting for verified accounts.",
    rootCause: [
      "Employees relied on unverified phone calls without out-of-band identity verification.",
      "Internal customer service tools lacked hardware security key (FIDO2) enforcement.",
      "Excessive internal administrative privileges were granted without multi-party approval requirements."
    ],
    defensiveLessons: [
      "Enforce FIDO2 / WebAuthn security keys for all internal employee logins and VPNs.",
      "Require multi-party authorization ('two-person rule') for high-impact account alterations.",
      "Establish strict verification procedures for internal IT helpdesk calls."
    ],
    sources: "US Department of Justice Indictments, Twitter Incident Reports (July 2020), New York Department of Financial Services (NYDFS) Investigation Report. Verify details from the cited sources."
  },
  {
    id: "dnc_2016",
    title: "The 2016 Democratic National Committee Spear-Phishing Campaign",
    year: "March 2016",
    target: "Senior Political Campaign Officials (John Podesta & DNC Staff)",
    threatActor: "APT28 / Fancy Bear (Russian Military Intelligence GRU)",
    primaryTechnique: "Targeted Spear Phishing with Lookalike Google Security Warning",
    summary: "A targeted spear-phishing email arrived disguised as an official Google security notification warning the user that an unauthorized party had their password. The email provided a bit.ly shortened link that redirected to an attacker-controlled lookalike portal ('myaccount.google.com-securitysettingpage.ml') designed to harvest Google account credentials.",
    impact: "Over 50,000 emails and confidential documents were exfiltrated, published on WikiLeaks and DCLeaks, and dominated global news cycles during the 2016 US presidential election.",
    rootCause: [
      "Use of external URL shorteners that disguised the true destination domain.",
      "An internal IT helpdesk staff member mistakenly characterized the phishing email as 'legitimate' during a quick email review.",
      "Absence of phishing-resistant authentication methods (such as FIDO2 keys)."
    ],
    defensiveLessons: [
      "Train internal IT and SOC analysts to meticulously inspect raw email headers and domain strings.",
      "Mandate FIDO2 hardware keys across all political campaigns and high-risk organizations.",
      "Deploy Domain-based Message Authentication (DMARC, SPF, DKIM) and advanced link-rewriting defenses."
    ],
    sources: "US Department of Justice Indictment (July 2018), Office of the Director of National Intelligence (ODNI) Declassified Report. Verify details from the cited sources."
  },
  {
    id: "rimasauskas_bec",
    title: "The $120M Google & Facebook Supply-Chain Invoice Fraud (Evaldas Rimasauskas)",
    year: "2013 - 2015",
    target: "Tech Giants (Google & Facebook Accounting Departments)",
    threatActor: "Evaldas Rimasauskas (Lithuanian national) and co-conspirators",
    primaryTechnique: "Business Email Compromise (BEC) & Vendor Impersonation",
    summary: "The perpetrator registered a company in Latvia with the exact same name as Quanta Computer, a Taiwan-based hardware manufacturing contractor with legitimate multi-million dollar contracts with Google and Facebook. The actor sent forged invoices, contracts, and spoofed corporate emails to corporate accounting teams requesting payments be wired to fraudulent bank accounts in Latvia and Cyprus.",
    impact: "Approximately $99 million was wired by Facebook and $23 million by Google over two years before the discrepancy was uncovered. Rimasauskas was extradited to the US, pleaded guilty to wire fraud, and ordered to forfeit over $49 million.",
    rootCause: [
      "Accounting teams failed to perform out-of-band verification before altering international vendor wire bank details.",
      "Inadequate vendor validation controls and automated cross-referencing between purchase orders and bank account numbers.",
      "Corporate trust assumed purely on matching email display names and standard invoice formatting."
    ],
    defensiveLessons: [
      "Mandate strict, independent out-of-band verbal confirmation (via a pre-established contact number) for any requested change to vendor banking details.",
      "Establish strict dual-authorization workflows for wire transfers exceeding corporate thresholds.",
      "Audit vendor master files regularly and cross-check supplier banking origins against geographic norms."
    ],
    sources: "US Department of Justice Southern District of New York (SDNY) Sentencing Statement (December 2019). Verify details from the cited sources."
  },
  {
    id: "rsa_2011",
    title: "The 2011 RSA SecurID APT Spear-Phishing Compromise",
    year: "March 2011",
    target: "RSA (The Security Division of EMC)",
    threatActor: "Advanced Persistent Threat (APT) Group",
    primaryTechnique: "Spear Phishing with Malicious Flash Zero-Day Excel Attachment",
    summary: "Two small groups of lower-profile RSA employees received targeted spear-phishing emails with the subject line '2011 Recruitment plan'. The email contained an attached Microsoft Excel spreadsheet ('2011 Recruitment plan.xls') embedding a zero-day Adobe Flash exploit (CVE-2011-0609) that installed the Poison Ivy remote access trojan upon opening.",
    impact: "Attackers pivoted through the internal network and exfiltrated sensitive proprietary data related to RSA SecurID two-factor authentication tokens, which was later utilized to compromise defense contractor Lockheed Martin.",
    rootCause: [
      "Users opened unsolicited email attachments that had been routed into their junk mail folders.",
      "Vulnerable software components (Flash embedded in Office documents) permitted arbitrary code execution.",
      "Lateral movement and privilege escalation went undetected for several days internally."
    ],
    defensiveLessons: [
      "Isolate and sandbox high-risk file attachments using automated detonation pipelines.",
      "Train employees that legitimate recruiters or human resources will never send recruitment plans from external or suspicious addresses.",
      "Implement robust network segmentation and behavioral anomaly monitoring to detect internal lateral movement."
    ],
    sources: "EMC/RSA Official Security Disclosures (March/April 2011), First.org Technical Incident Analyses. Verify details from the cited sources."
  }
];
