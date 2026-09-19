// FILE: backend/siem/ruleEngine.js  (FULL REPLACEMENT)
// SentinelCore Rule Engine v2 — 25+ rules, full MITRE ATT&CK + CVE mapping

let CustomRule = null;
try {
  CustomRule = require("../models/CustomRule");
} catch {
  /* not available */
}

// Returns the most meaningful target label for use in descriptions.
// Priority: domain (most specific for URLs) → rawInput → url → email → text → "unknown"
const getTargetLabel = (e, maxLen = 80) => {
  const raw =
    e.target?.domain ||
    e.target?.rawInput ||
    e.target?.url ||
    e.target?.email ||
    e.target?.text ||
    e.target?.ip ||
    null;
  if (!raw) return "unknown";
  const s = String(raw).trim();
  return s.length > maxLen ? s.substring(0, maxLen) + "…" : s;
};

const RULES = [
  // ═══════════════════════════════
  // PHISHING RULES
  // ═══════════════════════════════

  {
    id: "PHI-001",
    name: "Critical Phishing URL — High Risk Score",
    category: "phishing",
    severity: 5,
    mitre: {
      tactic: "TA0001 - Initial Access",
      technique: "T1566.002 - Spearphishing Link",
      sub: "T1566.002",
      mitigation:
        "M1054 - Software Configuration | M1021 - Restrict Web-Based Content",
      detection: "DS0015 - Application Log | DS0029 - Network Traffic",
      url: "https://attack.mitre.org/techniques/T1566/002/",
    },
    cve: null,
    condition: (e) => e.category === "phishing" && e.riskScore >= 75,
    description: (e) =>
      `Phishing URL detected — risk score ${e.riskScore}/100. Target: ${getTargetLabel(e)}`,
    dedupWindow: 5 * 60 * 1000,
    compliance: ["PCI-DSS 6.4", "NIST SP 800-61"],
  },

  {
    id: "PHI-002",
    name: "Brand Impersonation Attack",
    category: "phishing",
    severity: 4,
    mitre: {
      tactic: "TA0001 - Initial Access",
      technique: "T1566.002 - Spearphishing Link",
      sub: "T1036.005 - Masquerading: Match Legitimate Name",
      mitigation: "M1017 - User Training | M1032 - Multi-factor Authentication",
      detection: "DS0015 - Application Log | DS0007 - Image",
      url: "https://attack.mitre.org/techniques/T1036/005/",
    },
    cve: null,
    condition: (e) =>
      e.category === "phishing" &&
      e.rawData?.issues?.some((i) => /impersonat|spoofing/i.test(i)),
    description: (e) =>
      `Brand impersonation detected — scanned: ${getTargetLabel(e)}`,
    dedupWindow: 10 * 60 * 1000,
    compliance: ["GDPR Art.32"],
  },

  {
    id: "PHI-003",
    name: "OTP Credential Harvesting",
    category: "phishing",
    severity: 5,
    mitre: {
      tactic: "TA0006 - Credential Access",
      technique: "T1111 - MFA Interception",
      sub: "T1556.006 - Modify Authentication Process: MFA",
      mitigation:
        "M1032 - Multi-factor Authentication | M1054 - Software Configuration",
      detection: "DS0028 - Logon Session | DS0002 - User Account",
      url: "https://attack.mitre.org/techniques/T1111/",
    },
    cve: null,
    condition: (e) =>
      e.category === "phishing" &&
      e.rawData?.issues?.some((i) => /otp|credential request/i.test(i)),
    description: (e) =>
      `OTP/credential harvesting detected in: ${getTargetLabel(e)} — immediate action required`,
    dedupWindow: 2 * 60 * 1000,
    compliance: ["PCI-DSS 8.3", "NIST AC-7"],
  },

  {
    id: "PHI-004",
    name: "Suspicious URL — Medium Risk",
    category: "phishing",
    severity: 2,
    mitre: { tactic: "TA0001 - Initial Access", technique: "T1566 - Phishing" },
    cve: null,
    condition: (e) =>
      e.category === "phishing" && e.riskScore >= 30 && e.riskScore < 65,
    description: (e) =>
      `Suspicious content — score ${e.riskScore}/100. Input: ${getTargetLabel(e)}`,
    dedupWindow: 15 * 60 * 1000,
    compliance: [],
  },

  {
    id: "PHI-005",
    name: "Typosquatting Domain",
    category: "phishing",
    severity: 4,
    mitre: {
      tactic: "TA0001 - Initial Access",
      technique: "T1583.001 - Acquire Infrastructure: Domains",
      sub: "T1036.005 - Masquerading: Match Legitimate Name",
      mitigation: "M1021 - Restrict Web-Based Content | M1056 - Pre-compromise",
      detection: "DS0038 - Domain Name | DS0029 - Network Traffic",
      url: "https://attack.mitre.org/techniques/T1583/001/",
    },
    cve: null,
    condition: (e) =>
      e.category === "phishing" &&
      e.rawData?.issues?.some((i) => /typosquatting/i.test(i)),
    description: (e) =>
      `Typosquatting detected — scanned: ${getTargetLabel(e)}`,
    dedupWindow: 30 * 60 * 1000,
    compliance: ["GDPR Art.32"],
  },

  {
    id: "PHI-006",
    name: "Homoglyph / Unicode Attack",
    category: "phishing",
    severity: 4,
    mitre: {
      tactic: "TA0001 - Initial Access",
      technique: "T1583.001 - Acquire Infrastructure: Domains",
      sub: "T1036.007 - Masquerading: Double File Extension",
      mitigation: "M1056 - Pre-compromise | M1021 - Restrict Web-Based Content",
      detection: "DS0038 - Domain Name",
      url: "https://attack.mitre.org/techniques/T1583/001/",
    },
    cve: "CWE-451 - User Interface Misrepresentation",
    condition: (e) =>
      e.category === "phishing" &&
      e.rawData?.issues?.some((i) => /homoglyph|lookalike/i.test(i)),
    description: (e) =>
      `Homoglyph attack — lookalike characters detected in: ${getTargetLabel(e)}`,
    dedupWindow: 30 * 60 * 1000,
    compliance: ["NIST SI-3"],
  },

  {
    id: "PHI-007",
    name: "Punycode / IDN Homograph Attack",
    category: "phishing",
    severity: 4,
    mitre: {
      tactic: "TA0001 - Initial Access",
      technique: "T1583.001 - Acquire Infrastructure: Domains",
      sub: "T1036 - Masquerading (Internationalized Domain Name)",
      mitigation: "M1056 - Pre-compromise",
      detection:
        "DS0038 - Domain Name | DS0029 - Network Traffic: Network Traffic Flow",
      url: "https://attack.mitre.org/techniques/T1583/001/",
    },
    cve: "CVE-2021-28879 - IDN Homograph in Browsers",
    condition: (e) =>
      e.category === "phishing" &&
      e.rawData?.issues?.some((i) => /punycode|idn/i.test(i)),
    description: (e) =>
      `Punycode/IDN homograph attack — scanned: ${getTargetLabel(e)}`,
    dedupWindow: 30 * 60 * 1000,
    compliance: ["NIST SI-3"],
  },

  {
    id: "PHI-008",
    name: "Display Text vs Actual Link Mismatch",
    category: "phishing",
    severity: 4,
    mitre: {
      tactic: "TA0001 - Initial Access",
      technique: "T1566.002 - Spearphishing Link",
      sub: "T1036 - Masquerading (Deceptive Anchor Text)",
      mitigation: "M1017 - User Training",
      detection: "DS0015 - Application Log",
      url: "https://attack.mitre.org/techniques/T1566/002/",
    },
    cve: "CWE-451 - UI Misrepresentation of Critical Information",
    condition: (e) =>
      e.category === "phishing" &&
      e.rawData?.issues?.some((i) =>
        /display.*mismatch|mismatch.*display|link.*shows|shows.*links/i.test(i),
      ),
    description: (e) =>
      `Deceptive link in: ${getTargetLabel(e)} — display text differs from actual destination`,
    dedupWindow: 10 * 60 * 1000,
    compliance: ["NIST SI-3"],
  },

  {
    id: "PHI-009",
    name: "Open Redirect Chain",
    category: "phishing",
    severity: 3,
    mitre: {
      tactic: "TA0005 - Defense Evasion",
      technique: "T1027.006 - Obfuscated Files: HTML Smuggling",
      sub: "T1204.001 - User Execution: Malicious Link",
      mitigation: "M1021 - Restrict Web-Based Content | M1017 - User Training",
      detection: "DS0029 - Network Traffic: Network Traffic Content",
      url: "https://attack.mitre.org/techniques/T1027/006/",
    },
    cve: "CWE-601 - URL Redirection to Untrusted Site",
    condition: (e) =>
      e.category === "phishing" &&
      e.rawData?.issues?.some((i) => /redirect/i.test(i)),
    description: (e) =>
      `Open redirect in: ${getTargetLabel(e)} — forwards to hidden malicious destination`,
    dedupWindow: 15 * 60 * 1000,
    compliance: [],
  },

  {
    id: "PHI-010",
    name: "Financial Scam / Advance Fee Fraud",
    category: "phishing",
    severity: 4,
    mitre: { tactic: "TA0040 - Impact", technique: "T1657 - Financial Theft" },
    cve: null,
    condition: (e) =>
      e.category === "phishing" &&
      e.rawData?.issues?.some((i) =>
        /financial lure|wire transfer|gift card|bitcoin/i.test(i),
      ),
    description: (e) =>
      `Financial scam in: ${getTargetLabel(e)} — money lure or wire transfer request`,
    dedupWindow: 10 * 60 * 1000,
    compliance: ["PCI-DSS 12.10"],
  },

  {
    id: "PHI-011",
    name: "Tech Support Scam",
    category: "phishing",
    severity: 4,
    mitre: { tactic: "TA0001 - Initial Access", technique: "T1566 - Phishing" },
    cve: null,
    condition: (e) =>
      e.category === "phishing" &&
      e.rawData?.attackTypes?.includes("tech_support_scam"),
    description: (e) =>
      `Tech support scam in: ${getTargetLabel(e)} — fake support number with threat language`,
    dedupWindow: 15 * 60 * 1000,
    compliance: [],
  },

  {
    id: "PHI-012",
    name: "Email Spoofing — Sender Forgery",
    category: "phishing",
    severity: 4,
    mitre: {
      tactic: "TA0001 - Initial Access",
      technique: "T1566.001 - Spearphishing Attachment",
    },
    cve: null,
    condition: (e) =>
      e.category === "phishing" &&
      e.rawData?.attackTypes?.includes("email_spoofing"),
    description: (e) =>
      `Email spoofing detected — ${getTargetLabel(e)} — sender address is forged`,
    dedupWindow: 10 * 60 * 1000,
    compliance: ["NIST AC-17"],
  },

  {
    id: "PHI-013",
    name: "Malicious Attachment Indicator",
    category: "phishing",
    severity: 4,
    mitre: {
      tactic: "TA0001 - Initial Access",
      technique: "T1566.001 - Spearphishing Attachment",
    },
    cve: null,
    condition: (e) =>
      e.category === "phishing" &&
      e.rawData?.issues?.some((i) => /attachment|macro/i.test(i)),
    description: (e) =>
      `Malicious attachment in: ${getTargetLabel(e)} — macro or suspicious file reference`,
    dedupWindow: 10 * 60 * 1000,
    compliance: ["NIST SI-3"],
  },

  {
    id: "PHI-014",
    name: "IP Address as Domain",
    category: "phishing",
    severity: 4,
    mitre: {
      tactic: "TA0011 - Command and Control",
      technique: "T1071 - Application Layer Protocol",
    },
    cve: null,
    condition: (e) =>
      e.category === "phishing" &&
      e.rawData?.issues?.some((i) => /ip address used/i.test(i)),
    description: (e) =>
      `Raw IP address used as domain — scanned: ${getTargetLabel(e)}`,
    dedupWindow: 5 * 60 * 1000,
    compliance: ["PCI-DSS 1.3"],
  },

  {
    id: "KIT-001",
    name: "Expert-Level Phishing Kit Detected",
    category: "phishing",
    severity: 5,
    mitre: {
      tactic: "TA0006 - Credential Access",
      technique: "T1557 - Adversary-in-the-Middle",
      sub: "T1111 - MFA Interception (Session Token Theft)",
      mitigation:
        "M1041 - Encrypt Sensitive Information | M1035 - Limit Access to Resource",
      detection: "DS0029 - Network Traffic | DS0028 - Logon Session",
      url: "https://attack.mitre.org/techniques/T1557/",
    },
    cve: "CVE-2022-26925 — AiTM session relay",
    condition: (e) =>
      e.category === "phishing" &&
      e.rawData?.kitMatch?.sophistication === "expert",
    description: (e) =>
      `Expert phishing kit identified: ${e.rawData?.kitMatch?.kitName} — ${e.rawData?.kitMatch?.confidence}% confidence`,
    dedupWindow: 15 * 60 * 1000,
    compliance: ["NIST SI-3", "PCI-DSS 6.4"],
  },

  {
    id: "KIT-002",
    name: "High-Sophistication Phishing Kit",
    category: "phishing",
    severity: 4,
    mitre: {
      tactic: "TA0001 - Initial Access",
      technique: "T1566.002 - Spearphishing Link",
    },
    cve: null,
    condition: (e) =>
      e.category === "phishing" &&
      e.rawData?.kitMatch?.sophistication === "high",
    description: (e) =>
      `High-sophistication kit: ${e.rawData?.kitMatch?.kitName}`,
    dedupWindow: 20 * 60 * 1000,
    compliance: ["NIST SI-3"],
  },

  {
    id: "EVA-001",
    name: "Sophisticated Evasion Attempt Detected",
    category: "phishing",
    severity: 4,
    mitre: {
      tactic: "TA0005 - Defense Evasion",
      technique: "T1027.003 - Obfuscated Files: Steganography",
      sub: "T1059.007 - Command and Scripting: JavaScript",
      mitigation:
        "M1049 - Antivirus/Antimalware | M1040 - Behavior Prevention on Endpoint",
      detection: "DS0015 - Application Log | DS0022 - File",
      url: "https://attack.mitre.org/techniques/T1027/",
    },
    cve: "CWE-116 — Improper Encoding or Escaping of Output",
    condition: (e) =>
      e.category === "phishing" &&
      e.rawData?.evasion?.level === "SOPHISTICATED",
    description: (e) =>
      `Sophisticated evasion detected — ${e.rawData?.evasion?.signals} evasion techniques: ${e.rawData?.evasion?.techniques?.join(", ")}`,
    dedupWindow: 10 * 60 * 1000,
    compliance: ["NIST SI-3"],
  },

  {
    id: "EVA-002",
    name: "Evasion Technique Detected — Score Manipulation",
    category: "phishing",
    severity: 3,
    mitre: {
      tactic: "TA0005 - Defense Evasion",
      technique: "T1027 - Obfuscated Files or Information",
    },
    cve: null,
    condition: (e) =>
      e.category === "phishing" &&
      e.rawData?.evasion?.detected === true &&
      e.rawData?.evasion?.level !== "SOPHISTICATED",
    description: (e) =>
      `Evasion technique detected — ${e.rawData?.evasion?.level} level, ${e.rawData?.evasion?.signals} signal(s)`,
    dedupWindow: 15 * 60 * 1000,
    compliance: [],
  },
  {
    id: "CRP-001",
    name: "Corporate Phishing — IT Security Impersonation",
    category: "phishing",
    severity: 4,
    mitre: { tactic: "TA0001 - Initial Access", technique: "T1566 - Phishing" },
    cve: null,
    condition: (e) =>
      e.category === "phishing" &&
      (e.rawData?.attackTypes || []).includes("corporate_phishing"),
    description: () =>
      "Corporate phishing — IT/Security team impersonation with session verification lure",
    dedupWindow: 15 * 60 * 1000,
    compliance: ["NIST AC-17", "PCI-DSS 8.3"],
  },
  {
    id: "CRP-002",
    name: "Conversation Hijacking — Thread Injection Attack",
    category: "phishing",
    severity: 4,
    mitre: {
      tactic: "TA0001 - Initial Access",
      technique: "T1534 - Internal Spearphishing",
    },
    cve: null,
    condition: (e) =>
      e.category === "phishing" &&
      (e.rawData?.attackTypes || []).includes("conversation_hijacking"),
    description: () =>
      "Conversation hijacking — references fake prior interaction to establish trust",
    dedupWindow: 15 * 60 * 1000,
    compliance: ["NIST SI-3"],
  },
  {
    id: "CRP-003",
    name: "Low-and-Slow Phishing — Professional System Notification",
    category: "phishing",
    severity: 3,
    mitre: { tactic: "TA0001 - Initial Access", technique: "T1566 - Phishing" },
    cve: null,
    condition: (e) =>
      e.category === "phishing" &&
      (e.rawData?.attackTypes || []).includes("low_and_slow"),
    description: () =>
      "Low-and-slow phishing — professional notification language avoids urgency detection",
    dedupWindow: 20 * 60 * 1000,
    compliance: [],
  },
  {
    id: "CRP-004",
    name: "Defanged URL in Scanned Input",
    category: "phishing",
    severity: 3,
    mitre: {
      tactic: "TA0005 - Defense Evasion",
      technique: "T1027 - Obfuscated Files or Information",
    },
    cve: null,
    condition: (e) =>
      e.category === "phishing" &&
      (e.rawData?.issues || []).some((i) => /defanged/i.test(i)),
    description: () =>
      "Defanged URL (hxxps:// or [.] notation) — evasion attempt or analyst-submitted sample",
    dedupWindow: 30 * 60 * 1000,
    compliance: [],
  },

  {
    id: "CSV-001",
    name: "CSV Dataset: Confirmed Phishing Match",
    category: "phishing",
    severity: 5,
    mitre: { tactic: "TA0001 - Initial Access", technique: "T1566 - Phishing" },
    cve: null,
    condition: (e) =>
      e.category === "phishing" &&
      (e.rawData?.attackTypes || []).includes("csv_confirmed") &&
      e.rawData?.csvMatch?.label === "phishing" &&
      e.rawData?.csvMatch?.matchLevel === "exact",
    description: (e) =>
      `CSV dataset exact match — confirmed phishing in "${e.rawData?.csvMatch?.source}" ` +
      `(${e.rawData?.csvMatch?.count || 1} report${(e.rawData?.csvMatch?.count || 1) !== 1 ? "s" : ""})`,
    dedupWindow: 15 * 60 * 1000,
    compliance: ["NIST SI-3"],
  },
  {
    id: "SBX-001",
    name: "Sandbox: Credential Harvesting Form Detected",
    category: "phishing",
    severity: 5,
    mitre: {
      tactic: "TA0006 - Credential Access",
      technique: "T1056 - Input Capture",
    },
    cve: null,
    condition: (e) =>
      e.category === "phishing" &&
      e.rawData?.sandbox?.hasCredentialForm === true,
    description: (e) =>
      `Sandbox confirmed credential harvesting form on: ${getTargetLabel(e)}`,
    dedupWindow: 10 * 60 * 1000,
    compliance: ["PCI-DSS 8.3", "NIST AC-7"],
  },

  {
    id: "SBX-002",
    name: "Sandbox: Live Phishing Page with Phishing Kit",
    category: "phishing",
    severity: 5,
    mitre: {
      tactic: "TA0001 - Initial Access",
      technique: "T1566.002 - Spearphishing Link",
    },
    cve: null,
    condition: (e) =>
      e.category === "phishing" &&
      e.rawData?.sandbox?.isLive === true &&
      e.rawData?.sandbox?.hasPhishingKit === true,
    description: () =>
      "Live phishing page with identified phishing kit — immediate takedown recommended",
    dedupWindow: 5 * 60 * 1000,
    compliance: ["NIST SI-3"],
  },

  {
    id: "SBX-003",
    name: "Sandbox: Cross-Domain Redirect Chain",
    category: "phishing",
    severity: 3,
    mitre: {
      tactic: "TA0005 - Defense Evasion",
      technique: "T1027 - Obfuscated Files",
    },
    cve: "CWE-601 — URL Redirection to Untrusted Site",
    condition: (e) =>
      e.category === "phishing" &&
      e.rawData?.sandbox?.crossDomainRedirect === true,
    description: (e) =>
      `Cross-domain redirect chain detected — ${e.rawData?.sandbox?.redirectHops} hops`,
    dedupWindow: 15 * 60 * 1000,
    compliance: [],
  },

  {
    id: "SBX-004",
    name: "Sandbox: Obfuscated JavaScript Detected",
    category: "phishing",
    severity: 4,
    mitre: {
      tactic: "TA0005 - Defense Evasion",
      technique: "T1027 - Obfuscated Files",
    },
    cve: "CWE-116 — Improper Encoding or Escaping",
    condition: (e) =>
      e.category === "phishing" && e.rawData?.sandbox?.hasObfuscation === true,
    description: () =>
      "Obfuscated JavaScript detected on phishing page — advanced kit in use",
    dedupWindow: 10 * 60 * 1000,
    compliance: [],
  },

  {
    id: "SMS-001",
    name: "Smishing — Delivery Scam Detected",
    category: "phishing",
    severity: 4,
    mitre: {
      tactic: "TA0001 - Initial Access",
      technique: "T1660 - Phishing via SMS",
    },
    cve: null,
    condition: (e) =>
      e.category === "phishing" &&
      (e.rawData?.attackTypes || []).includes("delivery_smish"),
    description: () =>
      "Delivery smishing detected — fake carrier notification with fraudulent fee link",
    dedupWindow: 15 * 60 * 1000,
    compliance: [],
  },

  {
    id: "SMS-002",
    name: "Smishing — OTP Interception Attempt",
    category: "phishing",
    severity: 5,
    mitre: {
      tactic: "TA0006 - Credential Access",
      technique: "T1111 - MFA Interception",
    },
    cve: null,
    condition: (e) =>
      e.category === "phishing" &&
      (e.rawData?.attackTypes || []).includes("otp_smish"),
    description: () =>
      "OTP smishing detected — attacker attempting to intercept one-time password via SMS",
    dedupWindow: 5 * 60 * 1000,
    compliance: ["PCI-DSS 8.3", "NIST AC-7"],
  },

  {
    id: "SMS-003",
    name: "Smishing — Government Impersonation",
    category: "phishing",
    severity: 4,
    mitre: {
      tactic: "TA0001 - Initial Access",
      technique: "T1660 - Phishing via SMS",
    },
    cve: null,
    condition: (e) =>
      e.category === "phishing" &&
      (e.rawData?.attackTypes || []).includes("gov_smish"),
    description: () =>
      "Government smishing — impersonates IRS/HMRC/DVLA for credential or payment theft",
    dedupWindow: 15 * 60 * 1000,
    compliance: ["NIST SI-3"],
  },

  // ═══════════════════════════════
  // BRUTE FORCE / RECON RULES
  // ═══════════════════════════════

  {
    id: "BRU-001",
    name: "High-Volume Scan Burst",
    category: "brute_force",
    severity: 3,
    mitre: {
      tactic: "TA0006 - Credential Access",
      technique: "T1110.001 - Brute Force: Password Guessing",
      sub: "T1110.003 - Brute Force: Password Spraying",
      mitigation:
        "M1032 - Multi-factor Authentication | M1036 - Account Use Policies",
      detection:
        "DS0002 - User Account: User Account Authentication | DS0028 - Logon Session",
      url: "https://attack.mitre.org/techniques/T1110/001/",
    },
    cve: null,
    condition: (e) =>
      e.category === "reconnaissance" && e.rawData?.scanCount >= 10,
    description: (e) =>
      `${e.rawData?.scanCount} scans from ${e.source?.ip || "unknown"} in short window`,
    dedupWindow: 5 * 60 * 1000,
    compliance: ["PCI-DSS 8.3"],
  },

  {
    id: "BRU-002",
    name: "Automated Campaign Burst (50+)",
    category: "brute_force",
    severity: 4,
    mitre: {
      tactic: "TA0043 - Reconnaissance",
      technique: "T1595 - Active Scanning",
    },
    cve: null,
    condition: (e) =>
      e.category === "reconnaissance" && e.rawData?.scanCount >= 50,
    description: (e) =>
      `${e.rawData?.scanCount} scans — possible automated phishing campaign`,
    dedupWindow: 2 * 60 * 1000,
    compliance: ["NIST SI-3"],
  },

  // ═══════════════════════════════
  // ANOMALY RULES
  // ═══════════════════════════════

  {
    id: "ANO-001",
    name: "Phishing Rate Spike Above Baseline",
    category: "anomaly",
    severity: 4,
    mitre: { tactic: "TA0001 - Initial Access", technique: "T1566 - Phishing" },
    cve: null,
    condition: (e) =>
      e.category === "anomaly" &&
      (e.subcategory === "phishing_rate_spike" ||
        e.rawData?.metric === "phishing_rate"),
    description: (e) =>
      `Phishing rate ${e.rawData?.value}% — ${e.rawData?.increasePC}% above baseline`,
    dedupWindow: 30 * 60 * 1000,
    compliance: ["NIST SI-3"],
  },

  {
    id: "ANO-002",
    name: "New Malicious Domain Family",
    category: "anomaly",
    severity: 3,
    mitre: {
      tactic: "TA0001 - Initial Access",
      technique: "T1583.001 - Acquire Infrastructure",
    },
    cve: null,
    condition: (e) =>
      e.category === "phishing" && e.rawData?.isNewDomainFamily === true,
    description: (e) => `New malicious domain pattern: ${getTargetLabel(e)}`,
    dedupWindow: 60 * 60 * 1000,
    compliance: [],
  },

  {
    id: "ANO-003",
    name: "Scan Volume Spike",
    category: "anomaly",
    severity: 3,
    mitre: {
      tactic: "TA0043 - Reconnaissance",
      technique: "T1595 - Active Scanning",
    },
    cve: null,
    condition: (e) =>
      e.category === "anomaly" && e.subcategory === "volume_spike",
    description: (e) => `Scan volume ${e.rawData?.increasePC}% above baseline`,
    dedupWindow: 60 * 60 * 1000,
    compliance: [],
  },

  {
    id: "ANO-004",
    name: "Phishing Burst — Critical Threshold",
    category: "anomaly",
    severity: 5,
    mitre: { tactic: "TA0001 - Initial Access", technique: "T1566 - Phishing" },
    cve: null,
    condition: (e) =>
      e.category === "anomaly" && e.subcategory === "phishing_burst",
    description: (e) =>
      `${e.rawData?.value} phishing detections in 1 hour — far exceeds baseline`,
    dedupWindow: 30 * 60 * 1000,
    compliance: ["PCI-DSS 6.4", "NIST SI-3"],
  },

  // ═══════════════════════════════
  // NETWORK RULES
  // ═══════════════════════════════

  {
    id: "NET-001",
    name: "Malicious IP Range Access",
    category: "network",
    severity: 4,
    mitre: {
      tactic: "TA0011 - Command and Control",
      technique: "T1071.004 - Application Layer Protocol: DNS",
      sub: "T1568 - Dynamic Resolution",
      mitigation:
        "M1037 - Filter Network Traffic | M1021 - Restrict Web-Based Content",
      detection: "DS0029 - Network Traffic | DS0038 - Domain Name",
      url: "https://attack.mitre.org/techniques/T1071/004/",
    },
    cve: null,
    condition: (e) =>
      e.category === "network" && e.rawData?.threatType === "malicious_ip",
    description: (e) =>
      `Access to/from malicious IP: ${e.target?.ip || e.source?.ip}`,
    dedupWindow: 5 * 60 * 1000,
    compliance: ["NIST SI-3", "PCI-DSS 1.3"],
  },

  {
    id: "NET-002",
    name: "High-Risk Free TLD Domain",
    category: "network",
    severity: 3,
    mitre: { tactic: "TA0001 - Initial Access", technique: "T1566 - Phishing" },
    cve: null,
    condition: (e) =>
      e.category === "phishing" &&
      e.rawData?.issues?.some((i) => /high-risk free tld/i.test(i)),
    description: (e) =>
      `High-risk free TLD domain accessed: ${getTargetLabel(e)}`,
    dedupWindow: 15 * 60 * 1000,
    compliance: [],
  },

  {
    id: "NET-003",
    name: "URL Shortener Masking Destination",
    category: "network",
    severity: 2,
    mitre: {
      tactic: "TA0005 - Defense Evasion",
      technique: "T1027 - Obfuscated Files",
    },
    cve: "CWE-601 - URL Redirection to Untrusted Site",
    condition: (e) =>
      e.category === "phishing" &&
      e.rawData?.issues?.some((i) => /url shortener/i.test(i)),
    description: () => "URL shortener hides true destination",
    dedupWindow: 15 * 60 * 1000,
    compliance: [],
  },

  {
    id: "NET-004",
    name: "Data URI Phishing Page",
    category: "network",
    severity: 5,
    mitre: {
      tactic: "TA0001 - Initial Access",
      technique: "T1566.002 - Spearphishing Link",
    },
    cve: null,
    condition: (e) =>
      e.category === "phishing" &&
      e.rawData?.issues?.some((i) => /data uri/i.test(i)),
    description: () =>
      "Data URI scheme — phishing page delivered inline without server",
    dedupWindow: 5 * 60 * 1000,
    compliance: ["NIST SI-3"],
  },

  // ═══════════════════════════════
  // EXECUTION RULES (TA0002)
  // ═══════════════════════════════

  {
    id: "EXE-001",
    name: "Malicious Macro Execution Attempt",
    category: "execution",
    severity: 5,
    mitre: {
      tactic: "TA0002 - Execution",
      technique: "T1059.005 - Command and Scripting Interpreter: VBA",
      sub: "T1204.002 - User Execution: Malicious File",
      mitigation:
        "M1049 - Antivirus/Antimalware | M1040 - Behavior Prevention on Endpoint",
      detection: "DS0022 - File | DS0009 - Process",
      url: "https://attack.mitre.org/techniques/T1059/005/",
    },
    description: (e) =>
      `Macro-enabled document attachment detected in: ${getTargetLabel(e)} — VBA/XLM macro execution vector`,
    condition: (e) =>
      e.attackTypes?.includes("malicious_attachment") &&
      e.result?.attachmentFindings?.some(
        (f) => f.category === "macro" && f.severity === "critical",
      ),
    score: 85,
    dedupWindow: 10 * 60 * 1000,
    compliance: ["NIST SI-3"],
  },

  {
    id: "EXE-002",
    name: "PowerShell Obfuscated Execution",
    category: "execution",
    severity: 5,
    mitre: {
      tactic: "TA0002 - Execution",
      technique: "T1059.001 - Command and Scripting Interpreter: PowerShell",
      sub: "T1027.010 - Obfuscated Files: Command Obfuscation",
      mitigation: "M1049 - Antivirus/Antimalware | M1045 - Code Signing",
      detection: "DS0009 - Process | DS0017 - Command",
      url: "https://attack.mitre.org/techniques/T1059/001/",
    },
    description: (e) =>
      `Obfuscated PowerShell detected on ${e.source?.host || "endpoint"} — ` +
      `encoded command or IEX download cradle pattern`,
    condition: (e) =>
      e.logType === "powershell_execution" &&
      e.attackTypes?.includes("obfuscated_powershell"),
    score: 90,
    dedupWindow: 5 * 60 * 1000,
    compliance: ["NIST SI-3", "PCI-DSS 6.4"],
  },

  {
    id: "EXE-003",
    name: "HTML Smuggling Payload Delivery",
    category: "execution",
    severity: 4,
    mitre: {
      tactic: "TA0002 - Execution",
      technique: "T1027.006 - Obfuscated Files: HTML Smuggling",
      sub: "T1204.002 - User Execution: Malicious File",
      mitigation:
        "M1049 - Antivirus/Antimalware | M1021 - Restrict Web-Based Content",
      detection: "DS0022 - File | DS0015 - Application Log",
      url: "https://attack.mitre.org/techniques/T1027/006/",
    },
    description: (e) =>
      `HTML smuggling detected in attachment from: ${getTargetLabel(e)} — ` +
      `Base64-encoded payload delivered via HTML file to bypass email gateway`,
    condition: (e) =>
      e.result?.attachmentFindings?.some((f) => f.category === "obfuscation") &&
      e.result?.extension === "html",
    score: 75,
    dedupWindow: 10 * 60 * 1000,
    compliance: ["NIST SI-3"],
  },

  // ═══════════════════════════════
  // PERSISTENCE RULES (TA0003)
  // ═══════════════════════════════

  {
    id: "PER-001",
    name: "MFA Device Registration Abuse",
    category: "persistence",
    severity: 5,
    mitre: {
      tactic: "TA0003 - Persistence",
      technique: "T1556.006 - Modify Authentication Process: MFA",
      sub: "T1098.005 - Account Manipulation: Device Registration",
      mitigation:
        "M1032 - Multi-factor Authentication | M1026 - Privileged Account Management",
      detection: "DS0002 - User Account | DS0028 - Logon Session",
      url: "https://attack.mitre.org/techniques/T1098/005/",
    },
    description: (e) =>
      `MFA QR phishing detected — attacker attempting to register their own device: ${getTargetLabel(e)}`,
    condition: (e) =>
      e.attackTypes?.includes("quishing") &&
      /mfa|2fa|authenticator|device.*register/i.test(e.result?.rawText || ""),
    score: 90,
    dedupWindow: 5 * 60 * 1000,
    compliance: ["PCI-DSS 8.3", "NIST AC-7"],
  },

  {
    id: "PER-002",
    name: "Email Forwarding Rule Establishment",
    category: "persistence",
    severity: 4,
    mitre: {
      tactic: "TA0003 - Persistence",
      technique: "T1114.003 - Email Collection: Email Forwarding Rule",
      sub: "T1564.008 - Hide Artifacts: Email Hiding Rules",
      mitigation: "M1047 - Audit | M1032 - Multi-factor Authentication",
      detection: "DS0015 - Application Log | DS0002 - User Account",
      url: "https://attack.mitre.org/techniques/T1114/003/",
    },
    description: (e) =>
      `Credential harvest via email — successful compromise may enable attacker to set forwarding rules: ${getTargetLabel(e)}`,
    condition: (e) =>
      e.riskScore >= 80 &&
      e.attackTypes?.includes("credential_harvest") &&
      e.result?.inputType === "email",
    score: 70,
    dedupWindow: 10 * 60 * 1000,
    compliance: ["NIST AC-17", "GDPR Art.32"],
  },

  // ═══════════════════════════════
  // DISCOVERY RULES (TA0007)
  // ═══════════════════════════════

  {
    id: "DIS-001",
    name: "Victim Network Intelligence Gathering",
    category: "discovery",
    severity: 3,
    mitre: {
      tactic: "TA0007 - Discovery",
      technique: "T1590 - Gather Victim Network Information",
      sub: "T1590.001 - Gather Victim Network Information: Domain Properties",
      mitigation: "M1056 - Pre-compromise",
      detection: "DS0038 - Domain Name | DS0029 - Network Traffic",
      url: "https://attack.mitre.org/techniques/T1590/",
    },
    description: (e) =>
      `Reconnaissance: combo-squatted domain targets ${getTargetLabel(e)} — ` +
      `attacker mapped victim network before domain registration`,
    condition: (e) =>
      e.attackTypes?.includes("brand_impersonation") &&
      e.result?.domainAnalysis?.signals?.length >= 2,
    score: 50,
    dedupWindow: 30 * 60 * 1000,
    compliance: [],
  },

  {
    id: "DIS-002",
    name: "Phishing Kit Fingerprint — Infrastructure Mapping",
    category: "discovery",
    severity: 4,
    mitre: {
      tactic: "TA0007 - Discovery",
      technique: "T1592 - Gather Victim Host Information",
      sub: "T1589 - Gather Victim Identity Information",
      mitigation: "M1056 - Pre-compromise | M1054 - Software Configuration",
      detection: "DS0015 - Application Log | DS0029 - Network Traffic",
      url: "https://attack.mitre.org/techniques/T1592/",
    },
    description: (e) =>
      `Phishing kit detected with victim pre-targeting — scanned: ${getTargetLabel(e)}. ` +
      `Kit encodes victim email in URL parameter (identity pre-loaded)`,
    condition: (e) =>
      e.attackTypes?.includes("aitm") &&
      e.result?.urlPreview?.technologies?.hasAiTMSignal,
    score: 80,
    dedupWindow: 10 * 60 * 1000,
    compliance: ["NIST SI-3"],
  },

  // ═══════════════════════════════
  // COLLECTION RULES (TA0009)
  // ═══════════════════════════════

  {
    id: "COL-001",
    name: "Credential Form Collection",
    category: "collection",
    severity: 5,
    mitre: {
      tactic: "TA0009 - Collection",
      technique: "T1056.003 - Input Capture: Web Portal Capture",
      sub: "T1185 - Browser Session Hijacking",
      mitigation: "M1032 - Multi-factor Authentication | M1017 - User Training",
      detection: "DS0009 - Process | DS0022 - File | DS0029 - Network Traffic",
      url: "https://attack.mitre.org/techniques/T1056/003/",
    },
    description: (e) =>
      `Credential harvesting form detected on: ${getTargetLabel(e)} — ` +
      `page contains password input that POSTs to external domain`,
    condition: (e) =>
      e.result?.urlPreview?.forms?.hasCredentialForm &&
      e.result?.urlPreview?.forms?.hasExternalAction,
    score: 90,
    dedupWindow: 5 * 60 * 1000,
    compliance: ["PCI-DSS 8.3", "NIST AC-7"],
  },

  {
    id: "COL-002",
    name: "Email Data Collection via Phishing",
    category: "collection",
    severity: 4,
    mitre: {
      tactic: "TA0009 - Collection",
      technique: "T1114 - Email Collection",
      sub: "T1530 - Data from Cloud Storage",
      mitigation: "M1032 - Multi-factor Authentication | M1047 - Audit",
      detection: "DS0015 - Application Log | DS0002 - User Account",
      url: "https://attack.mitre.org/techniques/T1114/",
    },
    description: (e) =>
      `Email phishing collection attempt targeting account credentials: ${getTargetLabel(e)}`,
    condition: (e) =>
      e.result?.inputType === "email" &&
      e.riskScore >= 70 &&
      e.attackTypes?.some((a) =>
        ["credential_harvest", "otp_harvest", "brand_impersonation"].includes(
          a,
        ),
      ),
    score: 72,
    dedupWindow: 10 * 60 * 1000,
    compliance: ["GDPR Art.32", "NIST AC-17"],
  },

  {
    id: "COL-003",
    name: "Telegram/Discord Webhook Exfiltration Channel",
    category: "collection",
    severity: 5,
    mitre: {
      tactic: "TA0009 - Collection",
      technique: "T1041 - Exfiltration Over C2 Channel",
      sub: "T1071.001 - Application Layer Protocol: Web Protocols",
      mitigation:
        "M1057 - Data Loss Prevention | M1037 - Filter Network Traffic",
      detection: "DS0029 - Network Traffic | DS0015 - Application Log",
      url: "https://attack.mitre.org/techniques/T1041/",
    },
    description: (e) =>
      `Credential exfiltration channel detected on: ${getTargetLabel(e)} — ` +
      `Telegram bot API or Discord webhook found in page source`,
    condition: (e) =>
      e.result?.urlPreview?.technologies?.detected?.some(
        (t) =>
          t.name?.includes("Telegram Bot Exfil") ||
          t.name?.includes("Discord Webhook Exfil"),
      ),
    score: 95,
    dedupWindow: 5 * 60 * 1000,
    compliance: ["NIST SI-3", "PCI-DSS 6.4"],
  },

  // ═══════════════════════════════
  // EXFILTRATION RULES (TA0010)
  // ═══════════════════════════════

  {
    id: "EXF-001",
    name: "USB Data Exfiltration Risk",
    category: "exfiltration",
    severity: 4,
    mitre: {
      tactic: "TA0010 - Exfiltration",
      technique: "T1052.001 - Exfiltration Over Physical Medium: USB",
      sub: "T1025 - Data from Removable Media",
      mitigation:
        "M1057 - Data Loss Prevention | M1034 - Limit Hardware Installation",
      detection: "DS0016 - Drive | DS0022 - File",
      url: "https://attack.mitre.org/techniques/T1052/001/",
    },
    description: (e) =>
      `Unregistered USB storage device connected on ${e.source?.host || "endpoint"} — ` +
      `potential data exfiltration or malware delivery vector`,
    condition: (e) =>
      e.logType === "usb_activity" &&
      e.attackTypes?.includes("unregistered_usb_device"),
    score: 65,
    dedupWindow: 15 * 60 * 1000,
    compliance: ["PCI-DSS 12.10", "NIST MP-7"],
  },

  {
    id: "EXF-002",
    name: "Polyglot/Disk Image Payload Delivery",
    category: "exfiltration",
    severity: 5,
    mitre: {
      tactic: "TA0010 - Exfiltration",
      technique: "T1553.005 - Subvert Trust Controls: Mark-of-the-Web Bypass",
      sub: "T1027.009 - Obfuscated Files: Embedded Payloads",
      mitigation:
        "M1049 - Antivirus/Antimalware | M1038 - Execution Prevention",
      detection: "DS0022 - File | DS0009 - Process",
      url: "https://attack.mitre.org/techniques/T1553/005/",
    },
    description: (e) =>
      `MOTW bypass via disk image — ${getTargetLabel(e)} uses ISO/IMG/VHD to deliver ` +
      `payload without Zone.Identifier warning (no MOTW flag on contained files)`,
    condition: (e) =>
      e.result?.attachmentFindings?.some(
        (f) => f.detail?.includes("MOTW") || f.detail?.includes("disk image"),
      ),
    score: 88,
    dedupWindow: 10 * 60 * 1000,
    compliance: ["NIST SI-3"],
  },

  // ═══════════════════════════════
  // LATERAL MOVEMENT RULES (TA0008)
  // ═══════════════════════════════

  {
    id: "LAT-001",
    name: "Internal Spearphishing — Thread Hijack",
    category: "lateral_movement",
    severity: 4,
    mitre: {
      tactic: "TA0008 - Lateral Movement",
      technique: "T1534 - Internal Spearphishing",
      sub: "T1566.001 - Spearphishing Attachment (Internal)",
      mitigation: "M1049 - Antivirus/Antimalware | M1017 - User Training",
      detection: "DS0015 - Application Log | DS0002 - User Account",
      url: "https://attack.mitre.org/techniques/T1534/",
    },
    description: (e) =>
      `Conversation hijacking pattern — ${getTargetLabel(e)} references prior thread ` +
      `without verifiable context (thread injection technique for lateral phishing)`,
    condition: (e) =>
      e.attackTypes?.includes("conversation_hijacking") && e.riskScore >= 60,
    score: 72,
    dedupWindow: 15 * 60 * 1000,
    compliance: ["NIST SI-3", "NIST AC-17"],
  },

  {
    id: "LAT-002",
    name: "BEC — Account Takeover Pivot",
    category: "lateral_movement",
    severity: 5,
    mitre: {
      tactic: "TA0008 - Lateral Movement",
      technique: "T1078 - Valid Accounts",
      sub: "T1534 - Internal Spearphishing (Post-Compromise)",
      mitigation:
        "M1032 - Multi-factor Authentication | M1026 - Privileged Account Management",
      detection: "DS0028 - Logon Session | DS0002 - User Account",
      url: "https://attack.mitre.org/techniques/T1078/",
    },
    description: (e) =>
      `BEC lateral movement risk — ${getTargetLabel(e)} targets financial approval chain ` +
      `with bypass-controls instruction (post-compromise pivot pattern)`,
    condition: (e) =>
      e.attackTypes?.includes("bec") &&
      e.riskScore >= 75 &&
      /bypass|confidential|do not.*discuss|wire/i.test(e.result?.rawText || ""),
    score: 90,
    dedupWindow: 5 * 60 * 1000,
    compliance: ["PCI-DSS 12.10", "NIST AC-17"],
  },

  // ═══════════════════════════════
  // BEC — Business Email Compromise
  // ═══════════════════════════════
  {
    id: "BEC-001",
    name: "BEC — CEO / Executive Fraud Wire Transfer",
    category: "bec",
    severity: 5,
    mitre: { tactic: "TA0008 - Lateral Movement", technique: "T1534 - Internal Spearphishing", sub: "T1078 - Valid Accounts (BEC Impersonation)" },
    cve: null,
    condition: (e) => e.category === "phishing" && e.rawData?.attackTypes?.includes("bec") && e.rawData?.issues?.some((i) => /wire|transfer|urgent|ceo|executive/i.test(i)),
    description: (e) => `BEC wire transfer fraud — executive impersonation targeting: ${getTargetLabel(e)}`,
    dedupWindow: 5 * 60 * 1000,
    compliance: ["PCI-DSS 6.4", "NIST SP 800-61", "ISO 27001 A.12.6"],
  },
  {
    id: "BEC-002",
    name: "BEC — Gift Card / Prepaid Card Request",
    category: "bec",
    severity: 4,
    mitre: { tactic: "TA0001 - Initial Access", technique: "T1566 - Phishing", sub: "T1534 - Internal Spearphishing" },
    cve: null,
    condition: (e) => e.category === "phishing" && e.rawData?.attackTypes?.includes("bec") && e.rawData?.issues?.some((i) => /gift.?card|prepaid|itunes|amazon.gift|google.play/i.test(i)),
    description: (e) => `BEC gift card scam — attacker requesting prepaid cards: ${getTargetLabel(e)}`,
    dedupWindow: 10 * 60 * 1000,
    compliance: ["FTC BEC Advisory"],
  },
  {
    id: "BEC-003",
    name: "BEC — Payroll / HR Direct Deposit Redirect",
    category: "bec",
    severity: 5,
    mitre: { tactic: "TA0009 - Collection", technique: "T1114 - Email Collection", sub: "T1098.005 - Account Manipulation" },
    cve: null,
    condition: (e) => e.category === "phishing" && e.rawData?.attackTypes?.includes("bec") && e.rawData?.issues?.some((i) => /payroll|direct.deposit|bank.account|routing/i.test(i)),
    description: (e) => `BEC payroll redirect — attacker attempting to hijack direct deposit: ${getTargetLabel(e)}`,
    dedupWindow: 5 * 60 * 1000,
    compliance: ["PCI-DSS 8.3", "NIST AC-7", "SOX"],
  },
  {
    id: "BEC-004",
    name: "BEC — Vendor / Supplier Invoice Fraud",
    category: "bec",
    severity: 4,
    mitre: { tactic: "TA0001 - Initial Access", technique: "T1566 - Phishing" },
    cve: null,
    condition: (e) => e.category === "phishing" && e.rawData?.issues?.some((i) => /invoice|vendor|supplier|payment.due|outstanding.balance/i.test(i)) && e.riskScore >= 50,
    description: (e) => `BEC vendor invoice fraud — fake invoice targeting AP department: ${getTargetLabel(e)}`,
    dedupWindow: 15 * 60 * 1000,
    compliance: ["PCI-DSS 6.4"],
  },
  {
    id: "BEC-005",
    name: "BEC — Confidentiality / Bypass Normal Process",
    category: "bec",
    severity: 5,
    mitre: { tactic: "TA0008 - Lateral Movement", technique: "T1534 - Internal Spearphishing" },
    cve: null,
    condition: (e) => e.category === "phishing" && e.rawData?.issues?.some((i) => /bypass.*approval|confidential.*do not|do not.*discuss|keep.*secret|skip.*normal.*process/i.test(i)),
    description: (e) => `BEC control bypass — request instructs recipient to skip approval chain: ${getTargetLabel(e)}`,
    dedupWindow: 5 * 60 * 1000,
    compliance: ["NIST SP 800-61", "ISO 27001 A.6.1"],
  },
  {
    id: "BEC-006",
    name: "BEC — Lawyer / Legal Department Impersonation",
    category: "bec",
    severity: 4,
    mitre: { tactic: "TA0001 - Initial Access", technique: "T1566 - Phishing" },
    cve: null,
    condition: (e) => e.category === "phishing" && e.rawData?.issues?.some((i) => /attorney|lawyer|legal.counsel|law.firm|litigation|settlement/i.test(i)) && e.riskScore >= 45,
    description: (e) => `BEC legal impersonation — fake attorney/law firm creating urgency: ${getTargetLabel(e)}`,
    dedupWindow: 15 * 60 * 1000,
    compliance: ["GDPR Art.32"],
  },

  // ═══════════════════════════════
  // QSH — QR Code Phishing / Quishing
  // ═══════════════════════════════
  {
    id: "QSH-001",
    name: "Quishing — QR Code Phishing Detected",
    category: "quishing",
    severity: 4,
    mitre: { tactic: "TA0001 - Initial Access", technique: "T1566 - Phishing", sub: "T1204.001 - User Execution: Malicious Link" },
    cve: null,
    condition: (e) => e.category === "phishing" && e.rawData?.attackTypes?.includes("quishing"),
    description: (e) => `QR code phishing (quishing) — QR used to bypass email security filters: ${getTargetLabel(e)}`,
    dedupWindow: 10 * 60 * 1000,
    compliance: ["NIST SP 800-61"],
  },
  {
    id: "QSH-002",
    name: "Quishing — MFA QR Registration Abuse",
    category: "quishing",
    severity: 5,
    mitre: { tactic: "TA0003 - Persistence", technique: "T1556.006 - Modify Authentication Process: MFA", sub: "T1098.005 - Device Registration" },
    cve: null,
    condition: (e) => e.category === "phishing" && e.rawData?.attackTypes?.includes("quishing") && e.rawData?.issues?.some((i) => /mfa|2fa|authenticator|register.*device/i.test(i)),
    description: (e) => `Quishing MFA abuse — QR attempts to register attacker's device for persistent access: ${getTargetLabel(e)}`,
    dedupWindow: 5 * 60 * 1000,
    compliance: ["NIST SP 800-63B", "PCI-DSS 8.3"],
  },
  {
    id: "QSH-003",
    name: "Quishing — QR Code from Decoded Image Scan",
    category: "quishing",
    severity: 4,
    mitre: { tactic: "TA0001 - Initial Access", technique: "T1566.002 - Spearphishing Link" },
    cve: null,
    condition: (e) => e.category === "phishing" && e.rawData?.inputSource === "qr_decode",
    description: (e) => `QR image decoded — malicious URL extracted from QR code: ${getTargetLabel(e)}`,
    dedupWindow: 10 * 60 * 1000,
    compliance: ["NIST SP 800-61"],
  },
  {
    id: "QSH-004",
    name: "Quishing — Parking / Payment QR Scam",
    category: "quishing",
    severity: 3,
    mitre: { tactic: "TA0001 - Initial Access", technique: "T1566 - Phishing" },
    cve: null,
    condition: (e) => e.category === "phishing" && e.rawData?.attackTypes?.includes("quishing") && e.rawData?.issues?.some((i) => /parking|meter|restaurant|pay.*fee/i.test(i)),
    description: (e) => `Quishing payment scam — fake QR overlay on physical payment terminal: ${getTargetLabel(e)}`,
    dedupWindow: 30 * 60 * 1000,
    compliance: ["PCI-DSS 6.4"],
  },

  // ═══════════════════════════════
  // ATO — Account Takeover
  // ═══════════════════════════════
  {
    id: "ATO-001",
    name: "Account Takeover — Credential Stuffing Precursor",
    category: "account_takeover",
    severity: 4,
    mitre: { tactic: "TA0006 - Credential Access", technique: "T1110.004 - Brute Force: Credential Stuffing" },
    cve: null,
    condition: (e) => e.category === "phishing" && e.rawData?.issues?.some((i) => /credential.*harvest|password.*steal|login.*phish/i.test(i)) && e.riskScore >= 65,
    description: (e) => `Account takeover precursor — credential harvesting for stuffing attack: ${getTargetLabel(e)}`,
    dedupWindow: 5 * 60 * 1000,
    compliance: ["NIST SP 800-63B", "PCI-DSS 8.3"],
  },
  {
    id: "ATO-002",
    name: "Account Takeover — Social Media Credential Harvest",
    category: "account_takeover",
    severity: 3,
    mitre: { tactic: "TA0006 - Credential Access", technique: "T1056.003 - Web Portal Capture" },
    cve: null,
    condition: (e) => e.category === "phishing" && e.rawData?.issues?.some((i) => /instagram|facebook|twitter|tiktok|snapchat|discord/i.test(i)) && e.rawData?.issues?.some((i) => /login|credential|password|verify|account/i.test(i)),
    description: (e) => `Social media ATO — credential harvest targeting social platform: ${getTargetLabel(e)}`,
    dedupWindow: 15 * 60 * 1000,
    compliance: ["GDPR Art.32"],
  },
  {
    id: "ATO-003",
    name: "Account Takeover — AiTM Session Token Theft",
    category: "account_takeover",
    severity: 5,
    mitre: { tactic: "TA0006 - Credential Access", technique: "T1557 - Adversary-in-the-Middle", sub: "T1111 - MFA Interception" },
    cve: null,
    condition: (e) => e.category === "phishing" && e.rawData?.attackTypes?.includes("aitm"),
    description: (e) => `AiTM session token theft — real-time MFA bypass via reverse proxy: ${getTargetLabel(e)}`,
    dedupWindow: 2 * 60 * 1000,
    compliance: ["NIST SP 800-63B", "PCI-DSS 8.3", "ISO 27001 A.9"],
  },
  {
    id: "ATO-004",
    name: "Account Takeover — Password Reset Phishing",
    category: "account_takeover",
    severity: 4,
    mitre: { tactic: "TA0006 - Credential Access", technique: "T1078 - Valid Accounts" },
    cve: null,
    condition: (e) => e.category === "phishing" && e.rawData?.issues?.some((i) => /password.*reset|reset.*password|forgot.*password|account.*recovery/i.test(i)),
    description: (e) => `Password reset phishing — fake reset link for account takeover: ${getTargetLabel(e)}`,
    dedupWindow: 10 * 60 * 1000,
    compliance: ["NIST SP 800-63B"],
  },

  // ═══════════════════════════════
  // SOC — Social Engineering
  // ═══════════════════════════════
  {
    id: "SOC-001",
    name: "Social Engineering — Romance / Dating Scam",
    category: "social_engineering",
    severity: 3,
    mitre: { tactic: "TA0001 - Initial Access", technique: "T1566 - Phishing" },
    cve: null,
    condition: (e) => e.category === "phishing" && e.rawData?.attackTypes?.includes("romance_scam"),
    description: (e) => `Romance scam detected — long-con social engineering for financial fraud: ${getTargetLabel(e)}`,
    dedupWindow: 30 * 60 * 1000,
    compliance: ["FTC Consumer Alert"],
  },
  {
    id: "SOC-002",
    name: "Social Engineering — Prize / Lottery Scam",
    category: "social_engineering",
    severity: 3,
    mitre: { tactic: "TA0001 - Initial Access", technique: "T1566 - Phishing" },
    cve: null,
    condition: (e) => e.category === "phishing" && e.rawData?.issues?.some((i) => /prize|lottery|winner|won|reward|claim.*now|selected.*recipient/i.test(i)),
    description: (e) => `Prize/lottery scam — fake winnings used as social engineering lure: ${getTargetLabel(e)}`,
    dedupWindow: 30 * 60 * 1000,
    compliance: ["FTC 16 CFR Part 251"],
  },
  {
    id: "SOC-003",
    name: "Social Engineering — Pig Butchering Investment Scam",
    category: "social_engineering",
    severity: 4,
    mitre: { tactic: "TA0001 - Initial Access", technique: "T1566 - Phishing", sub: "T1598 - Gather Victim Organization Information" },
    cve: null,
    condition: (e) => e.category === "phishing" && e.rawData?.issues?.some((i) => /invest|trading.*platform|crypto.*profit|guaranteed.*return|withdraw.*profit/i.test(i)) && e.riskScore >= 50,
    description: (e) => `Pig butchering investment scam — fake trading platform for long-con fraud: ${getTargetLabel(e)}`,
    dedupWindow: 15 * 60 * 1000,
    compliance: ["FBI IC3 Advisory", "FTC"],
  },
  {
    id: "SOC-004",
    name: "Social Engineering — Authority Impersonation",
    category: "social_engineering",
    severity: 4,
    mitre: { tactic: "TA0001 - Initial Access", technique: "T1566 - Phishing" },
    cve: null,
    condition: (e) => e.category === "phishing" && e.rawData?.issues?.some((i) => /irs|fbi|police|court.*order|law.enforcement|government.*notice|arrest.*warrant/i.test(i)),
    description: (e) => `Authority impersonation — fake law enforcement / government threat: ${getTargetLabel(e)}`,
    dedupWindow: 15 * 60 * 1000,
    compliance: ["NIST SP 800-61"],
  },
  {
    id: "SOC-005",
    name: "Social Engineering — Urgency + Threat Combination",
    category: "social_engineering",
    severity: 3,
    mitre: { tactic: "TA0001 - Initial Access", technique: "T1566 - Phishing" },
    cve: null,
    condition: (e) => e.category === "phishing" && e.rawData?.issues?.some((i) => /within.*(hour|minute)|expire.*today|immediate.*action|account.*suspend/i.test(i)) && e.rawData?.issues?.some((i) => /threat|suspend|block|arrest|penalty|fine/i.test(i)) && e.riskScore >= 40,
    description: (e) => `Urgency + threat combination — dual-pressure social engineering tactic: ${getTargetLabel(e)}`,
    dedupWindow: 20 * 60 * 1000,
    compliance: ["NIST SP 800-61"],
  },

  // ═══════════════════════════════
  // INF — Infrastructure / Domain
  // ═══════════════════════════════
  {
    id: "INF-001",
    name: "Infrastructure — Combo-Squatting Domain",
    category: "infrastructure",
    severity: 4,
    mitre: { tactic: "TA0001 - Initial Access", technique: "T1583.001 - Acquire Infrastructure: Domains" },
    cve: null,
    condition: (e) => e.category === "phishing" && e.rawData?.attackTypes?.includes("brand_impersonation") && e.rawData?.issues?.some((i) => /combo.squat|brand.*action.word|security.*keyword.*domain/i.test(i)),
    description: (e) => `Combo-squatting — brand name combined with action keyword in domain: ${getTargetLabel(e)}`,
    dedupWindow: 30 * 60 * 1000,
    compliance: ["NIST SP 800-61"],
  },
  {
    id: "INF-002",
    name: "Infrastructure — Newly Registered Phishing Domain",
    category: "infrastructure",
    severity: 4,
    mitre: { tactic: "TA0001 - Initial Access", technique: "T1583.001 - Acquire Infrastructure: Domains" },
    cve: null,
    condition: (e) => e.category === "phishing" && e.rawData?.issues?.some((i) => /newly.registered|registration.*length|domain.*age/i.test(i)) && e.riskScore >= 45,
    description: (e) => `Newly registered domain — phishing infrastructure created recently: ${getTargetLabel(e)}`,
    dedupWindow: 30 * 60 * 1000,
    compliance: ["NIST SP 800-61"],
  },
  {
    id: "INF-003",
    name: "Infrastructure — TLS Certificate Anomaly",
    category: "infrastructure",
    severity: 3,
    mitre: { tactic: "TA0005 - Defense Evasion", technique: "T1553.004 - Subvert Trust Controls: Install Root Certificate" },
    cve: null,
    condition: (e) => e.category === "phishing" && e.rawData?.urlPreview?.tlsCertificate?.signals?.length > 0,
    description: (e) => `TLS anomaly — certificate signals indicate phishing infrastructure: ${getTargetLabel(e)}. Issues: ${e.rawData?.urlPreview?.tlsCertificate?.signals?.slice(0,2).join("; ")}`,
    dedupWindow: 30 * 60 * 1000,
    compliance: ["NIST SP 800-52"],
  },
  {
    id: "INF-004",
    name: "Infrastructure — High-Abuse Country Hosting",
    category: "infrastructure",
    severity: 3,
    mitre: { tactic: "TA0001 - Initial Access", technique: "T1583.003 - Acquire Infrastructure: Virtual Private Server" },
    cve: null,
    condition: (e) => e.category === "phishing" && e.rawData?.urlPreview?.ipGeolocation?.isHighAbuseRegion === true && e.riskScore >= 40,
    description: (e) => `High-abuse region hosting — phishing site hosted in elevated-risk geography: ${e.rawData?.urlPreview?.ipGeolocation?.country || "unknown"} | Target: ${getTargetLabel(e)}`,
    dedupWindow: 30 * 60 * 1000,
    compliance: ["NIST SP 800-61"],
  },
  {
    id: "INF-005",
    name: "Infrastructure — Stacked Security Keywords in URL Path",
    category: "infrastructure",
    severity: 3,
    mitre: { tactic: "TA0001 - Initial Access", technique: "T1583.001 - Acquire Infrastructure: Domains" },
    cve: null,
    condition: (e) => e.category === "phishing" && e.rawData?.issues?.some((i) => /stacked.security.keyword|repeated.*path.*keyword/i.test(i)),
    description: (e) => `Stacked security keywords in URL path — credential harvesting path pattern: ${getTargetLabel(e)}`,
    dedupWindow: 20 * 60 * 1000,
    compliance: [],
  },

  // ═══════════════════════════════
  // ATT — Attachment Threats
  // ═══════════════════════════════
  {
    id: "ATT-001",
    name: "Attachment — PE Executable Disguised as Document",
    category: "attachment",
    severity: 5,
    mitre: { tactic: "TA0002 - Execution", technique: "T1204.002 - User Execution: Malicious File", sub: "T1036.007 - Masquerading: Double File Extension" },
    cve: null,
    condition: (e) => e.category === "phishing" && e.rawData?.attachmentResult?.findings?.some((f) => f.detail?.includes("PE executable") || f.detail?.includes("MZ header")),
    description: (e) => `Executable disguised as document — Windows PE binary with false extension: ${getTargetLabel(e)}`,
    dedupWindow: 5 * 60 * 1000,
    compliance: ["NIST SP 800-83", "ISO 27001 A.12.2"],
  },
  {
    id: "ATT-002",
    name: "Attachment — Password-Protected Archive Evasion",
    category: "attachment",
    severity: 4,
    mitre: { tactic: "TA0005 - Defense Evasion", technique: "T1027 - Obfuscated Files or Information" },
    cve: null,
    condition: (e) => e.category === "phishing" && e.rawData?.attachmentResult?.findings?.some((f) => f.detail?.includes("Password-protected")),
    description: (e) => `Encrypted archive — password protection prevents AV sandbox inspection: ${getTargetLabel(e)}`,
    dedupWindow: 10 * 60 * 1000,
    compliance: ["ISO 27001 A.12.2"],
  },
  {
    id: "ATT-003",
    name: "Attachment — OneNote Embedded Payload",
    category: "attachment",
    severity: 5,
    mitre: { tactic: "TA0002 - Execution", technique: "T1204.002 - User Execution: Malicious File" },
    cve: null,
    condition: (e) => e.category === "phishing" && e.rawData?.attachmentResult?.findings?.some((f) => f.detail?.includes("OneNote")),
    description: (e) => `OneNote (.one) malicious attachment — embedded executable payload: ${getTargetLabel(e)}`,
    dedupWindow: 5 * 60 * 1000,
    compliance: ["NIST SP 800-83", "CISA Advisory AA23-040A"],
  },
  {
    id: "ATT-004",
    name: "Attachment — MOTW Bypass via Disk Image",
    category: "attachment",
    severity: 5,
    mitre: { tactic: "TA0005 - Defense Evasion", technique: "T1553.005 - Subvert Trust Controls: Mark-of-the-Web Bypass" },
    cve: null,
    condition: (e) => e.category === "phishing" && e.rawData?.attachmentResult?.findings?.some((f) => f.detail?.includes("MOTW") || f.detail?.includes("disk image")),
    description: (e) => `MOTW bypass — disk image delivery evades Windows zone identifier warnings: ${getTargetLabel(e)}`,
    dedupWindow: 5 * 60 * 1000,
    compliance: ["NIST SP 800-83", "Microsoft Security Advisory"],
  },
  {
    id: "ATT-005",
    name: "Attachment — Polyglot File Detected",
    category: "attachment",
    severity: 5,
    mitre: { tactic: "TA0005 - Defense Evasion", technique: "T1027.009 - Obfuscated Files: Embedded Payloads" },
    cve: null,
    condition: (e) => e.category === "phishing" && e.rawData?.attachmentResult?.findings?.some((f) => f.detail?.includes("Polyglot")),
    description: (e) => `Polyglot file — valid in two formats simultaneously (PDF+ZIP/JAR). Extremely high-risk: ${getTargetLabel(e)}`,
    dedupWindow: 5 * 60 * 1000,
    compliance: ["NIST SP 800-83"],
  },

  // ═══════════════════════════════
  // SMS — Enhanced Smishing (4 more)
  // ═══════════════════════════════
  {
    id: "SMS-004",
    name: "Smishing — Bank / Financial Alert Scam",
    category: "phishing",
    severity: 4,
    mitre: { tactic: "TA0001 - Initial Access", technique: "T1660 - Phishing via SMS" },
    cve: null,
    condition: (e) => e.category === "phishing" && e.rawData?.inputType === "sms" && e.rawData?.issues?.some((i) => /bank|transaction|account.*suspicious|fraud.*alert|card.*blocked/i.test(i)),
    description: (e) => `Banking smishing — fake fraud alert targeting financial credentials: ${getTargetLabel(e)}`,
    dedupWindow: 10 * 60 * 1000,
    compliance: ["PCI-DSS 6.4"],
  },
  {
    id: "SMS-005",
    name: "Smishing — SIM Swap Precursor",
    category: "phishing",
    severity: 5,
    mitre: { tactic: "TA0006 - Credential Access", technique: "T1586.002 - Compromise Accounts: Phone Numbers" },
    cve: null,
    condition: (e) => e.category === "phishing" && e.rawData?.issues?.some((i) => /sim.?swap|port.*number|carrier.*verify|account.*pin/i.test(i)),
    description: (e) => `SIM swap precursor — attacker harvesting carrier PIN for phone number port: ${getTargetLabel(e)}`,
    dedupWindow: 5 * 60 * 1000,
    compliance: ["FCC Advisory", "NIST SP 800-63B"],
  },
  {
    id: "SMS-006",
    name: "Smishing — Crypto / Investment Fraud SMS",
    category: "phishing",
    severity: 4,
    mitre: { tactic: "TA0001 - Initial Access", technique: "T1660 - Phishing via SMS" },
    cve: null,
    condition: (e) => e.category === "phishing" && e.rawData?.inputType === "sms" && e.rawData?.issues?.some((i) => /bitcoin|crypto|investment|trading.*app|profit.*guaranteed/i.test(i)),
    description: (e) => `Crypto smishing — fake investment opportunity via SMS: ${getTargetLabel(e)}`,
    dedupWindow: 20 * 60 * 1000,
    compliance: ["SEC Advisory"],
  },
  {
    id: "SMS-007",
    name: "Smishing — Prize / Gift Card SMS Scam",
    category: "phishing",
    severity: 3,
    mitre: { tactic: "TA0001 - Initial Access", technique: "T1660 - Phishing via SMS" },
    cve: null,
    condition: (e) => e.category === "phishing" && e.rawData?.inputType === "sms" && e.rawData?.issues?.some((i) => /prize|gift.card|won|reward|winner|claim/i.test(i)),
    description: (e) => `Prize/gift card smishing — fake reward notification via SMS: ${getTargetLabel(e)}`,
    dedupWindow: 30 * 60 * 1000,
    compliance: ["FTC 16 CFR Part 251"],
  },

  // ═══════════════════════════════
  // COR — Correlation / Multi-Signal
  // ═══════════════════════════════
  {
    id: "COR-001",
    name: "Correlation — Same Domain Multiple Attack Types",
    category: "correlation",
    severity: 5,
    mitre: { tactic: "TA0043 - Reconnaissance", technique: "T1598 - Phishing for Information" },
    cve: null,
    condition: (e) => e.category === "phishing" && e.rawData?.attackTypes?.length >= 4 && e.riskScore >= 70,
    description: (e) => `Multi-vector phishing — ${e.rawData?.attackTypes?.length} simultaneous attack types: ${e.rawData?.attackTypes?.slice(0,3).join(", ")} | Target: ${getTargetLabel(e)}`,
    dedupWindow: 5 * 60 * 1000,
    compliance: ["NIST SP 800-61", "ISO 27001 A.16"],
  },
  {
    id: "COR-002",
    name: "Correlation — IOC Re-sighting (Known Malicious)",
    category: "correlation",
    severity: 5,
    mitre: { tactic: "TA0001 - Initial Access", technique: "T1566 - Phishing" },
    cve: null,
    condition: (e) => e.category === "phishing" && e.rawData?.iocMatches?.length > 0,
    description: (e) => `IOC re-sighting — previously confirmed malicious indicator seen again: ${e.rawData?.iocMatches?.[0]?.type} "${e.rawData?.iocMatches?.[0]?.value}" (seen ${e.rawData?.iocMatches?.[0]?.hitCount}× total)`,
    dedupWindow: 5 * 60 * 1000,
    compliance: ["NIST SP 800-61", "ISO 27001 A.16"],
  },
  {
    id: "COR-003",
    name: "Correlation — High Entropy + Phishing Kit",
    category: "correlation",
    severity: 5,
    mitre: { tactic: "TA0005 - Defense Evasion", technique: "T1027 - Obfuscated Files or Information" },
    cve: null,
    condition: (e) => e.category === "phishing" && e.rawData?.urlPreview?.jsEntropy?.highEntropyBlocks > 0 && e.rawData?.urlPreview?.technologies?.hasPhishingKit,
    description: (e) => `Confirmed kit + obfuscation — phishing kit with ${e.rawData?.urlPreview?.jsEntropy?.highEntropyBlocks} high-entropy JS blocks (max entropy: ${e.rawData?.urlPreview?.jsEntropy?.maxEntropy}): ${getTargetLabel(e)}`,
    dedupWindow: 5 * 60 * 1000,
    compliance: ["NIST SP 800-61"],
  },
  {
    id: "COR-004",
    name: "Correlation — Exfiltration Channel + Credential Form",
    category: "correlation",
    severity: 5,
    mitre: { tactic: "TA0009 - Collection", technique: "T1041 - Exfiltration Over C2 Channel" },
    cve: null,
    condition: (e) => e.category === "phishing" && e.rawData?.urlPreview?.forms?.hasCredentialForm && e.rawData?.urlPreview?.technologies?.detected?.some((t) => t.name?.includes("Telegram Bot Exfil") || t.name?.includes("Discord Webhook Exfil")),
    description: (e) => `Complete exfil pipeline — credential form + Telegram/Discord C2 exfil channel: ${getTargetLabel(e)}`,
    dedupWindow: 2 * 60 * 1000,
    compliance: ["NIST SP 800-61", "PCI-DSS 12.10", "ISO 27001 A.16"],
  },

  // ═══════════════════════════════
  // LOG — Endpoint Log Rules
  // ═══════════════════════════════
  {
    id: "LOG-001",
    name: "Endpoint — Suspicious Process from Office Application",
    category: "endpoint",
    severity: 5,
    mitre: { tactic: "TA0002 - Execution", technique: "T1059.001 - PowerShell", sub: "T1204.002 - User Execution: Malicious File" },
    cve: null,
    condition: (e) => e.logType === "suspicious_process" && e.rawData?.attackTypes?.includes("office_macro_spawn"),
    description: (e) => `Office macro spawn — ${e.rawData?.parentProcess || "Office app"} spawned ${e.rawData?.process || "shell"} on ${e.source?.host || "endpoint"}. Classic macro malware chain.`,
    dedupWindow: 5 * 60 * 1000,
    compliance: ["NIST SP 800-83", "ISO 27001 A.12.2"],
  },
  {
    id: "LOG-002",
    name: "Endpoint — Execution from Temp / Downloads Path",
    category: "endpoint",
    severity: 4,
    mitre: { tactic: "TA0002 - Execution", technique: "T1204.002 - User Execution: Malicious File" },
    cve: null,
    condition: (e) => e.logType === "suspicious_process" && e.rawData?.attackTypes?.includes("execution_from_temp_path"),
    description: (e) => `Temp/Downloads execution — ${e.rawData?.process || "process"} ran from ${e.rawData?.processPath || "temp path"} on ${e.source?.host || "endpoint"}`,
    dedupWindow: 10 * 60 * 1000,
    compliance: ["NIST SP 800-83"],
  },
  {
    id: "LOG-003",
    name: "Endpoint — Multiple Failed Logins Followed by Success",
    category: "endpoint",
    severity: 5,
    mitre: { tactic: "TA0006 - Credential Access", technique: "T1110.001 - Brute Force: Password Guessing" },
    cve: null,
    condition: (e) => e.logType === "multiple_login_attempts" && e.rawData?.attemptCount >= 10,
    description: (e) => `High-volume brute force — ${e.rawData?.attemptCount || "multiple"} failed logins for "${e.source?.user || "unknown"}" from ${e.source?.ip || "unknown"} within 2 minutes`,
    dedupWindow: 2 * 60 * 1000,
    compliance: ["NIST SP 800-63B", "PCI-DSS 8.3", "ISO 27001 A.9"],
  },
];

const SEVERITY_LABELS = {
  1: "INFO",
  2: "LOW",
  3: "MEDIUM",
  4: "HIGH",
  5: "CRITICAL",
};

function matchRules(event) {
  const matches = [];
  for (const rule of RULES) {
    try {
      if (rule.condition(event)) {
        matches.push({
          ruleId: rule.id,
          ruleName: rule.name,
          category: rule.category,
          severity: rule.severity,
          severityLabel: SEVERITY_LABELS[rule.severity],
          description: rule.description(event),
          mitre: rule.mitre,
          cve: rule.cve,
          dedupWindow: rule.dedupWindow || 5 * 60 * 1000,
          compliance: rule.compliance || [],
        });
      }
    } catch {
      /* skip bad rule */
    }
  }
  return matches;
}

function getAllRules() {
  return RULES.map((r) => ({
    id: r.id,
    name: r.name,
    category: r.category,
    severity: r.severity,
    severityLabel: SEVERITY_LABELS[r.severity],
    mitre: r.mitre,
    cve: r.cve,
    compliance: r.compliance || [],
  }));
}

// ── Evaluate custom (DB-stored) rules against an event ──
async function matchCustomRules(event) {
  if (!CustomRule) return [];
  try {
    const rules = await CustomRule.find({ enabled: true }).lean();
    const matches = [];

    for (const rule of rules) {
      const c = rule.conditions;
      let pass = true;
      const failReasons = [];

      // ── Condition 1: riskScoreMin ──
      if (c.riskScoreMin !== null && c.riskScoreMin !== undefined) {
        const score = event.riskScore ?? event.rawData?.riskScore ?? 0;
        if (score < c.riskScoreMin) {
          pass = false;
          failReasons.push(`riskScore ${score} < required ${c.riskScoreMin}`);
        }
      }

      // ── Condition 2: inputType ──
      if (c.inputType !== null && c.inputType !== undefined && c.inputType !== "") {
        const evType = event.rawData?.inputType
          || event.inputType
          || event.target?.inputType
          || null;
        if (evType !== c.inputType) {
          pass = false;
          failReasons.push(`inputType "${evType}" != "${c.inputType}"`);
        }
      }

      // ── Condition 3: statusMatch ──
      if (c.statusMatch !== null && c.statusMatch !== undefined && c.statusMatch !== "") {
        const evStatus = event.rawData?.status || event.subcategory || null;
        if (evStatus !== c.statusMatch) {
          pass = false;
          failReasons.push(`status "${evStatus}" != "${c.statusMatch}"`);
        }
      }

      // ── Condition 4: issueContains ──
      // FIX: search in issues[] AND raw input AND title AND desc AND rawData strings
      // so custom rules work even when issues array is empty or keyword is in input
      if (c.issueContains !== null && c.issueContains !== undefined && c.issueContains !== "") {
        const kw      = c.issueContains.toLowerCase().trim();
        const issues  = event.rawData?.issues || [];
        const inIssues = issues.some(i => String(i).toLowerCase().includes(kw));
        const inInput  = String(event.target?.rawInput || event.target?.url || "").toLowerCase().includes(kw);
        const inTitle  = String(event.title || "").toLowerCase().includes(kw);
        const inDesc   = String(event.description || "").toLowerCase().includes(kw);
        const inTypes  = (event.rawData?.attackTypes || []).some(t => String(t).toLowerCase().includes(kw));
        const inRaw    = Object.values(event.rawData || {})
          .filter(v => typeof v === "string")
          .some(v => v.toLowerCase().includes(kw));

        if (!inIssues && !inInput && !inTitle && !inDesc && !inTypes && !inRaw) {
          pass = false;
          failReasons.push(`keyword "${kw}" not found in issues/input/title/desc/attackTypes`);
        }
      }

      // ── Condition 5: attackTypeIn ──
      // FIX: normalize case before comparing
      if (c.attackTypeIn && c.attackTypeIn.length > 0) {
        const evTypes   = (event.rawData?.attackTypes || []).map(t => String(t).toLowerCase());
        const ruleTypes = c.attackTypeIn.map(t => String(t).toLowerCase());
        if (!ruleTypes.some(rt => evTypes.includes(rt))) {
          pass = false;
          failReasons.push(`attackType [${ruleTypes}] not in event [${evTypes}]`);
        }
      }

      if (pass) {
        CustomRule.findByIdAndUpdate(rule._id, {
          $inc: { triggerCount: 1 },
          $set: { lastTriggered: new Date() },
        }).catch(() => {});

        console.log(`⚡ Custom Rule MATCHED: "${rule.name}" (${rule.ruleId})`);

        const kw = c.issueContains ? `keyword: "${c.issueContains}"` : "conditions matched";
        matches.push({
          ruleId:        rule.ruleId,
          ruleName:      rule.name,
          category:      rule.category,
          severity:      rule.severity,
          severityLabel: SEVERITY_LABELS[rule.severity],
          description:   `Custom rule "${rule.name}" triggered — ${kw}`,
          mitre:         rule.mitre,
          cve:           null,
          dedupWindow:   rule.dedupWindowMin * 60 * 1000,
          compliance:    [],
          isCustom:      true,
        });
      } else if (process.env.NODE_ENV === "development") {
        console.log(`  Custom Rule "${rule.name}" — no match: ${failReasons.join("; ")}`);
      }
    }
    return matches;
  } catch (err) {
    console.error("matchCustomRules error:", err.message);
    return [];
  }
}

module.exports = { matchRules, matchCustomRules, getAllRules, SEVERITY_LABELS };