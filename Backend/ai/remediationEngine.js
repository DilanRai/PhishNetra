// FILE: backend/ai/remediationEngine.js
// Generates specific, actionable remediation steps per threat type

const REPORT_URLS = {
  google:     "https://safebrowsing.google.com/safebrowsing/report_phish/",
  microsoft:  "https://www.microsoft.com/en-us/wdsi/support/report-unsafe-site",
  apwg:       "https://apwg.org/reportphishing/",
  phishtank:  "https://www.phishtank.com/add_web_phish.php",
  icann:      "https://lookup.icann.org/",
};

// ── Map technique → specific remediation steps ──
const TECHNIQUE_REMEDIATIONS = {
  credential_harvest: [
    { priority: "CRITICAL", action: "Do NOT enter any credentials — close this page immediately" },
    { priority: "CRITICAL", action: "If credentials were already entered — change passwords NOW on the real site" },
    { priority: "HIGH",     action: "Enable 2FA/MFA on all affected accounts immediately" },
    { priority: "HIGH",     action: "Check account activity for unauthorized logins" },
    { priority: "MEDIUM",   action: "Notify your security team / IT department" },
    { priority: "LOW",      action: "Report to APWG: " + REPORT_URLS.apwg },
  ],
  brand_impersonation: [
    { priority: "HIGH",   action: "Verify the real domain by typing it directly in your browser" },
    { priority: "HIGH",   action: "Report fake domain to the impersonated brand's abuse team" },
    { priority: "HIGH",   action: "Report to Google Safe Browsing: " + REPORT_URLS.google },
    { priority: "MEDIUM", action: "Block domain at DNS/firewall level" },
    { priority: "MEDIUM", action: "Alert colleagues who may receive the same message" },
    { priority: "LOW",    action: "Check ICANN WHOIS for domain registration details: " + REPORT_URLS.icann },
  ],
  typosquatting: [
    { priority: "HIGH",   action: "Do not visit — the domain is intentionally similar to a legitimate brand" },
    { priority: "HIGH",   action: "Report to PhishTank: " + REPORT_URLS.phishtank },
    { priority: "HIGH",   action: "Block domain at DNS level" },
    { priority: "MEDIUM", action: "Check for similar domains targeting your organization" },
    { priority: "LOW",    action: "Report to Microsoft: " + REPORT_URLS.microsoft },
  ],
  redirect_chain: [
    { priority: "HIGH",   action: "Do not follow — redirect chains hide the true malicious destination" },
    { priority: "HIGH",   action: "Block the originating domain at perimeter firewall" },
    { priority: "MEDIUM", action: "Scan the final destination URL separately for confirmation" },
    { priority: "LOW",    action: "Report URL shortener abuse to the shortener service" },
  ],
  homograph: [
    { priority: "CRITICAL", action: "This domain uses Unicode lookalike characters — extremely deceptive" },
    { priority: "HIGH",     action: "Block punycode/IDN variant at DNS level (block xn-- prefixed domains)" },
    { priority: "HIGH",     action: "Report to ICANN: " + REPORT_URLS.icann },
    { priority: "MEDIUM",   action: "Educate users about homograph attacks" },
  ],
  social_engineering: [
    { priority: "HIGH",   action: "Do NOT comply with any requests in the message" },
    { priority: "HIGH",   action: "Verify the sender through an independent channel (call, separate email)" },
    { priority: "HIGH",   action: "Report to your organization's security team" },
    { priority: "MEDIUM", action: "Forward message as attachment to abuse@[sender-domain]" },
    { priority: "LOW",    action: "File a report with IC3: https://www.ic3.gov/" },
  ],
  financial_scam: [
    { priority: "CRITICAL", action: "Do NOT send money, gift cards, or cryptocurrency under any circumstances" },
    { priority: "CRITICAL", action: "If payment already made — contact your bank/financial institution IMMEDIATELY" },
    { priority: "HIGH",     action: "Report to FTC: https://reportfraud.ftc.gov/" },
    { priority: "HIGH",     action: "File report with IC3: https://www.ic3.gov/" },
    { priority: "MEDIUM",   action: "Preserve all communications as evidence" },
  ],
  malicious_attachment: [
    { priority: "CRITICAL", action: "Do NOT open, enable macros, or run any files from this source" },
    { priority: "CRITICAL", action: "If already opened — disconnect from network and run antivirus scan" },
    { priority: "HIGH",     action: "Submit attachment hash to VirusTotal for community analysis" },
    { priority: "HIGH",     action: "Alert IT/security team for incident response" },
    { priority: "MEDIUM",   action: "Check endpoint logs for any execution events" },
  ],
  generic_phishing: [
    { priority: "HIGH",   action: "Do not click links or download attachments" },
    { priority: "HIGH",   action: "Report to Google Safe Browsing: " + REPORT_URLS.google },
    { priority: "MEDIUM", action: "Block sender/domain at email gateway" },
    { priority: "MEDIUM", action: "Report to APWG: " + REPORT_URLS.apwg },
    { priority: "LOW",    action: "Notify users who may have received the same message" },
  ],
};

// ── Status-level general remediations ──
const STATUS_REMEDIATIONS = {
  phishing: [
    { priority: "CRITICAL", action: "Isolate — do not interact with this URL/message in any way" },
    { priority: "HIGH",     action: "Log the incident with timestamp, source IP, and full URL" },
    { priority: "HIGH",     action: "Check if any users in your organization already accessed this" },
  ],
  suspicious: [
    { priority: "HIGH",   action: "Verify through an independent trusted source before proceeding" },
    { priority: "MEDIUM", action: "Log for monitoring — check again in 24 hours" },
  ],
  safe: [
    { priority: "LOW", action: "No action required — continue normal browsing" },
    { priority: "LOW", action: "Remain vigilant — phishing sites can appear safe initially" },
  ],
};

// ── Compliance obligations ──
const COMPLIANCE_NOTES = {
  credential_harvest: "PCI-DSS Req 8.3 — Credential theft incidents must be reported within 72h. GDPR Art.33 — Data breach notification required if credentials were compromised.",
  financial_scam:     "PCI-DSS Req 12.10 — Financial fraud incidents require immediate response plan activation.",
  brand_impersonation:"GDPR Art.32 — Document incident. Notify DPA if customer data at risk.",
};

// ── Priority color for UI ──
const PRIORITY_CONFIG = {
  CRITICAL: { color: "#ff4444", bg: "rgba(255,68,68,0.08)",  border: "rgba(255,68,68,0.25)"  },
  HIGH:     { color: "#f97316", bg: "rgba(249,115,22,0.08)", border: "rgba(249,115,22,0.25)" },
  MEDIUM:   { color: "#f5a623", bg: "rgba(245,166,35,0.08)", border: "rgba(245,166,35,0.25)" },
  LOW:      { color: "#00ff88", bg: "rgba(0,255,136,0.06)",  border: "rgba(0,255,136,0.2)"   },
};

// ── MAIN: generate remediation plan ──
function generateRemediation(status, issues = [], dna = null) {
  if (status === "safe") {
    return {
      severity:    "none",
      steps:       STATUS_REMEDIATIONS.safe,
      compliance:  null,
      reportLinks: [],
      summary:     "No remediation required — this appears to be safe.",
    };
  }

  const technique    = dna?.technique || "generic_phishing";
  const techniqueSteps = TECHNIQUE_REMEDIATIONS[technique] || TECHNIQUE_REMEDIATIONS.generic_phishing;
  const statusSteps    = STATUS_REMEDIATIONS[status]       || [];

  // Merge: status-level first, then technique-specific
  // Deduplicate by action text
  const seen = new Set();
  const allSteps = [...statusSteps, ...techniqueSteps].filter((s) => {
    if (seen.has(s.action)) return false;
    seen.add(s.action);
    return true;
  });

  // Sort: CRITICAL → HIGH → MEDIUM → LOW
  const order = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
  allSteps.sort((a, b) => (order[a.priority] ?? 4) - (order[b.priority] ?? 4));

  // Report links relevant to this technique
  const reportLinks = [
    { label: "Google Safe Browsing",  url: REPORT_URLS.google    },
    { label: "APWG PhishReport",      url: REPORT_URLS.apwg      },
    { label: "PhishTank",             url: REPORT_URLS.phishtank  },
  ];

  if (technique === "typosquatting" || technique === "homograph") {
    reportLinks.push({ label: "ICANN WHOIS", url: REPORT_URLS.icann });
  }

  return {
    severity:    status === "phishing" ? "critical" : "medium",
    steps:       allSteps.slice(0, 8), // max 8 steps
    compliance:  COMPLIANCE_NOTES[technique] || null,
    reportLinks,
    summary: status === "phishing"
      ? `Immediate action required — ${technique.replace(/_/g, " ")} attack detected`
      : `Caution advised — suspicious ${technique.replace(/_/g, " ")} pattern detected`,
    priorityConfig: PRIORITY_CONFIG,
  };
}

module.exports = { generateRemediation, PRIORITY_CONFIG };