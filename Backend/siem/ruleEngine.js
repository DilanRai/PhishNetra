// ================================================================
// FILE: backend/siem/ruleEngine.js
// SentinelCore Rule Engine
// Our own rule language — JSON-based, unlike Wazuh's XML rules
// ================================================================

// ── Rule Registry ──
// Each rule: { id, name, category, severity, condition, action, mitre }
const RULES = [

  // ═══════════════════════════════
  // PHISHING RULES (Our specialty)
  // ═══════════════════════════════

  {
    id:       "PHI-001",
    name:     "High-Risk Phishing URL Detected",
    category: "phishing",
    severity: 5, // CRITICAL
    mitre:    { tactic: "TA0001 - Initial Access", technique: "T1566.002 - Spearphishing Link" },
    condition: (event) =>
      event.category === "phishing" &&
      event.riskScore >= 75,
    description: (event) =>
      `Phishing URL detected with risk score ${event.riskScore}/100. Target: ${event.target?.url || "unknown"}`,
    dedupWindow: 5 * 60 * 1000, // 5 min dedup
    compliance: ["PCI-DSS 6.4", "NIST SP 800-61"],
  },

  {
    id:       "PHI-002",
    name:     "Brand Impersonation Attack",
    category: "phishing",
    severity: 4, // HIGH
    mitre:    { tactic: "TA0001 - Initial Access", technique: "T1566.002 - Spearphishing Link" },
    condition: (event) =>
      event.category === "phishing" &&
      event.rawData?.issues?.some((i) => /impersonat|spoofing/i.test(i)),
    description: (event) =>
      `Brand impersonation detected in ${event.target?.url || event.target?.domain || "unknown"}`,
    dedupWindow: 10 * 60 * 1000,
    compliance: ["GDPR Art.32"],
  },

  {
    id:       "PHI-003",
    name:     "OTP Credential Harvesting Attempt",
    category: "phishing",
    severity: 5, // CRITICAL
    mitre:    { tactic: "TA0006 - Credential Access", technique: "T1056 - Input Capture" },
    condition: (event) =>
      event.category === "phishing" &&
      event.rawData?.issues?.some((i) => /otp|credential request/i.test(i)),
    description: () => "OTP/credential harvesting phishing message detected — immediate action required",
    dedupWindow: 2 * 60 * 1000,
    compliance: ["PCI-DSS 8.3", "NIST AC-7"],
  },

  {
    id:       "PHI-004",
    name:     "Suspicious URL - Medium Risk",
    category: "phishing",
    severity: 2, // LOW
    mitre:    { tactic: "TA0001 - Initial Access", technique: "T1566 - Phishing" },
    condition: (event) =>
      event.category === "phishing" &&
      event.riskScore >= 30 &&
      event.riskScore < 65,
    description: (event) =>
      `Suspicious URL flagged with score ${event.riskScore}/100`,
    dedupWindow: 15 * 60 * 1000,
    compliance: [],
  },

  {
    id:       "PHI-005",
    name:     "Typosquatting Domain Detected",
    category: "phishing",
    severity: 4,
    mitre:    { tactic: "TA0001 - Initial Access", technique: "T1583.001 - Acquire Infrastructure: Domains" },
    condition: (event) =>
      event.category === "phishing" &&
      event.rawData?.issues?.some((i) => /typosquatting/i.test(i)),
    description: (event) =>
      `Typosquatting domain detected: ${event.target?.domain || "unknown"}`,
    dedupWindow: 30 * 60 * 1000,
    compliance: ["GDPR Art.32"],
  },

  // ═══════════════════════════════
  // BRUTE FORCE RULES
  // ═══════════════════════════════

  {
    id:       "BRU-001",
    name:     "Multiple Scan Attempts - Same Source",
    category: "brute_force",
    severity: 3, // MEDIUM
    mitre:    { tactic: "TA0006 - Credential Access", technique: "T1110 - Brute Force" },
    condition: (event) =>
      event.category === "reconnaissance" &&
      event.rawData?.scanCount >= 10,
    description: (event) =>
      `${event.rawData?.scanCount} scans from source ${event.source?.ip || "unknown"} in short window`,
    dedupWindow: 5 * 60 * 1000,
    compliance: ["PCI-DSS 8.3"],
  },

  {
    id:       "BRU-002",
    name:     "High-Volume Phishing Scan Burst",
    category: "brute_force",
    severity: 4,
    mitre:    { tactic: "TA0043 - Reconnaissance", technique: "T1595 - Active Scanning" },
    condition: (event) =>
      event.category === "reconnaissance" &&
      event.rawData?.scanCount >= 50,
    description: (event) =>
      `Burst of ${event.rawData?.scanCount} scans — possible automated phishing campaign`,
    dedupWindow: 2 * 60 * 1000,
    compliance: ["NIST SI-3"],
  },

  // ═══════════════════════════════
  // ANOMALY RULES
  // ═══════════════════════════════

  {
    id:       "ANO-001",
    name:     "Unusual Phishing Pattern Spike",
    category: "anomaly",
    severity: 3,
    mitre:    { tactic: "TA0001 - Initial Access", technique: "T1566 - Phishing" },
    condition: (event) =>
      event.category === "anomaly" &&
      event.rawData?.type === "spike" &&
      event.rawData?.metric === "phishing_rate",
    description: (event) =>
      `Phishing rate spike: ${event.rawData?.value}% above baseline (threshold: ${event.rawData?.threshold}%)`,
    dedupWindow: 30 * 60 * 1000,
    compliance: [],
  },

  {
    id:       "ANO-002",
    name:     "New Malicious Domain Family Observed",
    category: "anomaly",
    severity: 3,
    mitre:    { tactic: "TA0001 - Initial Access", technique: "T1583.001 - Acquire Infrastructure" },
    condition: (event) =>
      event.category === "phishing" &&
      event.rawData?.isNewDomainFamily === true,
    description: (event) =>
      `New malicious domain pattern observed: ${event.target?.domain}`,
    dedupWindow: 60 * 60 * 1000,
    compliance: [],
  },

  // ═══════════════════════════════
  // NETWORK / INFRASTRUCTURE RULES
  // ═══════════════════════════════

  {
    id:       "NET-001",
    name:     "Malicious IP Range Access",
    category: "network",
    severity: 4,
    mitre:    { tactic: "TA0011 - Command and Control", technique: "T1071 - App Layer Protocol" },
    condition: (event) =>
      event.category === "network" &&
      event.rawData?.threatType === "malicious_ip",
    description: (event) =>
      `Access to/from known malicious IP: ${event.target?.ip || event.source?.ip}`,
    dedupWindow: 5 * 60 * 1000,
    compliance: ["NIST SI-3", "PCI-DSS 1.3"],
  },

  {
    id:       "NET-002",
    name:     "URL Redirect Chain Detected",
    category: "network",
    severity: 3,
    mitre:    { tactic: "TA0001 - Initial Access", technique: "T1566.002 - Spearphishing Link" },
    condition: (event) =>
      event.category === "phishing" &&
      event.rawData?.issues?.some((i) => /redirect/i.test(i)),
    description: (event) =>
      `Suspicious URL redirect chain detected — possible cloaking technique`,
    dedupWindow: 15 * 60 * 1000,
    compliance: [],
  },

  {
    id:       "NET-003",
    name:     "Punycode / IDN Domain Attack",
    category: "network",
    severity: 4,
    mitre:    { tactic: "TA0001 - Initial Access", technique: "T1583.001 - Acquire Infrastructure: Domains" },
    condition: (event) =>
      event.category === "phishing" &&
      event.rawData?.issues?.some((i) => /punycode|idn/i.test(i)),
    description: (event) =>
      `Punycode/IDN homograph attack detected on domain: ${event.target?.domain}`,
    dedupWindow: 30 * 60 * 1000,
    compliance: ["NIST SI-3"],
  },
];

// ── Severity label map ──
const SEVERITY_LABELS = { 1: "INFO", 2: "LOW", 3: "MEDIUM", 4: "HIGH", 5: "CRITICAL" };

// ── Match event against all rules ──
function matchRules(event) {
  const matches = [];
  for (const rule of RULES) {
    try {
      if (rule.condition(event)) {
        matches.push({
          ruleId:      rule.id,
          ruleName:    rule.name,
          category:    rule.category,
          severity:    rule.severity,
          severityLabel: SEVERITY_LABELS[rule.severity],
          description: rule.description(event),
          mitre:       rule.mitre,
          dedupWindow: rule.dedupWindow || 5 * 60 * 1000,
          compliance:  rule.compliance || [],
        });
      }
    } catch { /* rule eval error — skip */ }
  }
  return matches;
}

// ── Get all rules (for dashboard display) ──
function getAllRules() {
  return RULES.map((r) => ({
    id:          r.id,
    name:        r.name,
    category:    r.category,
    severity:    r.severity,
    severityLabel: SEVERITY_LABELS[r.severity],
    mitre:       r.mitre,
    compliance:  r.compliance || [],
  }));
}

module.exports = { matchRules, getAllRules, SEVERITY_LABELS };