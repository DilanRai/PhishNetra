// ════════════════════════════════════════════════════════════════
// FILE: backend/services/govtPortalDetector.js — CREATE NEW
// Fake Website / Government Portal Detection
// Real-world use: India has hundreds of fake government portal clones
// (fake IRCTC, fake DigiLocker, fake income tax, fake passport seva).
// This detector checks for govt impersonation with India-specific
// pattern matching — TLD abuse, fake aadhaar/pan portals, fake
// state govt sites, and visual lookalike detection signals.
// ════════════════════════════════════════════════════════════════

// ── Real Indian govt domains (authoritative list) ─────────────
const REAL_GOVT_DOMAINS = new Set([
  // Central government
  "gov.in",
  "nic.in",
  "ernet.in",
  "res.in",
  "ac.in",
  // Specific portals
  "incometax.gov.in",
  "efiling.incometax.gov.in",
  "uidai.gov.in",
  "irctc.co.in",
  "indianrailways.gov.in",
  "passportindia.gov.in",
  "digilocker.gov.in",
  "umang.gov.in",
  "india.gov.in",
  "mca.gov.in",
  "epfindia.gov.in",
  "esic.gov.in",
  "mahadbt.maharashtra.gov.in",
  "serviceonline.bihar.gov.in",
  "ksrtc.in",
  "tnreginet.gov.in",
  "cybercrime.gov.in",
  "digitalindia.gov.in",
  "nhm.gov.in",
  "nhp.gov.in",
  "ayushman.gov.in",
  "pmjay.gov.in",
  "pmkisan.gov.in",
  "mkisan.gov.in",
  "nsdl.co.in",
  "cibil.com",
  "crif.com",
  "rbi.org.in",
  "sebi.gov.in",
  "nse.co.in",
  "bseindia.com",
]);

// ── Fake govt URL patterns ────────────────────────────────────
const FAKE_GOVT_PATTERNS = [
  // Misspellings / typos of official sites
  {
    pattern: /uidai[^.]*\.(com|net|org|in(?!dia)|io|xyz|top)/i,
    name: "Fake UIDAI/Aadhaar",
    real: "uidai.gov.in",
    risk: 90,
  },
  {
    pattern: /irctc[^.]*\.(com(?!\.in)|net|org|xyz|top|me)/i,
    name: "Fake IRCTC",
    real: "irctc.co.in",
    risk: 88,
  },
  {
    pattern: /incometax[^.]*\.(com|net|org(?!\.in)|xyz|top)/i,
    name: "Fake Income Tax Portal",
    real: "incometax.gov.in",
    risk: 88,
  },
  {
    pattern: /passport[^.]*india[^.]*\.(com|net|org|xyz)/i,
    name: "Fake Passport Seva",
    real: "passportindia.gov.in",
    risk: 85,
  },
  {
    pattern: /digilocker[^.]*\.(com|net|org|app|xyz)/i,
    name: "Fake DigiLocker",
    real: "digilocker.gov.in",
    risk: 90,
  },
  {
    pattern: /epf[^.]*india[^.]*\.(com|net|org(?!\.in))/i,
    name: "Fake EPF India",
    real: "epfindia.gov.in",
    risk: 85,
  },
  {
    pattern: /pmkisan[^.]*\.(com|net|org|xyz|top|io)/i,
    name: "Fake PM Kisan Portal",
    real: "pmkisan.gov.in",
    risk: 85,
  },
  {
    pattern: /pmjay[^.]*\.(com|net|org|xyz|top)/i,
    name: "Fake Ayushman Bharat",
    real: "pmjay.gov.in",
    risk: 85,
  },
  {
    pattern: /rbi[^.]*\.(com(?!\.in)|net|org(?!\.in)|xyz|app)/i,
    name: "Fake RBI Portal",
    real: "rbi.org.in",
    risk: 90,
  },
  {
    pattern: /sebi[^.]*\.(com(?!\.in)|net|app|xyz|top)/i,
    name: "Fake SEBI Portal",
    real: "sebi.gov.in",
    risk: 88,
  },
  {
    pattern: /nsdl[^.]*\.(com(?!\.co\.in)|net|org|xyz)/i,
    name: "Fake NSDL",
    real: "nsdl.co.in",
    risk: 85,
  },
  {
    pattern: /cibil[^.]*\.(com(?!\.com)|net|org|app|xyz)/i,
    name: "Fake CIBIL Score",
    real: "cibil.com",
    risk: 85,
  },

  // Generic fake govt patterns
  {
    pattern: /(?:govt|government|sarkari)[^.]*\.(com|net|xyz|top|tk|ml)/i,
    name: "Fake Government Website",
    real: "Verify at india.gov.in",
    risk: 75,
  },
  {
    pattern: /(?:aadhar|aadhaar)[^.]*\.(com|net|org|xyz|app|top)/i,
    name: "Fake Aadhaar Portal",
    real: "uidai.gov.in",
    risk: 90,
  },
  {
    pattern: /pan[^.]*card[^.]*\.(com|net|org|xyz|app)/i,
    name: "Fake PAN Card Portal",
    real: "nsdl.co.in",
    risk: 85,
  },
  {
    pattern: /driving[^.]*licen[^.]*\.(com|net|xyz|top)/i,
    name: "Fake Driving License",
    real: "parivahan.gov.in",
    risk: 80,
  },
  {
    pattern: /ration[^.]*card[^.]*\.(com|net|xyz|org)/i,
    name: "Fake Ration Card Portal",
    real: "dfpd.gov.in",
    risk: 78,
  },
  {
    pattern: /e.?shram[^.]*\.(com|net|xyz|top|org)/i,
    name: "Fake e-SHRAM Portal",
    real: "eshram.gov.in",
    risk: 82,
  },
  {
    pattern: /scholarship[^.]*gov[^.]*\.(com|net|xyz)/i,
    name: "Fake Scholarship Portal",
    real: "scholarships.gov.in",
    risk: 80,
  },
  {
    pattern: /(?:free|muft).*(?:laptop|mobile|phone)[^.]*\.(com|net)/i,
    name: "Fake Govt Free Device Scheme",
    real: "None — this is fraud",
    risk: 88,
  },
  // NEW patterns
  {
    pattern: /voter[^.]*id[^.]*\.(com|net|xyz|org|app)/i,
    name: "Fake Voter ID / NVSP Portal",
    real: "voterportal.eci.gov.in",
    risk: 82,
  },
  {
    pattern: /nvsp[^.]*\.(com|net|org|xyz)/i,
    name: "Fake NVSP Voter Portal",
    real: "voterportal.eci.gov.in",
    risk: 85,
  },
  {
    pattern: /pfms[^.]*\.(com|net|xyz|top)/i,
    name: "Fake PFMS / Government Payment",
    real: "pfms.nic.in",
    risk: 85,
  },
  {
    pattern: /cowin[^.]*\.(com|net|org|xyz|app)/i,
    name: "Fake CoWIN Vaccination Portal",
    real: "cowin.gov.in",
    risk: 85,
  },
  {
    pattern: /umang[^.]*\.(com|net|xyz|app|org)/i,
    name: "Fake UMANG App Portal",
    real: "umang.gov.in",
    risk: 82,
  },
  {
    pattern: /income.*tax.*return[^.]*\.(com|net|org|xyz)/i,
    name: "Fake ITR Filing Portal",
    real: "incometax.gov.in",
    risk: 88,
  },
  {
    pattern: /gst[^.]*(?:refund|portal|filing|pay)[^.]*\.(com|net|xyz|app)/i,
    name: "Fake GST Portal",
    real: "gst.gov.in",
    risk: 88,
  },
  {
    pattern: /epfo[^.]*\.(com|net|xyz|app|org(?!\.in))/i,
    name: "Fake EPFO Portal",
    real: "epfindia.gov.in",
    risk: 85,
  },
  {
    pattern: /mca21[^.]*\.(com|net|xyz|top)/i,
    name: "Fake MCA21 / Company Registration",
    real: "mca.gov.in",
    risk: 85,
  },
  {
    pattern: /nhb[^.]*(?:housing|loan)[^.]*\.(com|net|xyz)/i,
    name: "Fake NHB / Housing Loan Portal",
    real: "nhb.org.in",
    risk: 80,
  },
  {
    pattern: /cert.*in[^.]*\.(com|net|xyz|app)/i,
    name: "Fake CERT-In Portal",
    real: "cert-in.org.in",
    risk: 85,
  },
  {
    pattern: /cyber.*crime[^.]*(?:gov|portal)[^.]*\.(com|net|xyz|app)/i,
    name: "Fake Cybercrime Portal",
    real: "cybercrime.gov.in",
    risk: 90,
  },
  {
    pattern: /dbtharvest[^.]*\.(com|net|xyz)/i,
    name: "Fake DBT / Subsidy Portal",
    real: "dbtbharat.gov.in",
    risk: 82,
  },
  {
    pattern: /nationalscholarship[^.]*\.(com|net|xyz|org)/i,
    name: "Fake National Scholarship Portal",
    real: "scholarships.gov.in",
    risk: 80,
  },
];

// ── Content signals for fake govt pages ──────────────────────
const FAKE_GOVT_CONTENT_SIGNALS = [
  {
    pattern: /aadhar\s*number|aadhaar\s*number/i,
    weight: 15,
    signal: "Aadhaar number harvesting",
  },
  {
    pattern: /pan\s*number|pan\s*card\s*number/i,
    weight: 15,
    signal: "PAN number harvesting",
  },
  {
    pattern: /bank\s*account\s*number|ifsc/i,
    weight: 20,
    signal: "Bank account harvesting",
  },
  { pattern: /otp\s*enter|enter\s*otp/i, weight: 25, signal: "OTP phishing" },
  {
    pattern: /registration\s*fee|processing\s*fee/i,
    weight: 30,
    signal: "Fake govt fee (red flag — real portals are free)",
  },
  {
    pattern: /apply.*subsidy|claim.*benefit.*now/i,
    weight: 20,
    signal: "Fake subsidy claim page",
  },
  {
    pattern: /ministry\s*of|government\s*of\s*india/i,
    weight: 10,
    signal: "Government branding",
  },
  {
    pattern: /sarkari|sarkar|government\s*scheme/i,
    weight: 10,
    signal: "Hindi government keyword",
  },
];

// ── Homoglyph / Unicode substitution detection ───────────────
function detectHomoglyphs(url) {
  // Common homoglyph substitutions used in phishing
  const HOMOGLYPH_PAIRS = [
    [/xn--/i,          "Punycode IDN domain (potential homoglyph attack)"],
    [/[а-яА-Я]/,       "Cyrillic characters (lookalike attack)"],
    [/[αβγδεζηθικλμνξοπρστυφχψω]/i, "Greek characters (lookalike attack)"],
    [/rnin|rni|vv(?=[a-z])/i, "Visually similar letter combinations (rn→m, vv→w)"],
    [/g[o0][o0]gle|face[b8]ook|paypa[l1]|micros[o0]ft|[a4]mazon/i, "Brand name typosquatting"],
    [/gov[\-_.]in|\.gov\.in\./i, "gov.in subdomain manipulation"],
    [/[0-9]+gov|gov[0-9]+/i, "Numeric prefix/suffix on gov domain"],
  ];
  const hits = [];
  for (const [pattern, label] of HOMOGLYPH_PAIRS) {
    if (pattern.test(url)) hits.push(label);
  }
  return hits;
}

function detectFakeGovtPortal(url, pageContent = "") {
  const detections = [];
  const urlLower = (url || "").toLowerCase();

  // 1. Check URL against fake govt patterns
  for (const fp of FAKE_GOVT_PATTERNS) {
    if (fp.pattern.test(url)) {
      // Verify it's not the real domain
      const isReal = [...REAL_GOVT_DOMAINS].some((d) => urlLower.includes(d));
      if (!isReal) {
        detections.push({
          type: "fake_govt_portal",
          name: fp.name,
          real: fp.real,
          risk: fp.risk,
          severity: fp.risk >= 88 ? 5 : 4,
          signal: `URL matches fake government portal pattern. Real portal: ${fp.real}`,
          mitre: "T1036.005 - Masquerading: Match Legitimate Name",
        });
      }
    }
  }

  // 2. Check for .gov.in in path (not TLD) — e.g. fake-site.com/gov.in/
  if (
    /\/gov\.in\//i.test(url) &&
    !urlLower.endsWith(".gov.in") &&
    !urlLower.includes(".gov.in/")
  ) {
    detections.push({
      type: "govt_domain_in_path",
      name: "gov.in used in URL path (not TLD)",
      risk: 85,
      severity: 5,
      signal:
        "Attacker put 'gov.in' in the URL path to deceive users — the site is NOT a government site.",
      mitre: "T1036.005 - Masquerading",
    });
  }

  // 3. Homoglyph / Unicode substitution check
  const homoglyphHits = detectHomoglyphs(url);
  if (homoglyphHits.length > 0) {
    detections.push({
      type: "homoglyph_attack",
      name: "Unicode / Homoglyph Domain Attack",
      risk: 88,
      severity: 5,
      signal: `Homoglyph/lookalike attack detected: ${homoglyphHits.join("; ")}`,
      mitre: "T1036.005 - Masquerading: Match Legitimate Name",
    });
  }

  // 4. HTTP (not HTTPS) check for claimed govt portals
  if (/^http:\/\//i.test(url) && /gov|uidai|irctc|income.*tax|passport|digilocker/i.test(url)) {
    detections.push({
      type: "insecure_protocol",
      name: "Government portal without HTTPS",
      risk: 70,
      severity: 4,
      signal: "Real government portals always use HTTPS. HTTP-only site impersonating a govt portal is suspicious.",
      mitre: "T1036.005 - Masquerading",
    });
  }

  // 5. Suspicious URL structure patterns
  const SUSPICIOUS_STRUCTURES = [
    { pattern: /\d{3,}\.[a-z]{3,}\/.*gov/i,     label:"Numeric subdomain with gov in path", risk:80 },
    { pattern: /gov[.-]in\.[a-z]{2,}/i,          label:"gov.in used as subdomain", risk:88 },
    { pattern: /bit\.ly|tinyurl|t\.co.*gov/i,    label:"URL shortener masking govt link", risk:75 },
    { pattern: /[a-z]{3,}-gov-[a-z]{2,}\./i,     label:"Hyphenated fake govt domain", risk:80 },
    { pattern: /\.(tk|ml|ga|cf|gq|icu|sbs)\//i,  label:"High-abuse free TLD used for govt impersonation", risk:85 },
    { pattern: /apply|register|claim|subsidy/i,  label:"Action keyword in govt URL (phishing landing)", risk:60 },
  ];
  for (const ss of SUSPICIOUS_STRUCTURES) {
    if (ss.pattern.test(url) && detections.length > 0) {
      detections.push({
        type: "suspicious_url_structure",
        name: "Suspicious URL Structure",
        risk: ss.risk,
        severity: ss.risk >= 80 ? 5 : 4,
        signal: ss.label,
        mitre: "T1036.005 - Masquerading",
      });
    }
  }

  // 6. Content signals
  let contentRisk = 0;
  const contentSignals = [];
  for (const cs of FAKE_GOVT_CONTENT_SIGNALS) {
    if (cs.pattern.test(pageContent)) {
      contentRisk += cs.weight;
      contentSignals.push(cs.signal);
    }
  }
  if (contentRisk >= 25) {
    const baseRisk = detections.length > 0 ? Math.min(65 + contentRisk, 98) : Math.min(40 + contentRisk, 70);
    detections.push({
      type: "govt_content_harvesting",
      name: "Government portal impersonation with sensitive data harvesting",
      risk: baseRisk,
      severity: baseRisk >= 80 ? 5 : 4,
      signal: `Fake govt page harvesting sensitive data: ${contentSignals.join(", ")}`,
      mitre: "T1056.003 - Web Portal Capture",
      contentScore: contentRisk,
    });
  }

  const isDetected = detections.length > 0;
  const maxRisk = isDetected ? Math.max(...detections.map((d) => d.risk)) : 0;

  return {
    isGovtImpersonation: isDetected,
    riskBoost: maxRisk,
    detections,
    homoglyphs: homoglyphHits,
    contentScore: contentRisk,
    helpline: isDetected ? "Report at cybercrime.gov.in or call 1930" : null,
    realPortal: detections[0]?.real || null,
  };
}

module.exports.detectFakeGovtPortal = detectFakeGovtPortal;
module.exports.REAL_GOVT_DOMAINS = REAL_GOVT_DOMAINS;

// ════════════════════════════════════════════════════════════════
// FILE: backend/services/networkAnomalyEngine.js — CREATE NEW
// AI-Based Network Anomaly Detection
// Real-world use: Processes log events (from Fluent Bit) and
// builds a baseline of normal behavior per host/user. Detects
// deviations: unusual login times, impossible travel, data
// exfiltration spikes, lateral movement patterns, and C2 beaconing.
// Uses statistical z-score deviation for anomaly scoring.
// ════════════════════════════════════════════════════════════════

const AnomalySchema = new mongoose.Schema({
  anomalyId: {
    type: String,
    default: () => `ANO-${Date.now().toString(36).toUpperCase()}`,
    unique: true,
  },
  type: {
    type: String,
    enum: [
      "impossible_travel",
      "unusual_time",
      "high_volume",
      "lateral_movement",
      "data_exfiltration",
      "c2_beaconing",
      "port_scan",
      "dns_tunneling",
      "privilege_escalation",
      "new_device",
      "credential_stuffing",
      "other",
    ],
    required: true,
    index: true,
  },
  severity: { type: Number, min: 1, max: 5, required: true },
  score: { type: Number, min: 0, max: 100, default: 50 },
  host: { type: String, default: null, index: true },
  user: { type: String, default: null, index: true },
  sourceIp: { type: String, default: null },
  destIp: { type: String, default: null },
  description: { type: String, required: true },
  evidence: { type: mongoose.Schema.Types.Mixed, default: {} },
  baseline: { type: mongoose.Schema.Types.Mixed, default: {} },
  observed: { type: mongoose.Schema.Types.Mixed, default: {} },
  zScore: { type: Number, default: null },
  mitre: { type: String, default: null },
  status: {
    type: String,
    enum: ["open", "investigating", "resolved", "false_positive"],
    default: "open",
  },
  createdAt: { type: Date, default: Date.now, index: true },
});

const NetworkAnomaly = mongoose.model("NetworkAnomaly", AnomalySchema);

// ── Baseline profile schema (per host/user) ───────────────────
const BaselineSchema = new mongoose.Schema(
  {
    entityType: { type: String, enum: ["host", "user", "ip"], required: true },
    entityId: { type: String, required: true },
    // Login patterns
    loginHours: { type: [Number], default: [] }, // hour of day (0-23) distribution
    loginDays: { type: [Number], default: [] }, // day of week (0-6)
    avgDailyLogins: { type: Number, default: 0 },
    // Geographic
    knownIPs: { type: [String], default: [] },
    knownCountries: { type: [String], default: [] },
    // Volume
    avgDailyBytes: { type: Number, default: 0 },
    avgDailyDns: { type: Number, default: 0 },
    avgDailyLogsPerHour: { type: Number, default: 0 },
    // Process
    knownProcesses: { type: [String], default: [] },
    // Metadata
    sampleCount: { type: Number, default: 0 },
    lastUpdated: { type: Date, default: Date.now },
  },
  { timestamps: true },
);
BaselineSchema.index({ entityType: 1, entityId: 1 }, { unique: true });

const Baseline = mongoose.model("NetworkBaseline", BaselineSchema);

// ── Z-score computation ────────────────────────────────────────
function zScore(value, mean, stddev) {
  if (!stddev || stddev === 0) return 0;
  return Math.abs((value - mean) / stddev);
}

function stdDev(arr) {
  if (!arr.length) return 0;
  const mean = arr.reduce((a, b) => a + b, 0) / arr.length;
  const sq = arr.map((v) => (v - mean) ** 2);
  return Math.sqrt(sq.reduce((a, b) => a + b, 0) / arr.length);
}

// ── Core anomaly detection ─────────────────────────────────────
async function detectAnomaly(logEvent) {
  const { logType, sourceIp, sourceUser, sourceHost, rawData, timestamp } =
    logEvent;
  const anomalies = [];
  const now = new Date(timestamp || Date.now());
  const hour = now.getHours();
  const day = now.getDay();

  // Get baseline for this user/host
  const entityId = sourceUser || sourceHost || sourceIp;
  if (!entityId) return [];

  let baseline = await Baseline.findOne({
    entityType: sourceUser ? "user" : "host",
    entityId,
  }).lean();

  // ── 1. Unusual login time ──────────────────────────────────
  if (logType === "failed_login" || logType === "successful_login") {
    if (baseline?.loginHours?.length >= 10) {
      const mean =
        baseline.loginHours.reduce((a, b) => a + b, 0) /
        baseline.loginHours.length;
      const sd = stdDev(baseline.loginHours);
      const z = zScore(hour, mean, sd);
      if (z > 3) {
        anomalies.push({
          type: "unusual_time",
          severity: 3,
          score: Math.min(50 + z * 10, 90),
          host: sourceHost,
          user: sourceUser,
          sourceIp,
          description: `Unusual login time: ${hour}:00 for user "${sourceUser}". Baseline peak: ${Math.round(mean)}:00 ±${Math.round(sd)}h (z=${z.toFixed(1)})`,
          evidence: { hour, baseline_mean: mean, baseline_sd: sd, z_score: z },
          zScore: z,
          mitre: "T1078 - Valid Accounts",
        });
      }
    }
  }

  // ── 2. High-volume failed logins (brute force) ────────────
  if (logType === "failed_login") {
    const recent = await Baseline.findOne({
      entityType: "ip",
      entityId: sourceIp,
    }).lean();
    if (rawData?.attemptCount >= 20 || !recent) {
      anomalies.push({
        type: "credential_stuffing",
        severity: 4,
        score: 80,
        host: sourceHost,
        user: sourceUser,
        sourceIp,
        description: `High-volume login failures from ${sourceIp}: ${rawData?.attemptCount || "multiple"} attempts. Pattern matches credential stuffing attack.`,
        evidence: { attemptCount: rawData?.attemptCount, sourceIp },
        mitre: "T1110.004 - Credential Stuffing",
      });
    }
  }

  // ── 3. Lateral movement (process on unusual host) ─────────
  if (logType === "suspicious_process" && rawData?.process) {
    const LATERAL_TOOLS = [
      "psexec",
      "wmic",
      "net use",
      "mimikatz",
      "cobalt",
      "beacon",
      "meterpreter",
      "powershell -enc",
      "invoke-expression",
      "iex ",
      "certutil",
      "bitsadmin",
    ];
    const cmdline = (rawData.commandLine || "").toLowerCase();
    const hits = LATERAL_TOOLS.filter((t) => cmdline.includes(t));
    if (hits.length > 0) {
      anomalies.push({
        type: "lateral_movement",
        severity: 5,
        score: 90,
        host: sourceHost,
        user: sourceUser,
        sourceIp,
        description: `Lateral movement tool detected on ${sourceHost}: "${hits[0]}" in command line. MITRE T1570/T1021.`,
        evidence: {
          process: rawData.process,
          commandLine: rawData.commandLine?.substring(0, 200),
          matchedTools: hits,
        },
        mitre: "T1570 - Lateral Tool Transfer",
      });
    }
  }

  // ── 4. DNS anomaly (tunneling / C2 beaconing) ─────────────
  if (logType === "dns_query" && rawData?.queriedDomain) {
    const domain = rawData.queriedDomain;
    const domainLen = domain.length;
    const labelCount = domain.split(".").length;
    // Long domain with many labels = potential DNS tunneling
    if (domainLen > 50 || labelCount > 5) {
      anomalies.push({
        type: "dns_tunneling",
        severity: 4,
        score: 75,
        host: sourceHost,
        description: `Suspicious DNS query: "${domain.substring(0, 60)}..." — unusually long domain (${domainLen} chars, ${labelCount} labels). Possible DNS tunneling or C2 beaconing.`,
        evidence: {
          domain: domain.substring(0, 100),
          length: domainLen,
          labels: labelCount,
        },
        mitre: "T1071.004 - DNS Application Layer Protocol",
      });
    }
    // Known C2/malware domains (simplified check)
    const BAD_TLDS = [
      ".top",
      ".xyz",
      ".tk",
      ".ml",
      ".ga",
      ".cf",
      ".gq",
      ".icu",
      ".sbs",
    ];
    if (BAD_TLDS.some((t) => domain.endsWith(t))) {
      anomalies.push({
        type: "c2_beaconing",
        severity: 4,
        score: 70,
        host: sourceHost,
        description: `DNS query to high-abuse TLD domain: ${domain} — commonly used for malware C2 infrastructure.`,
        evidence: { domain },
        mitre: "T1071.004 - DNS C2",
      });
    }
  }

  // ── 5. PowerShell obfuscation ──────────────────────────────
  if (logType === "powershell_execution" && rawData?.commandLine) {
    const cmd = rawData.commandLine;
    const OBFUS_SIGNALS = [
      "-enc ", "-encodedcommand", "-nop ", "-noprofile",
      "-w hidden", "invoke-expression", "iex(", "frombase64",
      "downloadstring", "net.webclient", "bypass", "unrestricted",
      "invoke-mimikatz", "invoke-shellcode", "invoke-reflectivepeinjection",
    ];
    const hits = OBFUS_SIGNALS.filter((s) => cmd.toLowerCase().includes(s));
    if (hits.length >= 2) {
      anomalies.push({
        type: "lateral_movement",
        severity: 5,
        score: Math.min(85 + hits.length * 2, 95),
        host: sourceHost,
        user: sourceUser,
        description: `Obfuscated PowerShell: ${hits.length} evasion signals (${hits.slice(0, 3).join(", ")}). Possible payload download or in-memory execution.`,
        evidence: { commandLine: cmd.substring(0, 300), signals: hits },
        mitre: "T1059.001 - PowerShell Obfuscation",
      });
    }
  }

  // ── 6. Data exfiltration — large outbound transfer ────────
  if (logType === "network_connection" && rawData?.bytesSent) {
    const MB = rawData.bytesSent / (1024 * 1024);
    const destPort = rawData.destPort;
    const NON_STANDARD_PORTS = [4444, 1337, 31337, 8888, 9999, 6666, 2222];
    if (MB > 100 || (MB > 10 && NON_STANDARD_PORTS.includes(destPort))) {
      anomalies.push({
        type: "data_exfiltration",
        severity: MB > 500 ? 5 : 4,
        score: Math.min(60 + MB / 10, 95),
        host: sourceHost,
        user: sourceUser,
        sourceIp,
        destIp: rawData.destIp,
        description: `Large outbound transfer: ${Math.round(MB)} MB to ${rawData.destIp || "unknown"}:${destPort}. Possible data exfiltration.`,
        evidence: { bytesSent: rawData.bytesSent, destPort, destIp: rawData.destIp },
        mitre: "T1041 - Exfiltration Over C2 Channel",
      });
    }
  }

  // ── 7. C2 beaconing — regular interval connections ────────
  if (logType === "c2_beacon_detected" || (logType === "network_connection" && rawData?.isBeaconing)) {
    anomalies.push({
      type: "c2_beaconing",
      severity: 5,
      score: 90,
      host: sourceHost,
      user: sourceUser,
      sourceIp,
      description: `C2 beaconing detected from ${sourceHost}: regular-interval connections to ${rawData?.destIp || "external IP"}. Possible malware callback.`,
      evidence: rawData || {},
      mitre: "T1071 - Application Layer Protocol (C2 Beaconing)",
    });
  }

  // ── 8. Privilege escalation ───────────────────────────────
  if (logType === "privilege_escalation" || (logType === "suspicious_process" && rawData?.process)) {
    const PRIV_ESC_TOOLS = [
      "mimikatz","metasploit","cobalt strike","empire","meterpreter",
      "printspoofer","juicypotato","sweetpotato","rottenpotato",
      "beroot","wesng","sherlock","powerup","seatbelt",
      "winpeas","linpeas","linux-exploit-suggester",
    ];
    const cmdline = ((rawData?.commandLine || "") + " " + (rawData?.process || "")).toLowerCase();
    const hits = PRIV_ESC_TOOLS.filter(t => cmdline.includes(t));
    if (hits.length > 0 || logType === "privilege_escalation") {
      anomalies.push({
        type: "privilege_escalation",
        severity: 5,
        score: 92,
        host: sourceHost,
        user: sourceUser,
        sourceIp,
        description: `Privilege escalation ${hits.length > 0 ? `tool: "${hits[0]}"` : "event"}. Attacker attempting SYSTEM/root access on ${sourceHost}.`,
        evidence: { process: rawData?.process, commandLine: rawData?.commandLine?.substring(0, 200), tools: hits },
        mitre: "T1068 - Exploitation for Privilege Escalation",
      });
    }
  }

  // ── 9. USB / removable media (data exfil vector) ──────────
  if (logType === "usb_activity" && rawData?.isRegistered === false) {
    anomalies.push({
      type: "data_exfiltration",
      severity: 3,
      score: 65,
      host: sourceHost,
      user: sourceUser,
      description: `Unregistered USB device on ${sourceHost} by ${sourceUser || "unknown"}. Potential data theft or malware delivery.`,
      evidence: { deviceId: rawData?.deviceId, host: sourceHost },
      mitre: "T1091 - Replication Through Removable Media",
    });
  }

  // ── 10. New device login ──────────────────────────────────
  if ((logType === "successful_login" || logType === "failed_login") && baseline?.knownIPs?.length >= 3) {
    if (sourceIp && !baseline.knownIPs.includes(sourceIp)) {
      anomalies.push({
        type: "new_device",
        severity: 2,
        score: 55,
        host: sourceHost,
        user: sourceUser,
        sourceIp,
        description: `Login from new/unrecognized IP: ${sourceIp} for "${sourceUser}". Not in baseline (${baseline.knownIPs.length} known IPs).`,
        evidence: { newIp: sourceIp, knownIps: baseline.knownIPs.slice(0, 5) },
        zScore: 2.0,
        mitre: "T1078 - Valid Accounts (New Location)",
      });
    }
  }

  // Save detected anomalies
  const saved = [];
  for (const a of anomalies) {
    try {
      const doc = await new NetworkAnomaly({ ...a }).save();
      saved.push(doc);
    } catch {}
  }

  // Update baseline (async, non-blocking)
  updateBaseline(entityId, sourceUser ? "user" : "host", logEvent).catch(
    () => {},
  );

  return saved;
}

// ── Update behavioral baseline ─────────────────────────────────
async function updateBaseline(entityId, entityType, logEvent) {
  const now = new Date();
  const hour = now.getHours();
  const update = {
    $push: { loginHours: { $each: [hour], $slice: -200 } },
    $set: { lastUpdated: now },
    $inc: { sampleCount: 1 },
  };
  if (logEvent.sourceIp) update.$addToSet = { knownIPs: logEvent.sourceIp };
  await Baseline.findOneAndUpdate({ entityType, entityId }, update, {
    upsert: true,
    new: true,
  }).catch(() => {});
}

async function getAnomalyStats() {
  const since24h = new Date(Date.now() - 24 * 60 * 60 * 1000);
  const [total, open, byType, recent, critical] = await Promise.all([
    NetworkAnomaly.countDocuments({}),
    NetworkAnomaly.countDocuments({ status: "open" }),
    NetworkAnomaly.aggregate([
      { $group: { _id: "$type", count: { $sum: 1 } } },
    ]),
    NetworkAnomaly.find({ createdAt: { $gte: since24h } })
      .sort({ createdAt: -1 })
      .limit(10)
      .lean(),
    NetworkAnomaly.countDocuments({ severity: 5, status: "open" }),
  ]);
  return {
    total,
    open,
    critical,
    byType: Object.fromEntries(byType.map((t) => [t._id, t.count])),
    recent,
  };
}

module.exports.NetworkAnomaly = NetworkAnomaly;
module.exports.detectAnomaly = detectAnomaly;
module.exports.getAnomalyStats = getAnomalyStats;
