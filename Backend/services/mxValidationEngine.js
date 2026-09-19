"use strict";

// ════════════════════════════════════════════════════════════════
// GAP 5 FIX: MX Record Validation + Live SPF Cross-Check
// FILE: backend/services/mxValidationEngine.js
//
// Validates whether the actual sending server matches the domain's
// declared mail infrastructure via live DNS lookups.
// ════════════════════════════════════════════════════════════════

const dns = require("dns").promises;

// ── DNS cache (10 min TTL) ────────────────────────────────────
const MX_CACHE = new Map();
const SPF_CACHE = new Map();
const CACHE_TTL = 10 * 60 * 1000;

// ── Known mail providers by MX pattern ───────────────────────
const MX_PROVIDERS = [
  {
    pattern: /google\.com|gmail-smtp-in\.l\.google\.com|googlemail\.com/i,
    name: "Google Workspace",
    tier: "enterprise",
  },
  {
    pattern: /outlook\.com|mail\.protection\.outlook\.com|hotmail\.com/i,
    name: "Microsoft 365",
    tier: "enterprise",
  },
  {
    pattern: /amazonses\.com|amazon\.com|amazonaws\.com/i,
    name: "Amazon SES",
    tier: "enterprise",
  },
  {
    pattern: /sendgrid\.net|sendgrid\.com/i,
    name: "SendGrid",
    tier: "transactional",
  },
  {
    pattern: /mailgun\.org|mailgun\.net/i,
    name: "Mailgun",
    tier: "transactional",
  },
  {
    pattern: /zoho\.com|zohomail\.com/i,
    name: "Zoho Mail",
    tier: "enterprise",
  },
  {
    pattern: /mimecast\.com|mimecast\.org/i,
    name: "Mimecast",
    tier: "enterprise",
  },
  { pattern: /pphosted\.com/i, name: "Proofpoint", tier: "enterprise" },
  { pattern: /barracudanetworks\.com/i, name: "Barracuda", tier: "enterprise" },
  {
    pattern: /messagelabs\.com|symantec\.com/i,
    name: "Symantec/MessageLabs",
    tier: "enterprise",
  },
  {
    pattern: /securesmtp|secureserver\.net|godaddy/i,
    name: "GoDaddy",
    tier: "consumer",
  },
  { pattern: /yandex\.net|yandex\.ru/i, name: "Yandex Mail", tier: "consumer" },
  {
    pattern: /yahoo\.com|yahoodns\.net/i,
    name: "Yahoo Mail",
    tier: "consumer",
  },
  {
    pattern: /protonmail\.ch|proton\.me/i,
    name: "ProtonMail",
    tier: "privacy",
  },
  { pattern: /forwardemail\.net/i, name: "Forward Email", tier: "forwarding" },
];

// ── DNS lookup with timeout ───────────────────────────────────
async function dnsWithTimeout(fn, ms = 2500) {
  return Promise.race([
    fn(),
    new Promise((_, rej) =>
      setTimeout(() => rej(new Error("dns_timeout")), ms),
    ),
  ]).catch(() => null);
}

// ── Fetch MX records with cache ───────────────────────────────
async function getMXRecords(domain) {
  const cached = MX_CACHE.get(domain);
  if (cached && Date.now() - cached.ts < CACHE_TTL) return cached.data;

  const records =
    (await dnsWithTimeout(() =>
      dns
        .resolveMx(domain)
        .then((r) => r.map((m) => m.exchange.toLowerCase()).sort()),
    )) || [];

  MX_CACHE.set(domain, { ts: Date.now(), data: records });
  return records;
}

// ── Fetch SPF record with cache ───────────────────────────────
async function getSPFRecord(domain) {
  const cached = SPF_CACHE.get(domain);
  if (cached && Date.now() - cached.ts < CACHE_TTL) return cached.data;

  const records =
    (await dnsWithTimeout(() =>
      dns.resolveTxt(domain).then((recs) => recs.flat()),
    )) || [];

  const spf = records.find((r) => r.toLowerCase().startsWith("v=spf1")) || null;
  SPF_CACHE.set(domain, { ts: Date.now(), data: spf });
  return spf;
}

// ── Parse SPF record into authorized IP ranges ────────────────
function parseSPFRecord(spfRecord) {
  if (!spfRecord)
    return { ip4Ranges: [], ip6Ranges: [], includes: [], all: null };

  const ip4Ranges = [];
  const ip6Ranges = [];
  const includes = [];
  let all = null;

  const parts = spfRecord.split(/\s+/);
  for (const part of parts) {
    const lower = part.toLowerCase();
    if (lower.startsWith("ip4:")) {
      ip4Ranges.push(part.substring(4));
    } else if (lower.startsWith("ip6:")) {
      ip6Ranges.push(part.substring(4));
    } else if (lower.startsWith("include:")) {
      includes.push(part.substring(8));
    } else if (
      lower === "-all" ||
      lower === "~all" ||
      lower === "?all" ||
      lower === "+all"
    ) {
      all = lower;
    }
  }

  return { ip4Ranges, ip6Ranges, includes, all };
}

// ── Check if IP is in CIDR range ─────────────────────────────
function ipInCIDR(ip, cidr) {
  try {
    const [range, bits] = cidr.split("/");
    const mask = bits ? parseInt(bits) : 32;
    const ipNum = ipToNum(ip);
    const rangeNum = ipToNum(range);
    if (ipNum === null || rangeNum === null) return false;
    const shift = 32 - mask;
    return ipNum >>> shift === rangeNum >>> shift;
  } catch {
    return false;
  }
}

function ipToNum(ip) {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  return parts.reduce((acc, oct) => (acc << 8) + parseInt(oct), 0) >>> 0;
}

// ── Live SPF validation against originating IP ────────────────
async function validateSPFLive(domain, sourceIP) {
  if (!domain || !sourceIP) return { result: "error", mechanism: null };

  const spfRecord = await getSPFRecord(domain);
  if (!spfRecord) return { result: "none", mechanism: null, spfRecord: null };

  const { ip4Ranges, ip6Ranges, includes, all } = parseSPFRecord(spfRecord);

  // Check ip4 ranges
  for (const range of ip4Ranges) {
    if (ipInCIDR(sourceIP, range.includes("/") ? range : range + "/32")) {
      return { result: "pass", mechanism: `ip4:${range}`, spfRecord };
    }
  }

  // Check includes (one level deep — full recursive resolve would require
  // more DNS calls, so we check the include domain's SPF)
  for (const includeDomain of includes.slice(0, 5)) {
    // max 5 includes
    const includeSPF = await getSPFRecord(includeDomain);
    if (!includeSPF) continue;
    const { ip4Ranges: incIP4 } = parseSPFRecord(includeSPF);
    for (const range of incIP4) {
      if (ipInCIDR(sourceIP, range.includes("/") ? range : range + "/32")) {
        return {
          result: "pass",
          mechanism: `include:${includeDomain} → ip4:${range}`,
          spfRecord,
        };
      }
    }
  }

  // Check all directive
  if (all === "-all") return { result: "fail", mechanism: "-all", spfRecord };
  if (all === "~all")
    return { result: "softfail", mechanism: "~all", spfRecord };
  if (all === "?all")
    return { result: "neutral", mechanism: "?all", spfRecord };

  return { result: "neutral", mechanism: null, spfRecord };
}

// ── Identify MX provider ──────────────────────────────────────
function identifyMXProvider(mxRecords) {
  if (!mxRecords?.length) return { name: "None", tier: "none" };

  const mxStr = mxRecords.join(" ");
  for (const provider of MX_PROVIDERS) {
    if (provider.pattern.test(mxStr))
      return { name: provider.name, tier: provider.tier };
  }

  return { name: "Unknown/Self-hosted", tier: "unknown" };
}

// ── Check if relay chain passes through declared MX ───────────
function checkMXMismatch(mxRecords, relayChain) {
  if (!mxRecords?.length || !relayChain?.length) {
    return { mismatch: false, detail: "Insufficient data for MX validation" };
  }

  // Get all hostnames from the relay chain "by" fields
  const relayHosts = relayChain
    .map((h) => h.byHost?.toLowerCase() || "")
    .filter(Boolean);

  // Check if any relay host matches any MX record
  for (const relay of relayHosts) {
    for (const mx of mxRecords) {
      if (
        relay.includes(mx) ||
        mx.includes(relay) ||
        relay.split(".").slice(-2).join(".") ===
          mx.split(".").slice(-2).join(".")
      ) {
        return {
          mismatch: false,
          detail: `Email routed through declared MX server: ${mx}`,
        };
      }
    }
  }

  // No match — MX mismatch
  return {
    mismatch: true,
    detail:
      `Email relay chain (${relayHosts.slice(0, 2).join(", ")}) does not pass through ` +
      `declared MX servers (${mxRecords.slice(0, 2).join(", ")}). ` +
      `Legitimate emails always route through the domain's declared mail servers.`,
  };
}

// ════════════════════════════════════════════════════════════════
// MAIN FUNCTION — validateMXAndSPF()
// ════════════════════════════════════════════════════════════════

async function validateMXAndSPF(domain, sourceIP, relayChain = []) {
  if (!domain) return null;

  const anomalies = [];
  let mxRiskScore = 0;

  const addAnomaly = (a) => {
    anomalies.push(a);
    mxRiskScore += a.risk;
  };

  // ── 1. Fetch MX records ───────────────────────────────────
  const mxRecords = await getMXRecords(domain);
  const mxProvider = identifyMXProvider(mxRecords);
  const hasMX = mxRecords.length > 0;

  // ── 2. Live SPF validation ────────────────────────────────
  const spfResult = sourceIP
    ? await validateSPFLive(domain, sourceIP)
    : { result: "error", mechanism: null, spfRecord: null };

  // ── 3. MX mismatch check ─────────────────────────────────
  const mxCheck = checkMXMismatch(mxRecords, relayChain);

  // ── 4. Infrastructure anomaly detection ──────────────────

  // No MX at all
  if (!hasMX) {
    addAnomaly({
      type: "no_mx",
      label: "No MX records — domain cannot send email",
      detail: `"${domain}" has no MX records. Legitimate organizations always configure MX records for their mail domain.`,
      risk: 35,
    });
  }

  // Live SPF fail (more reliable than header-based check)
  if (spfResult.result === "fail") {
    addAnomaly({
      type: "spf_live_fail",
      label: "Live SPF validation: FAIL",
      detail:
        `Real-time DNS SPF check: IP ${sourceIP} is NOT authorized to send email for ${domain}. ` +
        `SPF policy: ${spfResult.spfRecord?.substring(0, 80) || "none"}`,
      risk: 45,
    });
  } else if (spfResult.result === "softfail") {
    addAnomaly({
      type: "spf_live_softfail",
      label: "Live SPF validation: SOFTFAIL",
      detail: `Real-time DNS SPF check: IP ${sourceIP} is not fully authorized (softfail ~all). ${domain}'s SPF policy doesn't explicitly permit this sender.`,
      risk: 20,
    });
  } else if (spfResult.result === "none") {
    addAnomaly({
      type: "no_spf_record",
      label: "No SPF record published",
      detail: `Domain "${domain}" has no SPF TXT record — anyone can forge email from this domain without SPF protection.`,
      risk: 15,
    });
  }

  // MX mismatch
  if (mxCheck.mismatch) {
    addAnomaly({
      type: "mx_mismatch",
      label: "MX server mismatch",
      detail: mxCheck.detail,
      risk: 30,
    });
  }

  // Consumer MX for corporate-looking domain
  if (
    mxProvider.tier === "consumer" &&
    !domain.includes("gmail") &&
    !domain.includes("yahoo") &&
    !domain.includes("hotmail")
  ) {
    addAnomaly({
      type: "consumer_mx_corporate_domain",
      label: `Consumer mail platform for corporate domain`,
      detail:
        `"${domain}" routes email through ${mxProvider.name} — unusual for a legitimate corporate domain. ` +
        `Attackers often use consumer email services to send spoofed corporate emails.`,
      risk: 20,
    });
  }

  // SPF pass but MX mismatch is a contradiction
  if (spfResult.result === "pass" && mxCheck.mismatch && hasMX) {
    addAnomaly({
      type: "spf_pass_mx_mismatch",
      label: "SPF pass but MX route bypassed",
      detail: `Email passed SPF but bypassed the domain's MX servers — possible authorized third-party sender or forwarding service. Verify legitimacy.`,
      risk: 10,
    });
  }

  return {
    domain,

    // MX data
    mxRecords,
    hasMX,
    mxProvider: mxProvider.name,
    mxProviderTier: mxProvider.tier,

    // SPF data
    spfRecord: spfResult.spfRecord,
    spfLiveResult: spfResult.result, // our live check
    spfMatchedMechanism: spfResult.mechanism,

    // Mismatch
    mxMismatch: mxCheck.mismatch,
    mxMismatchDetail: mxCheck.detail,

    // Summary
    infrastructureAnomaly: anomalies.length > 0,
    anomalies,
    mxRiskScore: Math.min(mxRiskScore, 70), // cap at 70
  };
}

module.exports = { validateMXAndSPF, getSPFRecord, getMXRecords };
