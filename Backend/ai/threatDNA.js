// FILE: backend/ai/threatDNA.js

const crypto = require("crypto");

// Brand targeted extraction
function extractBrand(issues = []) {
  for (const i of issues) {
    const m = i.match(/impersonat.*?"([^"]+)"|spoofing.*?"([^"]+)"/i);
    if (m) return (m[1] || m[2]).toLowerCase();
  }
  return "unknown";
}

// Attack technique from issues
function extractTechnique(issues = []) {
  if (issues.some(i => /otp|credential/i.test(i)))     return "credential_harvest";
  if (issues.some(i => /typosquat/i.test(i)))           return "typosquatting";
  if (issues.some(i => /impersonat|spoofing/i.test(i))) return "brand_impersonation";
  if (issues.some(i => /redirect/i.test(i)))            return "redirect_chain";
  if (issues.some(i => /punycode|homoglyph/i.test(i)))  return "homograph";
  if (issues.some(i => /social engineering/i.test(i)))  return "social_engineering";
  if (issues.some(i => /financial lure/i.test(i)))      return "financial_scam";
  if (issues.some(i => /attachment/i.test(i)))          return "malicious_attachment";
  return "generic_phishing";
}

// TLD extraction
function extractTLD(input = "") {
  try {
    const url   = input.startsWith("http") ? input : `https://${input}`;
    const host  = new URL(url).hostname;
    const parts = host.split(".");
    return parts.length >= 2 ? `.${parts[parts.length - 1]}` : "unknown";
  } catch { return "unknown"; }
}

// Severity bucket
function severityBucket(score) {
  if (score >= 75) return "critical";
  if (score >= 50) return "high";
  if (score >= 30) return "medium";
  return "low";
}

// ── MAIN: generate PhishDNA fingerprint ──
function generateDNA(input, result) {
  const brand     = extractBrand(result.issues);
  const technique = extractTechnique(result.issues);
  const tld       = result.inputType === "url" ? extractTLD(input) : "n/a";
  const severity  = severityBucket(result.riskScore);
  const inputType = result.inputType;

  // Canonical string — same attack pattern = same DNA
  const canonical = `${brand}::${technique}::${tld}::${inputType}`;

  // Short 8-char hex fingerprint
  const fingerprint = crypto
    .createHash("sha256")
    .update(canonical)
    .digest("hex")
    .slice(0, 8)
    .toUpperCase();

  return {
    fingerprint,          // e.g. "A3F9C21B"
    brand,                // e.g. "paypal"
    technique,            // e.g. "brand_impersonation"
    tld,                  // e.g. ".tk"
    severity,             // e.g. "critical"
    inputType,
    canonical,            // full pattern string
    generatedAt: new Date(),
  };
}

// ── Get campaign timeline for a fingerprint ──
async function getCampaignTimeline(fingerprint) {
  const Scan = require("../models/Scan");
  const scans = await Scan.find(
    { "dna.fingerprint": fingerprint },
    { input: 1, status: 1, riskScore: 1, createdAt: 1, sourceIp: 1 }
  ).sort({ createdAt: 1 }).lean();

  if (scans.length === 0) return null;

  // Group by hour for timeline
  const hourly = {};
  scans.forEach(s => {
    const hour = new Date(s.createdAt).toISOString().slice(0, 13);
    if (!hourly[hour]) hourly[hour] = { hour, count: 0, maxScore: 0 };
    hourly[hour].count++;
    hourly[hour].maxScore = Math.max(hourly[hour].maxScore, s.riskScore);
  });

  // Predicted next target (most targeted brand by same actor)
  const brands = scans.map(s => s.dna?.brand).filter(Boolean);
  const brandFreq = brands.reduce((a, b) => { a[b] = (a[b]||0)+1; return a; }, {});
  const topBrand  = Object.entries(brandFreq).sort((a,b) => b[1]-a[1])[0]?.[0];

  return {
    fingerprint,
    totalScans:    scans.length,
    firstSeen:     scans[0].createdAt,
    lastSeen:      scans[scans.length-1].createdAt,
    timeline:      Object.values(hourly).slice(-24),
    predictedTarget: topBrand || null,
    uniqueIPs:     [...new Set(scans.map(s => s.sourceIp).filter(Boolean))].length,
    peakScore:     Math.max(...scans.map(s => s.riskScore)),
  };
}

module.exports = { generateDNA, getCampaignTimeline };