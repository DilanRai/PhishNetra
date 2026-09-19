// FILE: backend/siem/behaviorEngine.js
// Tracks IP behavior over time — detects threat actors, campaign patterns

const Scan = require("../models/Scan");

// ── Analyze behavior for a specific IP ──
async function buildIPProfile(ip) {
  if (!ip || ip === "unknown" || ip === "::1") return null;
  const since = new Date(Date.now() - 24 * 60 * 60 * 1000);

  const scans = await Scan.find(
    { sourceIp: ip, createdAt: { $gte: since } },
    { status: 1, riskScore: 1, "dna.brand": 1, "dna.technique": 1, inputType: 1, createdAt: 1 }
  ).lean();

  if (scans.length === 0) return null;

  const phishing   = scans.filter(s => s.status === "phishing");
  const brands     = [...new Set(scans.map(s => s.dna?.brand).filter(Boolean))];
  const techniques = [...new Set(scans.map(s => s.dna?.technique).filter(Boolean))];
  const avgScore   = scans.reduce((a, s) => a + s.riskScore, 0) / scans.length;

  // Threat level calculation
  let threatLevel = "low";
  if (phishing.length >= 10 || avgScore >= 75)              threatLevel = "critical";
  else if (phishing.length >= 5  || avgScore >= 55)          threatLevel = "high";
  else if (phishing.length >= 2  || avgScore >= 35)          threatLevel = "medium";

  return {
    ip,
    totalScans:    scans.length,
    phishingCount: phishing.length,
    phishingRate:  Math.round((phishing.length / scans.length) * 100),
    avgRiskScore:  Math.round(avgScore),
    targetedBrands: brands,
    techniques,
    threatLevel,
    firstSeen: scans[scans.length - 1]?.createdAt,
    lastSeen:  scans[0]?.createdAt,
    isThreatActor: phishing.length >= 3,
  };
}

// ── Get all active threat actors (last 24h) ──
async function getActiveThreatActors() {
  const since = new Date(Date.now() - 24 * 60 * 60 * 1000);

  const ipGroups = await Scan.aggregate([
    { $match: {
        createdAt: { $gte: since },
        status:    "phishing",           // only look at confirmed phishing scans
        sourceIp:  { $nin: [null, "unknown"] },  // keep loopback IPs — useful in dev/testing
    }},
    { $group: {
        _id:           "$sourceIp",
        totalScans:    { $sum: 1 },
        phishingCount: { $sum: 1 },      // every doc here is phishing (filtered above)
        avgScore:      { $avg: "$riskScore" },
        brands:        { $addToSet: "$dna.brand" },
        techniques:    { $addToSet: "$dna.technique" },
        lastSeen:      { $max: "$createdAt" },
    }},
    { $match: { phishingCount: { $gte: 1 } } },  // threshold: 1+ phishing scan from the same IP
    { $sort:  { phishingCount: -1 } },
    { $limit: 20 },
  ]);

  // Also get total scans per IP (for rate calculation)
  const ips = ipGroups.map(g => g._id);
  const totalsByIp = ips.length > 0
    ? await Scan.aggregate([
        { $match: { createdAt: { $gte: since }, sourceIp: { $in: ips } } },
        { $group: { _id: "$sourceIp", total: { $sum: 1 } } },
      ])
    : [];
  const totalsMap = Object.fromEntries(totalsByIp.map(t => [t._id, t.total]));

  return ipGroups.map(g => {
    const total = totalsMap[g._id] || g.phishingCount;
    return {
      ip:             g._id,
      totalScans:     total,
      phishingCount:  g.phishingCount,
      phishingRate:   Math.round((g.phishingCount / total) * 100),
      avgScore:       Math.round(g.avgScore),
      targetedBrands: g.brands.filter(Boolean),
      techniques:     g.techniques.filter(Boolean),
      lastSeen:       g.lastSeen,
      threatLevel:    g.phishingCount >= 10 ? "critical"
                    : g.phishingCount >= 5  ? "high"
                    : g.phishingCount >= 2  ? "medium"
                    : "low",
    };
  });
}

// ── Detect brand-specific campaign spikes ──
async function detectCampaignSpikes() {
  // Widen window to 24h — 2h is too narrow to ever show anything in dev/testing
  const since = new Date(Date.now() - 24 * 60 * 60 * 1000);

  const brandSpikes = await Scan.aggregate([
    { $match: {
        createdAt:   { $gte: since },
        status:      "phishing",
        "dna.brand": { $nin: [null, "unknown", ""] },
    }},
    { $group: {
        _id:   "$dna.brand",
        count: { $sum: 1 },
        ips:   { $addToSet: "$sourceIp" },
    }},
    { $match: { count: { $gte: 2 } } },   // lowered from 3 so small datasets show up
    { $sort:  { count: -1 } },
  ]);

  return brandSpikes.map(b => ({
    brand:       b._id,
    count:       b.count,
    uniqueIPs:   b.ips.filter(Boolean).length,
    isCampaign:  b.count >= 5 || b.ips.length >= 3,
  }));
}

module.exports = { buildIPProfile, getActiveThreatActors, detectCampaignSpikes };