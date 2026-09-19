// FILE: backend/services/adversaryEngine.js
// Adversary Fingerprinting — builds actor profiles from scan patterns
// Technique: behavioral clustering + TTP extraction (CrowdStrike/Mandiant approach)

const Scan = require("../models/Scan");
const crypto = require("crypto");
const geoip = require("geoip-lite");

// ── Generate a stable actor ID from IP range + technique pattern ──
function generateActorId(ip, primaryTechnique) {
  const ipBlock = ip.split(".").slice(0, 3).join(".");
  const hash = crypto
    .createHash("sha256")
    .update(`${ipBlock}::${primaryTechnique}`)
    .digest("hex")
    .slice(0, 6)
    .toUpperCase();
  return `ACTOR-${hash}`;
}

// ── Analyze operating schedule from timestamps ──
function analyzeSchedule(timestamps) {
  if (!timestamps.length) return null;

  const hourCounts = Array(24).fill(0);
  const dayCounts = Array(7).fill(0);
  const DAY_NAMES = [
    "Sunday",
    "Monday",
    "Tuesday",
    "Wednesday",
    "Thursday",
    "Friday",
    "Saturday",
  ];

  timestamps.forEach((ts) => {
    const d = new Date(ts);
    hourCounts[d.getHours()]++;
    dayCounts[d.getDay()]++;
  });

  // Find active hours (top 50% of activity)
  const maxHour = Math.max(...hourCounts);
  const activeHours = hourCounts
    .map((c, h) => ({ h, c }))
    .filter((x) => x.c >= maxHour * 0.4)
    .map((x) => x.h);

  // Operating window
  const minHour = activeHours.length ? Math.min(...activeHours) : 0;
  const maxHr = activeHours.length ? Math.max(...activeHours) : 23;

  // Peak day
  const peakDayIdx = dayCounts.indexOf(Math.max(...dayCounts));
  const activeDays = dayCounts
    .map((c, d) => ({ d, c }))
    .filter((x) => x.c >= Math.max(...dayCounts) * 0.3)
    .map((x) => DAY_NAMES[x.d]);

  return {
    operatingHours: `${String(minHour).padStart(2, "0")}:00–${String(maxHr).padStart(2, "0")}:00 UTC`,
    peakDay: DAY_NAMES[peakDayIdx],
    activeDays,
    hourDistribution: hourCounts,
    dayDistribution: dayCounts,
  };
}

// ── Estimate domain rotation speed ──
function estimateDomainRotation(scans) {
  if (scans.length < 4) return null;
  const domains = [
    ...new Set(
      scans
        .filter((s) => s.inputType === "url")
        .map((s) => {
          try {
            const input = typeof s.input === "string" ? s.input : "";
            if (!input) return null;
            return new URL(
              input.startsWith("http") ? input : `https://${input}`,
            ).hostname;
          } catch {
            return null;
          }
        })
        .filter(Boolean),
    ),
  ];

  if (domains.length < 2) return null;
  const span =
    new Date(scans[scans.length - 1].createdAt) - new Date(scans[0].createdAt);
  const hours = span / (1000 * 60 * 60);
  const hoursPerDomain = hours / domains.length;
  return {
    uniqueDomains: domains.length,
    rotationEvery:
      hoursPerDomain < 1
        ? `~${Math.round(hoursPerDomain * 60)}min`
        : hoursPerDomain < 24
          ? `~${Math.round(hoursPerDomain)}h`
          : `~${Math.round(hoursPerDomain / 24)}d`,
    recentDomains: domains.slice(-5),
  };
}

// ── Infrastructure analysis ──
function analyzeInfrastructure(scans) {
  const ips = [...new Set(scans.map((s) => s.sourceIp).filter(Boolean))];
  const tlds = {};
  const domains = [];

  scans.forEach((s) => {
    if (s.dna?.tld && s.dna.tld !== "unknown" && s.dna.tld !== "n/a") {
      tlds[s.dna.tld] = (tlds[s.dna.tld] || 0) + 1;
    }
    if (s.inputType === "url") {
      try {
        const input = typeof s.input === "string" ? s.input : "";
        if (!input) return;
        const host = new URL(
          input.startsWith("http") ? input : `https://${input}`,
        ).hostname;
        domains.push(host);
      } catch {}
    }
  });

  // Geo analysis of source IPs
  const geoData = ips.slice(0, 10).map((ip) => {
    const geo = geoip.lookup(ip);
    return { ip, country: geo?.country || "Unknown", city: geo?.city || null };
  });

  const topTLD = Object.entries(tlds).sort((a, b) => b[1] - a[1])[0]?.[0];

  // Hosting provider heuristics based on known IP ranges
  const BULLETPROOF_RANGES = [
    { range: "185.234.", provider: "Frantech Solutions (bulletproof host)" },
    { range: "91.108.", provider: "AS62041 (known phishing infrastructure)" },
    { range: "194.165.", provider: "AS199712 (frequently abused)" },
    { range: "45.142.", provider: "AS207713 (bulletproof hosting)" },
    { range: "185.220.", provider: "Tor exit node / anonymous infrastructure" },
  ];

  const infrastructure = ips
    .slice(0, 3)
    .map((ip) => {
      const known = BULLETPROOF_RANGES.find((b) => ip.startsWith(b.range));
      return { ip, provider: known?.provider || null };
    })
    .filter((i) => i.provider);

  return {
    uniqueIPs: ips.length,
    geoDistribution: geoData,
    preferredTLD: topTLD || "unknown",
    tldBreakdown: tlds,
    uniqueDomains: [...new Set(domains)].length,
    knownInfrastructure: infrastructure,
  };
}

// ── TTP (Tactics Techniques Procedures) profile ──
function buildTTPs(scans) {
  const techniques = {};
  const brands = {};
  const fingerprints = {};
  const attackTypes = {};

  scans.forEach((s) => {
    if (s.dna?.technique)
      techniques[s.dna.technique] = (techniques[s.dna.technique] || 0) + 1;
    if (s.dna?.brand && s.dna.brand !== "unknown")
      brands[s.dna.brand] = (brands[s.dna.brand] || 0) + 1;
    if (s.dna?.fingerprint)
      fingerprints[s.dna.fingerprint] =
        (fingerprints[s.dna.fingerprint] || 0) + 1;
    (s.attackTypes || []).forEach((a) => {
      attackTypes[a] = (attackTypes[a] || 0) + 1;
    });
  });

  const sortedTechs = Object.entries(techniques).sort((a, b) => b[1] - a[1]);
  const sortedBrands = Object.entries(brands).sort((a, b) => b[1] - a[1]);
  const sortedFingers = Object.entries(fingerprints).sort(
    (a, b) => b[1] - a[1],
  );
  const sortedAttacks = Object.entries(attackTypes).sort((a, b) => b[1] - a[1]);

  // Always pairs same brands (cross-targeting pattern)
  const topBrandPairs =
    sortedBrands.length >= 2
      ? [sortedBrands[0][0], sortedBrands[1][0]]
      : sortedBrands.map((b) => b[0]);

  return {
    primaryTechnique: sortedTechs[0]?.[0] || "generic_phishing",
    allTechniques: sortedTechs.map(([t, c]) => ({ technique: t, count: c })),
    targetedBrands: sortedBrands.map(([b, c]) => ({ brand: b, count: c })),
    topBrandPairs,
    campaigns: sortedFingers.map(([f, c]) => ({ fingerprint: f, count: c })),
    attackVectors: sortedAttacks
      .slice(0, 6)
      .map(([a, c]) => ({ type: a, count: c })),
    isBEC: Object.keys(techniques).some((t) =>
      /bec|social|pretexting/i.test(t),
    ),
    isMultiPlatform: Object.keys(brands).length >= 3,
  };
}

// ── Predict next campaign ──
function predictNextCampaign(actor, schedule, ttps) {
  if (!schedule || !ttps.primaryTechnique) return null;

  // Find next peak activity window
  const now = new Date();
  const currentDay = now.getDay();
  const DAY_NAMES = [
    "Sunday",
    "Monday",
    "Tuesday",
    "Wednesday",
    "Thursday",
    "Friday",
    "Saturday",
  ];
  const peakDayIdx = DAY_NAMES.indexOf(schedule.peakDay);
  const daysUntilPeak =
    peakDayIdx >= 0 ? (peakDayIdx - currentDay + 7) % 7 || 7 : 3;

  const nextDate = new Date(
    now.getTime() + daysUntilPeak * 24 * 60 * 60 * 1000,
  );
  const predictedBrand = ttps.targetedBrands[0]?.brand || "unknown";

  // Confidence based on data volume + pattern consistency
  const confidence = Math.min(
    20 + actor.totalScans * 2 + ttps.campaigns.length * 5,
    90,
  );

  return {
    expectedDate: nextDate.toLocaleDateString("en-US", {
      weekday: "long",
      month: "short",
      day: "numeric",
    }),
    daysFromNow: daysUntilPeak,
    predictedTarget: predictedBrand,
    predictedTechnique: ttps.primaryTechnique,
    confidence,
    operatingWindow: schedule.operatingHours,
    note: `Based on ${actor.totalScans} historical scans and ${ttps.campaigns.length} campaign pattern${ttps.campaigns.length !== 1 ? "s" : ""}`,
  };
}

// ── MAIN: build full adversary profile ──
async function buildAdversaryProfile(ip) {
  if (!ip || ip === "unknown" || ip === "::1" || ip === "127.0.0.1")
    return null;

  const since30d = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
  const scans = await Scan.find(
    { sourceIp: ip, createdAt: { $gte: since30d } },
    {
      input: 1,
      status: 1,
      riskScore: 1,
      inputType: 1,
      createdAt: 1,
      "dna.fingerprint": 1,
      "dna.brand": 1,
      "dna.technique": 1,
      "dna.tld": 1,
      attackTypes: 1,
      issues: 1,
    },
  )
    .sort({ createdAt: 1 })
    .lean();

  if (scans.length < 3) return null;

  const phishScans = scans.filter((s) => s.status === "phishing");
  const timestamps = scans.map((s) => s.createdAt);

  const ttps = buildTTPs(scans);
  const schedule = analyzeSchedule(timestamps);
  const infrastructure = analyzeInfrastructure(scans);
  const rotation = estimateDomainRotation(phishScans);
  const actorId = generateActorId(ip, ttps.primaryTechnique);

  // Threat classification
  const persistenceScore =
    (phishScans.length >= 20
      ? 40
      : phishScans.length >= 10
        ? 25
        : phishScans.length >= 5
          ? 15
          : 5) +
    (ttps.campaigns.length >= 3 ? 30 : ttps.campaigns.length >= 2 ? 20 : 10) +
    (schedule?.activeDays?.length >= 3 ? 20 : 10) +
    (infrastructure.knownInfrastructure.length > 0 ? 20 : 0);

  const threatClass =
    persistenceScore >= 80
      ? "PERSISTENT THREAT ACTOR"
      : persistenceScore >= 50
        ? "ACTIVE THREAT ACTOR"
        : persistenceScore >= 30
          ? "RECURRING THREAT"
          : "OPPORTUNISTIC ACTOR";

  const riskLevel =
    persistenceScore >= 80
      ? "critical"
      : persistenceScore >= 50
        ? "high"
        : persistenceScore >= 30
          ? "medium"
          : "low";

  // Campaign history (group by fingerprint + time window)
  const campaignHistory = [];
  let currentCampaign = null;
  phishScans.forEach((s) => {
    const month = new Date(s.createdAt).toLocaleDateString("en-US", {
      month: "long",
      year: "numeric",
    });
    if (!currentCampaign || currentCampaign.month !== month) {
      currentCampaign = {
        month,
        count: 0,
        fingerprints: new Set(),
        brands: new Set(),
      };
      campaignHistory.push(currentCampaign);
    }
    currentCampaign.count++;
    if (s.dna?.fingerprint) currentCampaign.fingerprints.add(s.dna.fingerprint);
    if (s.dna?.brand && s.dna.brand !== "unknown")
      currentCampaign.brands.add(s.dna.brand);
  });

  const nextCampaign = predictNextCampaign(
    { totalScans: scans.length },
    schedule,
    ttps,
  );

  return {
    actorId,
    ip,
    threatClass,
    riskLevel,
    persistenceScore,

    // Stats
    totalScans: scans.length,
    phishingCount: phishScans.length,
    phishingRate: Math.round((phishScans.length / scans.length) * 100),
    firstSeen: scans[0].createdAt,
    lastSeen: scans[scans.length - 1].createdAt,

    // Intelligence
    ttps,
    schedule,
    infrastructure,
    domainRotation: rotation,
    campaignHistory: campaignHistory.map((c) => ({
      month: c.month,
      count: c.count,
      fingerprints: c.fingerprints.size,
      brands: [...c.brands],
    })),

    // Prediction
    nextCampaignPrediction: nextCampaign,

    generatedAt: new Date().toISOString(),
  };
}

// ── Get all adversary profiles (top threat actors) ──
async function getAllAdversaryProfiles() {
  const since30d = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);

  const topIPs = await Scan.aggregate([
    {
      $match: {
        createdAt: { $gte: since30d },
        status: "phishing",
        sourceIp: { $nin: [null, "unknown", "::1", "127.0.0.1"] },
      },
    },
    {
      $group: {
        _id: "$sourceIp",
        count: { $sum: 1 },
        lastSeen: { $max: "$createdAt" },
      },
    },
    { $match: { count: { $gte: 3 } } },
    { $sort: { count: -1 } },
    { $limit: 10 },
  ]);

  const profiles = await Promise.all(
    topIPs.map((t) => buildAdversaryProfile(t._id)),
  );

  return profiles
    .filter(Boolean)
    .sort((a, b) => b.persistenceScore - a.persistenceScore);
}

module.exports = {
  buildAdversaryProfile,
  getAllAdversaryProfiles,
  generateActorId,
};
