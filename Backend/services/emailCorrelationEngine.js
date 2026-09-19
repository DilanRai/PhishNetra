"use strict";

const crypto    = require("crypto");
const EmailScan = require("../models/EmailScan");

// ── Correlation keys — what we group by ──────────────────────
// Each key represents a shared infrastructure signal.
// Higher weight = stronger evidence of same actor.
const CORRELATION_KEYS = [
  { key: "sourceIP",       weight: 40, label: "Same originating IP",       minCount: 2 },
  { key: "fromDomain",     weight: 30, label: "Same sender domain",         minCount: 2 },
  { key: "replyToDomain",  weight: 35, label: "Same reply-to domain",       minCount: 2 },
  { key: "firstRelayIP",   weight: 35, label: "Same first relay server",    minCount: 2 },
  { key: "mxProvider",     weight: 20, label: "Same mail infrastructure",   minCount: 3 },
  { key: "lookalikeBrand", weight: 25, label: "Targeting same brand",       minCount: 2 },
];

// ── Persist an email scan to MongoDB ─────────────────────────
async function persistEmailScan(analysisResult, options = {}) {
  const { scannedBy = "analyst" } = options;
  const r = analysisResult;

  try {
    const doc = new EmailScan({
      // Sender
      fromDomain:    r.fromDomain       || null,
      replyToDomain: r.replyToDomain    || null,

      // Network origin
      sourceIP:        r.sourceIP              || null,
      sourceCountry:   r.sourceGeo?.country    || null,
      sourceCity:      r.sourceGeo?.city       || null,
      sourceISP:       r.sourceGeo?.isp        || null,
      originType:      r.originType            || null,
      attributionConf: r.attributionConfidence ?? null,

      // Mail infrastructure
      mxProvider: r.mxValidation?.mxProvider || r.domainIntel?.mxProvider || null,
      mxServers:  r.mxValidation?.mxRecords  || r.domainIntel?.mxRecords  || [],
      spfResult:  r.mxValidation?.spfLiveResult || null,
      mxMismatch: r.mxValidation?.mxMismatch   || false,

      // Relay chain
      hopCount:       r.hops                    || 0,
      relayAnomalies: r.relayAnomalies?.length  || 0,
      firstRelayIP:   r.relayChain?.[0]?.fromIP || null,

      // IP reputation
      ipReputationScore: r.ipReputation?.reputationScore ?? null,
      ipVerdict:         r.ipReputation?.verdict          || null,
      isTorExitNode:     r.ipReputation?.isTorExitNode    || false,
      isBotnet:          r.ipReputation?.isBotnet         || false,
      isVPN:             r.sourceGeo?.isVPN               || false,
      dnsblHitCount:     r.ipReputation?.dnsblHits?.length || 0,

      // Domain intel
      tld:             r.domainIntel?.tld             || null,
      isHighRiskTLD:   r.domainIntel?.isHighRiskTLD   || false,
      lookalikeBrand:  r.domainIntel?.lookalikeBrand  || null,
      domainRiskScore: r.domainIntel?.domainRiskScore || 0,

      // Verdict
      status:      r.status      || "safe",
      riskScore:   r.riskScore   || 0,
      issues:      r.issues      || [],
      signals:     r.signals     || [],
      attackTypes: r.attackTypes || [],

      scannedBy,
    });

    await doc.save();

    // Auto-correlate — find if this scan belongs to an existing cluster
    const cluster = await findOrCreateCluster(doc);
    if (cluster) {
      doc.clusterId   = cluster.clusterId;
      doc.clusterKeys = cluster.matchedKeys;
      await doc.save();
    }

    return doc;
  } catch (err) {
    console.error("EmailScan persist error:", err.message);
    return null;
  }
}

// ── Find or create a correlation cluster ─────────────────────
async function findOrCreateCluster(newScan) {
  // Build query — look for existing scans that share infrastructure
  const orClauses  = [];
  const matchedKeys = [];

  if (newScan.sourceIP && newScan.sourceIP !== "unknown") {
    orClauses.push({ sourceIP: newScan.sourceIP });
  }
  if (newScan.fromDomain) {
    orClauses.push({ fromDomain: newScan.fromDomain });
  }
  if (newScan.replyToDomain) {
    orClauses.push({ replyToDomain: newScan.replyToDomain });
  }
  if (newScan.firstRelayIP) {
    orClauses.push({ firstRelayIP: newScan.firstRelayIP });
  }
  if (newScan.lookalikeBrand) {
    orClauses.push({ lookalikeBrand: newScan.lookalikeBrand });
  }

  if (!orClauses.length) return null;

  // Find recent related scans (last 30 days)
  const since30d = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);

  const related = await EmailScan.find({
    $or:       orClauses,
    _id:       { $ne: newScan._id },
    createdAt: { $gte: since30d },
    status:    { $in: ["phishing", "suspicious"] },
  }).sort({ createdAt: -1 }).limit(20).lean();

  if (!related.length) return null;

  // Score the relatedness
  let maxScore      = 0;
  let bestClusterId = null;

  for (const rel of related) {
    let score = 0;
    const keys = [];

    if (rel.sourceIP       && rel.sourceIP       === newScan.sourceIP)       { score += 40; keys.push("sourceIP"); }
    if (rel.replyToDomain  && rel.replyToDomain  === newScan.replyToDomain)  { score += 35; keys.push("replyToDomain"); }
    if (rel.firstRelayIP   && rel.firstRelayIP   === newScan.firstRelayIP)   { score += 35; keys.push("firstRelayIP"); }
    if (rel.fromDomain     && rel.fromDomain     === newScan.fromDomain)     { score += 30; keys.push("fromDomain"); }
    if (rel.lookalikeBrand && rel.lookalikeBrand === newScan.lookalikeBrand) { score += 25; keys.push("lookalikeBrand"); }
    if (rel.mxProvider     && rel.mxProvider     === newScan.mxProvider)     { score += 20; keys.push("mxProvider"); }

    if (score >= 30 && score > maxScore) {
      maxScore      = score;
      bestClusterId = rel.clusterId || generateClusterId(rel);
      matchedKeys.push(...keys);
    }
  }

  if (!bestClusterId) return null;

  // Update all related scans that don't yet have a clusterId
  await EmailScan.updateMany(
    { $or: orClauses, _id: { $ne: newScan._id }, clusterId: null },
    { clusterId: bestClusterId }
  ).catch(() => {});

  return { clusterId: bestClusterId, matchedKeys: [...new Set(matchedKeys)] };
}

function generateClusterId(scan) {
  const key = [scan.sourceIP, scan.fromDomain, scan.replyToDomain]
    .filter(Boolean)
    .join("|");
  return `EC-${crypto.createHash("sha256").update(key).digest("hex").substring(0, 10).toUpperCase()}`;
}

// ── Get all clusters with their scans ────────────────────────
async function getEmailClusters(options = {}) {
  const { limit = 20, minSize = 2, status = null } = options;
  const since30d = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);

  const match = {
    clusterId: { $ne: null },
    createdAt: { $gte: since30d },
  };
  if (status) match.status = status;

  const clusters = await EmailScan.aggregate([
    { $match: match },
    { $group: {
      _id:           "$clusterId",
      scanCount:     { $sum: 1 },
      phishingCount: { $sum: { $cond: [{ $eq: ["$status", "phishing"] }, 1, 0] } },
      avgRiskScore:  { $avg: "$riskScore" },
      sourceIPs:     { $addToSet: "$sourceIP" },
      fromDomains:   { $addToSet: "$fromDomain" },
      replyToDomains:{ $addToSet: "$replyToDomain" },
      brands:        { $addToSet: "$lookalikeBrand" },
      mxProviders:   { $addToSet: "$mxProvider" },
      countries:     { $addToSet: "$sourceCountry" },
      clusterKeys:   { $first: "$clusterKeys" },
      firstSeen:     { $min: "$createdAt" },
      lastSeen:      { $max: "$createdAt" },
      isTorCount:    { $sum: { $cond: ["$isTorExitNode", 1, 0] } },
      isBotnetCount: { $sum: { $cond: ["$isBotnet", 1, 0] } },
    }},
    { $match: { scanCount: { $gte: minSize } } },
    { $sort:  { phishingCount: -1, scanCount: -1 } },
    { $limit: limit },
  ]);

  // Enrich each cluster with its recent scans
  return Promise.all(clusters.map(async (c) => {
    const scans = await EmailScan.find({ clusterId: c._id })
      .sort({ createdAt: -1 })
      .limit(10)
      .select("fromDomain sourceIP replyToDomain riskScore status createdAt originType lookalikeBrand")
      .lean();

    // Determine threat level
    const threatLevel =
      c.isTorCount > 0    ? "critical" :
      c.phishingCount > 3 ? "high"     :
      c.phishingCount > 0 ? "medium"   : "low";

    // Build a human-readable label from shared signals
    const sharedIP     = c.sourceIPs.filter(Boolean).length === 1 && c.sourceIPs[0];
    const sharedDomain = c.fromDomains.filter(Boolean).length === 1 && c.fromDomains[0];
    const sharedBrand  = c.brands.filter(Boolean)[0];

    const label = sharedBrand
      ? `${sharedBrand} phishing campaign`
      : sharedIP
      ? `IP ${sharedIP} campaign`
      : sharedDomain
      ? `${sharedDomain} campaign`
      : `Email cluster ${c._id}`;

    return {
      clusterId:     c._id,
      label,
      threatLevel,
      scanCount:     c.scanCount,
      phishingCount: c.phishingCount,
      avgRiskScore:  Math.round(c.avgRiskScore),
      sourceIPs:     c.sourceIPs.filter(Boolean),
      fromDomains:   c.fromDomains.filter(Boolean),
      replyToDomains:c.replyToDomains.filter(Boolean),
      targetBrands:  c.brands.filter(Boolean),
      mxProviders:   c.mxProviders.filter(Boolean),
      countries:     c.countries.filter(Boolean),
      clusterKeys:   c.clusterKeys || [],
      isTorCluster:  c.isTorCount > 0,
      hasBotnet:     c.isBotnetCount > 0,
      firstSeen:     c.firstSeen,
      lastSeen:      c.lastSeen,
      recentScans:   scans,
    };
  }));
}

// ── Get correlation for a single email scan ───────────────────
async function getRelatedScans(scanId) {
  const scan = await EmailScan.findById(scanId).lean();
  if (!scan) return null;

  const orClauses = [];
  if (scan.sourceIP)      orClauses.push({ sourceIP:      scan.sourceIP      });
  if (scan.fromDomain)    orClauses.push({ fromDomain:    scan.fromDomain    });
  if (scan.replyToDomain) orClauses.push({ replyToDomain: scan.replyToDomain });
  if (scan.firstRelayIP)  orClauses.push({ firstRelayIP:  scan.firstRelayIP  });

  if (!orClauses.length) return { related: [], sharedSignals: [] };

  const related = await EmailScan.find({
    $or: orClauses,
    _id: { $ne: scan._id },
  }).sort({ createdAt: -1 }).limit(20).lean();

  // Identify what signals are shared
  const sharedSignals = [];
  const ipMatch     = related.filter(r => r.sourceIP      === scan.sourceIP      && scan.sourceIP);
  const domainMatch = related.filter(r => r.fromDomain    === scan.fromDomain    && scan.fromDomain);
  const replyMatch  = related.filter(r => r.replyToDomain === scan.replyToDomain && scan.replyToDomain);
  const relayMatch  = related.filter(r => r.firstRelayIP  === scan.firstRelayIP  && scan.firstRelayIP);

  if (ipMatch.length)     sharedSignals.push({ signal: "sourceIP",      value: scan.sourceIP,      count: ipMatch.length,     label: "Same originating IP" });
  if (domainMatch.length) sharedSignals.push({ signal: "fromDomain",    value: scan.fromDomain,    count: domainMatch.length, label: "Same sender domain" });
  if (replyMatch.length)  sharedSignals.push({ signal: "replyToDomain", value: scan.replyToDomain, count: replyMatch.length,  label: "Same reply-to domain" });
  if (relayMatch.length)  sharedSignals.push({ signal: "firstRelayIP",  value: scan.firstRelayIP,  count: relayMatch.length,  label: "Same relay server" });

  return { related, sharedSignals };
}

// ── Stats ─────────────────────────────────────────────────────
async function getEmailCorrelationStats() {
  const since30d = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);

  const [total, phishing, clusters, torScans, recentClusters] = await Promise.all([
    EmailScan.countDocuments({}),
    EmailScan.countDocuments({ status: "phishing" }),
    EmailScan.distinct("clusterId", { clusterId: { $ne: null } }),
    EmailScan.countDocuments({ isTorExitNode: true }),
    EmailScan.distinct("clusterId", { clusterId: { $ne: null }, createdAt: { $gte: since30d } }),
  ]);

  return {
    totalEmailScans: total,
    phishingEmails:  phishing,
    activeClusters:  clusters.length,
    recentClusters:  recentClusters.length,
    torOriginScans:  torScans,
  };
}

module.exports = {
  persistEmailScan,
  getEmailClusters,
  getRelatedScans,
  getEmailCorrelationStats,
  EmailScan,
};
