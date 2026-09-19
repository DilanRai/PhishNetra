// FILE: backend/routes/threatshare.js
// Cross-Organization Threat Sharing — STIX 2.1 compatible
// Privacy-preserving: only SHA-256 hashes shared, never raw URLs

const express         = require("express");
const router          = express.Router();
const ThreatIndicator = require("../models/ThreatIndicator");
const Scan            = require("../models/Scan");
const crypto          = require("crypto");

// Rate limiting for public feed endpoint
const feedRequestMap  = new Map();
const FEED_RATE_LIMIT = 60; // requests per minute per IP

function feedRateLimit(req, res, next) {
  const ip  = req.headers["x-forwarded-for"]?.split(",")[0] || req.ip;
  const now = Date.now();
  const key = `${ip}:${Math.floor(now / 60000)}`;
  const cnt = (feedRequestMap.get(key) || 0) + 1;
  feedRequestMap.set(key, cnt);
  if (cnt > FEED_RATE_LIMIT) return res.status(429).json({ error: "Rate limit exceeded" });
  next();
}

// ── GET /api/threatshare/feed ──
// Public threat intel feed — returns hashed indicators only
router.get("/feed", feedRateLimit, async (req, res) => {
  try {
    const { since, type, severity, limit = 100 } = req.query;
    const query = {
      shared:    true,
      expiresAt: { $gt: new Date() },
    };
    if (since)    query.createdAt = { $gte: new Date(since) };
    if (type)     query.type      = type;
    if (severity) query.severity  = { $gte: Number(severity) };

    const indicators = await ThreatIndicator.find(query)
      .sort({ createdAt: -1 })
      .limit(Math.min(Number(limit), 500))
      .select("indicatorHash type confidence severity technique brand tld attackTypes reportCount firstSeen lastSeen stixId")
      .lean();

    // STIX 2.1 bundle format
    const stixBundle = {
      type:       "bundle",
      id:         `bundle--${crypto.randomUUID()}`,
      spec_version: "2.1",
      objects:    indicators.map(ind => ({
        type:         "indicator",
        id:           ind.stixId,
        spec_version: "2.1",
        created:      ind.firstSeen,
        modified:     ind.lastSeen,
        confidence:   ind.confidence,
        // Only hash shared — original value NEVER included
        pattern:      `[domain-name:value = '${ind.indicatorHash}']`,
        pattern_type: "stix",
        valid_from:   ind.firstSeen,
        labels:       ["malicious-activity", "phishing"],
        extensions: {
          "x-phishnetra-v1": {
            indicator_hash: ind.indicatorHash,
            severity:        ind.severity,
            technique:       ind.technique,
            brand:           ind.brand,
            tld:             ind.tld,
            attack_types:    ind.attackTypes,
            report_count:    ind.reportCount,
          },
        },
      })),
      meta: {
        total:      indicators.length,
        generated:  new Date().toISOString(),
        source:     "PhishNetra Community Feed v1.0",
        privacy:    "All indicators are SHA-256 hashed. Original URLs never shared.",
      },
    };

    res.json(stixBundle);
  } catch (err) {
    console.error("Threat feed error:", err.message);
    res.status(500).json({ error: "Feed unavailable" });
  }
});

// ── POST /api/threatshare/contribute ──
// Contribute confirmed phishing indicators to the community feed
router.post("/contribute", async (req, res) => {
  try {
    const { value, type = "url", technique, brand, attackTypes = [], severity = 3, tld, kitId } = req.body;
    if (!value?.trim()) return res.status(400).json({ error: "Indicator value required" });

    const hash = ThreatIndicator.hashIndicator(value);
    if (!hash)  return res.status(400).json({ error: "Invalid indicator" });

    // Upsert — if same hash exists, increment report count
    const existing = await ThreatIndicator.findOne({ indicatorHash: hash });
    if (existing) {
      existing.reportCount++;
      existing.lastSeen = new Date();
      // Boost confidence with each new report (max 95)
      existing.confidence = Math.min(existing.confidence + 5, 95);
      // Update severity if higher
      if (severity > existing.severity) existing.severity = severity;
      await existing.save();
      return res.json({
        status:      "updated",
        hash:        hash.slice(0, 8) + "...", // partial hash only in response
        reportCount: existing.reportCount,
        confidence:  existing.confidence,
        message:     "Indicator confidence boosted — multiple organizations confirmed",
      });
    }

    // New indicator
    const indicator = await ThreatIndicator.create({
      indicatorHash: hash,
      type,
      confidence:  Math.min(severity * 20, 90),
      severity,
      technique,
      brand,
      attackTypes,
      tld,
      kitId,
      pattern: `[domain-name:value = '${hash}']`,
    });

    res.status(201).json({
      status:      "created",
      hash:        hash.slice(0, 8) + "...", // partial hash only
      stixId:      indicator.stixId,
      message:     "Indicator contributed to PhishNetra community feed",
    });
  } catch (err) {
    if (err.code === 11000) {
      return res.json({ status: "exists", message: "Indicator already in feed" });
    }
    console.error("Contribute error:", err.message);
    res.status(500).json({ error: "Failed to contribute indicator" });
  }
});

// ── POST /api/threatshare/check ──
// Check if a value matches community-confirmed threats
router.post("/check", async (req, res) => {
  try {
    const { value } = req.body;
    if (!value?.trim()) return res.status(400).json({ found: false });

    const hash   = ThreatIndicator.hashIndicator(value);
    const result = await ThreatIndicator.checkHash(hash);

    if (!result) return res.json({ found: false });

    res.json({
      found:       true,
      confidence:  result.confidence,
      severity:    result.severity,
      technique:   result.technique,
      brand:       result.brand,
      attackTypes: result.attackTypes,
      reportCount: result.reportCount,
      firstSeen:   result.firstSeen,
      label:       "COMMUNITY CONFIRMED PHISHING",
      stixId:      result.stixId,
    });
  } catch (err) {
    res.status(500).json({ found: false, error: "Check failed" });
  }
});

// ── GET /api/threatshare/stats ──
// Feed statistics
router.get("/stats", async (req, res) => {
  try {
    const since24h = new Date(Date.now() - 24 * 60 * 60 * 1000);
    const since7d  = new Date(Date.now() -  7 * 24 * 60 * 60 * 1000);

    const [total, last24h, last7d, topTechniques, topBrands, highConf] = await Promise.all([
      ThreatIndicator.countDocuments({ expiresAt: { $gt: new Date() } }),
      ThreatIndicator.countDocuments({ createdAt: { $gte: since24h } }),
      ThreatIndicator.countDocuments({ createdAt: { $gte: since7d  } }),
      ThreatIndicator.aggregate([
        { $match:  { technique: { $ne: null }, expiresAt: { $gt: new Date() } } },
        { $group:  { _id: "$technique", count: { $sum: 1 } } },
        { $sort:   { count: -1 } }, { $limit: 5 },
      ]),
      ThreatIndicator.aggregate([
        { $match:  { brand: { $nin: [null, "unknown"] }, expiresAt: { $gt: new Date() } } },
        { $group:  { _id: "$brand", count: { $sum: 1 } } },
        { $sort:   { count: -1 } }, { $limit: 5 },
      ]),
      ThreatIndicator.countDocuments({ confidence: { $gte: 80 }, expiresAt: { $gt: new Date() } }),
    ]);

    res.json({
      total, last24h, last7d, highConf,
      topTechniques: topTechniques.map(t => ({ technique: t._id, count: t.count })),
      topBrands:     topBrands.map(b => ({ brand: b._id, count: b.count })),
      feedHealth:    "operational",
      privacy:       "SHA-256 hashed indicators only. Original URLs never stored or shared.",
      stixVersion:   "2.1",
      generatedAt:   new Date().toISOString(),
    });
  } catch (err) {
    res.status(500).json({ error: "Stats unavailable" });
  }
});

// ── GET /api/threatshare/export/stix ──
// Export full STIX 2.1 bundle for integration with other SIEM tools
router.get("/export/stix", async (req, res) => {
  try {
    const indicators = await ThreatIndicator.find({
      shared:    true,
      expiresAt: { $gt: new Date() },
      severity:  { $gte: 3 },
    }).limit(1000).lean();

    res.setHeader("Content-Type",        "application/json");
    res.setHeader("Content-Disposition", `attachment; filename="phishnetra-stix-bundle-${Date.now()}.json"`);

    res.json({
      type:         "bundle",
      id:           `bundle--${crypto.randomUUID()}`,
      spec_version: "2.1",
      objects:      indicators.map(ind => ({
        type:         "indicator",
        id:           ind.stixId,
        spec_version: "2.1",
        created:      ind.firstSeen,
        modified:     ind.lastSeen,
        name:         `PhishNetra - ${ind.technique || "phishing"} indicator`,
        description:  `Community-confirmed phishing indicator. Reports: ${ind.reportCount}`,
        confidence:   ind.confidence,
        pattern:      `[domain-name:value = '${ind.indicatorHash}']`,
        pattern_type: "stix",
        valid_from:   ind.firstSeen,
        valid_until:  ind.expiresAt,
        labels:       ["malicious-activity","phishing"],
        kill_chain_phases: [{ kill_chain_name:"mitre-attack", phase_name:"initial-access" }],
      })),
    });
  } catch (err) {
    res.status(500).json({ error: "Export failed" });
  }
});

module.exports = router;