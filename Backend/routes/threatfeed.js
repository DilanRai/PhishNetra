// FILE: backend/routes/threatfeed.js

const express = require("express");
const router = express.Router();
const Scan = require("../models/Scan");

// ── GET /api/feed — live threat feed ──
router.get("/", async (req, res) => {
  try {
    const since24h = new Date(Date.now() - 24 * 60 * 60 * 1000);
    const since7d = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
    const since1h = new Date(Date.now() - 60 * 60 * 1000);

    const [
      recentThreats,
      trendingBrands,
      trendingTechniques,
      trendingTLDs,
      hourlySpike,
      totalToday,
      phishingToday,
      activeCampaigns,
    ] = await Promise.all([
      // Last 20 phishing/suspicious detections — the live feed
      Scan.find(
        { status: { $in: ["phishing", "suspicious"] } },
        {
          input: 1,
          status: 1,
          riskScore: 1,
          inputType: 1,
          createdAt: 1,
          "dna.fingerprint": 1,
          "dna.brand": 1,
          "dna.technique": 1,
          issues: 1,
        },
      )
        .sort({ createdAt: -1 })
        .limit(20),

      // Top targeted brands in last 24h
      Scan.aggregate([
        {
          $match: {
            createdAt: { $gte: since24h },
            "dna.brand": { $nin: [null, "unknown"] },
            status: { $in: ["phishing", "suspicious"] },
          },
        },
        {
          $group: {
            _id: "$dna.brand",
            count: { $sum: 1 },
            lastSeen: { $max: "$createdAt" },
          },
        },
        { $sort: { count: -1 } },
        { $limit: 8 },
      ]),

      // Top attack techniques in last 24h
      Scan.aggregate([
        {
          $match: {
            createdAt: { $gte: since24h },
            "dna.technique": { $ne: null },
            status: { $in: ["phishing", "suspicious"] },
          },
        },
        { $group: { _id: "$dna.technique", count: { $sum: 1 } } },
        { $sort: { count: -1 } },
        { $limit: 6 },
      ]),

      // Top malicious TLDs in last 7d
      Scan.aggregate([
        {
          $match: {
            createdAt: { $gte: since7d },
            "dna.tld": { $nin: [null, "unknown", "n/a"] },
            status: "phishing",
          },
        },
        { $group: { _id: "$dna.tld", count: { $sum: 1 } } },
        { $sort: { count: -1 } },
        { $limit: 6 },
      ]),

      // Hourly scan count (last 24h buckets) — for sparkline
      Scan.aggregate([
        { $match: { createdAt: { $gte: since24h } } },
        {
          $group: {
            _id: {
              $dateToString: { format: "%Y-%m-%dT%H:00", date: "$createdAt" },
            },
            total: { $sum: 1 },
            phishing: {
              $sum: { $cond: [{ $eq: ["$status", "phishing"] }, 1, 0] },
            },
          },
        },
        { $sort: { _id: 1 } },
      ]),

      // Totals today
      Scan.countDocuments({ createdAt: { $gte: since24h } }),
      Scan.countDocuments({
        createdAt: { $gte: since24h },
        status: "phishing",
      }),

      // Active campaigns (distinct DNA fingerprints in last 1h)
      Scan.distinct("dna.fingerprint", {
        "dna.fingerprint": { $ne: null },
        status: "phishing",
        createdAt: { $gte: since1h },
      }),
    ]);

    res.json({
      updatedAt: new Date().toISOString(),
      recentThreats: recentThreats.map((s) => {
        const input = typeof s.input === "string" ? s.input : "";
        return {
          id: s._id,
          input: input.substring(0, 55) + (input.length > 55 ? "…" : ""),
          status: s.status,
          riskScore: s.riskScore,
          inputType: s.inputType,
          createdAt: s.createdAt,
          fingerprint: s.dna?.fingerprint || null,
          brand: s.dna?.brand || null,
          technique: s.dna?.technique || null,
          issue: s.issues?.[0] || null,
        };
      }),
      trendingBrands: trendingBrands.map((b) => ({
        brand: b._id,
        count: b.count,
        lastSeen: b.lastSeen,
      })),
      trendingTechniques: trendingTechniques.map((t) => ({
        technique: t._id,
        count: t.count,
      })),
      trendingTLDs: trendingTLDs.map((t) => ({ tld: t._id, count: t.count })),
      hourlySpike,
      summary: {
        totalToday,
        phishingToday,
        threatRate:
          totalToday > 0 ? Math.round((phishingToday / totalToday) * 100) : 0,
        activeCampaigns: activeCampaigns.length,
      },
    });
  } catch (err) {
    console.error("Feed error:", err);
    res.status(500).json({ error: "Failed to fetch threat feed" });
  }
});

module.exports = router;
