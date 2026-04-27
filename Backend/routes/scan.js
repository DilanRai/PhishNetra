// FILE: backend/routes/scan.js

const express          = require("express");
const router           = express.Router();
const { analyzeInput } = require("../ai/phishingDetector");
const { isModelReady } = require("../ai/mlModel");
const Scan             = require("../models/Scan");

// Lazy-load SIEM engine — won't crash if siem/ folder not yet added
let ingestFromScan = null;
try {
  ingestFromScan = require("../siem/eventEngine").ingestFromScan;
  console.log("🛡️  SentinelCore SIEM: connected to scan pipeline");
} catch {
  console.log("ℹ️  SentinelCore SIEM: not found — scan results won't be logged to SIEM");
}

// ── POST / — analyze ──
router.post("/", async (req, res) => {
  try {
    const { input } = req.body;

    if (!input || typeof input !== "string" || input.trim().length === 0) {
      return res.status(400).json({ error: "Input is required" });
    }
    if (input.trim().length > 5000) {
      return res.status(400).json({ error: "Input too long (max 5000 chars)" });
    }

    const trimmed = input.trim();
    const result  = await analyzeInput(trimmed);

    const newScan = new Scan({
      input:            trimmed,
      status:           result.status,
      riskScore:        result.riskScore,
      issues:           result.issues,
      inputType:        result.inputType,
      confidence:       result.confidence,
      detectionVersion: result.detectionVersion,
      mlEnabled:        result.mlEnabled,
      mlScore:          result.mlScore,
      ruleScore:        result.ruleScore,
      features:         result.features,
      createdAt:        new Date(),
    });

    await newScan.save();

    // ── Feed into SentinelCore SIEM (non-blocking fire-and-forget) ──
    if (ingestFromScan && (result.status !== "safe" || result.riskScore >= 20)) {
      ingestFromScan(result, trimmed, {
        sourceType: req.headers["x-source"] || "scanner",
        sourceIp:   req.ip,
        agent:      req.headers["user-agent"] || "PhishGuard API",
      }).catch((err) => console.error("SIEM ingest error:", err.message));
    }

    if (process.env.NODE_ENV === "development") {
      console.log(`📡 Scan | ${result.inputType.toUpperCase()} | ${result.status.toUpperCase()} | score:${result.riskScore} | ml:${result.mlEnabled ? result.mlScore : "off"} | rules:${result.ruleScore}`);
    }

    res.json(result);

  } catch (err) {
    console.error("Scan error:", err);
    res.status(500).json({ error: "Scan failed" });
  }
});

// ── GET /test ──
router.get("/test", (req, res) => {
  const testCases = [
    { input: "https://google.com",                       expected: "safe"       },
    { input: "http://paypal-secure-login.tk/verify",     expected: "phishing"   },
    { input: "Urgent! Your account has been suspended!", expected: "suspicious" },
    { input: "Enter your OTP to verify your account",    expected: "phishing"   },
  ];
  const results = testCases.map((tc) => {
    const r = analyzeInput(tc.input);
    return { input: tc.input, expected: tc.expected, result: r.status, score: r.riskScore, pass: r.status === tc.expected };
  });
  res.json({ tests: results, passed: results.filter((r) => r.pass).length, total: results.length, mlActive: isModelReady() });
});

// ── GET /ml-status ──
router.get("/ml-status", (req, res) => {
  res.json({
    mlEnabled:        isModelReady(),
    model:            "synaptic-neural-network",
    architecture:     "18 inputs → 14 hidden → 8 hidden → 1 output",
    detectionVersion: "3.0",
    hybridWeights:    isModelReady() ? "ML 45% + Rules 55%" : "Rules 100% (fallback)",
    siemEnabled:      !!ingestFromScan,
    trainingInfo: {
      samples: 50, features: 18,
      categories: ["safe", "suspicious", "phishing"],
      validation: "7/7 tests passed",
    },
  });
});

// ── GET /stats ──
router.get("/stats", async (req, res) => {
  try {
    const total      = await Scan.countDocuments();
    const phishing   = await Scan.countDocuments({ status: "phishing" });
    const suspicious = await Scan.countDocuments({ status: "suspicious" });
    const safe       = await Scan.countDocuments({ status: "safe" });
    const mlScanned  = await Scan.countDocuments({ mlEnabled: true });

    const avgAgg = await Scan.aggregate([{ $group: { _id: null, avg: { $avg: "$riskScore" } } }]);
    const byType = await Scan.aggregate([{ $group: { _id: "$inputType", count: { $sum: 1 } } }]);
    const byConf = await Scan.aggregate([{ $group: { _id: "$confidence", count: { $sum: 1 } } }]);

    const last7Days = await Scan.aggregate([
      { $match: { createdAt: { $gte: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) } } },
      { $group: {
          _id:      { $dateToString: { format: "%Y-%m-%d", date: "$createdAt" } },
          total:    { $sum: 1 },
          phishing: { $sum: { $cond: [{ $eq: ["$status", "phishing"] }, 1, 0] } },
          safe:     { $sum: { $cond: [{ $eq: ["$status", "safe"]     }, 1, 0] } },
      }},
      { $sort: { _id: 1 } },
    ]);

    const recentScans = await Scan.find(
      {}, { input: 1, status: 1, riskScore: 1, inputType: 1, createdAt: 1 }
    ).sort({ createdAt: -1 }).limit(10);

    res.json({
      total,
      breakdown:    { phishing, suspicious, safe },
      threatRate:   total > 0 ? Math.round((phishing / total) * 100) : 0,
      avgRiskScore: avgAgg[0] ? Math.round(avgAgg[0].avg) : 0,
      byInputType:  Object.fromEntries(byType.map((b) => [b._id || "unknown", b.count])),
      byConfidence: Object.fromEntries(byConf.map((b) => [b._id || "unknown", b.count])),
      mlScanned,
      mlCoverage:   total > 0 ? Math.round((mlScanned / total) * 100) : 0,
      siemEnabled:  !!ingestFromScan,
      last7Days,
      recentScans:  recentScans.map((s) => ({
        id:        s._id,
        input:     s.input.length > 55 ? s.input.substring(0, 55) + "…" : s.input,
        status:    s.status,
        riskScore: s.riskScore,
        inputType: s.inputType,
        createdAt: s.createdAt,
      })),
    });
  } catch (err) {
    console.error("Stats error:", err);
    res.status(500).json({ error: "Failed to fetch stats" });
  }
});

// ── GET /history ──
router.get("/history", async (req, res) => {
  try {
    const data = await Scan.find().sort({ createdAt: -1 }).limit(200);
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch history" });
  }
});

// ── DELETE /history (clear all — must be before /:id) ──
router.delete("/history", async (req, res) => {
  try {
    await Scan.deleteMany({});
    res.json({ message: "All history cleared" });
  } catch (err) {
    res.status(500).json({ error: "Failed to clear history" });
  }
});

// ── DELETE /history/:id ──
router.delete("/history/:id", async (req, res) => {
  try {
    const { id } = req.params;
    if (!id.match(/^[0-9a-fA-F]{24}$/)) {
      return res.status(400).json({ error: "Invalid ID format" });
    }
    const deleted = await Scan.findByIdAndDelete(id);
    if (!deleted) return res.status(404).json({ error: "Item not found" });
    res.json({ message: "Deleted successfully" });
  } catch (err) {
    res.status(500).json({ error: "Failed to delete item" });
  }
});

module.exports = router;