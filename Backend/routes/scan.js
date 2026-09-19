// FILE: backend/routes/scan.js

const express = require("express");
const router = express.Router();
const { analyzeInput } = require("../ai/phishingDetector");
const { isModelReady } = require("../ai/mlModel");
const Scan = require("../models/Scan");
const { generateDNA } = require("../ai/threatDNA");
const { generateReport } = require("../ai/reportGenerator");
const { generateRemediation } = require("../ai/remediationEngine");
const { sendCriticalAlert } = require("../ai/emailNotifier");
const { checkThreatIntel } = require("../services/threatIntel");
const { analyzeEmailHeaders } = require("../ai/emailHeaderAnalyzer");
const { lookup: geoLookup } = require("../services/geolocate");
const { getDomainIntelligence } = require("../services/domainIntel");
const { requireAuth, requireRole } = require("./auth");
const { getURLPreview } = require("../services/urlPreview");
const { getPredictiveInsights } = require("../services/predictiveEngine");
const crypto = require("crypto");
const { getCampaignForecast } = require("../services/forecastEngine");
const {
  getAllAdversaryProfiles,
  buildAdversaryProfile,
} = require("../services/adversaryEngine");
const {
  identifyKit,
  identifyKitsFromDatabase,
  SOPHISTICATION_META,
  getAllKitMatches,
  getKitRiskProfile,
} = require("../services/kitFingerprint");
const ThreatIndicator = require("../models/ThreatIndicator");
const path = require("path");

// Lazy-load SIEM engine — won't crash if siem/ folder not yet added
let ingestFromScan = null;
try {
  ingestFromScan = require("../siem/eventEngine").ingestFromScan;
  console.log("🛡️  SentinelCore SIEM: connected to scan pipeline");
} catch {
  console.log(
    "ℹ️  SentinelCore SIEM: not found — scan results won't be logged to SIEM",
  );
}

let processIOCs = null;
try {
  processIOCs = require("../siem/iocEngine").processIOCs;
} catch {
  /* non-blocking if iocEngine not yet present */
}

// ── POST / — analyze ──
router.post(
  "/",
  requireAuth,
  requireRole("admin", "analyst"),
  async (req, res) => {
    try {
      const { input } = req.body;

      if (!input || typeof input !== "string" || input.trim().length === 0) {
        return res.status(400).json({ error: "Input is required" });
      }

      if (input.trim().length > 5000) {
        return res
          .status(400)
          .json({ error: "Input too long (max 5000 chars)" });
      }

      const trimmed = input.trim();
      const result = await analyzeInput(trimmed);

      // Threat intel check (URLs only, non-blocking enrichment)
      let threatIntel = null;
      if (result.inputType === "url") {
        threatIntel = await checkThreatIntel(trimmed).catch(() => null);
        if (threatIntel?.found) {
          result.riskScore = Math.min(
            result.riskScore + (threatIntel.score || 40),
            100,
          );
          result.issues = [
            `🔴 ${threatIntel.label} (${threatIntel.sources.join(", ")})`,
            ...result.issues,
          ];
          if (result.status !== "phishing") result.status = "phishing";
        }
      }

      // ── Community threat share check ──
      let communityMatch = null;
      if (result.inputType === "url") {
        try {
          const hash = ThreatIndicator.hashIndicator(trimmed);
          communityMatch = await ThreatIndicator.checkHash(hash);
          if (communityMatch) {
            result.riskScore = Math.min(result.riskScore + 20, 100);
            if (result.status !== "phishing") result.status = "phishing";
            result.issues = [
              `🌐 COMMUNITY CONFIRMED — ${communityMatch.reportCount} organization(s) flagged this indicator`,
              ...result.issues,
            ];
          }
        } catch {
          /* non-blocking */
        }
      }

      // Generate PhishDNA fingerprint
      const dna =
        result.status !== "safe" ? generateDNA(trimmed, result) : null;

      // ── Auto-contribute confirmed phishing to community feed ──
      if (result.status === "phishing" && result.riskScore >= 70) {
        ThreatIndicator.hashIndicator &&
          new ThreatIndicator({
            indicatorHash: ThreatIndicator.hashIndicator(trimmed),
            type: result.inputType === "url" ? "url" : "email",
            confidence: Math.min(result.riskScore, 90),
            severity:
              result.riskScore >= 85 ? 5 : result.riskScore >= 70 ? 4 : 3,
            technique: dna?.technique || null,
            brand: dna?.brand || null,
            attackTypes: result.attackTypes || [],
            tld: dna?.tld || null,
          })
            .save()
            .catch(() => {}); // non-blocking, ignore duplicates
      }

      // ── IOC Engine — extract and cross-reference indicators ──
      const mongoose = require("mongoose");
      const scanId = new mongoose.Types.ObjectId();
      let iocResults = null;
      if (processIOCs) {
        iocResults = await processIOCs(
          trimmed,
          result,
          scanId.toString(),
        ).catch(() => null);
        // If IOC matches found, boost was already applied inside processIOCs
      }

      // Kit fingerprinting — only for phishing URLs
      let kitMatch = null;
      let allKitMatches = null;
      if (result.status === "phishing" && result.inputType === "url") {
        kitMatch = identifyKit(trimmed, result.issues, result.attackTypes);
        allKitMatches = getAllKitMatches(
          trimmed,
          result.issues,
          result.attackTypes,
        );
        // Add sophistication boost to risk score
        if (kitMatch) {
          const meta = SOPHISTICATION_META[kitMatch.sophistication];
          if (meta?.riskMod) {
            result.riskScore = Math.min(result.riskScore + meta.riskMod, 100);
          }
        }
      }

      // Generate remediation plan
      const remediation = generateRemediation(
        result.status,
        result.issues,
        dna,
      );

      const newScan = new Scan({
        _id: scanId,
        kitMatch: kitMatch
          ? {
              kitId: kitMatch.kitId,
              kitName: kitMatch.kitName,
              confidence: kitMatch.confidence,
              sophistication: kitMatch.sophistication,
            }
          : null,
        evasion: result.evasion
          ? {
              detected: result.evasion.detected,
              level: result.evasion.level,
              signals: result.evasion.signals,
              techniques: result.evasion.techniques,
            }
          : { detected: false, level: null, signals: 0, techniques: [] },
        csvMatch: result.csvMatch
          ? {
              matched: true,
              matchLevel: result.csvMatch.matchLevel,
              label: result.csvMatch.label,
              source: result.csvMatch.source,
              count: result.csvMatch.count,
            }
          : { matched: false },
        sourceIp: req.ip || null,
        input: trimmed,
        dna: dna,
        attackTypes: result.attackTypes || [],
        mitre: result.mitre || null,
        cve: result.cve || null,
        status: result.status,
        riskScore: Number.isFinite(result.riskScore) ? result.riskScore : 0,
        issues: result.issues,
        inputType: result.inputType,
        confidence: result.confidence,
        detectionVersion: result.detectionVersion,
        mlEnabled: result.mlEnabled,
        mlScore: Number.isFinite(result.mlScore) ? result.mlScore : null,
        ruleScore: Number.isFinite(result.ruleScore) ? result.ruleScore : 0,
        features: result.features,
        threatIntel: threatIntel,
        createdAt: new Date(),
      });

      // ★ FIX: If request came from Chrome extension AND result is safe
      // do NOT save to history — safe URLs from extension are noise.
      // Only phishing and suspicious extension scans get stored.
      const fromExtension =
        (req.headers["x-source"] || "").toLowerCase().includes("extension") ||
        (req.headers["user-agent"] || "").toLowerCase().includes("extension");

      if (fromExtension && result.status === "safe") {
        // Return result to extension but skip DB save
        // (fall through to res.json below without saving)
      } else {
        await newScan.save();
      }

      // ── Feed into SentinelCore SIEM (non-blocking fire-and-forget) ──
      // Always ingest into SIEM — custom rules must be evaluated on every scan
      // regardless of built-in verdict or risk score.
      // The ruleEngine decides what fires — not this gate.
      if (ingestFromScan) {
        ingestFromScan(result, trimmed, {
          sourceType: req.headers["x-source"] || "scanner",
          sourceIp: req.ip,
          agent: req.headers["user-agent"] || "Phishnetra API",
        }).catch((err) => console.error("SIEM ingest error:", err.message));
      }

      if (process.env.NODE_ENV === "development") {
        console.log(
          `📡 Scan | ${result.inputType.toUpperCase()} | ${result.status.toUpperCase()} | score:${result.riskScore} | ml:${result.mlEnabled ? result.mlScore : "off"} | rules:${result.ruleScore}`,
        );
      }

      const geo = geoLookup(req.ip);

      // Track API key behavior for zero-trust scoring
      if (req.apiKeyUser) {
        const ApiKey = require("../models/ApiKey");
        const key = await ApiKey.findOne({
          userId: req.apiKeyUser.id,
          active: true,
        });
        if (key) {
          if (result.status === "phishing")
            key.phishingSubmitted = (key.phishingSubmitted || 0) + 1;
          if (result.status === "safe")
            key.safeSubmitted = (key.safeSubmitted || 0) + 1;
          if (communityMatch?.found)
            key.knownPhishingHits = (key.knownPhishingHits || 0) + 1;
          await key.save();
        }
      }

      res.json({
        ...result,
        dna,
        remediation,
        threatIntel,
        geo,
        kitMatch,
        allKitMatches,
        communityMatch,
        iocResults: iocResults
          ? {
              matched: iocResults.matched,
              extracted: iocResults.extracted,
            }
          : null,
      });

      // Push real-time alert via WebSocket for threats
      if (result.status === "phishing" || result.status === "suspicious") {
        const io = req.app.get("io");
        if (io) {
          io.emit("threat_detected", {
            status: result.status,
            riskScore: result.riskScore,
            inputType: result.inputType,
            confidence: result.confidence,
            issues: result.issues.slice(0, 3),
            dna: dna,
            input: trimmed.substring(0, 60),
            detectedAt: new Date().toISOString(),
          });

          // FIX ISSUE 4: Emit new_scan so ThreatMap geo refreshes on every
          // phishing/suspicious scan (previously this event was never emitted)
          io.emit("new_scan", {
            status: result.status,
            riskScore: result.riskScore,
            inputType: result.inputType,
            domain: result.fromDomain || null,
          });
        }
      }

      // Send email for critical threats (riskScore >= 75)
      if (result.status === "phishing" && result.riskScore >= 75) {
        sendCriticalAlert({
          status: result.status,
          riskScore: result.riskScore,
          input: trimmed,
          issues: result.issues,
          dna,
        }).catch(() => {}); // non-blocking
      }
    } catch (err) {
      console.error("Scan error:", err);
      res.status(500).json({ error: "Scan failed" });
    }
  },
);

// ── GET /test ──
router.get("/test", async (req, res) => {
  const testCases = [
    { input: "https://google.com", expected: "safe" },
    { input: "http://paypal-secure-login.tk/verify", expected: "phishing" },
    {
      input: "Urgent! Your account has been suspended!",
      expected: "suspicious",
    },
    { input: "Enter your OTP to verify your account", expected: "phishing" },
  ];
  const results = await Promise.all(
    testCases.map(async (tc) => {
      const r = await analyzeInput(tc.input);
      return {
        input: tc.input,
        expected: tc.expected,
        result: r.status,
        score: r.riskScore,
        pass: r.status === tc.expected,
      };
    }),
  );
  res.json({
    tests: results,
    passed: results.filter((r) => r.pass).length,
    total: results.length,
    mlActive: isModelReady(),
  });
});

// ── GET /ml-status ──
router.get("/ml-status", (req, res) => {
  res.json({
    mlEnabled: isModelReady(),
    model: "synaptic-neural-network",
    architecture: "18 inputs → 14 hidden → 8 hidden → 1 output",
    detectionVersion: "5.0",
    hybridWeights: isModelReady()
      ? "ML 45% + Rules 55%"
      : "Rules 100% (fallback)",
    siemEnabled: !!ingestFromScan,
    trainingInfo: {
      samples: 60,
      features: 24,
      model: "v2 — 24→18→12→6→1 (4 layers)",
      categories: ["safe", "suspicious", "phishing"],
      validation: "7/7 tests passed",
    },
  });
});

// ── GET /stats ──
router.get("/stats", async (req, res) => {
  try {
    const total = await Scan.countDocuments();
    const phishing = await Scan.countDocuments({ status: "phishing" });
    const suspicious = await Scan.countDocuments({ status: "suspicious" });
    const safe = await Scan.countDocuments({ status: "safe" });
    const mlScanned = await Scan.countDocuments({ mlEnabled: true });

    const avgAgg = await Scan.aggregate([
      { $group: { _id: null, avg: { $avg: "$riskScore" } } },
    ]);
    const byType = await Scan.aggregate([
      { $group: { _id: "$inputType", count: { $sum: 1 } } },
    ]);
    const byConf = await Scan.aggregate([
      { $group: { _id: "$confidence", count: { $sum: 1 } } },
    ]);

    const last7Days = await Scan.aggregate([
      {
        $match: {
          createdAt: { $gte: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) },
        },
      },
      {
        $group: {
          _id: { $dateToString: { format: "%Y-%m-%d", date: "$createdAt" } },
          total: { $sum: 1 },
          phishing: {
            $sum: { $cond: [{ $eq: ["$status", "phishing"] }, 1, 0] },
          },
          safe: { $sum: { $cond: [{ $eq: ["$status", "safe"] }, 1, 0] } },
        },
      },
      { $sort: { _id: 1 } },
    ]);

    const recentScans = await Scan.find(
      {},
      { input: 1, status: 1, riskScore: 1, inputType: 1, createdAt: 1 },
    )
      .sort({ createdAt: -1 })
      .limit(10);

    res.json({
      total,
      breakdown: { phishing, suspicious, safe },
      threatRate: total > 0 ? Math.round((phishing / total) * 100) : 0,
      avgRiskScore: avgAgg[0] ? Math.round(avgAgg[0].avg) : 0,
      byInputType: Object.fromEntries(
        byType.map((b) => [b._id || "unknown", b.count]),
      ),
      byConfidence: Object.fromEntries(
        byConf.map((b) => [b._id || "unknown", b.count]),
      ),
      mlScanned,
      mlCoverage: total > 0 ? Math.round((mlScanned / total) * 100) : 0,
      siemEnabled: !!ingestFromScan,
      last7Days,
      recentScans: recentScans.map((s) => {
        const input = typeof s.input === "string" ? s.input : "";
        return {
          id: s._id,
          input: input.length > 55 ? input.substring(0, 55) + "…" : input,
          status: s.status,
          riskScore: s.riskScore,
          inputType: s.inputType,
          createdAt: s.createdAt,
        };
      }),
    });
  } catch (err) {
    console.error("Stats error:", err);
    res.status(500).json({ error: "Failed to fetch stats" });
  }
});

router.get("/ml-training-status", requireAuth, (req, res) => {
  try {
    const { getTrainingStatus } = require("../ai/autoTrainingEngine");
    res.json(getTrainingStatus());
  } catch {
    res.json({ state: "unavailable", accuracy: null });
  }
});

router.post(
  "/ml-retrain",
  requireAuth,
  requireRole("admin"),
  async (req, res) => {
    try {
      const { triggerRetrain } = require("../ai/autoTrainingEngine");
      // Fire and forget — training is async, client polls /ml-training-status
      triggerRetrain();
      res.json({
        message: "Retraining triggered — poll /ml-training-status for progress",
      });
    } catch (err) {
      res
        .status(500)
        .json({ error: "Failed to trigger retrain: " + err.message });
    }
  },
);

// GET /api/scan/datasets — CSV dataset index stats
router.get("/datasets", async (req, res) => {
  try {
    const { getIndexStats } = require("../ai/csvDatasetEngine");
    const stats = getIndexStats();
    res.json(stats);
  } catch (err) {
    res.json({ isLoaded: false, totalEntries: 0, files: [] });
  }
});

// POST /api/scan/datasets/reload — manually reload CSV index
router.post("/datasets/reload", async (req, res) => {
  try {
    const { reloadDatasets, getIndexStats } = require("../ai/csvDatasetEngine");
    reloadDatasets();
    setTimeout(() => {
      res.json({ message: "Dataset index reloaded", stats: getIndexStats() });
    }, 3000);
  } catch (err) {
    res.status(500).json({ error: "Failed to reload datasets" });
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
router.delete(
  "/history",
  requireAuth,
  requireRole("admin"),
  async (req, res) => {
    try {
      await Scan.deleteMany({});
      res.json({ message: "All history cleared" });
    } catch (err) {
      res.status(500).json({ error: "Failed to clear history" });
    }
  },
);

// ── DELETE /history/:id ──
router.delete(
  "/history/:id",
  requireAuth,
  requireRole("admin"),
  async (req, res) => {
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
  },
);

// GET /dna/stats — PhishDNA campaign clustering
router.get("/dna/stats", async (req, res) => {
  try {
    const [
      topFingerprints,
      topTechniques,
      topBrands,
      topTLDs,
      recentCampaigns,
    ] = await Promise.all([
      // Most seen attack fingerprints (campaigns)
      Scan.aggregate([
        { $match: { "dna.fingerprint": { $ne: null } } },
        {
          $group: {
            _id: "$dna.fingerprint",
            count: { $sum: 1 },
            brand: { $first: "$dna.brand" },
            technique: { $first: "$dna.technique" },
            tld: { $first: "$dna.tld" },
            severity: { $first: "$dna.severity" },
            lastSeen: { $max: "$createdAt" },
            firstSeen: { $min: "$createdAt" },
          },
        },
        { $sort: { count: -1 } },
        { $limit: 10 },
      ]),
      // Top attack techniques
      Scan.aggregate([
        { $match: { "dna.technique": { $ne: null } } },
        { $group: { _id: "$dna.technique", count: { $sum: 1 } } },
        { $sort: { count: -1 } },
      ]),
      // Top targeted brands
      Scan.aggregate([
        { $match: { "dna.brand": { $nin: [null, "unknown"] } } },
        { $group: { _id: "$dna.brand", count: { $sum: 1 } } },
        { $sort: { count: -1 } },
        { $limit: 8 },
      ]),
      // Top malicious TLDs
      Scan.aggregate([
        {
          $match: {
            "dna.tld": { $nin: [null, "unknown", "n/a"] },
            status: "phishing",
          },
        },
        { $group: { _id: "$dna.tld", count: { $sum: 1 } } },
        { $sort: { count: -1 } },
        { $limit: 8 },
      ]),
      // Recent unique campaigns (distinct fingerprints in last 24h)
      Scan.distinct("dna.fingerprint", {
        "dna.fingerprint": { $ne: null },
        createdAt: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) },
      }),
    ]);

    res.json({
      topFingerprints,
      topTechniques: topTechniques.map((t) => ({
        technique: t._id,
        count: t.count,
      })),
      topBrands: topBrands.map((b) => ({ brand: b._id, count: b.count })),
      topTLDs: topTLDs.map((t) => ({ tld: t._id, count: t.count })),
      activeCampaigns: recentCampaigns.length,
    });
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch DNA stats" });
  }
});

// POST /report — generate PDF for a scan result
router.post("/report", async (req, res) => {
  try {
    const {
      input,
      status,
      riskScore,
      issues,
      inputType,
      confidence,
      detectionVersion,
      mlEnabled,
      mlScore,
      ruleScore,
      dna,
      remediation,
      // ★ NEW: pass all enrichment fields to PDF generator
      mitreAttack,
      attackVectors,
      cveReferences,
      threatIntel,
      sourceIp,
    } = req.body;

    if (!input || !status) {
      return res.status(400).json({ error: "Scan data required" });
    }

    generateReport(res, {
      input,
      status,
      riskScore: riskScore || 0,
      issues: issues || [],
      inputType,
      confidence,
      detectionVersion,
      mlEnabled,
      mlScore,
      ruleScore,
      dna: dna || null,
      remediation: remediation || null,
      scannedAt: new Date(),
      // ★ NEW fields
      mitreAttack: mitreAttack || [],
      attackVectors: attackVectors || [],
      cveReferences: cveReferences || [],
      threatIntel: threatIntel || null,
      sourceIp: sourceIp || null,
    });
  } catch (err) {
    console.error("Report error:", err.message);
    if (!res.headersSent) {
      res.status(500).json({ error: "Failed to generate report" });
    }
  }
});

// POST /api/scan/headers — Email header analysis
router.post("/headers", async (req, res) => {
  try {
    const { headers } = req.body;
    if (!headers || typeof headers !== "string" || headers.trim().length < 20) {
      return res.status(400).json({ error: "Raw email headers required" });
    }

    const result = analyzeEmailHeaders(headers.trim());
    res.json(result);
  } catch (err) {
    console.error("Header analysis error:", err.message);
    res.status(500).json({ error: "Header analysis failed" });
  }
});

// GET /api/scan/threat-actors — active threat actors
router.get("/threat-actors", async (req, res) => {
  try {
    const {
      getActiveThreatActors,
      detectCampaignSpikes,
    } = require("../siem/behaviorEngine");
    const [actors, spikes] = await Promise.all([
      getActiveThreatActors(),
      detectCampaignSpikes(),
    ]);
    res.json({ actors, campaignSpikes: spikes });
  } catch (err) {
    res.status(500).json({ error: "Behavior data unavailable" });
  }
});

// GET /api/scan/dna/campaign/:fingerprint — campaign timeline
router.get("/dna/campaign/:fingerprint", async (req, res) => {
  try {
    const { getCampaignTimeline } = require("../ai/threatDNA");
    const data = await getCampaignTimeline(req.params.fingerprint);
    if (!data) return res.status(404).json({ error: "Campaign not found" });
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: "Campaign data unavailable" });
  }
});

// Geopolitical context helper
// Based on public CISA, FBI IC3, and Spamhaus data
function getGeopoliticalContext(country) {
  if (!country) return null;
  const GEO_INTEL = {
    RU: {
      risk: "high",
      label: "Russia",
      source: "CISA AA22-110A",
      note: "Frequent phishing campaign origin. State-sponsored and criminal groups.",
    },
    CN: {
      risk: "high",
      label: "China",
      source: "FBI IC3 2023",
      note: "Significant BEC campaign origin. APT group infrastructure frequently observed.",
    },
    NG: {
      risk: "medium",
      label: "Nigeria",
      source: "FBI IC3 2023",
      note: "High volume of advance-fee fraud and BEC campaigns.",
    },
    KP: {
      risk: "high",
      label: "North Korea",
      source: "CISA AA22-011A",
      note: "State-sponsored phishing campaigns targeting financial institutions.",
    },
    IR: {
      risk: "high",
      label: "Iran",
      source: "CISA AA22-257A",
      note: "Credential harvesting campaigns targeting US government and contractors.",
    },
    BR: {
      risk: "medium",
      label: "Brazil",
      source: "Spamhaus 2023",
      note: "High volume phishing infrastructure. Significant banking trojan origin.",
    },
    UA: {
      risk: "medium",
      label: "Ukraine",
      source: "Spamhaus",
      note: "Bulletproof hosting presence. Mixed legitimate/malicious usage.",
    },
    RO: {
      risk: "medium",
      label: "Romania",
      source: "Europol 2023",
      note: "Significant cybercrime activity. E-commerce fraud origin.",
    },
    IN: {
      risk: "low",
      label: "India",
      source: "FBI IC3",
      note: "Growing tech support scam origin. Primarily targets US/UK users.",
    },
  };
  return GEO_INTEL[country] || null;
}

// POST /api/scan/domain-intel — deep domain intelligence (called separately, non-blocking)
router.post("/domain-intel", async (req, res) => {
  try {
    const { url } = req.body;
    if (!url || typeof url !== "string") {
      return res.status(400).json({ error: "URL required" });
    }
    // Validate it's a URL
    try {
      new URL(url.startsWith("http") ? url : `https://${url}`);
    } catch {
      return res.status(400).json({ error: "Invalid URL format" });
    }

    const intel = await getDomainIntelligence(url);
    if (!intel)
      return res.status(400).json({ error: "Could not analyze domain" });

    const geoCtx = intel.dns?.country
      ? getGeopoliticalContext(intel.dns.country)
      : null;
    res.json({ ...intel, geopoliticalContext: geoCtx });
  } catch (err) {
    console.error("Domain intel error:", err.message);
    res.status(500).json({ error: "Domain intelligence unavailable" });
  }
});

// GET /api/scan/live — real-time scan velocity (last 60 seconds)
router.get("/live", async (req, res) => {
  try {
    const since60s = new Date(Date.now() - 60 * 1000);
    const since1m = new Date(Date.now() - 1 * 60 * 1000);
    const since5m = new Date(Date.now() - 5 * 60 * 1000);

    const [scans60s, phishing60s, scans5m, phishing5m, topAttacks] =
      await Promise.all([
        Scan.countDocuments({ createdAt: { $gte: since60s } }),
        Scan.countDocuments({
          createdAt: { $gte: since60s },
          status: "phishing",
        }),
        Scan.countDocuments({ createdAt: { $gte: since5m } }),
        Scan.countDocuments({
          createdAt: { $gte: since5m },
          status: "phishing",
        }),
        Scan.aggregate([
          {
            $match: {
              createdAt: { $gte: since5m },
              "dna.technique": { $ne: null },
            },
          },
          { $group: { _id: "$dna.technique", count: { $sum: 1 } } },
          { $sort: { count: -1 } },
          { $limit: 3 },
        ]),
      ]);

    res.json({
      scansPerMin: scans60s,
      phishingPerMin: phishing60s,
      scans5m,
      phishing5m,
      threatVelocity:
        scans5m > 0 ? Math.round((phishing5m / scans5m) * 100) : 0,
      topAttacks: topAttacks.map((t) => ({ technique: t._id, count: t.count })),
      timestamp: new Date().toISOString(),
    });
  } catch (err) {
    res.status(500).json({ error: "Live stats unavailable" });
  }
});

// POST /api/scan/preview — safe URL preview fetch
router.post("/preview", async (req, res) => {
  try {
    const { url } = req.body;
    if (!url || typeof url !== "string") {
      return res.status(400).json({ error: "URL required" });
    }
    const preview = await getURLPreview(url.trim());
    if (!preview)
      return res.status(400).json({ error: "Could not fetch preview" });
    res.json(preview);
  } catch (err) {
    res.status(500).json({ error: "Preview unavailable" });
  }
});

// PATCH /api/scan/history/:id/tags — update tags + notes on a scan
router.patch(
  "/history/:id/tags",
  requireAuth,
  requireRole("admin", "analyst"),
  async (req, res) => {
    try {
      const { id } = req.params;
      const { tags, notes } = req.body;
      if (!id.match(/^[0-9a-fA-F]{24}$/)) {
        return res.status(400).json({ error: "Invalid ID" });
      }
      const update = { taggedAt: new Date() };
      if (Array.isArray(tags))
        update.tags = tags
          .map((t) => t.trim().toLowerCase())
          .filter(Boolean)
          .slice(0, 10);
      if (typeof notes === "string") update.notes = notes.substring(0, 500);

      const scan = await Scan.findByIdAndUpdate(id, update, { new: true });
      if (!scan) return res.status(404).json({ error: "Scan not found" });
      res.json({ tags: scan.tags, notes: scan.notes });
    } catch (err) {
      res.status(500).json({ error: "Failed to update tags" });
    }
  },
);

// GET /api/scan/tags — get all unique tags for autocomplete
router.get("/tags", async (req, res) => {
  try {
    const tags = await Scan.aggregate([
      { $unwind: "$tags" },
      { $group: { _id: "$tags", count: { $sum: 1 } } },
      { $sort: { count: -1 } },
      { $limit: 50 },
    ]);
    res.json(tags.map((t) => ({ tag: t._id, count: t.count })));
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch tags" });
  }
});

// GET /api/scan/predict — predictive threat scoring
router.get("/predict", async (req, res) => {
  try {
    const insights = await getPredictiveInsights();
    res.json(insights);
  } catch (err) {
    console.error("Prediction error:", err.message);
    res.status(500).json({ error: "Prediction unavailable" });
  }
});

// POST /api/scan/history/:id/share — generate shareable link
router.post(
  "/history/:id/share",
  requireAuth,
  requireRole("admin", "analyst"),
  async (req, res) => {
    try {
      const { id } = req.params;
      if (!id.match(/^[0-9a-fA-F]{24}$/))
        return res.status(400).json({ error: "Invalid ID" });

      const scan = await Scan.findById(id);
      if (!scan) return res.status(404).json({ error: "Scan not found" });

      // Reuse existing shareId or generate new one
      if (!scan.shareId) {
        scan.shareId = crypto.randomBytes(8).toString("hex");
        scan.sharedAt = new Date();
        await scan.save();
      }

      res.json({
        shareId: scan.shareId,
        shareUrl: `${process.env.FRONTEND_URL || "http://localhost:5173"}/report/${scan.shareId}`,
        sharedAt: scan.sharedAt,
      });
    } catch (err) {
      res.status(500).json({ error: "Failed to generate share link" });
    }
  },
);

// GET /api/scan/report/:shareId — public report (no auth needed)
router.get("/report/:shareId", async (req, res) => {
  try {
    const scan = await Scan.findOne({ shareId: req.params.shareId })
      .select("-sourceIp -features -__v")
      .lean();
    if (!scan)
      return res
        .status(404)
        .json({ error: "Report not found or link expired" });
    res.json(scan);
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch report" });
  }
});

// POST /api/scan/report/bulk — consolidated PDF for multiple scans
router.post("/report/bulk", async (req, res) => {
  try {
    const { ids } = req.body;
    if (!Array.isArray(ids) || ids.length === 0 || ids.length > 50) {
      return res.status(400).json({ error: "Provide 1–50 scan IDs" });
    }

    const scans = await Scan.find({ _id: { $in: ids } })
      .sort({ createdAt: -1 })
      .lean();

    if (scans.length === 0)
      return res.status(404).json({ error: "No scans found" });

    const PDFDocument = require("pdfkit");
    const doc = new PDFDocument({
      size: "A4",
      margins: { top: 40, bottom: 40, left: 40, right: 40 },
    });

    res.setHeader("Content-Type", "application/pdf");
    res.setHeader(
      "Content-Disposition",
      `attachment; filename="PhishNetra-bulk-${Date.now()}.pdf"`,
    );
    doc.pipe(res);

    // Cover
    doc
      .fontSize(18)
      .fillColor("#00ff88")
      .font("Helvetica-Bold")
      .text("PhishNetra AI — Bulk Incident Report", 40, 40);
    doc
      .fontSize(9)
      .fillColor("#8b95a8")
      .font("Helvetica")
      .text(
        `${scans.length} scans · Generated: ${new Date().toLocaleString()}`,
        40,
        65,
      );

    doc.moveDown(2);

    // Summary
    const ph = scans.filter((s) => s.status === "phishing").length;
    const su = scans.filter((s) => s.status === "suspicious").length;
    const sa = scans.filter((s) => s.status === "safe").length;

    doc
      .fontSize(10)
      .fillColor("#e8edf5")
      .font("Helvetica-Bold")
      .text("SUMMARY");
    doc
      .fontSize(9)
      .fillColor("#8b95a8")
      .font("Helvetica")
      .text(
        `Total: ${scans.length}  |  Phishing: ${ph}  |  Suspicious: ${su}  |  Safe: ${sa}`,
      )
      .moveDown(1.5);

    // Each scan
    scans.forEach((s, i) => {
      if (doc.y > 700) doc.addPage();

      const color =
        s.status === "phishing"
          ? "#ff4444"
          : s.status === "suspicious"
            ? "#f5a623"
            : "#00ff88";

      const input = typeof s.input === "string" ? s.input : "";
      const firstIssue = typeof s.issues?.[0] === "string" ? s.issues[0] : "";

      doc
        .fontSize(9)
        .fillColor(color)
        .font("Helvetica-Bold")
        .text(
          `${i + 1}. [${s.status.toUpperCase()}] Score: ${s.riskScore}/100`,
        );
      doc
        .fontSize(8)
        .fillColor("#94a3c0")
        .font("Courier")
        .text(input.substring(0, 100), { indent: 12 });

      if (firstIssue) {
        doc
          .fontSize(8)
          .fillColor("#8b95a8")
          .font("Helvetica")
          .text(`↳ ${firstIssue.substring(0, 80)}`, { indent: 12 });
      }

      doc.moveDown(0.6);
    });

    doc.end();
  } catch (err) {
    if (!res.headersSent) res.status(500).json({ error: "Bulk PDF failed" });
  }
});

// GET /api/scan/forecast — predictive campaign intelligence
router.get("/forecast", async (req, res) => {
  try {
    const forecast = await getCampaignForecast();
    res.json(forecast);
  } catch (err) {
    console.error("Forecast error:", err.message);
    res.status(500).json({ error: "Forecast unavailable" });
  }
});

// GET /api/scan/adversaries — all adversary profiles
router.get("/adversaries", async (req, res) => {
  try {
    const profiles = await getAllAdversaryProfiles();
    res.json({ profiles, total: profiles.length });
  } catch (err) {
    console.error("Adversary profiling error:", err.message);
    res.status(500).json({ error: "Adversary intelligence unavailable" });
  }
});

// GET /api/scan/adversaries/:ip — single actor profile
router.get("/adversaries/:ip", async (req, res) => {
  try {
    const ip = decodeURIComponent(req.params.ip);
    const profile = await buildAdversaryProfile(ip);
    if (!profile)
      return res.status(404).json({ error: "Insufficient data for this IP" });
    res.json(profile);
  } catch (err) {
    res.status(500).json({ error: "Profile generation failed" });
  }
});

// GET /api/scan/kits — all kit stats from database
router.get("/kits", async (req, res) => {
  try {
    const kits = await identifyKitsFromDatabase();
    res.json({ kits, total: kits.length });
  } catch (err) {
    console.error("Kit fingerprinting error:", err.message);
    res.status(500).json({ error: "Kit intelligence unavailable" });
  }
});

// GET /api/scan/kits/signatures — full kit signature database
router.get("/kits/signatures", async (req, res) => {
  try {
    const { KIT_SIGNATURES } = require("../services/kitFingerprint");
    res.json({
      signatures: KIT_SIGNATURES.map((k) => ({
        kitId: k.kitId,
        kitName: k.kitName,
        version: k.version,
        targetBrands: k.targetBrands,
        sophistication: k.sophistication,
        description: k.description,
      })),
      total: KIT_SIGNATURES.length,
    });
  } catch (err) {
    res.status(500).json({ error: "Signatures unavailable" });
  }
});

// GET /api/scan/kits/paged — paginated kit stats (supports ?page=1&limit=20&days=30)
router.get("/kits/paged", async (req, res) => {
  try {
    const {
      identifyKitsFromDatabasePaged,
    } = require("../services/kitFingerprint");
    const page = Math.max(1, parseInt(req.query.page) || 1);
    const limit = Math.min(100, Math.max(1, parseInt(req.query.limit) || 20));
    const days = Math.min(365, Math.max(1, parseInt(req.query.days) || 30));
    const result = await identifyKitsFromDatabasePaged({ page, limit, days });
    res.json(result);
  } catch (err) {
    console.error("Kit paged error:", err.message);
    res.status(500).json({ error: "Kit intelligence unavailable" });
  }
});

// POST /api/scan/kits/analyze — analyze a URL for kit matches without saving a scan
router.post("/kits/analyze", async (req, res) => {
  try {
    const { url } = req.body;
    if (!url || typeof url !== "string") {
      return res.status(400).json({ error: "url is required" });
    }
    try {
      new URL(url.startsWith("http") ? url : `https://${url}`);
    } catch {
      return res.status(400).json({ error: "Invalid URL format" });
    }

    const trimmed = url.trim();
    const matches = getAllKitMatches(trimmed);
    const top = matches[0] || null;
    const profile = top ? getKitRiskProfile(top, trimmed) : null;

    res.json({
      url: trimmed,
      topMatch: profile,
      allMatches: matches,
      total: matches.length,
    });
  } catch (err) {
    console.error("Kit analyze error:", err.message);
    res.status(500).json({ error: "Kit analysis failed" });
  }
});

// POST /api/scan/preview/save — save sandbox results to an existing scan
router.post("/preview/save", async (req, res) => {
  try {
    const { scanId, preview } = req.body;
    if (!scanId || !preview)
      return res.status(400).json({ error: "scanId and preview required" });
    if (!scanId.match(/^[0-9a-fA-F]{24}$/))
      return res.status(400).json({ error: "Invalid scan ID" });

    await Scan.findByIdAndUpdate(scanId, {
      sandboxData: {
        hasCredentialForm: preview.forms?.hasCredentialForm || false,
        hasPasswordField: preview.forms?.hasPasswordField || false,
        hasPhishingKit: preview.technologies?.hasPhishingKit || false,
        hasObfuscation: preview.technologies?.hasObfuscation || false,
        crossDomainRedirect: preview.redirectChain?.crossDomain || false,
        redirectHops: preview.redirectChain?.hops || 1,
        liveStatus: preview.liveStatus || null,
        sandboxRiskLevel: preview.sandboxRisk?.riskLevel || null,
        sandboxRiskScore: preview.sandboxRisk?.riskScore || 0,
        techCount: preview.technologies?.detected?.length || 0,
      },
    });

    res.json({ saved: true });
  } catch (err) {
    res.json({ saved: false });
  }
});

// GET /api/scan/training/examples — returns training phishing examples
// These are synthetic examples for security awareness training ONLY
// All URLs are non-functional placeholder examples
router.get("/training/examples", async (req, res) => {
  const TRAINING_EXAMPLES = [
    {
      id: "ex-001",
      type: "URL",
      difficulty: "easy",
      verdict: "phishing",
      input: "http://paypa1-secure.tk/login/verify.php?token=abc123",
      hint: "Look carefully at the domain — 'paypa1' uses the number 1 instead of the letter l",
      explanation:
        "Typosquatting attack. 'paypa1.tk' impersonates 'paypal.com' using a number substitution and a free .tk domain. No HTTPS, suspicious TLD, credential keyword in path.",
      attackType: "typosquatting",
      mitre: "T1583.001 — Acquire Infrastructure: Domains",
      signals: [
        "Number substitution (l→1)",
        "Free .tk TLD",
        "No HTTPS",
        "login/verify in path",
      ],
    },
    {
      id: "ex-002",
      type: "URL",
      difficulty: "medium",
      verdict: "phishing",
      input: "https://accounts.google.com.signin-secure.xyz/oauth/authorize",
      hint: "The domain is not google.com — find where google.com appears vs where the actual domain is",
      explanation:
        "Domain confusion attack. The real domain is 'signin-secure.xyz' — 'accounts.google.com' is just a subdomain prefix. The browser only trusts the last two parts before the TLD.",
      attackType: "subdomain_spoof",
      mitre: "T1583.001 — Acquire Infrastructure: Domains",
      signals: [
        "Real domain: signin-secure.xyz",
        "Google.com is subdomain only",
        "Suspicious .xyz TLD",
      ],
    },
    {
      id: "ex-003",
      type: "URL",
      difficulty: "hard",
      verdict: "phishing",
      input: "https://xn--pypa1-xua.com/secure/login",
      hint: "This URL uses punycode encoding — what does xn-- mean?",
      explanation:
        "IDN Homograph attack using Punycode. 'xn--pypa1-xua.com' renders in browsers as 'ρaypal.com' using Greek rho (ρ) instead of Latin p. Even HTTPS can't protect you here.",
      attackType: "punycode",
      mitre: "CVE-2021-28879 — IDN Homograph in Browsers",
      signals: [
        "Punycode xn-- prefix",
        "Homograph characters",
        "HTTPS present but deceptive",
      ],
    },
    {
      id: "ex-004",
      type: "text",
      difficulty: "easy",
      verdict: "phishing",
      input:
        "URGENT: Your PayPal account has been suspended due to suspicious activity. Verify your account within 24 hours or it will be permanently closed: http://paypal-verify.ml/confirm",
      hint: "Count the red flags: urgency, threat, suspicious link",
      explanation:
        "Classic phishing email. Uses urgency ('24 hours'), threat ('permanently closed'), and a suspicious domain (paypal-verify.ml). PayPal would never ask you to verify via an unsolicited email.",
      attackType: "social_engineering",
      mitre: "T1566 — Phishing",
      signals: [
        "Urgency deadline",
        "Account threat",
        "Free .ml TLD in link",
        "Unsolicited verification request",
      ],
    },
    {
      id: "ex-005",
      type: "text",
      difficulty: "medium",
      verdict: "phishing",
      input:
        'From: "PayPal Support" <no-reply@paypa1-support.com>\nSubject: Action Required\n\nDear Customer, verify your account at https://paypal.com.secure-verify.tk/login',
      hint: "Check the sender email AND the link destination separately",
      explanation:
        "Display name spoofing + domain confusion double attack. The sender shows 'PayPal Support' but the actual email domain is 'paypa1-support.com'. The link also uses domain confusion (paypal.com is a subdomain of secure-verify.tk).",
      attackType: "display_mismatch",
      mitre: "T1566.002 — Spearphishing Link",
      signals: [
        "Display name ≠ actual domain",
        "Link domain confusion",
        "Generic greeting 'Dear Customer'",
      ],
    },
    {
      id: "ex-006",
      type: "text",
      difficulty: "hard",
      verdict: "phishing",
      input:
        "Hi, this is the CEO. I need you to urgently purchase 5x $200 Amazon gift cards for a client meeting. Keep this confidential and email me the codes. I'm in a meeting and can't talk.",
      hint: "This has no links or suspicious URLs — what makes it phishing?",
      explanation:
        "Business Email Compromise (BEC) — CEO fraud. No links, no malware. Pure social engineering using authority (CEO), urgency, confidentiality demand, and isolation (can't talk). The gift card request is the payload.",
      attackType: "bec_fraud",
      mitre: "T1566 — Phishing / T1534 — Internal Spearphishing",
      signals: [
        "CEO impersonation",
        "Gift card request",
        "Confidentiality demand",
        "Urgency + isolation",
      ],
    },
    {
      id: "ex-007",
      type: "text",
      difficulty: "easy",
      verdict: "phishing",
      input:
        "USPS: Your package #9400111899223467088 could not be delivered. Pay $2.99 redelivery fee: bit.ly/usps-redeliver",
      hint: "This is an SMS message — what delivery patterns make it suspicious?",
      explanation:
        "Delivery smishing (SMS phishing). Uses a fake tracking number, small fee to seem legitimate, and a URL shortener to hide the destination. USPS never charges redelivery fees via SMS links.",
      attackType: "smishing",
      mitre: "T1660 — Phishing via SMS",
      signals: [
        "Fake tracking number",
        "Urgency + small fee",
        "URL shortener hides destination",
        "USPS never charges via SMS",
      ],
    },
    {
      id: "ex-008",
      type: "URL",
      difficulty: "hard",
      verdict: "safe",
      input:
        "https://accounts.google.com/signin/v2/identifier?continue=https://mail.google.com",
      hint: "This looks suspicious but check carefully — is the domain actually Google?",
      explanation:
        "This is SAFE. The actual domain IS accounts.google.com — a legitimate Google subdomain. The 'continue' parameter is a standard OAuth redirect to Gmail. Not every login URL with parameters is phishing.",
      attackType: null,
      mitre: null,
      signals: [
        "✓ Legitimate Google domain",
        "✓ HTTPS",
        "✓ Standard OAuth parameter",
        "✓ Redirect to mail.google.com",
      ],
    },
  ];

  res.json({ examples: TRAINING_EXAMPLES, total: TRAINING_EXAMPLES.length });
});

// ── Idea 7: Attachment static analysis ──
const multer = require("multer");
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 }, // 10 MB
});

router.post("/attachment", upload.single("file"), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: "No file uploaded" });

  const { originalname, mimetype, buffer, size } = req.file;
  const ext = originalname.split(".").pop()?.toLowerCase() || "";
  const signals = [];
  const findings = []; // structured findings per category
  let score = 0;

  // ── File hash (SHA-256) ──
  // Useful for analyst reference and future hash-based threat intel integration
  const sha256 = crypto.createHash("sha256").update(buffer).digest("hex");

  // ── MIME type map (expanded) ──
  const MIME_EXT_MAP = {
    "application/pdf": ["pdf"],
    "image/jpeg": ["jpg", "jpeg"],
    "image/png": ["png"],
    "image/gif": ["gif"],
    "image/webp": ["webp"],
    "application/zip": ["zip"],
    "application/x-zip-compressed": ["zip"],
    "application/x-rar-compressed": ["rar"],
    "application/x-7z-compressed": ["7z"],
    "application/msword": ["doc"],
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": [
      "docx",
    ],
    "application/vnd.ms-excel": ["xls"],
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": [
      "xlsx",
    ],
    "application/vnd.ms-powerpoint": ["ppt"],
    "application/vnd.openxmlformats-officedocument.presentationml.presentation":
      ["pptx"],
    "text/plain": ["txt", "csv"],
    "text/html": ["html", "htm"],
    "application/javascript": ["js"],
    "application/x-sh": ["sh"],
    "application/x-msdownload": ["exe", "dll"],
  };

  // ── 1. MIME vs extension mismatch ──
  const expectedExts = MIME_EXT_MAP[mimetype] || [];
  if (expectedExts.length > 0 && !expectedExts.includes(ext)) {
    score += 40;
    const finding = `MIME mismatch: server reports "${mimetype}" but file has .${ext} extension — masking technique`;
    signals.push(finding);
    findings.push({ category: "identity", severity: "high", detail: finding });
  }

  // ── 2. High-risk executable extension ──
  const HIGH_RISK_EXTS = [
    "exe",
    "bat",
    "cmd",
    "ps1",
    "vbs",
    "js",
    "jar",
    "scr",
    "pif",
    "com",
    "dll",
    "lnk",
    "hta",
    "msi",
    "reg",
    "wsf",
    "wsh",
    "cpl",
    "inf",
    "sys",
    "drv",
  ];
  const MEDIUM_RISK_EXTS = ["iso", "img", "vhd", "dmg", "apk", "ipa"];

  if (HIGH_RISK_EXTS.includes(ext)) {
    score += 60;
    const finding = `High-risk executable extension: .${ext} — directly executable on Windows`;
    signals.push(finding);
    findings.push({
      category: "extension",
      severity: "critical",
      detail: finding,
    });
  } else if (MEDIUM_RISK_EXTS.includes(ext)) {
    score += 30;
    const finding = `Medium-risk container extension: .${ext} — can contain executables`;
    signals.push(finding);
    findings.push({
      category: "extension",
      severity: "medium",
      detail: finding,
    });
  }

  // ── 3. Double extension (report.pdf.exe) ──
  const parts = originalname.split(".");
  if (parts.length >= 3) {
    const hiddenExt = parts[parts.length - 2].toLowerCase();
    const lureExts = [
      "pdf",
      "doc",
      "docx",
      "xls",
      "xlsx",
      "jpg",
      "png",
      "txt",
      "mp4",
      "mp3",
    ];
    if (lureExts.includes(hiddenExt) && HIGH_RISK_EXTS.includes(ext)) {
      score += 50;
      const finding = `Double extension: "${originalname}" — hides .${ext} behind .${hiddenExt} to look like a document`;
      signals.push(finding);
      findings.push({
        category: "evasion",
        severity: "critical",
        detail: finding,
      });
    }
  }

  // ── 4. Unicode RLO character in filename ──
  // Right-to-left override makes "invoice_fdp.exe" display as "invoice_exe.pdf"
  if (originalname.includes("\u202E") || originalname.includes("%E2%80%AE")) {
    score += 70;
    const finding = `Unicode Right-to-Left Override (U+202E) in filename — reverses displayed extension to deceive user`;
    signals.push(finding);
    findings.push({
      category: "evasion",
      severity: "critical",
      detail: finding,
    });
  }

  // ── 5. Magic byte verification ──
  // Read the actual file signature regardless of extension
  const header4 = buffer.slice(0, 4).toString("hex");
  const header2 = buffer.slice(0, 2).toString("hex");

  const MAGIC_BYTES = {
    "504b0304": "zip/office", // ZIP (also DOCX/XLSX/PPTX/JAR)
    25504446: "pdf", // %PDF
    "4d5a": "pe_executable", // MZ — Windows PE/EXE/DLL
    "504b": "zip", // PK
    "1f8b": "gzip",
    52617221: "rar", // Rar!
    "377abcaf": "7zip",
    d0cf11e0: "ole", // OLE2 (legacy DOC/XLS/PPT)
    cafebabe: "java_class", // Java .class / JAR
    "7f454c46": "elf", // ELF Linux executable
    feedface: "macho", // Mach-O macOS executable
    ffd8ff: "jpeg",
    "89504e47": "png",
  };

  const actualType =
    MAGIC_BYTES[header4] ||
    MAGIC_BYTES[header4.substring(0, 4)] ||
    MAGIC_BYTES[header2] ||
    "unknown";

  // PE executable hiding as something else
  if (
    actualType === "pe_executable" &&
    !["exe", "dll", "scr", "com", "pif"].includes(ext)
  ) {
    score += 75;
    const finding = `File is a Windows PE executable (MZ header) but disguised as .${ext} — extremely high risk`;
    signals.push(finding);
    findings.push({
      category: "identity",
      severity: "critical",
      detail: finding,
    });
  }

  // Java class/JAR hiding as something else
  if (actualType === "java_class" && !["jar", "class"].includes(ext)) {
    score += 60;
    const finding = `File has Java bytecode signature (CAFEBABE) but named as .${ext}`;
    signals.push(finding);
    findings.push({
      category: "identity",
      severity: "critical",
      detail: finding,
    });
  }

  // ELF executable
  if (actualType === "elf") {
    score += 60;
    const finding = `File is a Linux/Unix ELF executable — unusual as an email attachment`;
    signals.push(finding);
    findings.push({ category: "identity", severity: "high", detail: finding });
  }

  // OLE2 (legacy Office) — can contain macros, no ZIP wrapper to inspect
  if (actualType === "ole") {
    const content = buffer.toString("latin1");
    if (/VBA|Macro|AutoOpen|Document_Open|Auto_Open/i.test(content)) {
      score += 55;
      const finding = `Legacy OLE2 Office document (.doc/.xls) with VBA macro signatures — high risk`;
      signals.push(finding);
      findings.push({
        category: "macro",
        severity: "critical",
        detail: finding,
      });
    }
  }

  // ── 6. ZIP-container analysis (DOCX/XLSX/PPTX/ZIP/JAR) ──
  if (actualType === "zip/office" || actualType === "zip") {
    try {
      const content = buffer.toString("latin1");
      const fullBuffer = buffer.toString(
        "utf8",
        0,
        Math.min(buffer.length, 500000),
      );

      // Macro detection
      if (
        /vbaProject\.bin|macroEnabled|xl\/vbaProject|word\/vbaProject/i.test(
          content,
        )
      ) {
        score += 45;
        const finding = `Macro code (vbaProject.bin) detected in ${ext.toUpperCase()} — high risk for macro malware delivery`;
        signals.push(finding);
        findings.push({
          category: "macro",
          severity: "critical",
          detail: finding,
        });
      }

      // PowerShell in macro / XML
      if (/powershell|pwsh|cmd\.exe|wscript|cscript/i.test(fullBuffer)) {
        score += 40;
        const finding = `Shell command reference (PowerShell/cmd) found inside document XML`;
        signals.push(finding);
        findings.push({
          category: "macro",
          severity: "critical",
          detail: finding,
        });
      }

      // External URLs embedded in document XML
      const urlMatches = content.match(/https?:\/\/[^\s"'<>]{10,}/g) || [];
      const externalUrls = urlMatches.filter(
        (u) =>
          !u.includes("schemas.microsoft.com") &&
          !u.includes("schemas.openxmlformats.org") &&
          !u.includes("purl.org") &&
          !u.includes("w3.org"),
      );
      if (externalUrls.length > 0) {
        score += 20;
        const finding = `${externalUrls.length} external URL(s) embedded in document: ${externalUrls.slice(0, 3).join(", ")}`;
        signals.push(finding);
        findings.push({
          category: "url",
          severity: "medium",
          detail: finding,
          extractedUrls: externalUrls.slice(0, 5),
        });
      }

      // DDE (Dynamic Data Exchange) attack pattern
      if (
        /=cmd\s*\||=MSEXCEL\||\bDDE\b|=SUM\s*\(/i.test(fullBuffer) &&
        ["xlsx", "xls", "csv"].some((e) => e === ext)
      ) {
        score += 45;
        const finding = `DDE (Dynamic Data Exchange) formula pattern detected — Excel formula injection technique`;
        signals.push(finding);
        findings.push({
          category: "macro",
          severity: "critical",
          detail: finding,
        });
      }

      // Template injection (remote template loading)
      if (
        /word\/_rels\/settings\.xml\.rels[\s\S]{0,500}Target="http/i.test(
          content,
        )
      ) {
        score += 50;
        const finding = `Remote template injection: document fetches template from external URL on open`;
        signals.push(finding);
        findings.push({
          category: "macro",
          severity: "critical",
          detail: finding,
        });
      }

      // Nested archive (ZIP in ZIP — common AV evasion)
      const nestedZipCount = (content.match(/PK\x03\x04/g) || []).length - 1;
      if (nestedZipCount > 0) {
        score += 25;
        const finding = `Nested archive detected (${nestedZipCount} inner ZIP${nestedZipCount > 1 ? "s" : ""}) — common antivirus evasion technique`;
        signals.push(finding);
        findings.push({
          category: "evasion",
          severity: "high",
          detail: finding,
        });
      }
    } catch {
      /* non-blocking */
    }
  }

  // ── 7. PDF analysis (expanded) ──
  if (ext === "pdf" || actualType === "pdf") {
    const pdfContent = buffer.toString("latin1");

    if (/\/JavaScript\s|\/JS\s/i.test(pdfContent)) {
      score += 55;
      const finding = `JavaScript action in PDF — executes code when document is opened`;
      signals.push(finding);
      findings.push({
        category: "active_content",
        severity: "critical",
        detail: finding,
      });
    }

    if (/\/Launch\s|\/OpenAction\s/i.test(pdfContent)) {
      score += 50;
      const finding = `PDF Launch/OpenAction detected — executes system command or opens file on view`;
      signals.push(finding);
      findings.push({
        category: "active_content",
        severity: "critical",
        detail: finding,
      });
    }

    if (/\/SubmitForm\s/i.test(pdfContent)) {
      score += 40;
      const finding = `PDF SubmitForm action — silently POSTs data to remote server`;
      signals.push(finding);
      findings.push({
        category: "active_content",
        severity: "critical",
        detail: finding,
      });
    }

    if (/\/GoToR\s/i.test(pdfContent)) {
      score += 30;
      const finding = `PDF GoToR (remote go-to) action — opens external file`;
      signals.push(finding);
      findings.push({
        category: "active_content",
        severity: "high",
        detail: finding,
      });
    }

    if (/\/EmbeddedFile\s/i.test(pdfContent)) {
      score += 35;
      const finding = `Embedded file inside PDF — may contain malicious payload`;
      signals.push(finding);
      findings.push({
        category: "embedded",
        severity: "high",
        detail: finding,
      });
    }

    // Extract embedded URLs from PDF
    const pdfUrls = pdfContent.match(/https?:\/\/[^\s)<>]{10,}/g) || [];
    if (pdfUrls.length > 0) {
      score += 15;
      const finding = `${pdfUrls.length} URL(s) embedded in PDF: ${pdfUrls.slice(0, 2).join(", ")}`;
      signals.push(finding);
      findings.push({
        category: "url",
        severity: "medium",
        detail: finding,
        extractedUrls: pdfUrls.slice(0, 5),
      });
    }

    // Incremental update abuse (common PDF malware technique — appends malicious content)
    const xrefCount = (pdfContent.match(/\bxref\b/g) || []).length;
    if (xrefCount > 1) {
      score += 15;
      const finding = `PDF incremental updates detected (${xrefCount} xref sections) — can hide malicious content appended after original`;
      signals.push(finding);
      findings.push({
        category: "evasion",
        severity: "medium",
        detail: finding,
      });
    }
  }

  // ── 8. LNK file analysis ──
  if (ext === "lnk" || header4 === "4c000000") {
    score += 50;
    const finding = `Windows LNK shortcut file — commonly abused to execute hidden PowerShell or batch commands`;
    signals.push(finding);
    findings.push({
      category: "extension",
      severity: "critical",
      detail: finding,
    });

    // Try to extract target command from binary
    const lnkContent = buffer.toString("latin1");
    if (
      /powershell|cmd\.exe|wscript|mshta|certutil|bitsadmin/i.test(lnkContent)
    ) {
      score += 30;
      const finding2 = `LNK target contains shell command reference (PowerShell/cmd/mshta) — likely malicious launcher`;
      signals.push(finding2);
      findings.push({
        category: "active_content",
        severity: "critical",
        detail: finding2,
      });
    }
  }

  // ── 9. HTML attachment analysis ──
  if (["html", "htm"].includes(ext) || mimetype === "text/html") {
    try {
      const htmlContent = buffer.toString("utf8");

      // Credential forms in HTML attachment
      const hasPwdInput = /<input[^>]+type=['"]password['"]/i.test(htmlContent);
      if (hasPwdInput) {
        score += 55;
        const finding = `HTML attachment contains password input field — credential harvesting lure`;
        signals.push(finding);
        findings.push({
          category: "credential_harvest",
          severity: "critical",
          detail: finding,
        });
      }

      // Obfuscated JS in HTML attachment
      if (
        /eval\s*\(\s*(?:unescape|atob|String\.fromCharCode)/i.test(htmlContent)
      ) {
        score += 40;
        const finding = `Obfuscated JavaScript in HTML attachment — common phishing kit delivery technique`;
        signals.push(finding);
        findings.push({
          category: "obfuscation",
          severity: "critical",
          detail: finding,
        });
      }

      // External resource loading (calls home)
      const extSrcs =
        htmlContent.match(
          /(?:src|href|action)\s*=\s*['"]https?:\/\/[^'"]{10,}['"]/gi,
        ) || [];
      if (extSrcs.length > 0) {
        score += 20;
        const finding = `HTML attachment loads ${extSrcs.length} external resource(s) — may beacon victim identity to attacker`;
        signals.push(finding);
        findings.push({ category: "url", severity: "high", detail: finding });
      }

      // Base64 encoded content (full page smuggling)
      const b64Blocks = htmlContent.match(/[A-Za-z0-9+\/]{200,}={0,2}/g) || [];
      if (b64Blocks.length > 0 && htmlContent.length > 5000) {
        score += 30;
        const finding = `Large Base64 block(s) in HTML attachment — possible HTML smuggling (full page encoded as data URI)`;
        signals.push(finding);
        findings.push({
          category: "obfuscation",
          severity: "critical",
          detail: finding,
        });
      }
    } catch {
      /* non-blocking */
    }
  }

  // ── NEW: Password-protected archive detection ──
  // Password-protected ZIPs are the #1 AV sandbox evasion technique —
  // the scanner can't see inside, so the payload passes undetected.
  // Detection: ZIP central directory has encryption flag set (bit 0 of general purpose bit flag)
  if (["zip", "7z", "rar"].includes(ext)) {
    try {
      // ZIP encryption flag: bytes 6-7 of local file header (after PK\x03\x04)
      // General purpose bit flag bit 0 = encrypted
      const localHeaderOffset = buffer.indexOf(
        Buffer.from([0x50, 0x4b, 0x03, 0x04]),
      );
      if (localHeaderOffset !== -1) {
        const gpFlag = buffer.readUInt16LE(localHeaderOffset + 6);
        const isEncrypted = (gpFlag & 0x01) !== 0;
        if (isEncrypted) {
          score += 40;
          const finding =
            `Password-protected ${ext.toUpperCase()} archive — encryption prevents AV/sandbox inspection; ` +
            `most ransomware and phishing kit delivery uses this to evade detection`;
          signals.push(finding);
          findings.push({
            category: "evasion",
            severity: "high",
            detail: finding,
          });
        }
      }
    } catch {
      /* non-blocking */
    }
  }

  // ── NEW: Macro 4.0 XLM detection (different from VBA) ──
  // Excel 4.0 macros (XLM) are a legacy format that bypasses many
  // modern macro security controls that only block VBA.
  if (["xls", "xlsx", "xlsm", "xlsb"].includes(ext)) {
    try {
      const content = buffer.toString("latin1");
      // XLM macro sheets are named "Macro1" or use FORMULA/EXEC records in legacy format
      if (
        /FORMULA\.FILL|EXEC\s*\(|CALL\s*\(|Macro\d+|Macrosheet|xlm\s+macro/i.test(
          content,
        ) ||
        /\\x00EXCEL\s*4\.0|BIFF8.*FORMULA.*RUN/i.test(content)
      ) {
        score += 55;
        const finding =
          `Excel 4.0 XLM macro detected — legacy macro format bypasses modern VBA controls; ` +
          `heavily used by Emotet, Qakbot, and Dridex malware families`;
        signals.push(finding);
        findings.push({
          category: "macro",
          severity: "critical",
          detail: finding,
        });
      }
    } catch {
      /* non-blocking */
    }
  }

  // ── NEW: Mark-of-the-Web (MOTW) bypass patterns ──
  // Files downloaded from the internet get a Zone.Identifier ADS tag.
  // Attackers use ISO/IMG/VHD containers to bypass MOTW — files inside
  // disk images don't inherit the internet zone marking.
  if (["iso", "img", "vhd", "vhdx", "vmdk"].includes(ext)) {
    score += 45;
    const finding =
      `Disk image file (.${ext}) — commonly used to bypass Mark-of-the-Web (MOTW) ` +
      `security warnings; files inside disk images don't inherit internet zone restrictions. ` +
      `Used in QakBot, IcedID, and Cobalt Strike delivery campaigns`;
    signals.push(finding);
    findings.push({
      category: "evasion",
      severity: "critical",
      detail: finding,
    });
  }

  // ── NEW: Polyglot file detection ──
  // A polyglot is a file that is simultaneously valid in two formats.
  // e.g. a file that is a valid PDF AND a valid ZIP/JAR — scanners
  // see a PDF but the runtime executes it as a JAR.
  if (
    ext === "pdf" &&
    (header4 === "504b0304" || buffer.slice(0, 2).toString("hex") === "504b")
  ) {
    score += 65;
    const finding =
      `Polyglot file detected — file starts with ZIP/JAR signature (PK) ` +
      `but has .pdf extension. PDF+ZIP polyglots are executed as JARs by Java while ` +
      `appearing as PDFs to scanners. Extremely high-confidence malware indicator`;
    signals.push(finding);
    findings.push({
      category: "identity",
      severity: "critical",
      detail: finding,
    });
  }

  // ── NEW: MSI installer disguised as document ──
  // Windows Installer (.msi) files have a specific magic byte sequence
  // and are commonly renamed to .doc, .pdf, or .jpg for delivery
  const MSI_MAGIC = Buffer.from([
    0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1,
  ]);
  const isMSI = buffer.slice(0, 8).equals(MSI_MAGIC);
  if (isMSI && !["msi", "msp", "doc", "xls", "ppt"].includes(ext)) {
    score += 60;
    const finding =
      `MSI installer (Windows Installer) disguised as .${ext} — ` +
      `MSI files silently install software with elevated privileges; ` +
      `renaming them is a common malware delivery technique`;
    signals.push(finding);
    findings.push({
      category: "identity",
      severity: "critical",
      detail: finding,
    });
  }

  // ── NEW: OneNote embedded script detection ──
  // OneNote (.one) files can embed executable attachments that run on click.
  // Heavily abused in 2023-2024 campaigns after macro-enabled Office docs
  // became harder to deliver following Microsoft's MOTW enforcement.
  if (
    ext === "one" ||
    buffer.slice(0, 16).toString("hex") === "e4525c7b8cd8a74daeb15378d02996d3"
  ) {
    score += 50;
    const finding =
      `OneNote file (.one) — OneNote files can embed and execute any file type ` +
      `when the user clicks an embedded object. Surged as primary malware delivery ` +
      `vector in 2023 after Microsoft blocked macros in Office files`;
    signals.push(finding);
    findings.push({
      category: "extension",
      severity: "critical",
      detail: finding,
    });

    // Check if it also has embedded executable references
    const content = buffer.toString("latin1");
    if (/\.exe|\.cmd|\.bat|\.ps1|\.vbs|\.hta/i.test(content)) {
      score += 25;
      const finding2 =
        `OneNote file contains embedded executable reference — likely contains ` +
        `click-to-run payload`;
      signals.push(finding2);
      findings.push({
        category: "embedded",
        severity: "critical",
        detail: finding2,
      });
    }
  }

  // ── 10. Suspiciously small document (lure document) ──
  if (size < 100 && ["docx", "xlsx", "pdf", "doc", "xls"].includes(ext)) {
    score += 20;
    const finding = `Suspiciously small ${ext.toUpperCase()} (${size} bytes) — likely an empty lure that triggers a remote template load`;
    signals.push(finding);
    findings.push({ category: "evasion", severity: "medium", detail: finding });
  }

  // ── Verdict ──
  const finalScore = Math.min(score, 100);
  const verdict =
    finalScore >= 70 ? "malicious" : finalScore >= 35 ? "suspicious" : "clean";

  const response = {
    filename: originalname,
    sha256,
    extension: ext,
    mimetype,
    actualType, // detected from magic bytes, not filename
    sizeKB: Math.round(size / 1024),
    score: finalScore,
    verdict,
    signals,
    findings, // structured, categorized findings
    categories: [...new Set(findings.map((f) => f.category))],
    analysisType: "static_v2",
    analyzedAt: new Date().toISOString(),
  };

  res.json(response);
});

router.post(
  "/qr-decode",
  requireAuth,
  requireRole("admin", "analyst"),
  upload.single("image"),
  async (req, res) => {
    if (!req.file) return res.status(400).json({ error: "No image uploaded" });

    // We decode the QR in the browser (jsqr) and POST the decoded URL here.
    // This endpoint receives the already-decoded URL string from the frontend
    // and runs it through the FULL phishing detection pipeline — not just
    // QUISHING_PATTERNS, but the complete URL analysis (all 26 checks).
    // The frontend sends: { decodedUrl: "https://evil.com/phish" }
    // This endpoint is the bridge between the browser's QR decode and
    // the backend's full-strength detection.
    const { decodedUrl } = req.body;
    if (!decodedUrl)
      return res.status(400).json({ error: "No decoded URL provided" });

    try {
      const result = await analyzeInput(decodedUrl);
      // Tag it as QR-sourced so the frontend can show the QR context
      result.inputSource = "qr_decode";
      result.originalQRData = decodedUrl;
      result.quishingContext = {
        decoded: true,
        note: "URL was extracted from a QR code image. QR codes are frequently used to bypass email security scanners (quishing). The URL has been analyzed through the full PhishNetra detection pipeline.",
        additionalRisk:
          result.riskScore > 0 ? Math.min(result.riskScore + 15, 100) : 0, // +15 bonus risk for QR delivery method specifically
      };
      res.json(result);
    } catch (err) {
      res.status(500).json({ error: "QR URL analysis failed" });
    }
  },
);

module.exports = router;
