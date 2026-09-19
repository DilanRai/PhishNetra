// ================================================================
// FILE: backend/routes/siem.js
// SentinelCore SIEM API Routes
// ================================================================

const express = require("express");
const router = express.Router();
const { ingestEvent, ingestFromScan } = require("../siem/eventEngine");
const { runCorrelation } = require("../siem/correlationEngine");
const { getAllRules } = require("../siem/ruleEngine");
const Event = require("../siem/models/Event");
const Alert = require("../siem/models/Alert");
const crypto = require("crypto");
const { formatIdForReport, parseForensicId } = require("../utils/forensicId");
const {
  runAnomalyCheck,
  computeBaseline,
  getCurrentHourStats,
} = require("../siem/anomalyBaseline");
const { requireAuth, requireRole } = require("../routes/auth");

// Safe-load models
let CustomRule;
try {
  CustomRule = require("../models/CustomRule");
} catch {}

let attackRuleMap = null;
try {
  attackRuleMap = require("../siem/attackRuleMap");
} catch {}

let ShiftNote;
try {
  ShiftNote = require("../models/ShiftNote");
} catch {}

// ─────────────────────────────────────────────────────────────
// POST /api/siem/event — Ingest a security event
// ─────────────────────────────────────────────────────────────
router.post("/event", async (req, res) => {
  try {
    const raw = req.body;
    if (!raw || !raw.type) {
      return res.status(400).json({ error: "Event type is required" });
    }
    const result = await ingestEvent({ ...raw, sourceIp: req.ip });
    // Push WebSocket event for new alerts
    if (result.alertsFired > 0) {
      const io = req.app.get("io");
      if (io) {
        io.emit("siem_alert", {
          alertsFired: result.alertsFired,
          rulesMatched: result.rulesMatched,
          severity: result.severity,
          eventId: result.eventId,
          timestamp: new Date().toISOString(),
        });
      }
    }
    res.json({ success: true, ...result });
  } catch (err) {
    console.error("SIEM ingest error:", err.message);
    res.status(500).json({ error: "Failed to ingest event" });
  }
});

// ─────────────────────────────────────────────────────────────
// GET /api/siem/alerts — Get alerts (with filters)
// ─────────────────────────────────────────────────────────────
router.get("/alerts", async (req, res) => {
  try {
    const { status, severity, category, limit = 50, page = 1 } = req.query;
    const filter = {};
    if (status) filter.status = status;
    if (severity) filter.severity = Number(severity);
    if (category) filter.category = category;

    const [alerts, total] = await Promise.all([
      Alert.find(filter)
        .sort({ firstSeen: -1 })
        .limit(Number(limit))
        .skip((Number(page) - 1) * Number(limit))
        .lean(),
      Alert.countDocuments(filter),
    ]);

    res.json({ alerts, total, page: Number(page), limit: Number(limit) });
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch alerts" });
  }
});

// ─────────────────────────────────────────────────────────────
// PATCH /api/siem/alerts/:alertId — Update alert status
// ─────────────────────────────────────────────────────────────
router.patch(
  "/alerts/:alertId",
  requireAuth,
  requireRole("admin", "analyst"),
  async (req, res) => {
    try {
      const { alertId } = req.params;
      const { status, notes, assignee } = req.body;

      const existingAlert = await Alert.findOne({ alertId });
      if (!existingAlert)
        return res.status(404).json({ error: "Alert not found" });

      const analyst = req.user?.username || "system";
      const update = {};

      if (status) {
        const prevStatus = existingAlert.status;
        update.status = status;
        if (status === "resolved") update.resolvedAt = new Date();

        // Chain of custody — status change entry
        update.$push = update.$push || {};
        update.$push.chainOfCustody = {
          action: "status_changed",
          by: analyst,
          at: new Date(),
          detail: notes || `Status updated via SIEM dashboard`,
          fromStatus: prevStatus,
          toStatus: status,
        };

        // Append legacy audit trail to notes field
        update.notes =
          (existingAlert?.notes || "") +
          `\n[${new Date().toISOString()}] Status → ${status} by ${analyst}`;
      }

      if (notes && !status)
        update.notes = existingAlert.notes
          ? existingAlert.notes + "\n" + notes
          : notes;
      if (assignee) update.assignee = assignee;

      const alert = await Alert.findOneAndUpdate({ alertId }, update, {
        new: true,
      });
      res.json(alert);
    } catch (err) {
      res.status(500).json({ error: "Failed to update alert" });
    }
  },
);

// ─────────────────────────────────────────────────────────────
// GET /api/siem/events — Get raw events
// ─────────────────────────────────────────────────────────────
router.get("/events", async (req, res) => {
  try {
    const { category, severity, limit = 100, page = 1 } = req.query;
    const filter = {};
    if (category) filter.category = category;
    if (severity) filter.severity = Number(severity);

    const events = await Event.find(filter)
      .sort({ timestamp: -1 })
      .limit(Number(limit))
      .skip((Number(page) - 1) * Number(limit))
      .lean();

    res.json({ events, count: events.length });
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch events" });
  }
});

// ─────────────────────────────────────────────────────────────
// GET /api/siem/stats — Dashboard statistics
// ─────────────────────────────────────────────────────────────
router.get("/stats", async (req, res) => {
  try {
    const since24h = new Date(Date.now() - 24 * 60 * 60 * 1000);
    const since7d = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);

    const [
      totalEvents,
      totalAlerts,
      openAlerts,
      criticalAlerts,
      events24h,
      alerts24h,
      bySeverity,
      byCategory,
      topTargets,
      alertTrend,
      correlatedAlerts,
    ] = await Promise.all([
      Event.countDocuments(),
      Alert.countDocuments(),
      Alert.countDocuments({ status: "open" }),
      Alert.countDocuments({ severity: 5, status: "open" }),
      Event.countDocuments({ timestamp: { $gte: since24h } }),
      Alert.countDocuments({ firstSeen: { $gte: since24h } }),
      Alert.aggregate([{ $group: { _id: "$severity", count: { $sum: 1 } } }]),
      Alert.aggregate([{ $group: { _id: "$category", count: { $sum: 1 } } }]),
      Event.aggregate([
        {
          $match: {
            timestamp: { $gte: since7d },
            "target.domain": { $ne: null },
          },
        },
        {
          $group: {
            _id: "$target.domain",
            count: { $sum: 1 },
            maxSeverity: { $max: "$severity" },
          },
        },
        { $sort: { count: -1 } },
        { $limit: 10 },
      ]),
      Alert.aggregate([
        { $match: { firstSeen: { $gte: since7d } } },
        {
          $group: {
            _id: { $dateToString: { format: "%Y-%m-%d", date: "$firstSeen" } },
            total: { $sum: 1 },
            critical: { $sum: { $cond: [{ $eq: ["$severity", 5] }, 1, 0] } },
            high: { $sum: { $cond: [{ $eq: ["$severity", 4] }, 1, 0] } },
          },
        },
        { $sort: { _id: 1 } },
      ]),
      Alert.countDocuments({ isCorrelated: true, status: "open" }),
    ]);

    // MITRE coverage
    const mitreTactics = await Alert.aggregate([
      { $match: { "mitre.tactic": { $ne: null } } },
      { $group: { _id: "$mitre.tactic", count: { $sum: 1 } } },
      { $sort: { count: -1 } },
      { $limit: 8 },
    ]);

    res.json({
      overview: {
        totalEvents,
        totalAlerts,
        openAlerts,
        criticalAlerts,
        events24h,
        alerts24h,
        correlatedAlerts,
      },
      severity: Object.fromEntries(bySeverity.map((b) => [b._id, b.count])),
      byCategory: Object.fromEntries(
        byCategory.map((b) => [b._id || "unknown", b.count]),
      ),
      topTargets: topTargets.map((t) => ({
        domain: t._id,
        count: t.count,
        maxSeverity: t.maxSeverity,
      })),
      alertTrend,
      mitreTactics: mitreTactics.map((m) => ({
        tactic: m._id,
        count: m.count,
      })),
    });
  } catch (err) {
    console.error("SIEM stats error:", err);
    res.status(500).json({ error: "Failed to fetch SIEM stats" });
  }
});

// ─────────────────────────────────────────────────────────────
// GET /api/siem/rules — List all detection rules
// ─────────────────────────────────────────────────────────────
router.get("/rules", (req, res) => {
  res.json({ rules: getAllRules(), total: getAllRules().length });
});

// ─────────────────────────────────────────────────────────────
// GET /api/siem/attack-rules — Full coverage map of MITRE techniques
// ─────────────────────────────────────────────────────────────
router.get("/attack-rules", (req, res) => {
  if (!attackRuleMap) {
    return res.status(503).json({
      error: "Attack rule map not loaded",
      message: "Ensure Backend/data/attack_rule_map.json exists",
    });
  }

  const { tech_id, platform } = req.query;

  // Lookup for a specific technique
  if (tech_id) {
    const entries = attackRuleMap.getAttackEntries(tech_id);
    const sigmaRules = attackRuleMap.getSigmaRules(tech_id);
    const splunkRules = attackRuleMap.getSplunkRules(tech_id);

    if (entries.length === 0) {
      return res.json({
        tech_id,
        found: false,
        sigmaRules: [],
        splunkRules: [],
        message: `No detection rules found for ${tech_id}`,
      });
    }

    return res.json({
      tech_id,
      found: true,
      entries: entries.map((e) => ({
        atomic_attack_name: e.atomic_attack_name,
        platform: e.platform,
        sigma_count: e.sigma_rules?.length || 0,
        splunk_count: e.splunk_rules?.length || 0,
      })),
      sigmaRules: sigmaRules,
      splunkRules: splunkRules,
    });
  }

  // Full coverage list
  let techniques = attackRuleMap.getAllCoveredTechniques();

  // Filter by platform if requested
  if (platform) {
    techniques = techniques.filter((t) =>
      t.platforms.toLowerCase().includes(platform.toLowerCase()),
    );
  }

  const stats = attackRuleMap.getStats();
  res.json({
    stats,
    techniques: techniques.sort((a, b) => b.sigma_count - a.sigma_count),
  });
});

// ─────────────────────────────────────────────────────────────
// GET /api/siem/attack-rules/stats — Quick stats for dashboard
// ─────────────────────────────────────────────────────────────
router.get("/attack-rules/stats", (req, res) => {
  if (!attackRuleMap) {
    return res.json({ loaded: false, sigmaRulesTotal: 0, splunkRulesTotal: 0 });
  }
  res.json(attackRuleMap.getStats());
});

// ─────────────────────────────────────────────────────────────
// POST /api/siem/correlate — Manually trigger correlation
// ─────────────────────────────────────────────────────────────
router.post("/correlate", async (req, res) => {
  try {
    const result = await runCorrelation();
    res.json({ success: true, ...result });
  } catch (err) {
    res.status(500).json({ error: "Correlation failed" });
  }
});

// DELETE /api/siem/events — Clear all SIEM events (admin only)
router.delete(
  "/events",
  requireAuth,
  requireRole("admin"),
  async (req, res) => {
    try {
      const result = await Event.deleteMany({});
      res.json({
        message: `${result.deletedCount} SIEM events permanently deleted`,
      });
    } catch (err) {
      res.status(500).json({ error: "Failed to delete events" });
    }
  },
);

// GET /api/siem/baseline — current behavior vs baseline
router.get("/baseline", async (req, res) => {
  try {
    const [baseline, current] = await Promise.all([
      computeBaseline(),
      getCurrentHourStats(),
    ]);
    res.json({
      baseline,
      current,
      healthy:
        !baseline ||
        (current.phishingRate <= baseline.avgPhishingRate * 1.4 &&
          current.total <= baseline.avgScansPerHour * 1.4),
    });
  } catch (err) {
    res.status(500).json({ error: "Baseline unavailable" });
  }
});

// POST /api/siem/baseline/check — manually trigger anomaly check
router.post("/baseline/check", async (req, res) => {
  try {
    const result = await runAnomalyCheck();
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: "Anomaly check failed" });
  }
});

// GET /api/siem/geo — geolocation data for threat map
// FIX ISSUE 5: Added requireAuth guard
router.get("/geo", requireAuth, async (req, res) => {
  try {
    const {
      lookup,
      lookupDomain,
      isPrivateIP,
    } = require("../services/geolocate");
    const Event = require("../siem/models/Event");
    const Scan = require("../models/Scan");
    const since = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);

    const points = [];
    const seen = new Set(); // deduplicate by IP+category

    // ── FIX ISSUE 9: Batch async tasks with concurrency limit ──────────
    async function batchProcess(items, fn, batchSize = 20) {
      for (let i = 0; i < items.length; i += batchSize) {
        await Promise.allSettled(items.slice(i, i + batchSize).map(fn));
      }
    }

    // ── FIX ISSUE 1+2: Deterministic geo fallback for dead/expired domains ──
    // Phishing domains often have expired DNS. Hash the domain name to a
    // plausible known phishing-hosting region so every scan shows on the map.
    const PHISHING_GEO_FALLBACKS = [
      { country: "NG", region: "Lagos", lat: 6.45, lon: 3.39 }, // Nigeria (high volume)
      { country: "RO", region: "Bucharest", lat: 44.43, lon: 26.1 }, // Romania
      { country: "UA", region: "Kyiv", lat: 50.45, lon: 30.52 }, // Ukraine
      { country: "RU", region: "Moscow", lat: 55.75, lon: 37.61 }, // Russia
      { country: "CN", region: "Shanghai", lat: 31.22, lon: 121.46 }, // China
      { country: "VN", region: "HCM", lat: 10.82, lon: 106.62 }, // Vietnam
      { country: "PH", region: "Manila", lat: 14.6, lon: 120.98 }, // Philippines
      { country: "IN", region: "Delhi", lat: 28.61, lon: 77.21 }, // India (domestic)
      { country: "BR", region: "SP", lat: -23.54, lon: -46.63 }, // Brazil
      { country: "ID", region: "Jakarta", lat: -6.21, lon: 106.84 }, // Indonesia
    ];

    function fallbackGeo(domain) {
      let hash = 0;
      for (let i = 0; i < domain.length; i++)
        hash = (hash << 5) - hash + domain.charCodeAt(i);
      const idx = Math.abs(hash) % PHISHING_GEO_FALLBACKS.length;
      const fb = PHISHING_GEO_FALLBACKS[idx];
      // Small jitter so multiple dead domains don't stack on the same pixel
      const jitterLat = ((hash % 100) / 100) * 4 - 2;
      const jitterLon = (((hash >> 8) % 100) / 100) * 4 - 2;
      return {
        ip: `fallback-${domain.substring(0, 8)}`,
        domain,
        country: fb.country,
        region: fb.region,
        city: fb.region,
        lat: fb.lat + jitterLat,
        lon: fb.lon + jitterLon,
        org: "Phishing Infrastructure",
        isFallback: true, // frontend renders these as dashed/outlined circles
      };
    }

    // ── Source 1: SIEM events ──────────────────────────────────────────
    const events = await Event.find(
      {
        timestamp: { $gte: since },
        $or: [
          { "source.ip": { $nin: [null, "unknown", "::1", "127.0.0.1"] } },
          { "target.domain": { $nin: [null, "", "unknown"] } },
        ],
      },
      {
        "source.ip": 1,
        "target.domain": 1,
        "target.url": 1,
        category: 1,
        severity: 1,
        timestamp: 1,
      },
    )
      .limit(300)
      .lean();

    await batchProcess(events, async (e) => {
      let geo = null;
      if (e.target?.domain)
        geo = await lookupDomain(e.target.domain).catch(() => null);
      if (!geo && e.source?.ip && !isPrivateIP(e.source.ip))
        geo = lookup(e.source.ip);
      // FIX ISSUE 1+2: Fallback for dead/expired phishing domains
      if (!geo && e.target?.domain) geo = fallbackGeo(e.target.domain);
      if (!geo) return;

      const key = `${geo.ip || geo.domain}:${e.category}`;
      if (seen.has(key)) return;
      seen.add(key);

      points.push({
        ip: geo.ip,
        domain: e.target?.domain || null,
        country: geo.country,
        region: geo.region,
        city: geo.city,
        lat: geo.lat,
        lon: geo.lon,
        org: geo.org || "",
        category: e.category || "phishing",
        severity: e.severity || 3,
        timestamp: e.timestamp,
        source: "siem",
        isFallback: geo.isFallback || false,
      });
    });

    // ── Source 2: Scan history ─────────────────────────────────────────
    const scans = await Scan.find(
      {
        createdAt: { $gte: since },
        status: { $in: ["phishing", "suspicious"] },
        inputType: "url",
        input: { $exists: true, $ne: "" },
      },
      { input: 1, status: 1, riskScore: 1, createdAt: 1 },
    )
      .limit(200)
      .lean();

    await batchProcess(scans, async (scan) => {
      let domain = null;
      try {
        const input = typeof scan.input === "string" ? scan.input : "";
        if (!input) return;
        const url = input.startsWith("http") ? input : `https://${input}`;
        domain = new URL(url).hostname.replace(/^www\./, "");

        // FIX ISSUE 2: Extract any literal IP embedded in the URL path
        const ipInUrl = input.match(/\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/);
        if (ipInUrl && !isPrivateIP(ipInUrl[1])) {
          const geo = lookup(ipInUrl[1]);
          if (geo) {
            const key = `${geo.ip}:phishing`;
            if (!seen.has(key)) {
              seen.add(key);
              points.push({
                ...geo,
                category: "phishing",
                severity: scan.riskScore >= 80 ? 5 : 4,
                timestamp: scan.createdAt,
                source: "scan",
                riskScore: scan.riskScore,
                isFallback: false,
              });
            }
            return;
          }
        }
      } catch {
        return;
      }

      if (!domain || domain.length < 4) return;

      let geo = await lookupDomain(domain).catch(() => null);
      // FIX ISSUE 1+2: Use fallback geo for dead/expired phishing domains
      if (!geo) geo = fallbackGeo(domain);

      const key = `${geo.ip || domain}:phishing`;
      if (seen.has(key)) return;
      seen.add(key);

      points.push({
        ip: geo.ip,
        domain,
        country: geo.country,
        region: geo.region,
        city: geo.city,
        lat: geo.lat,
        lon: geo.lon,
        org: geo.org || "",
        category: "phishing",
        severity: scan.riskScore >= 80 ? 5 : scan.riskScore >= 60 ? 4 : 3,
        timestamp: scan.createdAt,
        source: "scan",
        riskScore: scan.riskScore,
        isFallback: geo.isFallback || false,
      });
    });

    // ── FIX ISSUE 10: Source 3 — Honeypot hits ────────────────────────
    try {
      const mongoose = require("mongoose");
      // Try to resolve the Hit model — may be registered under various names
      let Hit = null;
      try {
        Hit = mongoose.model("Hit");
      } catch {}
      if (!Hit)
        try {
          Hit = require("../models/Trap");
        } catch {}

      if (Hit) {
        const hits = await Hit.find({ createdAt: { $gte: since } })
          .limit(50)
          .lean();
        await batchProcess(hits, async (hit) => {
          const ip = hit.ip || hit.attackerIp || hit.sourceIp;
          if (!ip || isPrivateIP(ip)) return;
          const geo = lookup(ip);
          if (!geo) return;

          const key = `${geo.ip}:honeypot`;
          if (seen.has(key)) return;
          seen.add(key);

          points.push({
            ip: geo.ip,
            domain: null,
            country: geo.country,
            region: geo.region,
            city: geo.city,
            lat: geo.lat,
            lon: geo.lon,
            org: geo.org || "",
            category: "honeypot",
            severity: 5, // honeypot hits are always critical
            timestamp: hit.createdAt,
            source: "honeypot",
            isFallback: false,
          });
        });
      }
    } catch {
      /* Honeypot model optional — fail silently */
    }

    // ── Country summary ────────────────────────────────────────────────
    const countryMap = {};
    points.forEach((p) => {
      if (!p.country) return;
      if (!countryMap[p.country])
        countryMap[p.country] = { count: 0, critical: 0 };
      countryMap[p.country].count++;
      if (p.severity >= 4) countryMap[p.country].critical++;
    });
    const topCountries = Object.entries(countryMap)
      .sort((a, b) => b[1].count - a[1].count)
      .slice(0, 10)
      .map(([country, data]) => ({ country, ...data }));

    res.json({
      points,
      total: points.length,
      topCountries,
      scannedSince: since.toISOString(),
      resolvedAt: new Date().toISOString(),
      fallbackCount: points.filter((p) => p.isFallback).length,
    });
  } catch (err) {
    console.error("Geo endpoint error:", err);
    res.status(500).json({ error: "Geo data unavailable", points: [] });
  }
});

// POST /api/siem/alerts/:alertId/comment — Add analyst comment
router.post(
  "/alerts/:alertId/comment",
  requireAuth,
  requireRole("admin", "analyst"),
  async (req, res) => {
    try {
      const { alertId } = req.params;
      const { text } = req.body;
      if (!text?.trim())
        return res.status(400).json({ error: "Comment text required" });

      const alert = await Alert.findOneAndUpdate(
        { alertId },
        {
          $push: {
            comments: {
              author: req.user.username,
              text: text.trim(),
              timestamp: new Date(),
            },
            chainOfCustody: {
              action: "commented",
              by: req.user.username,
              at: new Date(),
              detail: `Comment added (${text.trim().length} chars)`,
            },
          },
        },
        { new: true },
      );
      if (!alert) return res.status(404).json({ error: "Alert not found" });
      res.json({ comments: alert.comments });
    } catch (err) {
      console.error("Comment error:", err);
      res.status(500).json({ error: "Failed to add comment" });
    }
  },
);

// PATCH /api/siem/alerts/:alertId/assign — Assign alert to analyst
router.patch(
  "/alerts/:alertId/assign",
  requireAuth,
  requireRole("admin", "analyst"),
  async (req, res) => {
    try {
      const { alertId } = req.params;
      const { assignee } = req.body;

      const existingAlert = await Alert.findOne({ alertId });
      if (!existingAlert)
        return res.status(404).json({ error: "Alert not found" });

      const analyst = req.user?.username || "system";
      const alert = await Alert.findOneAndUpdate(
        { alertId },
        {
          assignee,
          notes:
            (existingAlert.notes || "") +
            `\n[${new Date().toISOString()}] Assigned to ${assignee} by ${analyst}`,
          $push: {
            chainOfCustody: {
              action: "assigned",
              by: analyst,
              at: new Date(),
              detail: `Assigned to ${assignee}`,
            },
          },
        },
        { new: true },
      );
      res.json(alert);
    } catch (err) {
      console.error("Assignment error:", err);
      res.status(500).json({ error: "Failed to assign alert" });
    }
  },
);

// GET /api/siem/kpi — MTTD, MTTR, FP rate, weekly trends
router.get("/kpi", async (req, res) => {
  try {
    const since7d = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
    const since30d = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);

    const [allAlerts, resolved, falsePositives, weeklyTrend, topTechniques] =
      await Promise.all([
        Alert.find(
          { firstSeen: { $gte: since30d } },
          { severity: 1, firstSeen: 1, resolvedAt: 1, status: 1, ruleId: 1 },
        ).lean(),
        Alert.find(
          {
            status: "resolved",
            resolvedAt: { $gte: since30d },
            firstSeen: { $gte: since30d },
          },
          { firstSeen: 1, resolvedAt: 1, severity: 1 },
        ).lean(),
        Alert.countDocuments({
          status: "false_positive",
          firstSeen: { $gte: since30d },
        }),
        Alert.aggregate([
          { $match: { firstSeen: { $gte: since7d } } },
          {
            $group: {
              _id: {
                $dateToString: { format: "%Y-%m-%d", date: "$firstSeen" },
              },
              total: { $sum: 1 },
              critical: { $sum: { $cond: [{ $eq: ["$severity", 5] }, 1, 0] } },
              resolved: {
                $sum: { $cond: [{ $eq: ["$status", "resolved"] }, 1, 0] },
              },
            },
          },
          { $sort: { _id: 1 } },
        ]),
        Alert.aggregate([
          { $match: { firstSeen: { $gte: since7d } } },
          {
            $group: {
              _id: "$ruleId",
              count: { $sum: 1 },
              ruleName: { $first: "$ruleName" },
            },
          },
          { $sort: { count: -1 } },
          { $limit: 8 },
        ]),
      ]);

    // MTTD — Mean Time to Detect (time from event to alert creation, approx 0 since we create immediately)
    // We measure as avg time alerts stay open before investigation
    const investigated = allAlerts.filter((a) => a.status !== "open");
    const mttdMs =
      investigated.length > 0
        ? investigated.reduce(
            (sum, a) =>
              sum +
              (new Date(a.resolvedAt || Date.now()) - new Date(a.firstSeen)),
            0,
          ) / investigated.length
        : 0;

    // MTTR — Mean Time to Respond (open → resolved)
    const mttrMs =
      resolved.length > 0
        ? resolved.reduce(
            (sum, a) => sum + (new Date(a.resolvedAt) - new Date(a.firstSeen)),
            0,
          ) / resolved.length
        : 0;

    const totalAlerts = allAlerts.length;
    const fpRate =
      totalAlerts > 0 ? Math.round((falsePositives / totalAlerts) * 100) : 0;

    // Alert severity distribution this week
    const sevDist = { 5: 0, 4: 0, 3: 0, 2: 0, 1: 0 };
    allAlerts
      .filter((a) => new Date(a.firstSeen) >= since7d)
      .forEach((a) => {
        sevDist[a.severity] = (sevDist[a.severity] || 0) + 1;
      });

    res.json({
      mttd: Math.round(mttdMs / 60000), // minutes
      mttr: Math.round(mttrMs / 60000), // minutes
      fpRate,
      totalAlerts30d: totalAlerts,
      resolved30d: resolved.length,
      resolutionRate:
        totalAlerts > 0 ? Math.round((resolved.length / totalAlerts) * 100) : 0,
      severityDist: sevDist,
      weeklyTrend,
      topTechniques: topTechniques.map((t) => ({
        ruleId: t._id,
        ruleName: t.ruleName,
        count: t.count,
      })),
    });
  } catch (err) {
    console.error("KPI error:", err);
    res.status(500).json({ error: "KPI data unavailable" });
  }
});

// POST /api/siem/rules/test — test a sample event against all rules
router.post("/rules/test", (req, res) => {
  try {
    const { event } = req.body;
    if (!event) return res.status(400).json({ error: "Event object required" });

    const { matchRules } = require("../siem/ruleEngine");
    const matches = matchRules(event);

    res.json({
      tested: true,
      input: event,
      matches,
      fired: matches.length,
      ruleIds: matches.map((m) => m.ruleId),
    });
  } catch (err) {
    res.status(500).json({ error: "Rule test failed: " + err.message });
  }
});

// GET /api/siem/rules/custom — list custom rules
router.get("/rules/custom", requireAuth, async (req, res) => {
  try {
    if (!CustomRule) return res.json({ rules: [] });
    const rules = await CustomRule.find().sort({ createdAt: -1 }).lean();
    res.json({ rules });
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch custom rules" });
  }
});

// POST /api/siem/rules/custom — create custom rule
router.post(
  "/rules/custom",
  requireAuth,
  requireRole("admin", "analyst"),
  async (req, res) => {
    try {
      if (!CustomRule)
        return res.status(503).json({ error: "Custom rules not available" });
      const { name, category, severity, conditions, mitre, dedupWindowMin } =
        req.body;
      if (!name?.trim())
        return res.status(400).json({ error: "Rule name required" });

      // Auto-generate ID
      const count = await CustomRule.countDocuments();
      const ruleId = `CUS-${String(count + 1).padStart(3, "0")}`;

      const rule = await CustomRule.create({
        ruleId,
        name: name.trim(),
        category,
        severity,
        conditions: conditions || {},
        mitre: mitre || {},
        dedupWindowMin: dedupWindowMin || 5,
        createdBy: req.user.username,
      });
      res.status(201).json(rule);
    } catch (err) {
      res.status(500).json({ error: "Failed to create rule: " + err.message });
    }
  },
);

// PATCH /api/siem/rules/custom/:id — update (toggle, edit)
router.patch(
  "/rules/custom/:id",
  requireAuth,
  requireRole("admin", "analyst"),
  async (req, res) => {
    try {
      if (!CustomRule)
        return res.status(503).json({ error: "Custom rules not available" });
      const rule = await CustomRule.findByIdAndUpdate(
        req.params.id,
        { ...req.body, updatedAt: new Date() },
        { new: true },
      );
      if (!rule) return res.status(404).json({ error: "Rule not found" });
      res.json(rule);
    } catch (err) {
      res.status(500).json({ error: "Failed to update rule" });
    }
  },
);

// DELETE /api/siem/rules/custom/:id — delete custom rule
router.delete(
  "/rules/custom/:id",
  requireAuth,
  requireRole("admin"),
  async (req, res) => {
    try {
      if (!CustomRule)
        return res.status(503).json({ error: "Custom rules not available" });
      await CustomRule.findByIdAndDelete(req.params.id);
      res.json({ message: "Rule deleted" });
    } catch (err) {
      res.status(500).json({ error: "Failed to delete rule" });
    }
  },
);

// GET /api/siem/shift-notes
router.get("/shift-notes", requireAuth, async (req, res) => {
  try {
    if (!ShiftNote) return res.json({ notes: [] });
    // Auto-delete expired non-pinned notes
    await ShiftNote.deleteMany({
      pinned: false,
      expiresAt: { $lt: new Date() },
    });
    const notes = await ShiftNote.find()
      .sort({ pinned: -1, createdAt: -1 })
      .limit(20)
      .lean();
    res.json({ notes });
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch shift notes" });
  }
});

// POST /api/siem/shift-notes
router.post(
  "/shift-notes",
  requireAuth,
  requireRole("admin", "analyst"),
  async (req, res) => {
    try {
      if (!ShiftNote)
        return res.status(503).json({ error: "Shift notes not available" });
      const {
        content,
        priority,
        pinned,
        referencedAlertIds,
        referencedLogIds,
        referencedCaseId,
        signedBy,
        isHandover,
      } = req.body;
      if (!content?.trim())
        return res.status(400).json({ error: "Content required" });
      const note = await ShiftNote.create({
        content: content.trim(),
        author: req.user.username,
        priority: priority || "normal",
        pinned: !!pinned,
        referencedAlertIds: referencedAlertIds || [],
        referencedLogIds: referencedLogIds || [],
        referencedCaseId: referencedCaseId || null,
        signedBy: signedBy || req.user.username,
        isHandover: !!isHandover,
      });
      res.status(201).json(note);
    } catch (err) {
      res.status(500).json({ error: "Failed to create note" });
    }
  },
);

// PATCH /api/siem/shift-notes/:id — pin/unpin or edit
router.patch(
  "/shift-notes/:id",
  requireAuth,
  requireRole("admin", "analyst"),
  async (req, res) => {
    try {
      if (!ShiftNote)
        return res.status(503).json({ error: "Shift notes not available" });
      const note = await ShiftNote.findByIdAndUpdate(
        req.params.id,
        { ...req.body, updatedAt: new Date() },
        { new: true },
      );
      if (!note) return res.status(404).json({ error: "Note not found" });
      res.json(note);
    } catch (err) {
      res.status(500).json({ error: "Failed to update note" });
    }
  },
);

// DELETE /api/siem/shift-notes/:id
router.delete(
  "/shift-notes/:id",
  requireAuth,
  requireRole("admin", "analyst"),
  async (req, res) => {
    try {
      if (!ShiftNote)
        return res.status(503).json({ error: "Shift notes not available" });
      await ShiftNote.findByIdAndDelete(req.params.id);
      res.json({ message: "Note deleted" });
    } catch (err) {
      res.status(500).json({ error: "Failed to delete note" });
    }
  },
);

// ─────────────────────────────────────────────────────────────
// Enterprise Policy
// In-memory policy store (use DB in production)
// ─────────────────────────────────────────────────────────────
let enterprisePolicy = {
  blockedTLDs: [".tk", ".ml", ".ga", ".cf", ".gq"],
  autoReportToSIEM: true,
  forceScanAllLinks: false,
  whitelistedDomains: ["google.com", "microsoft.com", "github.com"],
  alertEmail: null,
  policyVersion: "1.0",
  updatedAt: new Date().toISOString(),
};

// GET /api/siem/enterprise-policy
router.get("/enterprise-policy", (req, res) => {
  res.json(enterprisePolicy);
});

// PATCH /api/siem/enterprise-policy
router.patch(
  "/enterprise-policy",
  requireAuth,
  requireRole("admin"),
  async (req, res) => {
    enterprisePolicy = {
      ...enterprisePolicy,
      ...req.body,
      updatedAt: new Date().toISOString(),
    };
    res.json(enterprisePolicy);
  },
);

// DELETE /api/siem/alerts — permanently delete all alerts
router.delete(
  "/alerts",
  requireAuth,
  requireRole("admin"),
  async (req, res) => {
    try {
      const result = await Alert.deleteMany({});
      res.json({
        message: `${result.deletedCount} alerts permanently deleted`,
      });
    } catch (err) {
      res.status(500).json({ error: "Failed to delete alerts" });
    }
  },
);

// ── Idea 8: SIEM Alert export — CSV and PDF ──
router.get("/alerts/export", requireAuth, async (req, res) => {
  try {
    const format = req.query.format || "csv";
    const status = req.query.status || null;
    const query = status ? { status } : {};
    const alerts = await Alert.find(query)
      .sort({ createdAt: -1 })
      .limit(500)
      .lean();

    if (format === "csv") {
      const headers = [
        "ID",
        "Created",
        "Severity",
        "Category",
        "Rule",
        "Status",
        "Description",
      ];
      const rows = alerts.map((a) => [
        a._id,
        new Date(a.createdAt).toISOString(),
        a.severity,
        a.category,
        a.ruleId,
        a.status,
        `"${(a.description || "").replace(/"/g, '""')}"`,
      ]);
      const csv = [headers.join(","), ...rows.map((r) => r.join(","))].join(
        "\n",
      );
      res.setHeader("Content-Type", "text/csv");
      res.setHeader(
        "Content-Disposition",
        `attachment; filename="phishnetra-alerts-${Date.now()}.csv"`,
      );
      return res.send(csv);
    }

    if (format === "pdf") {
      const PDFDocument = require("pdfkit");
      const doc = new PDFDocument({ margin: 40, size: "A4" });
      res.setHeader("Content-Type", "application/pdf");
      res.setHeader(
        "Content-Disposition",
        `attachment; filename="phishnetra-siem-report-${Date.now()}.pdf"`,
      );
      doc.pipe(res);

      // ── Colour palette for print (white background) ──
      const C = {
        title: "#0f766e", // dark teal  — was #34d399 (too light on paper)
        meta: "#374151", // dark grey   — was #94a3b8
        section: "#111827", // near-black  — was #f1f5f9
        body: "#1f2937", // dark grey   — was #94a3b8
        divider: "#d1d5db", // light grey line — was #1c2840 (invisible on white)
      };

      // ── Severity colours darkened for print ──
      const sevColors = {
        5: "#7f1d1d", // deep dark red — was #b91c1c
        4: "#c2410c", // dark orange  — was #fb923c
        3: "#b45309", // dark amber   — was #fbbf24
        2: "#15803d", // dark green   — was #34d399
        1: "#374151", // dark grey    — was #64748b
      };
      const sevLabels = {
        5: "CRITICAL",
        4: "HIGH",
        3: "MEDIUM",
        2: "LOW",
        1: "INFO",
      };

      // Header
      doc
        .fontSize(18)
        .fillColor(C.title)
        .text("PhishNetra SIEM — Alert Report", { align: "center" });
      doc.moveDown(0.4);
      doc
        .fontSize(10)
        .fillColor(C.meta)
        .text(
          `Generated: ${new Date().toLocaleString()} · Total: ${alerts.length} alerts`,
          { align: "center" },
        );
      doc.moveDown(1);

      // Summary
      const bySev = { 5: 0, 4: 0, 3: 0, 2: 0, 1: 0 };
      alerts.forEach((a) => {
        bySev[a.severity] = (bySev[a.severity] || 0) + 1;
      });
      doc
        .fontSize(12)
        .fillColor(C.section)
        .text("Summary", { underline: true });
      doc.moveDown(0.3);
      [5, 4, 3, 2, 1].forEach((sev) => {
        if (bySev[sev] > 0) {
          doc
            .fontSize(9)
            .fillColor(sevColors[sev])
            .text(`${sevLabels[sev]}: ${bySev[sev]}`, { continued: true })
            .fillColor(C.meta)
            .text("   ", { continued: true });
        }
      });
      doc.text("").moveDown(1);

      // Column headers
      doc
        .fontSize(8)
        .fillColor(C.meta)
        .text(
          "SEV   RULE ID          CATEGORY         STATUS       DATE & DESCRIPTION",
          {
            underline: true,
          },
        );
      doc.moveDown(0.4);

      // Alert rows
      alerts.slice(0, 100).forEach((a, i) => {
        const color = sevColors[a.severity] || C.meta;
        const label = sevLabels[a.severity] || String(a.severity);
        // Rule ID line — severity + rule + category in bold-ish color
        doc
          .fontSize(9)
          .fillColor(color)
          .text(
            `[${label}]  ${a.ruleId || "—"}  ·  ${a.category || "—"}  ·  ${a.status || "open"}`,
            {
              continued: false,
            },
          );
        // Description + timestamp in dark readable grey
        doc
          .fontSize(8)
          .fillColor(C.body)
          .text(
            `${new Date(a.firstSeen || a.createdAt).toLocaleString()}  —  ${(a.description || a.title || "").substring(0, 130)}`,
          );
        doc.moveDown(0.4);
        // Divider
        if (i < alerts.slice(0, 100).length - 1) {
          doc
            .moveTo(40, doc.y)
            .lineTo(555, doc.y)
            .strokeColor(C.divider)
            .lineWidth(0.5)
            .stroke()
            .moveDown(0.3);
        }
      });

      if (alerts.length > 100) {
        doc
          .moveDown(0.5)
          .fontSize(8)
          .fillColor(C.meta)
          .text(
            `+ ${alerts.length - 100} more alerts not shown. Export CSV for full list.`,
            { align: "center" },
          );
      }

      doc.end();
      return;
    }

    res.status(400).json({ error: "Format must be csv or pdf" });
  } catch (err) {
    console.error("Export error:", err.message);
    res.status(500).json({ error: "Export failed" });
  }
});

// ─────────────────────────────────────────────────────────────
// IOC Engine routes
// ─────────────────────────────────────────────────────────────
const { getIOCStats, listIOCs, markFalsePositive } = (() => {
  try {
    return require("../siem/iocEngine");
  } catch {
    return {
      getIOCStats: () => ({}),
      listIOCs: () => ({ iocs: [], total: 0 }),
      markFalsePositive: () => null,
    };
  }
})();

// GET /api/siem/ioc/stats — IOC dashboard stats
router.get("/ioc/stats", requireAuth, async (req, res) => {
  try {
    res.json(await getIOCStats());
  } catch (err) {
    res.status(500).json({ error: "IOC stats unavailable" });
  }
});

// GET /api/siem/ioc — paginated IOC list with filters
// ?type=domain|url|ip|email_sender|file_hash
// ?severity=1-5
// ?status=active|false_positive
// ?page=1&limit=50
router.get("/ioc", requireAuth, async (req, res) => {
  try {
    const { type, severity, status, page, limit } = req.query;
    res.json(await listIOCs({ type, severity, status, page, limit }));
  } catch (err) {
    res.status(500).json({ error: "IOC list unavailable" });
  }
});

// PATCH /api/siem/ioc/:id/false-positive — analyst marks an IOC as FP
router.patch(
  "/ioc/:id/false-positive",
  requireAuth,
  requireRole("admin", "analyst"),
  async (req, res) => {
    try {
      const ioc = await markFalsePositive(req.params.id);
      if (!ioc) return res.status(404).json({ error: "IOC not found" });
      res.json({ message: "IOC marked as false positive", ioc });
    } catch (err) {
      res.status(500).json({ error: "Failed to update IOC" });
    }
  },
);

// DELETE /api/siem/ioc/:id — admin permanently removes an IOC
router.delete(
  "/ioc/:id",
  requireAuth,
  requireRole("admin"),
  async (req, res) => {
    try {
      const { IOC } = require("../siem/iocEngine");
      await IOC.findByIdAndDelete(req.params.id);
      res.json({ message: "IOC deleted" });
    } catch (err) {
      res.status(500).json({ error: "Failed to delete IOC" });
    }
  },
);

// ─────────────────────────────────────────────────────────────
// GET /api/siem/alerts/:alertId/custody-report
// Returns a formatted chain of custody document (plain text + JSON)
// ─────────────────────────────────────────────────────────────
router.get("/alerts/:alertId/custody-report", requireAuth, async (req, res) => {
  try {
    const LogEvent = require("../siem/models/LogEvent");
    const alert = await Alert.findOne({ alertId: req.params.alertId }).lean();
    if (!alert) return res.status(404).json({ error: "Alert not found" });

    // Fetch linked log events
    const linkedLogs = alert.linkedLogIds?.length
      ? await LogEvent.find({ logId: { $in: alert.linkedLogIds } }).lean()
      : [];

    const now = new Date();
    const SCORE_COLOR_LABEL =
      alert.riskScore >= 70 ? "HIGH" : alert.riskScore >= 40 ? "MEDIUM" : "LOW";

    const lines = [
      "╔══════════════════════════════════════════════════════════════╗",
      "║          PHISHNETRA AI — CHAIN OF CUSTODY DOCUMENT          ║",
      "╚══════════════════════════════════════════════════════════════╝",
      "",
      `Report Generated:  ${now.toUTCString()}`,
      `Generated By:      ${req.user?.username || "analyst"} via PhishNetra v6.0`,
      `Report Reference:  COC-${alert.alertId}`,
      "",
      "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
      "ALERT DETAILS",
      "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
      `Alert ID:          ${formatIdForReport(alert.alertId)}`,
      `Title:             ${alert.title}`,
      `Category:          ${alert.category}`,
      `Severity:          ${alert.severityLabel} (${alert.severity}/5)`,
      `Risk Score:        ${alert.riskScore}/100 [${SCORE_COLOR_LABEL}]`,
      `Current Status:    ${alert.status}`,
      `Rule Triggered:    ${alert.ruleId} — ${alert.ruleName}`,
      "",
      "TARGET",
      `  URL/Domain:      ${alert.target?.url || alert.target?.domain || "—"}`,
      `  IP Address:      ${alert.target?.ip || "—"}`,
      `  Email:           ${alert.target?.email || "—"}`,
      "",
      "MITRE ATT&CK",
      `  Tactic:          ${alert.mitre?.tactic || "—"}`,
      `  Technique:       ${alert.mitre?.technique || "—"}`,
      "",
      "TIMESTAMPS",
      `  First Seen:      ${new Date(alert.firstSeen).toUTCString()}`,
      `  Last Seen:       ${new Date(alert.lastSeen).toUTCString()}`,
      `  SLA Deadline:    ${alert.slaDeadline ? new Date(alert.slaDeadline).toUTCString() : "—"}`,
      `  Resolved At:     ${alert.resolvedAt ? new Date(alert.resolvedAt).toUTCString() : "Not resolved"}`,
      "",
      "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
      "CHAIN OF CUSTODY LOG",
      "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
      ...(alert.chainOfCustody?.length
        ? alert.chainOfCustody.map((entry, i) =>
            [
              `[${String(i + 1).padStart(2, "0")}] ${new Date(entry.at).toUTCString()}`,
              `     Action:   ${entry.action.replace(/_/g, " ").toUpperCase()}`,
              `     By:       ${entry.by}`,
              entry.fromStatus
                ? `     From:     ${entry.fromStatus} → ${entry.toStatus}`
                : null,
              entry.detail ? `     Detail:   ${entry.detail}` : null,
              "",
            ]
              .filter(Boolean)
              .join("\n"),
          )
        : ["  No custody chain entries recorded."]),
      "",
      "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
      "ANALYST COMMENTS",
      "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
      ...(alert.comments?.length
        ? alert.comments.map(
            (c, i) =>
              `[${String(i + 1).padStart(2, "0")}] ${new Date(c.timestamp).toUTCString()} — ${c.author}\n     ${c.text}`,
          )
        : ["  No analyst comments recorded."]),
      "",
      ...(linkedLogs.length > 0
        ? [
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
            "LINKED LOG EVENTS",
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
            ...linkedLogs.map((log, i) =>
              [
                `[${String(i + 1).padStart(2, "0")}] Log ID:    ${log.logId}`,
                `     Type:     ${log.logType}`,
                `     Host:     ${log.sourceHost || "—"}`,
                `     User:     ${log.sourceUser || "—"}`,
                `     Severity: ${log.severity}`,
                `     Collected:${new Date(log.collectedAt || log.createdAt).toUTCString()}`,
                `     Collector:${log.collectedBy || "fluent-bit"}`,
                `     Integrity:${log.integrityHash || "not verified"}`,
                `     Desc:     ${log.description}`,
                "",
              ].join("\n"),
            ),
          ]
        : []),
      "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
      "LEGAL NOTICE",
      "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
      "This chain of custody document was auto-generated by PhishNetra AI.",
      "All timestamps are in UTC. Log integrity hashes are SHA-256.",
      "This document supports forensic investigation under IT Act 2000,",
      "Section 65B of the Indian Evidence Act, and CyberCrime.gov.in",
      "complaint procedures. Reference this document using Alert ID:",
      `  ${alert.alertId}`,
      "",
      `Document Hash: ${crypto
        .createHash("sha256")
        .update(alert.alertId + alert.title + (alert.firstSeen || ""))
        .digest("hex")}`,
      "═══════════════════════════════════════════════════════════════",
    ];

    const report = lines.join("\n");

    res.json({
      alertId: alert.alertId,
      reportRef: `COC-${alert.alertId}`,
      generatedAt: now.toISOString(),
      generatedBy: req.user?.username || "analyst",
      report,
      custodyEntries: alert.chainOfCustody?.length || 0,
      linkedLogs: linkedLogs.length,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
