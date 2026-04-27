// ================================================================
// FILE: backend/routes/siem.js
// SentinelCore SIEM API Routes
// ================================================================
 
const express                      = require("express");
const router                       = express.Router();
const { ingestEvent, ingestFromScan } = require("../siem/eventEngine");
const { runCorrelation }           = require("../siem/correlationEngine");
const { getAllRules }               = require("../siem/ruleEngine");
const Event                        = require("../siem/models/Event");
const Alert                        = require("../siem/models/Alert");
 
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
    if (status)   filter.status   = status;
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
router.patch("/alerts/:alertId", async (req, res) => {
  try {
    const { alertId } = req.params;
    const { status, notes, assignee } = req.body;
 
    const update = {};
    if (status)   { update.status = status; if (status === "resolved") update.resolvedAt = new Date(); }
    if (notes)    update.notes    = notes;
    if (assignee) update.assignee = assignee;
 
    const alert = await Alert.findOneAndUpdate({ alertId }, update, { new: true });
    if (!alert) return res.status(404).json({ error: "Alert not found" });
    res.json(alert);
  } catch (err) {
    res.status(500).json({ error: "Failed to update alert" });
  }
});
 
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
    const since7d  = new Date(Date.now() - 7  * 24 * 60 * 60 * 1000);
 
    const [
      totalEvents, totalAlerts,
      openAlerts, criticalAlerts,
      events24h, alerts24h,
      bySeverity, byCategory,
      topTargets, alertTrend,
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
        { $match: { timestamp: { $gte: since7d }, "target.domain": { $ne: null } } },
        { $group: { _id: "$target.domain", count: { $sum: 1 }, maxSeverity: { $max: "$severity" } } },
        { $sort: { count: -1 } },
        { $limit: 10 },
      ]),
      Alert.aggregate([
        { $match: { firstSeen: { $gte: since7d } } },
        { $group: {
            _id:      { $dateToString: { format: "%Y-%m-%d", date: "$firstSeen" } },
            total:    { $sum: 1 },
            critical: { $sum: { $cond: [{ $eq: ["$severity", 5] }, 1, 0] } },
            high:     { $sum: { $cond: [{ $eq: ["$severity", 4] }, 1, 0] } },
        }},
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
        totalEvents, totalAlerts, openAlerts,
        criticalAlerts, events24h, alerts24h,
        correlatedAlerts,
      },
      severity: Object.fromEntries(
        bySeverity.map((b) => [b._id, b.count])
      ),
      byCategory: Object.fromEntries(
        byCategory.map((b) => [b._id || "unknown", b.count])
      ),
      topTargets: topTargets.map((t) => ({
        domain:      t._id,
        count:       t.count,
        maxSeverity: t.maxSeverity,
      })),
      alertTrend,
      mitreTactics: mitreTactics.map((m) => ({ tactic: m._id, count: m.count })),
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
 
// ─────────────────────────────────────────────────────────────
// DELETE /api/siem/events — Clear all events (dev only)
// ─────────────────────────────────────────────────────────────
router.delete("/events", async (req, res) => {
  if (process.env.NODE_ENV !== "development") {
    return res.status(403).json({ error: "Only available in development mode" });
  }
  await Event.deleteMany({});
  await Alert.deleteMany({});
  res.json({ message: "All SIEM data cleared" });
});
 
module.exports = router;