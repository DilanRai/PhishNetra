// ════════════════════════════════════════════════════════════════
// FILE: backend/routes/features.js — CREATE NEW
// Mount all 7 feature routes in one file
// In server.js ADD: app.use("/api", require("./routes/features"));
// ════════════════════════════════════════════════════════════════
"use strict";
const express = require("express");
const router = express.Router();
const { requireAuth, requireRole } = require("./auth");

// ── Lazy-load engines (non-blocking on startup) ───────────────
const getEngine = (name) => {
  try {
    return require(`../services/${name}`);
  } catch (e) {
    console.error(`Engine ${name} not loaded:`, e.message);
    return null;
  }
};

// ════════════════════════════════════════════════════════════════
// FEATURE 1 — Cybercrime Complaint Intelligence
// ════════════════════════════════════════════════════════════════

// POST /api/complaints — Submit new complaint
router.post("/complaints", requireAuth, async (req, res) => {
  try {
    const eng = getEngine("cyberComplaintEngine");
    if (!eng)
      return res.status(503).json({ error: "Complaint engine unavailable" });
    const {
      Complaint,
      classifyFraud,
      extractIOCsFromComplaint,
      calcPriority,
      calcSeverityScore,
      calcSlaHours,
      MITRE_MAP,
      findRelatedComplaints,
    } = eng;

    const {
      description,
      victimName,
      victimState,
      victimCity,
      victimContact,
      amountLost,
      currency,
      paymentMethod,
      incidentDate,
      fraudType: manualFraudType,
    } = req.body;

    if (!description?.trim())
      return res.status(400).json({ error: "Description is required" });

    // Auto-classify (allow manual override)
    const classification = classifyFraud(description);
    const resolvedType = manualFraudType || classification.type;
    const iocs = extractIOCsFromComplaint(description);
    const priority = calcPriority(
      parseFloat(amountLost) || 0,
      resolvedType,
      iocs,
    );
    const severityScore = calcSeverityScore(
      parseFloat(amountLost) || 0,
      resolvedType,
      iocs,
      classification,
    );
    const slaDeadlineHours = calcSlaHours(priority);

    const complaint = new Complaint({
      description,
      victimName,
      victimState,
      victimCity,
      victimContact,
      amountLost: parseFloat(amountLost) || 0,
      currency: currency || "INR",
      paymentMethod: paymentMethod || "unknown",
      incidentDate: incidentDate ? new Date(incidentDate) : new Date(),
      fraudType: resolvedType,
      classificationConfidence: classification.confidence,
      mlTags: classification.tags,
      iocs,
      priority,
      severityScore,
      slaDeadlineHours,
      riskCategory: priority,
      mitre: MITRE_MAP[resolvedType] || "T1566 - Phishing",
    });
    await complaint.save();

    // Find related complaints
    const related = await findRelatedComplaints(iocs, complaint._id);
    if (related.length > 0) {
      complaint.linkedComplaints = related.map((r) => r.complaintId);
      await complaint.save();
    }

    res.status(201).json({
      complaint,
      classification,
      iocs,
      relatedComplaints: related,
      message: `Complaint ${complaint.complaintId} filed successfully`,
    });
  } catch (err) {
    console.error("Complaint submit error:", err);
    res.status(500).json({ error: err.message });
  }
});

// GET /api/complaints — List complaints with filters
router.get("/complaints", requireAuth, async (req, res) => {
  try {
    const eng = getEngine("cyberComplaintEngine");
    if (!eng) return res.json({ complaints: [], total: 0 });
    const { Complaint } = eng;
    const {
      status,
      fraudType,
      priority,
      page = 1,
      limit = 50,
      search,
    } = req.query;
    const query = {};
    if (status) query.status = status;
    if (fraudType) query.fraudType = fraudType;
    if (priority) query.priority = priority;
    if (search) query.description = { $regex: search, $options: "i" };
    const skip = (Number(page) - 1) * Number(limit);
    const [complaints, total] = await Promise.all([
      Complaint.find(query)
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(Number(limit))
        .lean(),
      Complaint.countDocuments(query),
    ]);
    res.json({
      complaints,
      total,
      page: Number(page),
      pages: Math.ceil(total / Number(limit)),
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/complaints/stats — Dashboard stats
router.get("/complaints/stats", requireAuth, async (req, res) => {
  try {
    const eng = getEngine("cyberComplaintEngine");
    if (!eng) return res.json({});
    res.json(await eng.getComplaintStats());
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/complaints/:id/ncrp-draft — Generate NCRP complaint draft
router.get("/complaints/:id/ncrp-draft", requireAuth, async (req, res) => {
  try {
    const eng = getEngine("cyberComplaintEngine");
    if (!eng) return res.status(503).json({ error: "Engine unavailable" });
    const { Complaint, generateNCRPDraft } = eng;
    const complaint = await Complaint.findOne({
      $or: [{ _id: req.params.id }, { complaintId: req.params.id }],
    }).lean();
    if (!complaint)
      return res.status(404).json({ error: "Complaint not found" });
    const draft = generateNCRPDraft(complaint);
    res.json({ draft, complaintId: complaint.complaintId });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// PATCH /api/complaints/:id/status — Update complaint status
router.patch(
  "/complaints/:id/status",
  requireAuth,
  requireRole("admin", "analyst"),
  async (req, res) => {
    try {
      const eng = getEngine("cyberComplaintEngine");
      if (!eng) return res.status(503).json({ error: "Engine unavailable" });
      const { Complaint } = eng;
      const { status, resolution, ncrbRefId, assignedTo } = req.body;
      const complaint = await Complaint.findOneAndUpdate(
        { $or: [{ _id: req.params.id }, { complaintId: req.params.id }] },
        { status, resolution, ncrbRefId, assignedTo, updatedAt: new Date() },
        { new: true },
      );
      if (!complaint) return res.status(404).json({ error: "Not found" });
      res.json(complaint);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  },
);

// ════════════════════════════════════════════════════════════════
// FEATURE 2 — Automated Incident Response
// ════════════════════════════════════════════════════════════════

// POST /api/incidents — Create incident manually or auto
router.post(
  "/incidents",
  requireAuth,
  requireRole("admin", "analyst"),
  async (req, res) => {
    try {
      const eng = getEngine("incidentResponseEngine");
      if (!eng) return res.status(503).json({ error: "IR engine unavailable" });
      const { Incident, generatePlaybook } = eng;
      const {
        title,
        description,
        severity,
        category,
        affectedAssets,
        affectedUsers,
        iocs,
      } = req.body;
      if (!title || !severity || !category)
        return res
          .status(400)
          .json({ error: "title, severity, category required" });
      const incident = new Incident({
        title,
        description,
        severity: Number(severity),
        category,
        affectedAssets: affectedAssets || [],
        affectedUsers: affectedUsers || [],
        iocs: iocs || {},
        playbook: generatePlaybook(category),
        timeline: [
          {
            action: "Incident created manually",
            by: req.user?.username || "analyst",
            phase: "detection",
          },
        ],
        sourceType: "manual",
      });
      await incident.save();
      res.status(201).json(incident);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  },
);

// GET /api/incidents — List incidents
router.get("/incidents", requireAuth, async (req, res) => {
  try {
    const eng = getEngine("incidentResponseEngine");
    if (!eng) return res.json({ incidents: [], total: 0 });
    const { Incident } = eng;
    const { status, category, severity, page = 1, limit = 50 } = req.query;
    const query = {};
    if (status) query.status = status;
    if (category) query.category = category;
    if (severity) query.severity = Number(severity);
    const skip = (Number(page) - 1) * Number(limit);
    const [incidents, total] = await Promise.all([
      Incident.find(query)
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(Number(limit))
        .lean(),
      Incident.countDocuments(query),
    ]);
    res.json({ incidents, total });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/incidents/stats
router.get("/incidents/stats", requireAuth, async (req, res) => {
  try {
    const eng = getEngine("incidentResponseEngine");
    if (!eng) return res.json({});
    res.json(await eng.getIncidentStats());
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// PATCH /api/incidents/:id/step — Complete a playbook step
router.patch(
  "/incidents/:id/step/:stepId",
  requireAuth,
  requireRole("admin", "analyst"),
  async (req, res) => {
    try {
      const eng = getEngine("incidentResponseEngine");
      if (!eng) return res.status(503).json({ error: "Engine unavailable" });
      const { Incident } = eng;
      const { status, notes } = req.body;
      const incident = await Incident.findById(req.params.id);
      if (!incident)
        return res.status(404).json({ error: "Incident not found" });
      const step = incident.playbook.find(
        (s) => s.stepId === req.params.stepId,
      );
      if (!step) return res.status(404).json({ error: "Step not found" });
      step.status = status || "done";
      step.completedBy = req.user?.username || "analyst";
      step.completedAt = new Date();
      step.notes = notes || "";
      incident.timeline.push({
        action: `Step ${req.params.stepId} marked as ${status}`,
        by: req.user?.username || "analyst",
        phase: step.phase,
        detail: notes || step.title,
      });
      // Check if all steps done → auto-advance status
      const allDone = incident.playbook.every(
        (s) => s.status === "done" || s.status === "skipped",
      );
      if (allDone && incident.status !== "closed") {
        incident.status = "post_incident";
        incident.resolvedAt = new Date();
        incident.mttr = Math.round(
          (incident.resolvedAt - incident.detectedAt) / 60000,
        );
      }
      await incident.save();
      res.json(incident);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  },
);

// PATCH /api/incidents/:id/status — Update incident status
router.patch(
  "/incidents/:id/status",
  requireAuth,
  requireRole("admin", "analyst"),
  async (req, res) => {
    try {
      const eng = getEngine("incidentResponseEngine");
      if (!eng) return res.status(503).json({ error: "Engine unavailable" });
      const { Incident } = eng;
      const { status, notes } = req.body;
      const incident = await Incident.findById(req.params.id);
      if (!incident) return res.status(404).json({ error: "Not found" });
      incident.status = status;
      if (status === "containment" && !incident.containedAt)
        incident.containedAt = new Date();
      if (status === "closed" && !incident.resolvedAt) {
        incident.resolvedAt = new Date();
        incident.mttr = Math.round(
          (incident.resolvedAt - incident.detectedAt) / 60000,
        );
        if (incident.containedAt)
          incident.mttc = Math.round(
            (incident.containedAt - incident.detectedAt) / 60000,
          );
      }
      incident.timeline.push({
        action: `Status changed to ${status}`,
        by: req.user?.username || "analyst",
        detail: notes || "",
      });
      await incident.save();
      res.json(incident);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  },
);

// ════════════════════════════════════════════════════════════════
// FEATURE 3 — Digital Evidence Vault
// ════════════════════════════════════════════════════════════════

// POST /api/evidence — Add evidence item
router.post(
  "/evidence",
  requireAuth,
  requireRole("admin", "analyst"),
  async (req, res) => {
    try {
      const eng = getEngine("evidenceEngine");
      if (!eng)
        return res.status(503).json({ error: "Evidence engine unavailable" });
      const { Evidence } = eng;
      const {
        type,
        title,
        description,
        source,
        incidentId,
        complaintId,
        iocType,
        iocValue,
        tags,
      } = req.body;
      const evidence = new Evidence({
        type,
        title,
        description,
        source,
        incidentId,
        complaintId,
        iocType,
        iocValue,
        tags: tags || [],
        collectedBy: req.user?.username || "analyst",
        custodyChain: [
          {
            action: "Evidence added manually",
            by: req.user?.username || "analyst",
          },
        ],
      });
      await evidence.save();
      res.status(201).json(evidence);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  },
);

// GET /api/evidence — List evidence
router.get("/evidence", requireAuth, async (req, res) => {
  try {
    const eng = getEngine("evidenceEngine");
    if (!eng) return res.json({ evidence: [], total: 0 });
    const { Evidence } = eng;
    const { incidentId, complaintId, type, page = 1, limit = 50 } = req.query;
    const query = {};
    if (incidentId) query.incidentId = incidentId;
    if (complaintId) query.complaintId = complaintId;
    if (type) query.type = type;
    const skip = (Number(page) - 1) * Number(limit);
    const [items, total] = await Promise.all([
      Evidence.find(query)
        .sort({ collectedAt: -1 })
        .skip(skip)
        .limit(Number(limit))
        .lean(),
      Evidence.countDocuments(query),
    ]);
    res.json({ evidence: items, total });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/evidence/:incidentId/report — Chain of custody report
router.get("/evidence/:incidentId/report", requireAuth, async (req, res) => {
  try {
    const eng = getEngine("evidenceEngine");
    if (!eng) return res.status(503).json({ error: "Engine unavailable" });
    const result = await eng.generateEvidenceReport(req.params.incidentId);
    if (!result)
      return res
        .status(404)
        .json({ error: "No evidence found for this incident" });
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ════════════════════════════════════════════════════════════════
// FEATURE 4 — Ransomware Early Warning
// ════════════════════════════════════════════════════════════════

// POST /api/ransomware/analyze — Analyze text/URL/log for ransomware
router.post("/ransomware/analyze", requireAuth, async (req, res) => {
  try {
    const eng = getEngine("ransomwareDetector");
    if (!eng)
      return res.status(503).json({ error: "Ransomware engine unavailable" });
    const { input, context } = req.body;
    if (!input) return res.status(400).json({ error: "input required" });
    const result = await eng.analyzeForRansomware(input, context || {});
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/ransomware/stats
router.get("/ransomware/stats", requireAuth, async (req, res) => {
  try {
    const eng = getEngine("ransomwareDetector");
    if (!eng) return res.json({});
    res.json(await eng.getRansomwareStats());
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/ransomware/events — Recent ransomware events
router.get("/ransomware/events", requireAuth, async (req, res) => {
  try {
    const eng = getEngine("ransomwareDetector");
    if (!eng) return res.json([]);
    const { RansomwareEvent } = eng;
    const events = await RansomwareEvent.find({})
      .sort({ createdAt: -1 })
      .limit(50)
      .lean();
    res.json(events);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/ransomware/honeypot — Register honeypot file
router.post(
  "/ransomware/honeypot",
  requireAuth,
  requireRole("admin"),
  async (req, res) => {
    try {
      const eng = getEngine("ransomwareDetector");
      if (!eng) return res.status(503).json({ error: "Engine unavailable" });
      const result = await eng.registerHoneypot(req.body);
      res.status(201).json(result);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  },
);

// GET /api/ransomware/honeypots — List honeypots
router.get("/ransomware/honeypots", requireAuth, async (req, res) => {
  try {
    const eng = getEngine("ransomwareDetector");
    if (!eng) return res.json([]);
    const { HoneypotFile } = eng;
    res.json(await HoneypotFile.find({ active: true }).lean());
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ════════════════════════════════════════════════════════════════
// FEATURE 7 — Network Anomaly Detection
// ════════════════════════════════════════════════════════════════

// POST /api/network-anomaly/analyze — Analyze a log event for anomalies
router.post("/network-anomaly/analyze", requireAuth, async (req, res) => {
  try {
    const eng = getEngine("networkAnomalyEngine");
    if (!eng)
      return res.status(503).json({ error: "Anomaly engine unavailable" });
    const anomalies = await eng.detectAnomaly(req.body);
    res.json({ anomalies, count: anomalies.length });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/network-anomaly — List anomalies
router.get("/network-anomaly", requireAuth, async (req, res) => {
  try {
    const eng = getEngine("networkAnomalyEngine");
    if (!eng) return res.json({ anomalies: [], total: 0 });
    const { NetworkAnomaly } = eng;
    const { type, status, host, user, page = 1, limit = 50 } = req.query;
    const query = {};
    if (type) query.type = type;
    if (status) query.status = status;
    if (host) query.host = { $regex: host, $options: "i" };
    if (user) query.user = { $regex: user, $options: "i" };
    const skip = (Number(page) - 1) * Number(limit);
    const [anomalies, total] = await Promise.all([
      NetworkAnomaly.find(query)
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(Number(limit))
        .lean(),
      NetworkAnomaly.countDocuments(query),
    ]);
    res.json({ anomalies, total });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/network-anomaly/stats
router.get("/network-anomaly/stats", requireAuth, async (req, res) => {
  try {
    const eng = getEngine("networkAnomalyEngine");
    if (!eng) return res.json({});
    res.json(await eng.getAnomalyStats());
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// PATCH /api/network-anomaly/:id/status
router.patch(
  "/network-anomaly/:id/status",
  requireAuth,
  requireRole("admin", "analyst"),
  async (req, res) => {
    try {
      const eng = getEngine("networkAnomalyEngine");
      if (!eng) return res.status(503).json({ error: "Engine unavailable" });
      const { NetworkAnomaly } = eng;
      const anomaly = await NetworkAnomaly.findByIdAndUpdate(
        req.params.id,
        { status: req.body.status },
        { new: true },
      );
      if (!anomaly) return res.status(404).json({ error: "Not found" });
      res.json(anomaly);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  },
);

// ════════════════════════════════════════════════════════════════
// FEATURE 8 — IP Reputation (DNSBL / TOR / Botnet / VPN)
// ════════════════════════════════════════════════════════════════

// GET /api/ip-reputation/:ip — Full reputation check for a single IP
router.get("/ip-reputation/:ip", requireAuth, async (req, res) => {
  try {
    const { checkIPReputation } = require("../services/ipReputationEngine");
    const result = await checkIPReputation(req.params.ip);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/ip-reputation/stats — Dashboard stats (total, malicious, TOR, botnet, repeat offenders)
router.get("/ip-reputation/stats", requireAuth, async (req, res) => {
  try {
    const { getIPReputationStats } = require("../services/ipReputationEngine");
    res.json(await getIPReputationStats());
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/ip-reputation/offenders — Top repeat offenders sorted by score
router.get("/ip-reputation/offenders", requireAuth, async (req, res) => {
  try {
    const { IPReputation } = require("../services/ipReputationEngine");
    const offenders = await IPReputation.find({ seenInScans: { $gt: 1 } })
      .sort({ reputationScore: -1, seenInScans: -1 })
      .limit(50)
      .lean();
    res.json(offenders);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ════════════════════════════════════════════════════════════════
// GAP 7 — Email Campaign Correlation
// ════════════════════════════════════════════════════════════════

const {
  getEmailClusters,
  getRelatedScans,
  getEmailCorrelationStats,
} = require("../services/emailCorrelationEngine");

// GET /api/email-clusters — All email campaign clusters
router.get("/email-clusters", requireAuth, async (req, res) => {
  try {
    const { minSize = 2, status } = req.query;
    const clusters = await getEmailClusters({
      minSize: Number(minSize),
      status: status || null,
      limit: 50,
    });
    res.json({ clusters, total: clusters.length });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/email-clusters/stats
router.get("/email-clusters/stats", requireAuth, async (req, res) => {
  try {
    res.json(await getEmailCorrelationStats());
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/email-clusters/:scanId/related — Related scans for a specific email scan
router.get("/email-clusters/:scanId/related", requireAuth, async (req, res) => {
  try {
    const result = await getRelatedScans(req.params.scanId);
    if (!result) return res.status(404).json({ error: "Scan not found" });
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ════════════════════════════════════════════════════════════════
// GAP 9 — Email Campaign Case Management
// ════════════════════════════════════════════════════════════════

const EmailCase = require("../models/EmailCase");

// ── Helper: sync case metrics from linked EmailScans ─────────
async function syncCaseMetrics(caseDoc) {
  try {
    const EmailScan = require("../models/EmailScan");
    if (!caseDoc.clusterId) return;
    const scans = await EmailScan.find({ clusterId: caseDoc.clusterId }).lean();
    if (!scans.length) return;
    const ips = [...new Set(scans.map((s) => s.sourceIP).filter(Boolean))];
    const dates = scans.map((s) => new Date(s.createdAt)).filter(Boolean);
    await EmailCase.findByIdAndUpdate(caseDoc._id, {
      emailCount: scans.length,
      phishingCount: scans.filter((s) => s.status === "phishing").length,
      uniqueIPs: ips.length,
      firstSeen: dates.length ? new Date(Math.min(...dates)) : null,
      lastSeen: dates.length ? new Date(Math.max(...dates)) : null,
      avgRiskScore: Math.round(
        scans.reduce((a, s) => a + (s.riskScore || 0), 0) / scans.length,
      ),
      actorIPs: ips.slice(0, 20),
      actorDomains: [
        ...new Set(scans.map((s) => s.fromDomain).filter(Boolean)),
      ].slice(0, 20),
      actorCountries: [
        ...new Set(scans.map((s) => s.sourceCountry).filter(Boolean)),
      ],
    });
  } catch (_) {
    /* non-fatal */
  }
}

// POST /api/email-cases — Create new case (from cluster or manual)
router.post(
  "/email-cases",
  requireAuth,
  requireRole("admin", "analyst"),
  async (req, res) => {
    try {
      const {
        name,
        description,
        clusterId,
        campaignType,
        priority,
        severity,
        targetBrands,
        targetSectors,
        mitreTechniques,
        tags,
      } = req.body;
      if (!name?.trim())
        return res.status(400).json({ error: "Case name required" });

      const emailCase = new EmailCase({
        name: name.trim(),
        description: description || "",
        clusterId: clusterId || null,
        campaignType: campaignType || "phishing",
        priority: priority || "medium",
        severity: Number(severity) || 3,
        targetBrands: targetBrands || [],
        targetSectors: targetSectors || [],
        mitreTechniques: mitreTechniques || [],
        mitreTactics: ["TA0043 - Reconnaissance", "TA0001 - Initial Access"],
        tags: tags || [],
        createdBy: req.user?.username || "analyst",
      });
      await emailCase.save();

      // Auto-sync metrics from linked cluster
      if (clusterId) await syncCaseMetrics(emailCase);

      res.status(201).json(await EmailCase.findById(emailCase._id).lean());
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  },
);

// GET /api/email-cases — List all cases with filters
router.get("/email-cases", requireAuth, async (req, res) => {
  try {
    const {
      status,
      priority,
      campaignType,
      search,
      page = 1,
      limit = 50,
    } = req.query;
    const query = {};
    if (status) query.status = status;
    if (priority) query.priority = priority;
    if (campaignType) query.campaignType = campaignType;
    if (search) query.name = { $regex: search, $options: "i" };
    const skip = (Number(page) - 1) * Number(limit);
    const [cases, total] = await Promise.all([
      EmailCase.find(query)
        .sort({ updatedAt: -1 })
        .skip(skip)
        .limit(Number(limit))
        .lean(),
      EmailCase.countDocuments(query),
    ]);
    res.json({
      cases,
      total,
      page: Number(page),
      pages: Math.ceil(total / Number(limit)),
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/email-cases/stats
router.get("/email-cases/stats", requireAuth, async (req, res) => {
  try {
    const [total, open, investigating, escalated, byType, bySeverity] =
      await Promise.all([
        EmailCase.countDocuments({}),
        EmailCase.countDocuments({ status: "open" }),
        EmailCase.countDocuments({ status: "investigating" }),
        EmailCase.countDocuments({ status: "escalated" }),
        EmailCase.aggregate([
          { $group: { _id: "$campaignType", count: { $sum: 1 } } },
        ]),
        EmailCase.aggregate([
          { $group: { _id: "$severity", count: { $sum: 1 } } },
        ]),
      ]);
    res.json({
      total,
      open,
      investigating,
      escalated,
      byType: Object.fromEntries(byType.map((t) => [t._id, t.count])),
      bySeverity: Object.fromEntries(bySeverity.map((s) => [s._id, s.count])),
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/email-cases/:id — Get case with timeline
router.get("/email-cases/:id", requireAuth, async (req, res) => {
  try {
    const EmailScan = require("../models/EmailScan");
    const emailCase = await EmailCase.findOne({
      $or: [{ _id: req.params.id }, { caseId: req.params.id }],
    }).lean();
    if (!emailCase) return res.status(404).json({ error: "Case not found" });

    let timeline = [];
    if (emailCase.clusterId) {
      timeline = await EmailScan.find({ clusterId: emailCase.clusterId })
        .sort({ createdAt: -1 })
        .limit(50)
        .select(
          "fromDomain sourceIP riskScore status createdAt originType sourceCountry lookalikeBrand relayAnomalies spfResult",
        )
        .lean();
    }
    res.json({ ...emailCase, timeline });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// PATCH /api/email-cases/:id — Update case (status, notes, assignment)
router.patch(
  "/email-cases/:id",
  requireAuth,
  requireRole("admin", "analyst"),
  async (req, res) => {
    try {
      const { status, priority, assignedTo, resolution, note, noteType, tags } =
        req.body;
      const emailCase = await EmailCase.findOne({
        $or: [{ _id: req.params.id }, { caseId: req.params.id }],
      });
      if (!emailCase) return res.status(404).json({ error: "Case not found" });

      if (status) emailCase.status = status;
      if (priority) emailCase.priority = priority;
      if (assignedTo) emailCase.assignedTo = assignedTo;
      if (tags) emailCase.tags = tags;
      if (resolution) emailCase.resolution = resolution;

      if (status === "closed") {
        emailCase.closedAt = new Date();
        emailCase.closedBy = req.user?.username || "analyst";
      }

      if (note?.trim()) {
        emailCase.notes.push({
          content: note.trim(),
          addedBy: req.user?.username || "analyst",
          noteType: noteType || "observation",
          addedAt: new Date(),
        });
      }

      emailCase.updatedAt = new Date();
      await emailCase.save();
      await syncCaseMetrics(emailCase);
      res.json(emailCase.toObject());
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  },
);

module.exports = router;
