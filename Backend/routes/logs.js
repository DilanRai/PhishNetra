// Mirrors the pattern of your existing siem.js routes

const express = require("express");
const router = express.Router();
const crypto = require("crypto");
const LogEvent = require("../siem/models/LogEvent");
const { ingestLogEvent, getLogStats } = require("../siem/logIngestionEngine");
const { requireAuth, requireRole } = require("./auth"); // adjust path to match your existing auth middleware
const {
  apiKeyMiddleware: validateApiKey,
} = require("../middleware/apiKeyAuth");

// POST /api/logs/event — ingestion endpoint
// Called by the PowerShell collector script (Phase 1/3) or DNS reader (Phase 2)
// No requireAuth here by default since it's called by a local collector script —
// but you can add an API key check (reuses your existing apikeys.js validateApiKey middleware)
router.post("/event", async (req, res) => {
  try {
    const {
      logType,
      sourceHost,
      sourceIp,
      sourceUser,
      eventId,
      description,
      rawData,
      severity,
    } = req.body;

    // dns_query is the only logType that doesn't require `description` up front —
    // the ingestion engine generates it only if the domain turns out to be malicious
    if (!logType || (!description && logType !== "dns_query")) {
      return res
        .status(400)
        .json({ error: "logType and description are required" });
    }

    const event = await ingestLogEvent({
      logType,
      sourceHost,
      sourceIp,
      sourceUser,
      eventId,
      description,
      rawData,
      severity,
    });

    // event is null when a dns_query was checked and found clean —
    // this is the cost-control path, not an error
    if (!event) {
      return res.status(200).json({
        message: "DNS query checked — domain not malicious, not stored",
      });
    }

    res.status(201).json({ message: "Log event ingested", event });
  } catch (err) {
    res
      .status(500)
      .json({ error: "Failed to ingest log event: " + err.message });
  }
});

// GET /api/logs/stats — aggregate stats for dashboard
router.get("/stats", requireAuth, async (req, res) => {
  try {
    const stats = await getLogStats();
    res.json(stats);
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch log stats" });
  }
});

// GET /api/logs — paginated list with filters
router.get("/", requireAuth, async (req, res) => {
  try {
    const { logType, severity, status, page = 1, limit = 50 } = req.query;
    const query = {};
    if (logType) query.logType = logType;
    if (severity) query.severity = Number(severity);
    if (status) query.status = status;

    const skip = (Number(page) - 1) * Number(limit);
    const [logs, total] = await Promise.all([
      LogEvent.find(query)
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(Number(limit))
        .lean(),
      LogEvent.countDocuments(query),
    ]);

    res.json({
      logs,
      total,
      page: Number(page),
      pages: Math.ceil(total / Number(limit)),
    });
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch logs" });
  }
});

// PATCH /api/logs/:id/status — update investigation status
router.patch(
  "/:id/status",
  requireAuth,
  requireRole("admin", "analyst"),
  async (req, res) => {
    try {
      const { status } = req.body;
      const valid = ["new", "investigating", "resolved", "false_positive"];
      if (!valid.includes(status))
        return res.status(400).json({ error: "Invalid status" });

      const log = await LogEvent.findByIdAndUpdate(
        req.params.id,
        { status },
        { new: true },
      );
      if (!log) return res.status(404).json({ error: "Log not found" });
      res.json(log);
    } catch (err) {
      res.status(500).json({ error: "Failed to update status" });
    }
  },
);

// PATCH /api/logs/:id/trust-device — mark the USB device in this log as trusted
// Sets status to resolved and tags it so future identical devices won't re-alert
// (the actual suppression still happens client-side in the collector's
//  known_usb_devices.json — this just records the analyst's decision in PhishNetra)
router.patch(
  "/:id/trust-device",
  requireAuth,
  requireRole("admin", "analyst"),
  async (req, res) => {
    try {
      const log = await LogEvent.findById(req.params.id);
      if (!log || log.logType !== "usb_activity") {
        return res.status(404).json({ error: "USB log event not found" });
      }
      log.status = "resolved";
      log.rawData = {
        ...log.rawData,
        trustedByAnalyst: true,
        trustedAt: new Date(),
      };
      await log.save();
      res.json({ message: "Device marked as trusted", log });
    } catch (err) {
      res.status(500).json({ error: "Failed to update device trust status" });
    }
  },
);

// DELETE /api/logs — clear all log events (admin only, same pattern as your SIEM delete fix)
router.delete("/", requireAuth, requireRole("admin"), async (req, res) => {
  try {
    const result = await LogEvent.deleteMany({});
    res.json({
      message: `${result.deletedCount} log events permanently deleted`,
    });
  } catch (err) {
    res.status(500).json({ error: "Failed to delete logs" });
  }
});

// POST /api/logs/ingest — Fluent Bit HTTP output receiver
// Accepts batched JSON_Lines format from Fluent Bit Windows agent
router.post("/ingest", async (req, res) => {
  try {
    let body = req.body;

    if (Buffer.isBuffer(body)) {
      body = body.toString("utf8");
    }

    console.log("[FluentBit] body type:", typeof body);
    console.log("[FluentBit] body:", body);

    // Validate API key (Fluent Bit sends X-PhishNetra-Key header)
    const apiKey = req.headers["x-phishnetra-key"] || req.headers["x-api-key"];
    if (!apiKey) {
      return res.status(401).json({ error: "Missing X-PhishNetra-Key header" });
    }
    const ApiKey = require("../models/ApiKey");
    const validKey = await ApiKey.findOne({ key: apiKey, active: true });
    if (!validKey) {
      return res.status(401).json({ error: "Invalid API key" });
    }
    // Update last used
    ApiKey.findByIdAndUpdate(validKey._id, { lastUsed: new Date() }).catch(
      () => {},
    );

    // Parse Fluent Bit payload — supports JSON array, single object, JSON_Lines
    let events = [];

    if (Array.isArray(body)) {
      events = body;
    } else if (body && typeof body === "object") {
      events = [body];
    } else if (typeof body === "string") {
      const text = body.trim();

      if (text) {
        try {
          const parsed = JSON.parse(text);
          events = Array.isArray(parsed) ? parsed : [parsed];
        } catch {
          events = text
            .split(/\r?\n/)
            .filter(Boolean)
            .map((line) => {
              try {
                return JSON.parse(line);
              } catch {
                return null;
              }
            })
            .filter(Boolean);
        }
      }
    }

    if (!events.length) {
      return res.status(400).json({ error: "No valid events" });
    }

    // Normalize and ingest each event
    const results = await Promise.allSettled(
      events.map((raw) => normalizeFluentBitEvent(raw)),
    );
    const ingested = results.filter(
      (r) => r.status === "fulfilled" && r.value,
    ).length;

    res.json({
      received: events.length,
      ingested,
      skipped: events.length - ingested,
    });
  } catch (err) {
    console.error("Fluent Bit ingest error:", err.message);
    res.status(500).json({ error: "Ingest failed" });
  }
});

// Normalizes Fluent Bit Windows Event Log JSON to PhishNetra logIngestionEngine format
async function normalizeFluentBitEvent(raw) {
  const eid = Number(raw.EventID || raw.eventid || 0);
  const computer = raw.Computer || raw.computer || raw.hostname || "unknown";
  const edata = raw.EventData || raw.eventData || raw.UserData || {};
  const tag = raw.tag || "";
  const time = raw.TimeCreated || raw.timestamp || new Date().toISOString();

  let logType, description, sourceUser, sourceIp, severity, rawData;
  rawData = { ...edata, eventId: eid, computer, time };

  // Failed login (Event ID 4625)
  if (eid === 4625 || tag.includes("login_failed")) {
    logType = "failed_login";
    sourceUser = edata.TargetUserName || edata.SubjectUserName || "unknown";
    sourceIp = edata.IpAddress || edata.WorkstationName || "unknown";
    description = `Failed login for "${sourceUser}" from ${sourceIp}`;
    severity = 2;
    rawData.logonType = edata.LogonType;
  }
  // Account lockout (Event ID 4740)
  else if (eid === 4740 || tag.includes("lockout")) {
    logType = "account_lockout";
    sourceUser = edata.TargetUserName || "unknown";
    description = `Account locked out: "${sourceUser}"`;
    severity = 4;
  }
  // PowerShell script block (Event ID 4104)
  else if (eid === 4104 || tag.includes("powershell")) {
    logType = "powershell_execution";
    sourceUser = edata.UserId || "unknown";
    const script = edata.ScriptBlockText || "";
    description = `PowerShell executed by ${sourceUser}: ${script.substring(0, 200)}`;
    rawData.commandLine = script;
    severity = 2;
  }
  // Sysmon process creation (Event ID 1)
  else if (eid === 1 && tag.includes("process")) {
    logType = "suspicious_process";
    sourceUser = edata.User || "unknown";
    const proc = edata.Image || "unknown.exe";
    const parent = edata.ParentImage || "unknown";
    description = `Process: ${proc.split("\\").pop()} (parent: ${parent.split("\\").pop()})`;
    rawData.process = proc.split("\\").pop();
    rawData.processPath = edata.CurrentDirectory || proc;
    rawData.parentProcess = parent.split("\\").pop();
    rawData.commandLine = edata.CommandLine || "";
    severity = 2;
  }
  // DNS query (Event ID 3008)
  else if (eid === 3008 || tag.includes("dns")) {
    const domain = edata.QueryName || "";
    if (!domain) return null;
    logType = "dns_query";
    description = `DNS query: ${domain}`;
    rawData.queriedDomain = domain;
    severity = 1;
  }
  // USB device (Event ID 2003/2004)
  else if (eid === 2003 || eid === 2004 || tag.includes("usb")) {
    logType = "usb_activity";
    const device = edata.DeviceInstanceId || "unknown";
    description = `USB storage connected: ${device}`;
    rawData.deviceId = device;
    rawData.isRegistered = false;
    severity = 2;
  }
  // Windows Defender (Event ID 1116/1117/1006)
  else if (
    eid === 1116 ||
    eid === 1117 ||
    eid === 1006 ||
    tag.includes("defender")
  ) {
    logType = "malware_detected";
    const threat = edata.ThreatName || edata.Threat || "unknown";
    const fpath = edata.Path || edata.ProcessName || "unknown";
    description = `Defender: ${threat} at ${fpath}`;
    rawData.threatName = threat;
    rawData.filePath = fpath;
    severity = 5;
  }
  // Application error
  else if (tag.includes("apperror")) {
    logType = "application_error";
    const app = edata.Application || edata.Source || "unknown";
    description = `App error: ${app} on ${computer}`;
    severity = 2;
  } else {
    return null;
  }

  return ingestLogEvent({
    logType,
    sourceHost: computer,
    sourceIp: sourceIp || null,
    sourceUser: sourceUser || null,
    eventId: eid,
    description,
    rawData,
    severity,
    collectedAt: new Date(),
    collectedBy: "fluent-bit",
    integrityHash: crypto
      .createHash("sha256")
      .update(JSON.stringify(rawData || {}))
      .digest("hex"),
  });
}

module.exports = router;
