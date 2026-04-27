// ================================================================
// FILE: backend/siem/models/Event.js
// Raw security event schema — the atomic unit of SentinelCore SIEM
// ================================================================

const mongoose = require("mongoose");

const eventSchema = new mongoose.Schema({

  // ── Core Identity ──
  eventId: {
    type: String,
    default: () => `EVT-${Date.now()}-${Math.random().toString(36).slice(2, 7).toUpperCase()}`,
    unique: true,
    index: true,
  },

  // ── Timing ──
  timestamp:  { type: Date, default: Date.now, index: true },
  receivedAt: { type: Date, default: Date.now },

  // ── Event Classification ──
  category: {
    type: String,
    enum: [
      "phishing",        // Phishing attempt detected
      "malware",         // Malware indicators
      "brute_force",     // Login brute force
      "anomaly",         // Behavioral anomaly
      "network",         // Network threat
      "reconnaissance",  // Scanning/probing
      "data_exfil",      // Data exfiltration attempt
      "auth",            // Authentication event
      "policy",          // Policy violation
      "system",          // System event
    ],
    required: true,
    index: true,
  },

  subcategory: { type: String, default: "general" },

  // ── Severity (1=INFO, 2=LOW, 3=MEDIUM, 4=HIGH, 5=CRITICAL) ──
  severity: {
    type: Number,
    enum: [1, 2, 3, 4, 5],
    default: 2,
    index: true,
  },
  severityLabel: {
    type: String,
    enum: ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
    default: "LOW",
  },

  // ── Source ──
  source: {
    type:    { type: String, enum: ["api", "extension", "scanner", "manual", "agent", "webhook"], default: "api" },
    ip:      { type: String, default: null },
    host:    { type: String, default: null },
    agent:   { type: String, default: null },  // extension, API client, etc.
    userId:  { type: String, default: null },
  },

  // ── Target ──
  target: {
    url:     { type: String, default: null },
    domain:  { type: String, default: null },
    ip:      { type: String, default: null },
    email:   { type: String, default: null },
    file:    { type: String, default: null },
  },

  // ── Event Data ──
  title:       { type: String, required: true },
  description: { type: String, default: "" },
  rawData:     { type: mongoose.Schema.Types.Mixed, default: {} },

  // ── MITRE ATT&CK Mapping ──
  mitre: {
    tactic:    { type: String, default: null },  // e.g. "TA0001 - Initial Access"
    technique: { type: String, default: null },  // e.g. "T1566 - Phishing"
    subtechnique: { type: String, default: null },
  },

  // ── Correlation ──
  correlationId: { type: String, default: null, index: true }, // Groups related events
  alertId:       { type: String, default: null, index: true }, // Alert that spawned from this

  // ── Risk Score (from our ML engine if applicable) ──
  riskScore: { type: Number, min: 0, max: 100, default: null },

  // ── Processing State ──
  processed:   { type: Boolean, default: false },
  ruleMatches: { type: [String], default: [] }, // rule IDs that matched

  // ── Compliance Tags ──
  compliance: { type: [String], default: [] }, // ["PCI-DSS", "HIPAA", "GDPR"]

  // ── Status ──
  status: {
    type: String,
    enum: ["new", "processing", "alerted", "suppressed", "resolved"],
    default: "new",
    index: true,
  },

  tags: { type: [String], default: [] },
});

eventSchema.index({ timestamp: -1, severity: -1 });
eventSchema.index({ category: 1, timestamp: -1 });
eventSchema.index({ correlationId: 1, timestamp: 1 });

module.exports = mongoose.model("SiemEvent", eventSchema);