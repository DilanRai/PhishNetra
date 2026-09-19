// Stores endpoint/network log events (separate from phishing scan events)
// TTL index auto-expires old logs — zero storage growth concern

const mongoose = require("mongoose");
const { generateForensicId } = require("../../utils/forensicId");
// NOTE: "dns_query" is never persisted—only "dns_malicious" is saved after threat intel check.
// This ensures storage remains minimal for Phase 2.

const LogEventSchema = new mongoose.Schema(
  {
    // ── Forensic Identity ──
    logId: {
      type: String,
      default: () => generateForensicId("LOG"),
      unique: true,
      index: true,
    },

    // ── Source classification ──
    logType: {
      type: String,
      enum: [
        "failed_login",
        "successful_login",
        "multiple_login_attempts",
        "powershell_execution",
        "suspicious_process",
        "usb_activity",
        "dns_malicious",
        "browser_alert",
      ],
      required: true,
      index: true,
    },
    sourceHost: { type: String, default: "unknown" }, // hostname/machine name
    sourceIp: { type: String, default: null },
    sourceUser: { type: String, default: null },

    // ── Severity (matches your existing SIEM severity scale 1-5) ──
    severity: { type: Number, min: 1, max: 5, default: 2, index: true },

    // ── Event details ──
    eventId: { type: String, default: null }, // Windows Event ID (4625, 4104, etc.)
    description: { type: String, required: true },
    rawData: { type: mongoose.Schema.Types.Mixed, default: {} },

    // ── Correlation ──
    correlationKey: { type: String, default: null, index: true }, // for grouping related events
    attackTypes: { type: [String], default: [] },
    mitre: { type: mongoose.Schema.Types.Mixed, default: null },

    // ── Status (mirrors Alert workflow) ──
    status: {
      type: String,
      enum: ["new", "investigating", "resolved", "false_positive"],
      default: "new",
    },

    createdAt: { type: Date, default: Date.now, index: true },

    // ── Chain of Custody ───────────────────────────────────────
    collectedAt: { type: Date, default: Date.now },
    collectedBy: { type: String, default: "fluent-bit" }, // collector source
    integrityHash: { type: String, default: null }, // SHA-256 of rawData for tamper detection
    linkedAlertId: { type: String, default: null }, // ALT- ID if this log triggered an alert
    isEvidence: { type: Boolean, default: false }, // flagged as evidence for case
    evidenceNote: { type: String, default: null },
  },
  { timestamps: false },
);

// TTL index — auto-delete logs after 30 days (matches your ThreatIndicator pattern)
// Adjust the 30 if you want longer/shorter retention — storage is negligible either way
LogEventSchema.index(
  { createdAt: 1 },
  { expireAfterSeconds: 30 * 24 * 60 * 60 },
);

// Compound index for fast dashboard queries
LogEventSchema.index({ logType: 1, createdAt: -1 });
LogEventSchema.index({ sourceIp: 1, createdAt: -1 });

module.exports = mongoose.model("LogEvent", LogEventSchema);
