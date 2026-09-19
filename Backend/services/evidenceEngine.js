// ════════════════════════════════════════════════════════════════
// FILE: backend/services/evidenceEngine.js — CREATE NEW
// Digital Evidence Collection & Analysis
// Real-world use: Analysts collecting digital evidence from a
// phishing/fraud case need a structured chain-of-custody system.
// This engine: stores evidence metadata, computes SHA-256 hashes
// for integrity, tracks who collected/viewed evidence, and
// generates a court-admissible evidence report.
// ════════════════════════════════════════════════════════════════

"use strict";
const mongoose = require("mongoose");
const crypto = require("crypto");

const EvidenceSchema = new mongoose.Schema(
  {
    evidenceId: {
      type: String,
      default: () =>
        `EVD-${Date.now().toString(36).toUpperCase()}-${crypto.randomBytes(2).toString("hex").toUpperCase()}`,
      unique: true,
      index: true,
    },
    // Case linkage
    incidentId: { type: String, default: null, index: true },
    complaintId: { type: String, default: null, index: true },

    // Evidence item
    type: {
      type: String,
      enum: [
        "screenshot",
        "url_archive",
        "email_export",
        "file",
        "log_export",
        "network_capture",
        "chat_export",
        "financial_record",
        "other",
      ],
      required: true,
    },
    title: { type: String, required: true },
    description: { type: String, default: "" },
    source: { type: String, default: null }, // URL/path/device where collected

    // File integrity
    fileName: { type: String, default: null },
    fileSize: { type: Number, default: null },
    mimeType: { type: String, default: null },
    sha256Hash: { type: String, default: null, index: true }, // integrity verification
    md5Hash: { type: String, default: null },

    // URL/web evidence specific
    archivedUrl: { type: String, default: null },
    archiveService: { type: String, default: null }, // wayback, cachedview, etc.
    pageTitle: { type: String, default: null },
    tlsCert: { type: mongoose.Schema.Types.Mixed, default: null },
    ipResolution: { type: String, default: null },
    whoIsData: { type: mongoose.Schema.Types.Mixed, default: null },

    // Chain of custody
    collectedBy: { type: String, required: true },
    collectedAt: { type: Date, default: Date.now },
    deviceInfo: { type: String, default: null },
    toolUsed: { type: String, default: "PhishNetra v6.0" },
    custodyChain: [
      {
        action: { type: String },
        by: { type: String },
        at: { type: Date, default: Date.now },
        hash: { type: String, default: null }, // hash at time of action
        note: { type: String, default: "" },
      },
    ],

    // Tags and classification
    tags: { type: [String], default: [] },
    iocType: { type: String, default: null },
    iocValue: { type: String, default: null },
    admissible: { type: Boolean, default: true },
    notes: { type: String, default: "" },

    createdAt: { type: Date, default: Date.now },
  },
  { timestamps: true },
);

EvidenceSchema.index({ incidentId: 1, type: 1 });
EvidenceSchema.index({ sha256Hash: 1 });

const Evidence = mongoose.model("Evidence", EvidenceSchema);

// ── Auto-collect URL evidence ─────────────────────────────────
async function collectUrlEvidence({
  url,
  scanResult,
  collectedBy,
  incidentId,
  complaintId,
}) {
  const evidenceId = `EVD-${Date.now().toString(36).toUpperCase()}`;
  // Hash the URL itself as base integrity proof
  const sha256 = crypto.createHash("sha256").update(url).digest("hex");
  const evidence = new Evidence({
    incidentId,
    complaintId,
    type: "url_archive",
    title: `URL Evidence: ${url.substring(0, 80)}`,
    description: `Phishing URL captured at scan time. Risk score: ${scanResult?.riskScore}/100. Status: ${scanResult?.status}.`,
    source: url,
    sha256Hash: sha256,
    collectedBy: collectedBy || "system",
    toolUsed: "PhishNetra v6.0 URL Scanner",
    archivedUrl: url,
    pageTitle: scanResult?.urlPreview?.pageTitle || null,
    tlsCert: scanResult?.urlPreview?.tlsCertificate || null,
    ipResolution: scanResult?.geo?.ip || null,
    tags: [
      ...(scanResult?.attackTypes || []),
      "url_evidence",
      "auto_collected",
    ],
    iocType: "url",
    iocValue: url,
    custodyChain: [
      {
        action: "Evidence auto-collected by PhishNetra scan",
        by: "system",
        hash: sha256,
        note: `Scan verdict: ${scanResult?.status} · Score: ${scanResult?.riskScore}/100`,
      },
    ],
  });
  return evidence.save();
}

// ── Generate chain-of-custody report ─────────────────────────
async function generateEvidenceReport(incidentId) {
  const items = await Evidence.find({ incidentId })
    .sort({ collectedAt: 1 })
    .lean();
  if (!items.length) return null;

  const lines = [
    `DIGITAL EVIDENCE CHAIN OF CUSTODY REPORT`,
    `Generated: ${new Date().toLocaleString("en-IN")}`,
    `Incident ID: ${incidentId}`,
    `Total Evidence Items: ${items.length}`,
    `━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`,
    ``,
  ];

  items.forEach((ev, i) => {
    lines.push(`ITEM ${i + 1}: ${ev.evidenceId}`);
    lines.push(`Type:        ${ev.type}`);
    lines.push(`Title:       ${ev.title}`);
    lines.push(
      `Collected:   ${new Date(ev.collectedAt).toLocaleString("en-IN")} by ${ev.collectedBy}`,
    );
    lines.push(`SHA-256:     ${ev.sha256Hash || "not computed"}`);
    lines.push(`Source:      ${ev.source || "N/A"}`);
    lines.push(`Admissible:  ${ev.admissible ? "YES" : "DISPUTED"}`);
    lines.push(`Tool:        ${ev.toolUsed}`);
    if (ev.custodyChain?.length) {
      lines.push(`Custody Chain:`);
      ev.custodyChain.forEach((c) => {
        lines.push(
          `  ${new Date(c.at).toLocaleString("en-IN")} · ${c.by}: ${c.action}`,
        );
      });
    }
    lines.push(``);
  });

  lines.push(`━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`);
  lines.push(`This report is generated by PhishNetra AI.`);
  lines.push(
    `SHA-256 hashes serve as digital fingerprints for integrity verification.`,
  );
  lines.push(`Admissibility is subject to court jurisdiction.`);

  return { report: lines.join("\n"), itemCount: items.length, items };
}

module.exports.Evidence = Evidence;
module.exports.collectUrlEvidence = collectUrlEvidence;
module.exports.generateEvidenceReport = generateEvidenceReport;
