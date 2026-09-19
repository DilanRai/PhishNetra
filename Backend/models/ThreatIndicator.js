// FILE: backend/models/ThreatIndicator.js
// Stores hashed threat indicators for cross-org sharing
// STIX 2.1 compatible structure — OASIS standard

const mongoose = require("mongoose");
const crypto   = require("crypto");

const indicatorSchema = new mongoose.Schema({
  // Hashed indicator — SHA-256 of normalized input
  // Original URL/domain NEVER stored — privacy-preserving by design
  indicatorHash: { type: String, required: true, unique: true, index: true },

  // STIX 2.1 compatible fields
  type:        { type: String, enum: ["url","domain","ip","email","hash"], default: "url" },
  pattern:     { type: String, default: null }, // STIX pattern: [url:value = '...']
  confidence:  { type: Number, min: 0, max: 100, default: 70 },
  severity:    { type: Number, min: 1, max: 5, default: 3 },

  // Threat classification
  technique:   { type: String, default: null },
  brand:       { type: String, default: null },
  attackTypes: { type: [String], default: [] },
  tld:         { type: String, default: null },
  kitId:       { type: String, default: null },

  // Sharing metadata
  source:      { type: String, default: "phishnetra" },
  shared:      { type: Boolean, default: true },
  firstSeen:   { type: Date,   default: Date.now },
  lastSeen:    { type: Date,   default: Date.now },
  reportCount: { type: Number, default: 1 },      // how many orgs confirmed this

  // STIX 2.1 identity
  stixId:      { type: String, default: () => `indicator--${crypto.randomUUID()}` },
  createdAt:   { type: Date,   default: Date.now },
  expiresAt:   { type: Date,   default: () => new Date(Date.now() + 30 * 24 * 60 * 60 * 1000) }, // 30d TTL
});

indicatorSchema.index({ createdAt: -1 });
indicatorSchema.index({ type: 1, severity: 1 });
indicatorSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 }); // auto-expire

// ── Static: hash an indicator value ──
indicatorSchema.statics.hashIndicator = function(value) {
  if (!value) return null;
  // Normalize before hashing
  let normalized = value.trim().toLowerCase();
  // For URLs: extract domain only for hashing
  try {
    const u = normalized.startsWith("http") ? normalized : `https://${normalized}`;
    normalized = new URL(u).hostname.replace(/^www\./, "");
  } catch { /* use as-is */ }
  return crypto.createHash("sha256").update(normalized).digest("hex");
};

// ── Static: check if hash exists ──
indicatorSchema.statics.checkHash = async function(hash) {
  return this.findOne({ indicatorHash: hash, expiresAt: { $gt: new Date() } })
    .select("confidence severity technique brand attackTypes reportCount firstSeen stixId")
    .lean();
};

module.exports = mongoose.model("ThreatIndicator", indicatorSchema);