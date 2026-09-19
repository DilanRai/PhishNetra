const mongoose = require("mongoose");

const scanSchema = new mongoose.Schema({
  input: { type: String, required: true, trim: true },
  inputType: { type: String, enum: ["url", "email", "text"], default: "text" },
  status: {
    type: String,
    enum: ["safe", "suspicious", "phishing"],
    required: true,
  },
  riskScore: { type: Number, min: 0, max: 100, required: true },
  issues: { type: [String], default: [] },
  confidence: { type: String, enum: ["low", "medium", "high"], default: "low" },
  detectionVersion: { type: String, default: "3.0" },
  mlEnabled: { type: Boolean, default: false },
  mlScore: { type: Number, default: null },
  ruleScore: { type: Number, default: null },
  sourceIp: { type: String, default: null },
  tags: { type: [String], default: [] },
  notes: { type: String, default: "" },
  taggedAt: { type: Date, default: null },
  features: { type: mongoose.Schema.Types.Mixed, default: {} },
  attackTypes: { type: [String], default: [] },
  mitre: { type: mongoose.Schema.Types.Mixed, default: null },
  mitreAttack: { type: mongoose.Schema.Types.Mixed, default: null },
  cve: { type: String, default: null },
  dna: {
    fingerprint: { type: String, default: null, index: true },
    brand: { type: String, default: null },
    technique: { type: String, default: null },
    tld: { type: String, default: null },
    severity: { type: String, default: null },
    canonical: { type: String, default: null },
  },
  kitMatch: {
    kitId: { type: String, default: null },
    kitName: { type: String, default: null },
    confidence: { type: Number, default: null },
    sophistication: { type: String, default: null },
  },
  evasion: {
    detected: { type: Boolean, default: false },
    level: { type: String, default: null },
    signals: { type: Number, default: 0 },
    techniques: { type: [String], default: [] },
  },
  csvMatch: {
    matched: { type: Boolean, default: false },
    matchLevel: { type: String, default: null }, // exact / domain+path / domain
    label: { type: String, default: null }, // phishing / safe / suspicious
    source: { type: String, default: null }, // CSV filename
    count: { type: Number, default: 0 }, // reports in dataset
  },
  sandboxData: {
    hasCredentialForm: { type: Boolean, default: null },
    hasPasswordField: { type: Boolean, default: null },
    hasPhishingKit: { type: Boolean, default: null },
    hasObfuscation: { type: Boolean, default: null },
    crossDomainRedirect: { type: Boolean, default: null },
    redirectHops: { type: Number, default: null },
    liveStatus: { type: String, default: null },
    sandboxRiskLevel: { type: String, default: null },
    sandboxRiskScore: { type: Number, default: null },
    techCount: { type: Number, default: null },
  },
  createdAt: { type: Date, default: Date.now },
  shareId: { type: String, default: null, index: true, sparse: true },
  sharedAt: { type: Date, default: null },
});

scanSchema.index({ createdAt: -1 });
scanSchema.index({ status: 1 });
scanSchema.index({ mlEnabled: 1 });
scanSchema.index({ "dna.fingerprint": 1 });
scanSchema.index({ "dna.technique": 1 });
scanSchema.index({ "dna.brand": 1 });
scanSchema.index({ tags: 1 });
scanSchema.index({ "kitMatch.kitId": 1 });

module.exports = mongoose.model("Scan", scanSchema);
