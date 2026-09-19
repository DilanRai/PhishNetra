// FILE: backend/models/ApiKey.js

const mongoose = require("mongoose");
const crypto   = require("crypto");

const apiKeySchema = new mongoose.Schema({
  key: {
    type:    String,
    unique:  true,
    default: () => `pgk_${crypto.randomBytes(24).toString("hex")}`,
    index:   true,
  },
  name:      { type: String, required: true, trim: true },
  userId:    { type: String, required: true, index: true },
  username:  { type: String, required: true },
  rateLimit: { type: Number, default: 100 }, // requests per hour
  usageCount:{ type: Number, default: 0 },
  lastUsed:  { type: Date,   default: null },
  active:    { type: Boolean, default: true, index: true },
  createdAt: { type: Date,   default: Date.now },
  expiresAt: { type: Date,   default: null },
  // Usage window tracking
  windowStart:  { type: Date,   default: Date.now },
  windowCount:  { type: Number, default: 0 },
  // Zero-trust trust scoring
  trustScore:       { type: Number, default: 50 },   // 0-100, starts neutral
  trustLevel:       { type: String, default: "neutral", enum: ["trusted","neutral","suspicious","untrusted"] },
  // Behavioral tracking for trust scoring
  totalScans:       { type: Number, default: 0 },
  phishingSubmitted:{ type: Number, default: 0 },   // how many phishing URLs scanned
  safeSubmitted:    { type: Number, default: 0 },
  knownPhishingHits:{ type: Number, default: 0 },   // submitted URLs already in PhishTank
  scanBursts:       { type: Number, default: 0 },   // times rate limit nearly triggered
  firstScan:        { type: Date,   default: null },
  // Reputation signals
  isUnderAttack:    { type: Boolean, default: false }, // high phishing rate = org under attack
  isReconClient:    { type: Boolean, default: false }, // scanning known phishing = testing system
  notes:            { type: String,  default: "" },
});

apiKeySchema.index({ key: 1, active: 1 });

module.exports = mongoose.model("ApiKey", apiKeySchema);