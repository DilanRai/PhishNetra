// FILE: backend/models/CustomRule.js

const mongoose = require("mongoose");

const customRuleSchema = new mongoose.Schema({
  ruleId:   { type: String, required: true, unique: true },
  name:     { type: String, required: true, trim: true },
  category: { type: String, enum: ["phishing","anomaly","network","brute_force","auth","system"], default: "phishing" },
  severity: { type: Number, enum: [1,2,3,4,5], default: 3 },
  enabled:  { type: Boolean, default: true, index: true },
  // Threshold conditions (simple UI-configurable)
  conditions: {
    riskScoreMin:  { type: Number, default: null }, // e.g. riskScore > 75
    inputType:     { type: String, default: null }, // "url","email","text",null=any
    statusMatch:   { type: String, default: null }, // "phishing","suspicious",null=any
    issueContains: { type: String, default: null }, // keyword in issues list
    attackTypeIn:  { type: [String], default: [] }, // match any of these attack types
  },
  mitre: {
    tactic:    { type: String, default: null },
    technique: { type: String, default: null },
  },
  dedupWindowMin: { type: Number, default: 5 },   // minutes
  createdBy:      { type: String, default: "admin" },
  createdAt:      { type: Date,   default: Date.now },
  updatedAt:      { type: Date,   default: Date.now },
  triggerCount:   { type: Number, default: 0 },
  lastTriggered:  { type: Date,   default: null },
});

customRuleSchema.index({ enabled: 1 });
module.exports = mongoose.model("CustomRule", customRuleSchema);