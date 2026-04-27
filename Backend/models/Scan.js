// FILE: backend/models/Scan.js

const mongoose = require("mongoose");

const scanSchema = new mongoose.Schema({
  input:            { type: String, required: true, trim: true },
  inputType:        { type: String, enum: ["url", "email", "text"], default: "text" },
  status:           { type: String, enum: ["safe", "suspicious", "phishing"], required: true },
  riskScore:        { type: Number, min: 0, max: 100, required: true },
  issues:           { type: [String], default: [] },
  confidence:       { type: String, enum: ["low", "medium", "high"], default: "low" },
  detectionVersion: { type: String, default: "3.0" },
  mlEnabled:        { type: Boolean, default: false },
  mlScore:          { type: Number, default: null },
  ruleScore:        { type: Number, default: null },
  features:         { type: mongoose.Schema.Types.Mixed, default: {} },
  createdAt:        { type: Date, default: Date.now },
});

scanSchema.index({ createdAt: -1 });
scanSchema.index({ status: 1 });
scanSchema.index({ mlEnabled: 1 });

module.exports = mongoose.model("Scan", scanSchema);