"use strict";
const mongoose = require("mongoose");
const crypto   = require("crypto");
 
const EmailCaseSchema = new mongoose.Schema({
  caseId: {
    type:    String,
    default: () => `CASE-${Date.now().toString(36).toUpperCase()}-${crypto.randomBytes(2).toString("hex").toUpperCase()}`,
    unique:  true,
    index:   true,
  },
 
  // Case identity
  name:        { type: String, required: true },
  description: { type: String, default: "" },
  status: {
    type:    String,
    enum:    ["open","investigating","escalated","closed","false_positive"],
    default: "open",
    index:   true,
  },
  priority: {
    type:    String,
    enum:    ["low","medium","high","critical"],
    default: "medium",
  },
  severity: { type: Number, min:1, max:5, default: 3 },
 
  // Linked cluster from GAP 7
  clusterId:   { type: String, default: null, index: true },
 
  // Campaign intelligence
  campaignType: {
    type:    String,
    enum:    ["phishing","bec","credential_harvest","malware_delivery",
              "brand_impersonation","govt_impersonation","financial_fraud","other"],
    default: "phishing",
  },
  targetBrands:    { type: [String], default: [] },
  targetSectors:   { type: [String], default: [] },
  targetRegions:   { type: [String], default: [] },
 
  // Actor intelligence
  actorIPs:        { type: [String], default: [] },
  actorDomains:    { type: [String], default: [] },
  actorCountries:  { type: [String], default: [] },
  actorTTPs:       { type: [String], default: [] }, // MITRE techniques
 
  // Metrics (auto-computed from linked EmailScans)
  emailCount:      { type: Number, default: 0 },
  phishingCount:   { type: Number, default: 0 },
  uniqueIPs:       { type: Number, default: 0 },
  firstSeen:       { type: Date,   default: null },
  lastSeen:        { type: Date,   default: null },
  avgRiskScore:    { type: Number, default: 0 },
 
  // Case management
  assignedTo:      { type: String, default: null },
  createdBy:       { type: String, default: "analyst" },
  notes: [{
    content:   { type: String, required: true },
    addedBy:   { type: String, default: "analyst" },
    addedAt:   { type: Date,   default: Date.now },
    noteType:  { type: String, enum:["observation","action","escalation","closure"], default:"observation" },
  }],
 
  // Evidence + related entities
  evidenceIds:     { type: [String], default: [] },
  complaintIds:    { type: [String], default: [] },
  incidentIds:     { type: [String], default: [] },
  iocs: {
    urls:    { type: [String], default: [] },
    ips:     { type: [String], default: [] },
    domains: { type: [String], default: [] },
    hashes:  { type: [String], default: [] },
  },
 
  // MITRE ATT&CK
  mitreTactics:    { type: [String], default: [] },
  mitreTechniques: { type: [String], default: [] },
 
  // Closure
  closedAt:        { type: Date, default: null },
  closedBy:        { type: String, default: null },
  resolution:      { type: String, default: null },
 
  tags:            { type: [String], default: [] },
  createdAt:       { type: Date, default: Date.now },
  updatedAt:       { type: Date, default: Date.now },
}, { timestamps: true });
 
EmailCaseSchema.index({ status:1, priority:1 });
EmailCaseSchema.index({ clusterId:1 });
EmailCaseSchema.index({ createdAt:-1 });
 
const EmailCase = mongoose.model("EmailCase", EmailCaseSchema);
module.exports = EmailCase;