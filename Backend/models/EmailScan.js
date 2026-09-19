"use strict";

const mongoose = require("mongoose");

const EmailScanSchema = new mongoose.Schema({
  // Raw input
  rawHeaders:      { type: String, default: null },   // stored for re-analysis

  // Sender identity
  fromDomain:      { type: String, default: null, index: true },
  fromAddress:     { type: String, default: null },
  replyToDomain:   { type: String, default: null, index: true },
  displayName:     { type: String, default: null },
  subject:         { type: String, default: null },

  // Network origin (from GAPs 1-5)
  sourceIP:        { type: String, default: null, index: true },
  sourceCountry:   { type: String, default: null },
  sourceCity:      { type: String, default: null },
  sourceISP:       { type: String, default: null },
  originType:      { type: String, default: null }, // tor/vpn/datacenter/residential
  attributionConf: { type: Number, default: null },

  // Mail infrastructure
  mxProvider:      { type: String, default: null, index: true },
  mxServers:       { type: [String], default: [] },
  spfResult:       { type: String, default: null }, // pass/fail/softfail/none
  dkimResult:      { type: String, default: null },
  dmarcResult:     { type: String, default: null },
  mxMismatch:      { type: Boolean, default: false },

  // Relay chain
  hopCount:        { type: Number, default: 0 },
  relayAnomalies:  { type: Number, default: 0 },
  firstRelayIP:    { type: String, default: null }, // IP of first/originating hop

  // IP reputation (from GAP 4)
  ipReputationScore: { type: Number, default: null },
  ipVerdict:         { type: String, default: null },
  isTorExitNode:     { type: Boolean, default: false },
  isBotnet:          { type: Boolean, default: false },
  isVPN:             { type: Boolean, default: false },
  dnsblHitCount:     { type: Number, default: 0 },

  // Domain intel (from GAP 3)
  tld:             { type: String, default: null },
  isHighRiskTLD:   { type: Boolean, default: false },
  lookalikeBrand:  { type: String, default: null, index: true },
  domainRiskScore: { type: Number, default: 0 },

  // Detection verdict
  status:          { type: String, enum: ["safe", "suspicious", "phishing"], default: "safe" },
  riskScore:       { type: Number, default: 0 },
  issues:          { type: [String], default: [] },
  signals:         { type: [mongoose.Schema.Types.Mixed], default: [] },
  attackTypes:     { type: [String], default: [] },

  // Campaign correlation
  clusterId:       { type: String, default: null, index: true },
  clusterKeys:     { type: [String], default: [] }, // what keys caused clustering

  // Metadata
  scannedBy:       { type: String, default: "analyst" },
  createdAt:       { type: Date, default: Date.now, index: true },
});

// Compound indexes for correlation queries
EmailScanSchema.index({ sourceIP: 1, createdAt: -1 });
EmailScanSchema.index({ fromDomain: 1, createdAt: -1 });
EmailScanSchema.index({ replyToDomain: 1, createdAt: -1 });
EmailScanSchema.index({ mxProvider: 1, status: 1 });
EmailScanSchema.index({ lookalikeBrand: 1, status: 1 });
EmailScanSchema.index({ clusterId: 1, createdAt: -1 });

const EmailScan = mongoose.model("EmailScan", EmailScanSchema);

module.exports = EmailScan;
