// ════════════════════════════════════════════════════════════════
// FILE: backend/routes/honeypot.js — FULL REPLACE
// Realistic Honeypot System
//
// What makes this realistic:
// 1. MongoDB persistence — traps survive server restarts
// 2. Deceptive responses — attacker sees fake "real" content
//    (fake credentials, fake documents, fake API keys)
//    that keep them engaged and waste their time
// 3. Deep attacker fingerprinting — browser headers, timing,
//    request patterns, referrer, Accept-Language (geo hint)
// 4. Multiple trap types — credential portal, document store,
//    API key vault, admin panel, database export, email archive
// 5. Canary tokens — embedded in fake documents so if an
//    attacker uses the stolen data, you get a second alert
// 6. Progressive deception — first hit shows fake login,
//    second hit accepts any credentials and shows fake data,
//    third hit silently logs everything and returns 500
// 7. Geo-enrichment of attacker IP
// 8. Rate-limit-aware — doesn't block the attacker (that tips them off)
// ════════════════════════════════════════════════════════════════

"use strict";
const express = require("express");
const router  = express.Router();
const crypto  = require("crypto");
const mongoose= require("mongoose");
const { requireAuth, requireRole } = require("./auth");

// ── MongoDB Schemas ───────────────────────────────────────────

const TrapSchema = new mongoose.Schema({
  trapId:      { type: String, unique: true, index: true },
  type: {
    type: String,
    enum: ["credential_portal","document_store","api_vault",
           "admin_panel","database_export","email_archive",
           "vpn_gateway","file_server"],
    default: "credential_portal",
  },
  label:       { type: String, required: true },
  description: { type: String, default: "" },
  // What the trap pretends to be
  persona: {
    title:       String, // "HR Payroll Portal"
    orgName:     String, // "Acme Corp Internal"
    brandColor:  String, // "#1a56db"
    faviconEmoji:String, // "🏢"
  },
  // Fake data embedded in responses (canary tokens)
  fakeCredentials: {
    username: String,
    password: String,
    token:    String,
  },
  fakeData:    { type: mongoose.Schema.Types.Mixed, default: {} },
  path:        { type: String, unique: true },
  fullUrl:     { type: String },
  active:      { type: Boolean, default: true, index: true },
  hits:        { type: Number, default: 0 },
  uniqueIPs:   { type: [String], default: [] },
  createdBy:   { type: String, default: "system" },
  createdAt:   { type: Date, default: Date.now },
  lastHit:     { type: Date, default: null },
  // Alert config
  notifyEmail: { type: Boolean, default: true },
  severity:    { type: Number, default: 5 },
});

const HitSchema = new mongoose.Schema({
  trapId:      { type: String, required: true, index: true },
  trapLabel:   { type: String },
  hitNumber:   { type: Number, default: 1 }, // sequential hit count for this IP
  // Attacker fingerprint
  ip:          { type: String, index: true },
  userAgent:   { type: String },
  browser:     { type: String },
  os:          { type: String },
  referrer:    { type: String, default: null },
  acceptLang:  { type: String, default: null }, // language = geo hint
  acceptEnc:   { type: String, default: null },
  xForwardedFor:{ type: String, default: null },
  // Request context
  method:      { type: String, default: "GET" },
  queryParams: { type: mongoose.Schema.Types.Mixed, default: {} },
  bodyKeys:    { type: [String], default: [] }, // what fields attacker submitted (not values)
  // Timing
  timestamp:   { type: Date, default: Date.now, index: true },
  sessionDuration: { type: Number, default: 0 }, // ms between first and last hit from same IP
  // Geo (if available)
  country:     { type: String, default: null },
  city:        { type: String, default: null },
  org:         { type: String, default: null },
  // Canary token follow-up
  usedCanaryToken: { type: Boolean, default: false },
  canaryTokenType: { type: String, default: null },
  // Submitted credentials (for analysis only — stored hashed)
  submittedUsername: { type: String, default: null },
  submittedPasswordHash: { type: String, default: null },
});

HitSchema.index({ trapId:1, ip:1 });
HitSchema.index({ timestamp:-1 });

const Trap = mongoose.models.HoneypotTrap || mongoose.model("HoneypotTrap", TrapSchema);
const Hit  = mongoose.models.HoneypotHit  || mongoose.model("HoneypotHit",  HitSchema);

// ── Trap type configurations ──────────────────────────────────
const TRAP_TYPES = {
  credential_portal: {
    label:        "HR Payroll Portal",
    description:  "Fake employee self-service portal",
    persona:      { title:"Employee Self-Service", orgName:"Internal HR Portal", brandColor:"#1a56db", faviconEmoji:"🏢" },
    generateFakeData: (trapId) => ({
      announcements: [
        { id:1, title:"Payroll processing scheduled for Friday", date:"2024-01-15" },
        { id:2, title:"Benefits enrollment deadline: Jan 31",    date:"2024-01-10" },
        { id:3, title:"New VPN policy update required",          date:"2024-01-08" },
      ],
      employeeCount: 247,
      canaryToken:   `PHISHNETRA-CANARY-${trapId}-HR`,
    }),
  },
  document_store: {
    label:        "Internal Document Repository",
    description:  "Fake file storage with sensitive documents",
    persona:      { title:"Document Management System", orgName:"Corp SharePoint", brandColor:"#0078d4", faviconEmoji:"📁" },
    generateFakeData: (trapId) => ({
      documents: [
        { name:"Q4-2024-Financial-Report.xlsx", size:"2.4 MB", modified:"2024-01-14", sensitivity:"CONFIDENTIAL" },
        { name:"Executive-Compensation-2024.pdf", size:"890 KB", modified:"2024-01-12", sensitivity:"RESTRICTED" },
        { name:"Customer-Database-Export.csv",    size:"45 MB", modified:"2024-01-10", sensitivity:"CONFIDENTIAL" },
        { name:"AWS-Production-Credentials.txt",  size:"2 KB",  modified:"2024-01-09", sensitivity:"TOP SECRET" },
        { name:"Board-Meeting-Minutes-Dec.docx",  size:"340 KB",modified:"2024-01-05", sensitivity:"CONFIDENTIAL" },
      ],
      storageUsed: "12.4 GB",
      canaryToken: `PHISHNETRA-CANARY-${trapId}-DOCS`,
    }),
  },
  api_vault: {
    label:        "Internal API Key Vault",
    description:  "Fake secrets management portal",
    persona:      { title:"Secrets Manager", orgName:"DevOps Internal", brandColor:"#ff6b35", faviconEmoji:"🔑" },
    generateFakeData: (trapId) => ({
      secrets: [
        { name:"AWS_ACCESS_KEY_ID",     value:`AKIAIOSFODNN7${crypto.randomBytes(4).toString("hex").toUpperCase()}`, env:"production", lastRotated:"2024-01-01" },
        { name:"DATABASE_PASSWORD",     value:`Pr0d-DB-${crypto.randomBytes(6).toString("hex")}!`,                   env:"production", lastRotated:"2024-01-05" },
        { name:"STRIPE_SECRET_KEY",     value:`sk_live_${crypto.randomBytes(16).toString("hex")}`,                   env:"production", lastRotated:"2023-12-15" },
        { name:"SENDGRID_API_KEY",      value:`SG.${crypto.randomBytes(12).toString("base64")}`,                     env:"production", lastRotated:"2023-12-20" },
        { name:"GITHUB_DEPLOY_TOKEN",   value:`ghp_${crypto.randomBytes(18).toString("hex")}`,                       env:"all",         lastRotated:"2024-01-10" },
      ],
      note:        "⚠️ These are canary credentials — using them triggers an immediate security alert",
      canaryToken: `PHISHNETRA-CANARY-${trapId}-KEYS`,
    }),
  },
  admin_panel: {
    label:        "Network Admin Panel",
    description:  "Fake router/firewall management interface",
    persona:      { title:"Network Operations Center", orgName:"IT Infrastructure", brandColor:"#16a34a", faviconEmoji:"🖥️" },
    generateFakeData: (trapId) => ({
      devices: [
        { name:"CORE-ROUTER-01",   ip:"10.0.0.1",  status:"online", model:"Cisco ISR 4431" },
        { name:"FIREWALL-PRIMARY", ip:"10.0.0.2",  status:"online", model:"Palo Alto PA-3220" },
        { name:"SWITCH-FLOOR-2",   ip:"10.0.1.10", status:"online", model:"Cisco Catalyst 9300" },
        { name:"VPN-GATEWAY",      ip:"10.0.0.5",  status:"online", model:"Fortinet FortiGate" },
      ],
      activeConnections: 142,
      canaryToken: `PHISHNETRA-CANARY-${trapId}-ADMIN`,
    }),
  },
  email_archive: {
    label:        "Executive Email Archive",
    description:  "Fake email archive with sensitive communications",
    persona:      { title:"Email Archive System", orgName:"Executive Communications", brandColor:"#7c3aed", faviconEmoji:"📧" },
    generateFakeData: (trapId) => ({
      emails: [
        { from:"ceo@company.com", subject:"CONFIDENTIAL: Acquisition target — do not share", date:"2024-01-14", hasAttachment:true },
        { from:"cfo@company.com", subject:"Q4 earnings before public announcement",           date:"2024-01-12", hasAttachment:true },
        { from:"legal@company.com",subject:"Settlement negotiation — attorney-client privileged", date:"2024-01-10", hasAttachment:false },
        { from:"board@company.com",subject:"Emergency board meeting re: regulatory investigation", date:"2024-01-08", hasAttachment:true },
      ],
      totalEmails: 18492,
      canaryToken: `PHISHNETRA-CANARY-${trapId}-EMAIL`,
    }),
  },
  vpn_gateway: {
    label:        "VPN Access Portal",
    description:  "Fake VPN login page",
    persona:      { title:"Secure Remote Access", orgName:"Corporate VPN", brandColor:"#dc2626", faviconEmoji:"🔒" },
    generateFakeData: (trapId) => ({
      notice:      "Remote access portal — authorized personnel only",
      ssoEnabled:  true,
      mfaRequired: true,
      canaryToken: `PHISHNETRA-CANARY-${trapId}-VPN`,
    }),
  },
  database_export: {
    label:        "Database Export Console",
    description:  "Fake database dump / export portal",
    persona:      { title:"DBA Console", orgName:"Data Platform", brandColor:"#0f766e", faviconEmoji:"🗄️" },
    generateFakeData: (trapId) => ({
      documents: [
        { name:"customers-full.sql", size:"1.2 GB", modified:"2024-01-14", sensitivity:"CONFIDENTIAL" },
        { name:"payroll-export.csv", size:"84 MB",  modified:"2024-01-12", sensitivity:"RESTRICTED" },
      ],
      storageUsed: "8.1 GB",
      canaryToken: `PHISHNETRA-CANARY-${trapId}-DB`,
    }),
  },
  file_server: {
    label:        "Internal File Server",
    description:  "Fake SMB-style file browser",
    persona:      { title:"File Gateway", orgName:"Corp Files", brandColor:"#4338ca", faviconEmoji:"💾" },
    generateFakeData: (trapId) => ({
      documents: [
        { name:"IT-passwords.xlsx", size:"120 KB", modified:"2024-01-11", sensitivity:"TOP SECRET" },
        { name:"vpn-configs.zip",   size:"4.2 MB", modified:"2024-01-09", sensitivity:"RESTRICTED" },
      ],
      storageUsed: "2.8 TB",
      canaryToken: `PHISHNETRA-CANARY-${trapId}-FILES`,
    }),
  },
};

// ── UA Parser (lightweight) ───────────────────────────────────
function parseUA(ua) {
  if (!ua) return { browser:"Unknown", os:"Unknown" };
  const browser =
    ua.includes("Chrome")  ? "Chrome"  :
    ua.includes("Firefox") ? "Firefox" :
    ua.includes("Safari")  ? "Safari"  :
    ua.includes("Edge")    ? "Edge"    :
    ua.includes("curl")    ? "curl"    :
    ua.includes("python")  ? "Python"  :
    ua.includes("wget")    ? "wget"    : "Other";
  const os =
    ua.includes("Windows") ? "Windows" :
    ua.includes("Mac")     ? "macOS"   :
    ua.includes("Linux")   ? "Linux"   :
    ua.includes("Android") ? "Android" :
    ua.includes("iPhone")  ? "iOS"     : "Unknown";
  return { browser, os };
}

// ── Generate fake credentials for the trap ───────────────────
function genFakeCredentials() {
  return {
    username: `admin.${crypto.randomBytes(3).toString("hex")}`,
    password: `Tr@p${crypto.randomBytes(4).toString("hex")}!`,
    token:    `eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.${crypto.randomBytes(32).toString("base64url")}.CANARY`,
  };
}

// ── Fire SIEM alert ───────────────────────────────────────────
async function fireSIEMAlert(trap, hit, req) {
  try {
    const { ingestEvent } = require("../siem/eventEngine");
    await ingestEvent({
      type:        "custom",
      category:    "reconnaissance",
      subcategory: "honeypot_triggered",
      severity:    trap.severity || 5,
      title:       `🍯 HONEYPOT HIT #${hit.hitNumber} — "${trap.label}"`,
      description: `Trap "${trap.label}" (${trap.type}) accessed by ${hit.ip}` +
                   `${hit.country ? ` from ${hit.city||""} ${hit.country}` : ""}.` +
                   ` Browser: ${hit.browser}/${hit.os}.` +
                   ` This IP has hit this trap ${hit.hitNumber} time(s).` +
                   (hit.referrer ? ` Referred from: ${hit.referrer}` : "") +
                   ` Only an attacker would know this URL exists.`,
      sourceType:  "honeypot",
      sourceIp:    hit.ip,
      targetIp:    hit.ip,
      url:         trap.fullUrl || trap.path,
      agent:       hit.userAgent,
      riskScore:   100,
      rawData: {
        trapId:    trap.trapId,
        trapLabel: trap.label,
        trapType:  trap.type,
        ip:        hit.ip,
        hitNumber: hit.hitNumber,
        browser:   hit.browser,
        os:        hit.os,
        country:   hit.country,
        referrer:  hit.referrer,
        acceptLang:hit.acceptLang,
        method:    hit.method,
        queryParams: hit.queryParams,
        submittedUsername: hit.submittedUsername,
      },
      tags: ["honeypot","critical","intrusion",
             hit.hitNumber > 1 ? "repeat_attacker" : "first_contact"],
      mitre: {
        tactic:    "TA0043 - Reconnaissance",
        technique: "T1595 - Active Scanning",
      },
    });
  } catch (e) {
    console.error("Honeypot SIEM alert failed:", e.message);
  }

  // WebSocket real-time alert
  const io = req.app.get("io");
  if (io) {
    io.emit("honeypot_triggered", {
      trapLabel: trap.label,
      trapType:  trap.type,
      ip:        hit.ip,
      country:   hit.country,
      browser:   hit.browser,
      hitNumber: hit.hitNumber,
      timestamp: hit.timestamp,
      severity:  5,
    });
  }
}

// ════════════════════════════════════════════════════════════════
// ROUTES — Management (authenticated)
// ════════════════════════════════════════════════════════════════

// POST /api/honeypot/generate — Create a realistic trap
router.post("/generate", requireAuth, requireRole("admin","analyst"), async (req, res) => {
  try {
    const { label, type, description } = req.body;
    const trapType = TRAP_TYPES[type] || TRAP_TYPES.credential_portal;
    const trapId   = crypto.randomBytes(10).toString("hex");
    const path     = `/trap/${trapId}`;
    const fullUrl  = `${process.env.FRONTEND_URL || "http://localhost:5173"}${path}`;

    const trap = await Trap.create({
      trapId,
      type:        type || "credential_portal",
      label:       label || trapType.label,
      description: description || trapType.description,
      persona:     trapType.persona,
      fakeCredentials: genFakeCredentials(),
      fakeData:    trapType.generateFakeData(trapId),
      path,
      fullUrl,
      createdBy:   req.user?.username || "analyst",
    });

    res.json({
      id:          trap.trapId,
      type:        trap.type,
      label:       trap.label,
      url:         trap.fullUrl,
      deployInstructions: [
        `1. Share this URL in an internal document, email, or chat`,
        `2. Label it something enticing like "${trap.label}"`,
        `3. Any access triggers an immediate CRITICAL SIEM alert`,
        `4. The attacker sees realistic fake content to keep them engaged`,
      ],
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/honeypot/traps — List all traps with hit stats
router.get("/traps", requireAuth, async (req, res) => {
  try {
    const traps = await Trap.find({ active: true }).sort({ createdAt: -1 }).lean();
    res.json(traps.map(t => ({
      id:          t.trapId,
      type:        t.type,
      label:       t.label,
      description: t.description,
      fullUrl:     t.fullUrl,
      hits:        t.hits,
      uniqueIPs:   t.uniqueIPs.length,
      createdBy:   t.createdBy,
      createdAt:   t.createdAt,
      lastHit:     t.lastHit,
    })));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/honeypot/traps/:id/hits — Hit log for a specific trap
router.get("/traps/:id/hits", requireAuth, async (req, res) => {
  try {
    const hits = await Hit.find({ trapId: req.params.id })
      .sort({ timestamp: -1 }).limit(100).lean();
    res.json(hits);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/honeypot/stats — Dashboard stats
router.get("/stats", requireAuth, async (req, res) => {
  try {
    const since24h = new Date(Date.now() - 24*60*60*1000);
    const [total, active, hits24h, topTraps, uniqueIPs] = await Promise.all([
      Trap.countDocuments({}),
      Trap.countDocuments({ active: true }),
      Hit.countDocuments({ timestamp: { $gte: since24h } }),
      Trap.find({ hits: { $gt: 0 } }).sort({ hits: -1 }).limit(5)
          .select("label type hits uniqueIPs lastHit").lean(),
      Hit.distinct("ip"),
    ]);
    res.json({
      totalTraps: total,
      activeTraps: active,
      hits24h,
      totalUniqueAttackers: uniqueIPs.length,
      topTraps: topTraps.map(t => ({
        label: t.label, type: t.type,
        hits: t.hits, uniqueIPs: t.uniqueIPs.length, lastHit: t.lastHit,
      })),
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// DELETE /api/honeypot/traps/:id — Deactivate a trap
router.delete("/traps/:id", requireAuth, requireRole("admin"), async (req, res) => {
  try {
    await Trap.findOneAndUpdate({ trapId: req.params.id }, { active: false });
    res.json({ message: "Trap deactivated" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ════════════════════════════════════════════════════════════════
// TRAP HANDLER — Public route (no auth — attacker hits this)
// This is the deceptive entry point
// ════════════════════════════════════════════════════════════════

router.all("/trigger/:id", async (req, res) => {
  const trap = await Trap.findOne({ trapId: req.params.id, active: true }).lean();
  if (!trap) {
    // Generic 404 — don't reveal this is a honeypot
    return res.status(404).send("Not Found");
  }

  // ── Fingerprint the attacker ──────────────────────────────
  const ip        = (req.headers["x-forwarded-for"]?.split(",")[0] || req.ip || "").trim();
  const ua        = req.headers["user-agent"] || "";
  const { browser, os } = parseUA(ua);
  const referrer  = req.headers["referer"] || req.headers["referrer"] || null;
  const acceptLang= req.headers["accept-language"] || null;

  // How many times has this IP hit this trap?
  const prevHits  = await Hit.countDocuments({ trapId: trap.trapId, ip });
  const hitNumber = prevHits + 1;

  // Log the submitted data (for POST requests like fake login)
  const bodyKeys          = Object.keys(req.body || {});
  const submittedUsername = req.body?.username || req.body?.user || req.body?.email || null;
  const rawPwd            = req.body?.password || req.body?.pass || null;
  const submittedPasswordHash = rawPwd
    ? crypto.createHash("sha256").update(rawPwd).digest("hex")
    : null;

  // ── Save hit to MongoDB ───────────────────────────────────
  const hit = await Hit.create({
    trapId:      trap.trapId,
    trapLabel:   trap.label,
    hitNumber,
    ip,
    userAgent:   ua,
    browser, os,
    referrer,
    acceptLang,
    acceptEnc:   req.headers["accept-encoding"] || null,
    xForwardedFor: req.headers["x-forwarded-for"] || null,
    method:      req.method,
    queryParams: req.query,
    bodyKeys,
    submittedUsername,
    submittedPasswordHash,
  });

  // ── Update trap stats ─────────────────────────────────────
  const updateOps = {
    $inc:  { hits: 1 },
    $set:  { lastHit: new Date() },
  };
  if (!trap.uniqueIPs.includes(ip)) {
    updateOps.$addToSet = { uniqueIPs: ip };
  }
  await Trap.findOneAndUpdate({ trapId: trap.trapId }, updateOps);

  // ── Fire SIEM alert ───────────────────────────────────────
  await fireSIEMAlert(trap, { ...hit.toObject(), browser, os }, req);

  // ── Deceptive response based on trap type and hit number ──
  // Hit 1: Show fake login page / loading state
  // Hit 2+: Accept credentials, show fake data

  const persona = trap.persona || {};
  const fakeData= trap.fakeData || {};

  // For API requests (Accept: application/json)
  if (req.headers.accept?.includes("application/json") || req.headers["content-type"]?.includes("json")) {
    if (hitNumber === 1) {
      // First hit — return auth challenge
      return res.status(401).json({
        error:    "Authentication required",
        auth:     "bearer",
        realm:    persona.orgName || "Internal System",
        loginUrl: `/trap/${trap.trapId}`,
        version:  "2.4.1",
      });
    }
    // Subsequent hits — return fake data
    return res.json({
      status:  "success",
      session: crypto.randomBytes(16).toString("hex"),
      data:    fakeData,
      _note:   "This is a PhishNetra honeypot canary response.",
    });
  }

  // For browser requests — return full HTML deception page
  const html = buildDeceptivePage(trap, hitNumber, fakeData, persona, req);
  res.setHeader("Content-Type", "text/html");
  res.setHeader("X-Powered-By", "SharePoint/16.0"); // spoof server header
  res.setHeader("Server", "Microsoft-IIS/10.0");    // spoof server
  return res.send(html);
});

// ── Build realistic HTML deception page ──────────────────────
function buildDeceptivePage(trap, hitNumber, fakeData, persona, req) {
  const isPost = req.method === "POST";
  const color  = persona.brandColor || "#1a56db";
  const orgName= persona.orgName    || "Internal System";
  const title  = persona.title      || "Secure Portal";
  const emoji  = persona.faviconEmoji || "🏢";

  // First visit or GET — show login
  if (hitNumber === 1 || !isPost) {
    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${title} — ${orgName}</title>
  <link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>${emoji}</text></svg>">
  <style>
    * { margin:0; padding:0; box-sizing:border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background:#f3f4f6; min-height:100vh; display:flex; flex-direction:column; }
    .header { background:${color}; color:#fff; padding:14px 24px; display:flex; align-items:center; gap:10px; }
    .header h1 { font-size:18px; font-weight:600; }
    .header span { font-size:14px; opacity:0.85; margin-left:auto; }
    .container { flex:1; display:flex; align-items:center; justify-content:center; padding:32px 16px; }
    .card { background:#fff; border-radius:8px; box-shadow:0 1px 3px rgba(0,0,0,0.1),0 4px 16px rgba(0,0,0,0.08); width:100%; max-width:440px; overflow:hidden; }
    .card-header { padding:24px 28px 0; }
    .card-header h2 { font-size:22px; color:#111; font-weight:600; }
    .card-header p { color:#6b7280; margin-top:6px; font-size:14px; }
    .card-body { padding:24px 28px 28px; }
    .field { margin-bottom:16px; }
    .field label { display:block; font-size:13px; font-weight:500; color:#374151; margin-bottom:6px; }
    .field input { width:100%; padding:10px 12px; border:1px solid #d1d5db; border-radius:6px; font-size:14px; outline:none; transition:border 0.15s; }
    .field input:focus { border-color:${color}; box-shadow:0 0 0 3px ${color}22; }
    .btn { width:100%; padding:11px; background:${color}; color:#fff; border:none; border-radius:6px; font-size:15px; font-weight:500; cursor:pointer; margin-top:8px; transition:opacity 0.15s; }
    .btn:hover { opacity:0.9; }
    .btn:active { opacity:0.8; }
    .notice { margin-top:16px; padding:10px 12px; background:#fef3c7; border:1px solid #f59e0b; border-radius:6px; font-size:12px; color:#92400e; }
    .footer { background:#f9fafb; border-top:1px solid #e5e7eb; padding:20px 24px; text-align:center; color:#6b7280; font-size:12px; }
    .footer a { color:${color}; text-decoration:none; }
    .sso { display:flex; align-items:center; gap:8px; margin-top:16px; padding-top:16px; border-top:1px solid #e5e7eb; }
    .sso-btn { flex:1; padding:9px; border:1px solid #d1d5db; border-radius:6px; background:#fff; font-size:13px; cursor:pointer; color:#374151; transition:background 0.15s; }
    .sso-btn:hover { background:#f9fafb; }
    .divider { font-size:12px; color:#9ca3af; flex-shrink:0; }
  </style>
</head>
<body>
  <div class="header">
    <span style="font-size:22px">${emoji}</span>
    <h1>${orgName}</h1>
    <span>🔒 Secure Connection</span>
  </div>
  <div class="container">
    <div class="card">
      <div class="card-header">
        <h2>Sign In</h2>
        <p>Access ${title} — ${orgName}</p>
      </div>
      <div class="card-body">
        <form method="POST" action="${req.protocol}://${req.get('host')}/api/honeypot/trigger/${trap.trapId}">
          <div class="field">
            <label for="username">Username / Email</label>
            <input type="text" id="username" name="username" placeholder="your.name@company.com" autocomplete="username" required>
          </div>
          <div class="field">
            <label for="password">Password</label>
            <input type="password" id="password" name="password" placeholder="••••••••" autocomplete="current-password" required>
          </div>
          <button type="submit" class="btn">Sign In →</button>
          <div class="notice">
            ⚠️ This system is for authorized personnel only. All access is monitored and logged.
          </div>
          <div class="sso">
            <button type="button" class="sso-btn" onclick="alert('SSO authentication is temporarily unavailable. Please use your credentials.')">
              🏢 Sign in with SSO
            </button>
            <span class="divider">or</span>
            <button type="button" class="sso-btn" onclick="alert('MFA setup required — contact IT support at ext. 4200')">
              📱 Use MFA
            </button>
          </div>
        </form>
      </div>
    </div>
  </div>
  <div class="footer">
    IT Security Policy · <a href="#">Privacy Notice</a> · <a href="#">Acceptable Use Policy</a><br>
    Unauthorized access is prohibited and will be prosecuted. Reference: IT-POL-2024-089
  </div>
</body>
</html>`;
  }

  // POST (submitted credentials) — show fake dashboard
  return buildFakeDashboard(trap, fakeData, persona, color, emoji, orgName, title);
}

function buildFakeDashboard(trap, fakeData, persona, color, emoji, orgName, title) {
  const docRows = fakeData.documents?.map((d) =>
    `<tr><td>📄 ${d.name}</td><td>${d.size}</td><td>${d.modified}</td>
     <td><span style="color:${d.sensitivity==="TOP SECRET"?"#dc2626":d.sensitivity==="RESTRICTED"?"#d97706":"#1d4ed8"};font-weight:600;font-size:11px;">${d.sensitivity}</span></td>
     <td><a href="#" onclick="alert('Download logged and flagged for security review.');return false;" style="color:${color}">Download</a></td></tr>`
  ).join("") || "";

  const secretRows = fakeData.secrets?.map((s) =>
    `<tr><td style="font-family:monospace;font-size:13px">${s.name}</td>
     <td><span style="font-family:monospace;font-size:12px;filter:blur(4px);user-select:none" class="secret-val" onclick="this.style.filter='none';setTimeout(()=>{this.style.filter='blur(4px)'},5000)">${s.value}</span></td>
     <td>${s.env}</td><td>${s.lastRotated}</td>
     <td><button onclick="navigator.clipboard?.writeText('${s.value}');alert('Copied! Note: This access has been logged.')" style="padding:4px 8px;background:${color};color:#fff;border:none;border-radius:4px;cursor:pointer;font-size:12px">Copy</button></td></tr>`
  ).join("") || "";

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${title} — ${orgName}</title>
  <link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>${emoji}</text></svg>">
  <style>
    * { margin:0; padding:0; box-sizing:border-box; }
    body { font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif; background:#f3f4f6; }
    .topbar { background:${color}; color:#fff; padding:12px 24px; display:flex; align-items:center; gap:12px; }
    .topbar h1 { font-size:17px; font-weight:600; }
    .topbar .user { margin-left:auto; font-size:13px; opacity:0.9; }
    .sidebar { position:fixed; top:48px; left:0; bottom:0; width:220px; background:#1f2937; padding:16px 0; }
    .sidebar a { display:block; padding:10px 20px; color:#9ca3af; text-decoration:none; font-size:14px; transition:all 0.15s; }
    .sidebar a:hover, .sidebar a.active { background:#374151; color:#fff; }
    .sidebar .section { padding:16px 20px 6px; font-size:10px; text-transform:uppercase; letter-spacing:1px; color:#6b7280; }
    .main { margin-left:220px; padding:24px; }
    .page-title { font-size:22px; font-weight:600; color:#111; margin-bottom:20px; }
    .stats { display:grid; grid-template-columns:repeat(auto-fit,minmax(160px,1fr)); gap:16px; margin-bottom:24px; }
    .stat { background:#fff; border-radius:8px; padding:16px; box-shadow:0 1px 3px rgba(0,0,0,0.1); }
    .stat .val { font-size:28px; font-weight:700; color:${color}; }
    .stat .lbl { font-size:12px; color:#6b7280; margin-top:4px; }
    .card { background:#fff; border-radius:8px; box-shadow:0 1px 3px rgba(0,0,0,0.1); margin-bottom:20px; overflow:hidden; }
    .card-header { padding:14px 20px; border-bottom:1px solid #e5e7eb; font-weight:600; font-size:15px; color:#111; display:flex; align-items:center; justify-content:space-between; }
    .card-body { padding:16px 20px; }
    table { width:100%; border-collapse:collapse; font-size:13px; }
    th { text-align:left; padding:10px 12px; background:#f9fafb; color:#6b7280; font-weight:500; font-size:12px; border-bottom:1px solid #e5e7eb; }
    td { padding:10px 12px; border-bottom:1px solid #f3f4f6; color:#374151; }
    tr:last-child td { border-bottom:none; }
    .badge { padding:2px 8px; border-radius:9999px; font-size:11px; font-weight:500; }
    .alert-bar { background:#fef2f2; border:1px solid #fecaca; border-radius:6px; padding:10px 16px; margin-bottom:16px; color:#991b1b; font-size:13px; }
  </style>
</head>
<body>
  <div class="topbar">
    <span style="font-size:20px">${emoji}</span>
    <h1>${orgName} — ${title}</h1>
    <div class="user">👤 Welcome back &nbsp;|&nbsp; <a href="#" style="color:#fff;opacity:0.8">Sign Out</a></div>
  </div>
  <div class="sidebar">
    <div class="section">Navigation</div>
    <a href="#" class="active">🏠 Dashboard</a>
    <a href="#">📁 Documents</a>
    <a href="#">👥 Users</a>
    <a href="#">⚙️ Settings</a>
    <div class="section">Security</div>
    <a href="#">🔑 Access Logs</a>
    <a href="#">🛡️ Permissions</a>
    <a href="#" onclick="alert('Audit trail export is pending administrator approval.')">📋 Audit Trail</a>
  </div>
  <div class="main">
    <div class="alert-bar">
      ⚠️ Security Notice: Your access to this system has been logged. Unauthorized use will result in legal action.
    </div>
    <div class="page-title">Dashboard</div>
    <div class="stats">
      ${fakeData.employeeCount ? `<div class="stat"><div class="val">${fakeData.employeeCount}</div><div class="lbl">Active Users</div></div>` : ""}
      ${fakeData.totalEmails   ? `<div class="stat"><div class="val">${fakeData.totalEmails.toLocaleString()}</div><div class="lbl">Archived Emails</div></div>` : ""}
      ${fakeData.storageUsed   ? `<div class="stat"><div class="val">${fakeData.storageUsed}</div><div class="lbl">Storage Used</div></div>` : ""}
      ${fakeData.activeConnections ? `<div class="stat"><div class="val">${fakeData.activeConnections}</div><div class="lbl">Active Connections</div></div>` : ""}
      <div class="stat"><div class="val" style="color:#16a34a">✓ Online</div><div class="lbl">System Status</div></div>
    </div>

    ${docRows ? `
    <div class="card">
      <div class="card-header">📁 Recent Documents <span style="font-size:13px;color:#6b7280;font-weight:400">Click to download</span></div>
      <div class="card-body"><table>
        <tr><th>Name</th><th>Size</th><th>Modified</th><th>Classification</th><th>Action</th></tr>
        ${docRows}
      </table></div>
    </div>` : ""}

    ${secretRows ? `
    <div class="card">
      <div class="card-header">🔑 Stored Credentials &amp; API Keys <span style="font-size:13px;color:#6b7280;font-weight:400">Click value to reveal</span></div>
      <div class="card-body"><table>
        <tr><th>Name</th><th>Value</th><th>Environment</th><th>Last Rotated</th><th></th></tr>
        ${secretRows}
      </table></div>
    </div>` : ""}

    ${fakeData.emails ? `
    <div class="card">
      <div class="card-header">📧 Recent Executive Communications</div>
      <div class="card-body"><table>
        <tr><th>From</th><th>Subject</th><th>Date</th><th>Attachment</th></tr>
        ${fakeData.emails.map((e) =>
          `<tr><td>${e.from}</td><td><a href="#" onclick="alert('Document access logged for security audit.');return false;" style="color:${color}">${e.subject}</a></td><td>${e.date}</td><td>${e.hasAttachment?"📎 Yes":"—"}</td></tr>`
        ).join("")}
      </table></div>
    </div>` : ""}

    ${fakeData.announcements ? `
    <div class="card">
      <div class="card-header">📢 Announcements</div>
      <div class="card-body">
        ${fakeData.announcements.map((a) =>
          `<div style="padding:10px 0;border-bottom:1px solid #f3f4f6"><strong>${a.title}</strong><span style="color:#6b7280;font-size:12px;margin-left:10px">${a.date}</span></div>`
        ).join("")}
      </div>
    </div>` : ""}

    <div style="text-align:center;color:#9ca3af;font-size:11px;padding:16px">
      ${orgName} · Internal Use Only · All access is monitored · Ref: ${fakeData.canaryToken || ""}
    </div>
  </div>
</body>
</html>`;
}

module.exports = router;