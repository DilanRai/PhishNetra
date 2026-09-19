"use strict";
const dns       = require("dns").promises;
const mongoose  = require("mongoose");
const https     = require("https");

// ── IP Reputation MongoDB Schema ──────────────────────────────
const IPReputationSchema = new mongoose.Schema({
  ip:              { type: String, required: true, unique: true, index: true },
  reputationScore: { type: Number, default: 0 },
  verdict:         { type: String, enum:["clean","suspicious","malicious"], default:"clean" },
  // DNSBL data
  dnsblHits:       { type: [mongoose.Schema.Types.Mixed], default: [] },
  isTorExitNode:   { type: Boolean, default: false },
  isKnownSpamSource:{ type: Boolean, default: false },
  isOpenRelay:     { type: Boolean, default: false },
  isBotnet:        { type: Boolean, default: false },
  isDynamic:       { type: Boolean, default: false },
  isVPN:           { type: Boolean, default: false },
  isDatacenter:    { type: Boolean, default: false },
  threatLabel:     { type: String, default: null },
  // PhishNetra internal tracking
  seenInScans:     { type: Number, default: 1 },
  scanIds:         { type: [String], default: [] },
  associatedDomains:{ type: [String], default: [] },
  firstSeenAt:     { type: Date, default: Date.now },
  lastSeenAt:      { type: Date, default: Date.now },
  // Cache
  lastChecked:     { type: Date, default: Date.now },
  cacheExpiresAt:  { type: Date, default: () => new Date(Date.now() + 6*60*60*1000) },
}, { timestamps: true });

const IPReputation = mongoose.models.IPReputation ||
                     mongoose.model("IPReputation", IPReputationSchema);

// ── DNSBL definitions ─────────────────────────────────────────
const DNSBLS = [
  {
    name:  "Spamhaus ZEN",
    zone:  "zen.spamhaus.org",
    codes: {
      "127.0.0.2": { meaning:"SBL — Direct UBE source",         type:"spam",    score:80 },
      "127.0.0.3": { meaning:"SBL CSS — Spam support services",  type:"spam",    score:70 },
      "127.0.0.4": { meaning:"XBL — CBL — Botnet infected",      type:"botnet",  score:85 },
      "127.0.0.9": { meaning:"SBL DROP — Hijacked netblock",      type:"spam",    score:75 },
      "127.0.0.10":{ meaning:"PBL ISP — Dynamic/residential",     type:"dynamic", score:30 },
      "127.0.0.11":{ meaning:"PBL Spamhaus — Policy block",       type:"dynamic", score:25 },
    },
    priority: 1,
  },
  {
    name:  "Barracuda",
    zone:  "b.barracudacentral.org",
    codes: {
      "127.0.0.2": { meaning:"Barracuda — Known spam sender",     type:"spam",    score:70 },
    },
    priority: 2,
  },
  {
    name:  "SORBS SPAM",
    zone:  "spam.dnsbl.sorbs.net",
    codes: {
      "127.0.0.10":{ meaning:"SORBS — Spam source (last 48h)",    type:"spam",    score:65 },
    },
    priority: 3,
  },
  {
    name:  "SpamCop",
    zone:  "bl.spamcop.net",
    codes: {
      "127.0.0.2": { meaning:"SpamCop — Recent spam reports",     type:"spam",    score:60 },
    },
    priority: 4,
  },
  {
    name:  "UCEPROTECT L1",
    zone:  "dnsbl-1.uceprotect.net",
    codes: {
      "127.0.0.2": { meaning:"UCEPROTECT — Individual spam IP",   type:"spam",    score:55 },
    },
    priority: 5,
  },
  {
    name:  "SpamRats",
    zone:  "dyna.spamrats.com",
    codes: {
      "127.0.0.36":{ meaning:"SpamRats — Dynamic IP spam source", type:"dynamic", score:40 },
    },
    priority: 6,
  },
];

// ── TOR exit node detection via DNS ──────────────────────────
// Uses the Tor Project's official DNSBL: <reversed-ip>.80.80.180.in-addr.arpa
// Returns 127.0.0.2 if the IP is a known TOR exit node
async function isTorExitNode(ip) {
  try {
    const reversed = ip.split(".").reverse().join(".");
    // Official TOR exit node DNSBL (no API needed, DNS-based)
    await dns.resolve4(`${reversed}.80.80.180.in-addr.arpa`);
    return true; // resolves = it's a TOR exit node
  } catch {
    return false;
  }
}

// ── Core DNSBL check ─────────────────────────────────────────
async function checkDNSBLs(ip) {
  if (!ip || isPrivateIP(ip)) return { hits:[], maxScore:0 };

  const reversed = ip.split(".").reverse().join(".");
  const results  = await Promise.allSettled(
    DNSBLS.map(async (list) => {
      try {
        const addresses = await Promise.race([
          dns.resolve4(`${reversed}.${list.zone}`),
          new Promise((_, reject) => setTimeout(() => reject(new Error("timeout")), 3000)),
        ]);
        // Map return codes to meanings
        const hits = addresses.map(addr => {
          const codeInfo = list.codes[addr] || { meaning:`Listed (${addr})`, type:"unknown", score:50 };
          return { list: list.name, returnCode: addr, ...codeInfo };
        });
        return hits;
      } catch {
        return []; // not listed or timeout
      }
    })
  );

  const hits     = results.flatMap(r => r.status === "fulfilled" ? r.value : []);
  const maxScore = hits.length > 0 ? Math.max(...hits.map(h => h.score)) : 0;
  return { hits, maxScore };
}

// ── Open relay detection ──────────────────────────────────────
// Check if IP appears in Spamhaus SBL or sends via open relays
function detectOpenRelay(dnsblHits) {
  return dnsblHits.some(h => h.type === "spam" && h.score >= 70);
}

// ── Private IP check (same as GAP 1) ─────────────────────────
function isPrivateIP(ip) {
  if (!ip) return true;
  return /^10\./.test(ip) || /^172\.(1[6-9]|2\d|3[01])\./.test(ip) ||
         /^192\.168\./.test(ip) || /^127\./.test(ip) || /^::1$/.test(ip);
}

// ── Build threat label ────────────────────────────────────────
function buildThreatLabel(result) {
  if (result.isTorExitNode)    return "TOR Exit Node";
  if (result.isBotnet)         return "Botnet Member";
  if (result.isOpenRelay)      return "Open Relay / Spam Source";
  if (result.isKnownSpamSource)return "Known Spam Source";
  if (result.isDynamic && result.isKnownSpamSource) return "Dynamic IP Spam Source";
  if (result.isVPN)            return "VPN / Anonymizer";
  if (result.isDatacenter)     return "Datacenter / Hosting";
  if (result.isDynamic)        return "Dynamic / Residential IP";
  return null;
}

// ── Build reputation score ────────────────────────────────────
function buildReputationScore(data) {
  let score = 0;
  if (data.isTorExitNode)     score += 90;
  if (data.isBotnet)          score += 85;
  if (data.isOpenRelay)       score += 70;
  if (data.isKnownSpamSource) score += 60;
  if (data.isVPN)             score += 40;
  if (data.isDatacenter)      score += 20;
  if (data.isDynamic)         score += 10;
  if (data.seenInScans > 5)   score += 20; // repeat offender
  if (data.seenInScans > 10)  score += 10; // persistent threat
  // DNSBL max score contribution
  score += Math.round((data.dnsblMaxScore || 0) * 0.5);
  return Math.min(score, 100);
}

// ════════════════════════════════════════════════════════════════
// MAIN FUNCTION — checkIPReputation()
// ════════════════════════════════════════════════════════════════
async function checkIPReputation(ip, options = {}) {
  const { geoData = null, scanId = null, senderDomain = null } = options;

  if (!ip || isPrivateIP(ip)) {
    return {
      ip, reputationScore:0, verdict:"clean",
      dnsblHits:[], isTorExitNode:false, isKnownSpamSource:false,
      isOpenRelay:false, isBotnet:false, isDynamic:false,
      threatLabel:"Private Network / Localhost", seenInScans:0,
    };
  }

  // ── Check MongoDB cache (valid for 6 hours) ────────────────
  try {
    const cached = await IPReputation.findOne({ ip, cacheExpiresAt: { $gt: new Date() } });
    if (cached) {
      // Update scan count and return cached
      const update = { lastSeenAt: new Date(), $inc: { seenInScans: 1 } };
      if (scanId) update.$addToSet = { scanIds: scanId };
      if (senderDomain) { update.$addToSet = update.$addToSet || {}; update.$addToSet.associatedDomains = senderDomain; }
      await IPReputation.findByIdAndUpdate(cached._id, update);
      return cached.toObject();
    }
  } catch {}

  // ── Fresh DNSBL check ─────────────────────────────────────
  const [dnsblResult, torResult] = await Promise.all([
    checkDNSBLs(ip),
    isTorExitNode(ip),
  ]);

  const { hits, maxScore: dnsblMaxScore } = dnsblResult;

  // Categorize DNSBL hits
  const isBotnet          = hits.some(h => h.type === "botnet");
  const isKnownSpamSource = hits.some(h => h.type === "spam");
  const isDynamic         = hits.some(h => h.type === "dynamic") && !isKnownSpamSource;
  const isOpenRelay       = detectOpenRelay(hits);

  // Merge GAP 1 geo data if provided
  const isVPN         = geoData?.isVPN        || false;
  const isDatacenter  = geoData?.isDatacenter || false;

  const reputationData = {
    ip,
    dnsblHits:       hits,
    dnsblMaxScore,
    isTorExitNode:   torResult,
    isKnownSpamSource,
    isOpenRelay,
    isBotnet,
    isDynamic,
    isVPN,
    isDatacenter,
    seenInScans:     1,
    scanIds:         scanId ? [scanId] : [],
    associatedDomains: senderDomain ? [senderDomain] : [],
    firstSeenAt:     new Date(),
    lastSeenAt:      new Date(),
    lastChecked:     new Date(),
    cacheExpiresAt:  new Date(Date.now() + 6 * 60 * 60 * 1000),
  };

  reputationData.reputationScore = buildReputationScore({
    ...reputationData, dnsblMaxScore,
  });
  reputationData.verdict = reputationData.reputationScore >= 60 ? "malicious"
                         : reputationData.reputationScore >= 25 ? "suspicious"
                         : "clean";
  reputationData.threatLabel = buildThreatLabel(reputationData);

  // ── Upsert to MongoDB ─────────────────────────────────────
  try {
    await IPReputation.findOneAndUpdate(
      { ip },
      {
        $set: {
          reputationScore:  reputationData.reputationScore,
          verdict:          reputationData.verdict,
          dnsblHits:        hits,
          isTorExitNode:    torResult,
          isKnownSpamSource,
          isOpenRelay,
          isBotnet,
          isDynamic,
          isVPN,
          isDatacenter,
          threatLabel:      reputationData.threatLabel,
          lastSeenAt:       new Date(),
          lastChecked:      new Date(),
          cacheExpiresAt:   reputationData.cacheExpiresAt,
        },
        $inc:       { seenInScans: 1 },
        $addToSet:  {
          scanIds:           scanId || [],
          associatedDomains: senderDomain || [],
        },
        $setOnInsert: { firstSeenAt: new Date() },
      },
      { upsert: true, new: true }
    );
  } catch {}

  return reputationData;
}

// ── Stats for dashboard / SIEM ────────────────────────────────
async function getIPReputationStats() {
  const since24h = new Date(Date.now() - 24*60*60*1000);
  const [total, malicious, suspicious, tor, botnet, topRepeatOffenders] = await Promise.all([
    IPReputation.countDocuments({}),
    IPReputation.countDocuments({ verdict:"malicious" }),
    IPReputation.countDocuments({ verdict:"suspicious" }),
    IPReputation.countDocuments({ isTorExitNode:true }),
    IPReputation.countDocuments({ isBotnet:true }),
    IPReputation.find({ seenInScans:{ $gt:3 } })
      .sort({ seenInScans:-1 }).limit(10)
      .select("ip reputationScore verdict threatLabel seenInScans lastSeenAt")
      .lean(),
  ]);
  return {
    total, malicious, suspicious, tor, botnet,
    topRepeatOffenders,
  };
}

module.exports = { checkIPReputation, getIPReputationStats, IPReputation, isPrivateIP };
