// FILE: backend/siem/iocEngine.js — CREATE NEW
// IOC (Indicator of Compromise) Engine
// Extracts, stores, correlates, and alerts on IOCs from every scan.
// Completely separate from ThreatIndicator (which is STIX sharing only).
// This is the analyst-facing IOC system — what SOC teams use at 2am.

"use strict";
const mongoose = require("mongoose");
const crypto = require("crypto");

// ── IOC Schema ──────────────────────────────────────────────────
const IOCSchema = new mongoose.Schema(
  {
    // Type: what kind of indicator this is
    type: {
      type: String,
      enum: [
        "domain",
        "url",
        "ip",
        "email",
        "file_hash",
        "email_sender",
        "registrar",
        "asn",
        "keyword", // NEW — suspicious phrase from text/SMS scan
        "phone", // NEW — phone number found in fraudulent text
        "upi_id", // NEW — UPI ID found in fraud text
      ],
      required: true,
      index: true,
    },
    // The raw indicator value (stored — unlike ThreatIndicator which only stores the hash)
    // IOCs are analyst-facing data, not shared externally, so storage is appropriate
    value: { type: String, required: true, index: true },
    valueHash: { type: String, required: true, index: true }, // SHA-256 for dedup

    // Threat context
    confidence: { type: Number, min: 0, max: 100, default: 50 },
    severity: { type: Number, min: 1, max: 5, default: 3 },
    tags: { type: [String], default: [] },
    attackTypes: { type: [String], default: [] },
    mitreId: { type: String, default: null },

    // Attribution
    brand: { type: String, default: null },
    kitId: { type: String, default: null },
    riskScore: { type: Number, default: 0 },

    // Lifecycle
    status: {
      type: String,
      enum: ["active", "expired", "false_positive"],
      default: "active",
      index: true,
    },
    hitCount: { type: Number, default: 1 }, // how many scans matched this IOC
    firstSeen: { type: Date, default: Date.now, index: true },
    lastSeen: { type: Date, default: Date.now },
    expiresAt: {
      type: Date,
      default: () => new Date(Date.now() + 90 * 24 * 60 * 60 * 1000),
    }, // 90d TTL

    // Related scans (last 20 only — ring buffer)
    relatedScans: [
      {
        scanId: String,
        input: String,
        riskScore: Number,
        seenAt: { type: Date, default: Date.now },
      },
    ],

    // Source
    source: { type: String, default: "phishnetra_scan" },
    notes: { type: String, default: "" },

    // ── Keyword-specific fields ──────────────────────────────
    // Only populated for type="keyword"
    keywordContext: { type: String, default: null }, // which detector fired this keyword
    keywordLanguage: { type: String, default: null }, // "en" | "hi" | "hinglish"
    keywordCategory: { type: String, default: null }, // "urgency" | "otp" | "threat" | "financial" | "impersonation"
    rawSnippet: { type: String, default: null }, // the original sentence containing the keyword (max 120 chars)
  },
  { timestamps: false },
);

IOCSchema.index({ type: 1, value: 1 }, { unique: false });
IOCSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 }); // auto-expire
IOCSchema.index({ lastSeen: -1 });
IOCSchema.index({ status: 1, severity: -1 });

const IOC = mongoose.model("IOC", IOCSchema);

// ── Hash an IOC value for dedup ──
function hashValue(value) {
  return crypto
    .createHash("sha256")
    .update(String(value).trim().toLowerCase())
    .digest("hex");
}

// ── Extract domain from URL ──
function getDomain(input) {
  try {
    const u = input.startsWith("http") ? input : `https://${input}`;
    return new URL(u).hostname.toLowerCase().replace(/^www\./, "");
  } catch {
    return null;
  }
}

// ── Keyword IOC categories and extraction patterns ────────────
const KEYWORD_IOC_RULES = [
  // ── Urgency / Threat language ──────────────────────────────
  {
    category: "urgency",
    language: "en",
    patterns: [
      /your account (will be|has been) (suspended|blocked|limited|restricted|terminated)/i,
      /immediate(ly)? (action|verification|attention) (required|needed)/i,
      /account (will be )?(suspend|block|terminat|restrict)/i,
      /verify (your )?(account|identity|information) (immediately|now|urgently)/i,
      /failure to (comply|respond|verify) (will|may) result/i,
      /last (chance|warning|notice) (to |before )(verify|pay|respond)/i,
      /service (will be |has been )?(suspend|terminat|discontinu)/i,
      /within \d+ (hours?|minutes?|days?)/i,
      /urgent(ly)? (required|needed|action)/i,
    ],
  },
  // ── OTP / Credential harvesting ────────────────────────────
  {
    category: "otp",
    language: "en",
    patterns: [
      /share (your |the )?(otp|one.time.password|verification code)/i,
      /enter (your )?(otp|pin|password|passcode)/i,
      /do not share (your )?(otp|pin|password) with anyone/i,
      /otp (is |has been )?(sent|generated|received)/i,
      /confirm (your )?(otp|transaction) (to|by)/i,
    ],
  },
  // ── Financial fraud ────────────────────────────────────────
  {
    category: "financial",
    language: "en",
    patterns: [
      /pay (rs\.?|inr|₹|usd|\$)?\s*\d+/i,
      /wire transfer (of |for )?(rs\.?|inr|₹)?/i,
      /send (money|payment|funds) (to|via) (upi|gpay|phonepe|paytm)/i,
      /scan (the )?(qr|qr code) to (receive|pay|transfer)/i,
      /bitcoin (wallet|address|payment)/i,
      /gift card (payment|purchase|code)/i,
      /click here to (claim|receive|collect|get) (your )?(prize|reward|refund|payment)/i,
    ],
  },
  // ── Government / Authority impersonation ───────────────────
  {
    category: "impersonation",
    language: "en",
    patterns: [
      /cbi (officer|department|investigation)/i,
      /trai (notice|warning|action)/i,
      /income tax (department|notice|arrest|recovery)/i,
      /customs (department|officer|clearance|duty)/i,
      /narcotics (bureau|control|department)/i,
      /digital arrest/i,
      /cyber (crime )?police/i,
      /(court|arrest) (warrant|notice|order) (has been )?issued/i,
      /your (aadhaar|pan|sim) (has been |is )?(misused|linked|blocked)/i,
    ],
  },
  // ── Hindi / Hinglish urgency ───────────────────────────────
  {
    category: "urgency",
    language: "hinglish",
    patterns: [
      /account (band|block) (ho|hoga|kar)/i,
      /abhi (karo|kijiye|verify|pay)/i,
      /turant (action|karo|verify)/i,
      /otp (batao|share karo|dijiye|send karo)/i,
      /aapka (sim|number|account) (band|block|suspend)/i,
      /ghar (par|mein) (rahiye|raho)/i,
      /digital arrest/i,
      /police (aa rahi|aa jayegi|aayi)/i,
      /paise (wapas|bhejo|transfer)/i,
      /kyc (update|verify|complete) karo/i,
      /qr (code |)scan karo/i,
    ],
  },
  // ── Phishing delivery phrases ──────────────────────────────
  {
    category: "delivery",
    language: "en",
    patterns: [
      /click (the |this )?(link|here|button) to (verify|confirm|update|access)/i,
      /login to (your )?(account|portal|dashboard) (at|via|through)/i,
      /visit (our )?(website|portal|page) (to|for)/i,
      /download (the |our )?(app|application|file|document)/i,
      /update (your )?(kyc|details|information|account)/i,
      /re.?verify (your )?(account|email|phone|identity)/i,
      /your (package|parcel|shipment) (is |has been )?(held|delayed|stopped)/i,
    ],
  },
];

/**
 * extractKeywordsFromText(input, result, scanId)
 * Extracts suspicious keyword phrases from text/SMS scan results.
 * Returns array of keyword IOC objects.
 *
 * ONLY extracts from phishing/suspicious scans (not safe).
 * ONLY saves the matched phrase, not the full text.
 * Deduplicates across patterns — same phrase not saved twice.
 */
function extractKeywordsFromText(input, result, scanId) {
  if (!input || typeof input !== "string") return [];
  if (result.status === "safe") return [];

  const inputType = result.inputType || "text";
  if (inputType !== "text" && inputType !== "sms" && inputType !== "email")
    return [];

  const riskScore = result.riskScore || 0;
  const sev =
    riskScore >= 85 ? 5 : riskScore >= 70 ? 4 : riskScore >= 50 ? 3 : 2;
  const confidence = Math.min(riskScore, 95);
  const text = input.trim();
  const found = new Map(); // deduplicate by matched phrase

  for (const rule of KEYWORD_IOC_RULES) {
    for (const pattern of rule.patterns) {
      const match = text.match(pattern);
      if (!match) continue;

      // Extract the matched phrase (clean, lowercase, max 80 chars)
      const phrase = match[0]
        .trim()
        .toLowerCase()
        .replace(/\s+/g, " ")
        .substring(0, 80);

      if (phrase.length < 6) continue; // too short to be meaningful
      if (found.has(phrase)) continue; // already captured

      // Extract a context snippet (sentence containing the match)
      const matchIdx = text.toLowerCase().indexOf(match[0].toLowerCase());
      const start = Math.max(0, matchIdx - 30);
      const end = Math.min(text.length, matchIdx + match[0].length + 30);
      const snippet = text.substring(start, end).trim().substring(0, 120);

      found.set(phrase, {
        type: "keyword",
        value: phrase,
        valueHash: hashValue(phrase),
        confidence,
        severity: sev,
        riskScore,
        attackTypes: result.attackTypes || [],
        mitreId: "T1566 - Phishing",
        tags: [
          `category:${rule.category}`,
          `lang:${rule.language}`,
          `inputType:${inputType}`,
          ...(result.attackTypes || []),
        ],
        keywordContext: result.detectionVersion || "phishingDetector",
        keywordLanguage: rule.language,
        keywordCategory: rule.category,
        rawSnippet: snippet,
        source: "text_analysis",
        relatedScan: {
          scanId,
          input: text.substring(0, 120),
          riskScore,
          seenAt: new Date(),
        },
      });
    }
  }

  // Also extract from India fraud detector results if present
  if (result.indiaFraud?.detected && result.indiaFraud.detections) {
    for (const detection of result.indiaFraud.detections) {
      const phrase = detection.name.toLowerCase().substring(0, 80);
      if (!found.has(phrase)) {
        found.set(phrase, {
          type: "keyword",
          value: `[${detection.fraudType}] ${phrase}`,
          valueHash: hashValue(`india_fraud:${phrase}`),
          confidence: detection.confidence || confidence,
          severity: detection.severity || sev,
          riskScore,
          attackTypes: [detection.fraudType, "india_cyber_fraud"],
          mitreId: detection.mitre || "T1566",
          tags: [
            `category:india_fraud`,
            `lang:hinglish`,
            `fraud_type:${detection.fraudType}`,
          ],
          keywordContext: "indiaFraudDetector",
          keywordLanguage: "hinglish",
          keywordCategory: detection.fraudType,
          rawSnippet: detection.description?.substring(0, 120) || phrase,
          source: "india_fraud_analysis",
          relatedScan: {
            scanId,
            input: text.substring(0, 120),
            riskScore,
            seenAt: new Date(),
          },
        });
      }
    }
  }

  return [...found.values()];
}

/**
 * extractPhoneAndUPIFromText(input, result, scanId)
 * Extracts Indian phone numbers and UPI IDs from fraud text.
 * Returns array of phone/upi_id IOC objects.
 */
function extractPhoneAndUPIFromText(input, result, scanId) {
  if (!input || result.status === "safe") return [];

  const text = input.trim();
  const riskScore = result.riskScore || 0;
  const sev = riskScore >= 70 ? 4 : 3;
  const iocs = [];

  // Indian mobile numbers: +91XXXXXXXXXX or 0XXXXXXXXXX or 10 digits starting 6-9
  const phones = [
    ...new Set(
      (text.match(/(?:\+91|0)?[6-9]\d{9}/g) || []).map((p) =>
        p.replace(/^\+91|^0/, ""),
      ),
    ),
  ];

  for (const phone of phones.slice(0, 5)) {
    iocs.push({
      type: "phone",
      value: phone,
      valueHash: hashValue(`phone:${phone}`),
      confidence: Math.min(riskScore, 90),
      severity: sev,
      riskScore,
      attackTypes: result.attackTypes || [],
      mitreId: "T1566 - Phishing",
      tags: ["phone_number", "india", ...(result.attackTypes || [])],
      keywordContext: "phone_extraction",
      keywordLanguage: "en",
      keywordCategory: "contact",
      rawSnippet: text.substring(0, 80),
      source: "text_analysis",
      relatedScan: {
        scanId,
        input: text.substring(0, 120),
        riskScore,
        seenAt: new Date(),
      },
    });
  }

  // UPI IDs: anything@provider (excluding common email providers)
  const EMAIL_PROVIDERS = new Set([
    "gmail",
    "yahoo",
    "outlook",
    "hotmail",
    "rediffmail",
    "ymail",
  ]);
  const upis = [
    ...new Set(
      (text.match(/[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}/g) || []).filter(
        (u) => !EMAIL_PROVIDERS.has(u.split("@")[1]?.toLowerCase()),
      ),
    ),
  ];

  for (const upi of upis.slice(0, 5)) {
    iocs.push({
      type: "upi_id",
      value: upi.toLowerCase(),
      valueHash: hashValue(`upi:${upi.toLowerCase()}`),
      confidence: Math.min(riskScore, 90),
      severity: sev,
      riskScore,
      attackTypes: result.attackTypes || [],
      mitreId: "T1660 - Phishing via Financial Platform",
      tags: ["upi_id", "financial_fraud", ...(result.attackTypes || [])],
      keywordContext: "upi_extraction",
      keywordLanguage: "en",
      keywordCategory: "financial",
      rawSnippet: text.substring(0, 80),
      source: "text_analysis",
      relatedScan: {
        scanId,
        input: text.substring(0, 120),
        riskScore,
        seenAt: new Date(),
      },
    });
  }

  return iocs;
}

// ── Extract all IOCs from a scan result ──
// Returns an array of raw IOC objects ready to upsert
function extractIOCsFromScan(input, result, scanId) {
  const iocs = [];
  const inputType = result.inputType || "url";
  const attackTypes = result.attackTypes || [];
  const riskScore = result.riskScore || 0;

  // Only extract IOCs from phishing/suspicious scans (ignore safe)
  if (result.status === "safe") return [];

  // Severity based on risk score
  const sev =
    riskScore >= 85 ? 5 : riskScore >= 70 ? 4 : riskScore >= 50 ? 3 : 2;
  const confidence = Math.min(riskScore, 95);

  // MITRE technique for this scan
  const mitreId = attackTypes.includes("aitm")
    ? "T1557"
    : attackTypes.includes("homograph")
      ? "T1583.001"
      : attackTypes.includes("brand_impersonation")
        ? "T1036.005"
        : attackTypes.includes("credential_harvest")
          ? "T1056.003"
          : attackTypes.includes("bec")
            ? "T1534"
            : "T1566.002";

  // ── 1. URL indicator ──
  if (inputType === "url") {
    const cleanUrl = input.trim().toLowerCase();
    iocs.push({
      type: "url",
      value: cleanUrl,
      confidence,
      severity: sev,
      riskScore,
      attackTypes,
      mitreId,
      brand: result.brandImpersonated || null,
      kitId: result.kitMatch?.kitId || null,
      tags: [...attackTypes, `risk:${riskScore}`],
    });

    // ── 2. Domain indicator (extracted from URL) ──
    const domain = getDomain(input);
    if (domain) {
      iocs.push({
        type: "domain",
        value: domain,
        confidence,
        severity: sev,
        riskScore,
        attackTypes,
        mitreId,
        brand: result.brandImpersonated || null,
        tags: [...attackTypes, "domain"],
      });
    }
  }

  // ── 3. Email sender IOC (from email scans or BEC) ──
  if (inputType === "email" || attackTypes.includes("bec")) {
    const senderMatch = input.match(
      /from:?\s*[<\["]?([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})/i,
    );
    if (senderMatch) {
      iocs.push({
        type: "email_sender",
        value: senderMatch[1].toLowerCase(),
        confidence,
        severity: sev,
        riskScore,
        attackTypes,
        mitreId,
        tags: [...attackTypes, "email_sender"],
      });
    }
  }

  // ── 4. IP indicator (from urlPreview geolocation) ──
  const ip = result.urlPreview?.ipGeolocation?.ip;
  if (ip && !/^(10\.|192\.168\.|127\.|::1)/.test(ip)) {
    iocs.push({
      type: "ip",
      value: ip,
      confidence: Math.min(confidence - 10, 80),
      severity: Math.max(sev - 1, 2),
      riskScore,
      attackTypes,
      tags: [
        ...attackTypes,
        "hosting_ip",
        result.urlPreview?.ipGeolocation?.country || "",
      ],
    });
  }

  // ── 5. File hash IOC (from attachment scans) ──
  if (
    result.attachmentResult?.sha256 &&
    result.attachmentResult?.verdict !== "clean"
  ) {
    iocs.push({
      type: "file_hash",
      value: result.attachmentResult.sha256,
      confidence,
      severity: sev,
      riskScore,
      attackTypes: result.attachmentResult.categories || attackTypes,
      tags: [
        `ext:${result.attachmentResult.extension}`,
        `verdict:${result.attachmentResult.verdict}`,
        ...(result.attachmentResult.categories || []),
      ],
    });
  }

  // ── 6. Text keyword IOCs (text/SMS/email input type) ────────
  if (inputType === "text" || inputType === "sms" || inputType === "email") {
    const keywordIOCs = extractKeywordsFromText(input, result, scanId);
    iocs.push(...keywordIOCs);

    // Phone numbers and UPI IDs from fraud text
    const contactIOCs = extractPhoneAndUPIFromText(input, result, scanId);
    iocs.push(...contactIOCs);
  }

  // Also extract keywords from URL issue descriptions that contain fraud language
  if (inputType === "url" && result.issues?.length > 0) {
    const issueText = result.issues.join(" ");
    const keywordResult = { ...result, inputType: "text" };
    const keywordIOCs = extractKeywordsFromText(
      issueText,
      keywordResult,
      scanId,
    );
    iocs.push(...keywordIOCs.slice(0, 3)); // max 3 from issue text
  }

  return iocs.map((ioc) => ({
    ...ioc,
    // keyword/phone/upi_id IOCs pre-compute their own valueHash — don't overwrite
    valueHash: ioc.valueHash || hashValue(ioc.value),
    relatedScan: ioc.relatedScan || {
      scanId,
      input: typeof input === "string" ? input.substring(0, 200) : "",
      riskScore,
      seenAt: new Date(),
    },
  }));
}

// ── Upsert IOCs — dedup by valueHash, increment hit count ──
async function upsertIOCs(rawIOCs) {
  const results = [];
  for (const raw of rawIOCs) {
    try {
      const { relatedScan, ...iocData } = raw;
      const existing = await IOC.findOne({ valueHash: iocData.valueHash });

      if (existing) {
        // Update existing — increment hit count, push related scan (cap at 20)
        existing.hitCount += 1;
        existing.lastSeen = new Date();
        existing.riskScore = Math.max(existing.riskScore, iocData.riskScore);
        existing.severity = Math.max(existing.severity, iocData.severity);
        existing.confidence = Math.max(existing.confidence, iocData.confidence);
        // Merge attack types
        const merged = new Set([
          ...existing.attackTypes,
          ...iocData.attackTypes,
        ]);
        existing.attackTypes = [...merged];
        // Ring buffer for related scans
        if (relatedScan) {
          existing.relatedScans.push(relatedScan);
          if (existing.relatedScans.length > 20) {
            existing.relatedScans = existing.relatedScans.slice(-20);
          }
        }
        // Extend expiry on re-sighting
        existing.expiresAt = new Date(Date.now() + 90 * 24 * 60 * 60 * 1000);
        await existing.save();
        results.push({ ioc: existing, isNew: false });
      } else {
        // Create new IOC
        const newIOC = new IOC({
          ...iocData,
          relatedScans: relatedScan ? [relatedScan] : [],
        });
        await newIOC.save();
        results.push({ ioc: newIOC, isNew: true });
      }
    } catch (err) {
      if (err.code !== 11000) console.error("IOC upsert error:", err.message);
      // 11000 = duplicate key — safe to ignore, means concurrent upsert
    }
  }
  return results;
}

// ── Check if an input matches any existing active IOCs ──
// Returns array of matching IOCs for SIEM alert enrichment
async function checkIOCMatch(input, inputType) {
  const hashes = [];

  // Build all possible hashes for this input
  const cleanInput = input.trim().toLowerCase();
  hashes.push({
    hash: hashValue(cleanInput),
    type: inputType === "url" ? "url" : inputType,
  });

  if (inputType === "url") {
    const domain = getDomain(input);
    if (domain) hashes.push({ hash: hashValue(domain), type: "domain" });
  }

  // For text/SMS scans: check if any known keyword IOCs appear in the text
  if (inputType === "text" || inputType === "sms") {
    const knownKeywords = await IOC.find({
      type: "keyword",
      status: "active",
      expiresAt: { $gt: new Date() },
    })
      .select("value valueHash severity hitCount")
      .lean();

    const matchedKeywords = knownKeywords.filter((kw) =>
      input.toLowerCase().includes(kw.value.toLowerCase()),
    );

    // Add matched keyword hashes to the query
    matchedKeywords.forEach((kw) => {
      hashes.push({ hash: kw.valueHash, type: "keyword" });
    });
  }

  if (!hashes.length) return [];

  const matches = await IOC.find({
    valueHash: { $in: hashes.map((h) => h.hash) },
    status: "active",
    expiresAt: { $gt: new Date() },
  })
    .select(
      "type value confidence severity hitCount firstSeen lastSeen attackTypes brand kitId tags riskScore",
    )
    .lean();

  return matches;
}

// ── Get IOC stats for dashboard ──
async function getIOCStats() {
  const since7d = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
  const [total, active, new7d, byType, bySeverity, topIOCs] = await Promise.all(
    [
      IOC.countDocuments({}),
      IOC.countDocuments({ status: "active" }),
      IOC.countDocuments({ firstSeen: { $gte: since7d } }),
      IOC.aggregate([{ $group: { _id: "$type", count: { $sum: 1 } } }]),
      IOC.aggregate([{ $group: { _id: "$severity", count: { $sum: 1 } } }]),
      IOC.find({ status: "active" })
        .sort({ hitCount: -1, severity: -1 })
        .limit(10)
        .select(
          "type value severity hitCount firstSeen lastSeen attackTypes brand tags",
        )
        .lean(),
    ],
  );

  const typeMap = {};
  byType.forEach((t) => {
    typeMap[t._id] = t.count;
  });
  const sevMap = { 1: 0, 2: 0, 3: 0, 4: 0, 5: 0 };
  bySeverity.forEach((s) => {
    sevMap[s._id] = s.count;
  });

  return { total, active, new7d, byType: typeMap, bySeverity: sevMap, topIOCs };
}

// ── List IOCs with filters (for SIEM IOC tab) ──
async function listIOCs({ type, severity, status, page = 1, limit = 50 } = {}) {
  const query = {};
  if (type) query.type = type;
  if (severity) query.severity = Number(severity);
  if (status) query.status = status;
  else query.status = "active"; // default to active

  const skip = (Number(page) - 1) * Number(limit);
  const [iocs, total] = await Promise.all([
    IOC.find(query)
      .sort({ lastSeen: -1 })
      .skip(skip)
      .limit(Number(limit))
      .lean(),
    IOC.countDocuments(query),
  ]);
  return {
    iocs,
    total,
    page: Number(page),
    pages: Math.ceil(total / Number(limit)),
  };
}

// ── Mark IOC as false positive ──
async function markFalsePositive(iocId) {
  return IOC.findByIdAndUpdate(
    iocId,
    { status: "false_positive" },
    { new: true },
  );
}

// ── Main entry point: process a scan through the IOC engine ──
// Called from scan.js after phishingDetector runs
async function processIOCs(input, result, scanId) {
  if (!input || !result) return { extracted: [], matched: [] };
  try {
    // 1. Check if this input matches any known IOC FIRST
    const matched = await checkIOCMatch(input, result.inputType);

    // 2. Extract new IOCs from this scan and upsert
    const rawIOCs = extractIOCsFromScan(input, result, scanId);
    const upserted = rawIOCs.length > 0 ? await upsertIOCs(rawIOCs) : [];

    // 3. If we have IOC matches, boost the risk score
    if (matched.length > 0) {
      const maxSev = Math.max(...matched.map((m) => m.severity));
      const boost = maxSev >= 5 ? 25 : maxSev >= 4 ? 18 : 10;
      result.riskScore = Math.min(result.riskScore + boost, 100);
      result.iocMatches = matched;
      if (result.status === "safe" && matched.some((m) => m.severity >= 4)) {
        result.status = "suspicious";
      }
      // Surface in issues
      matched.forEach((m) => {
        result.issues = [
          `🔴 IOC MATCH — Known ${m.type.toUpperCase()}: "${m.value}" ` +
            `(seen ${m.hitCount}×, severity ${m.severity}/5, first seen ${new Date(m.firstSeen).toLocaleDateString()})`,
          ...(result.issues || []),
        ];
      });
    }

    return {
      extracted: upserted.map((u) => ({
        id: u.ioc._id,
        type: u.ioc.type,
        isNew: u.isNew,
      })),
      matched,
    };
  } catch (err) {
    console.error("IOC engine error:", err.message);
    return { extracted: [], matched: [] };
  }
}

module.exports = {
  IOC,
  processIOCs,
  checkIOCMatch,
  getIOCStats,
  listIOCs,
  markFalsePositive,
};
