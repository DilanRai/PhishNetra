// ================================================================
// FILE: Backend/ai/autoTrainingEngine.js — FULL REPLACE
//
// WHAT'S NEW vs previous version:
//   ★ JSON dataset support — drop .json files into datasets/
//   ★ JSON schema auto-detection (array, JSONL, wrapped object)
//   ★ JSON label + text/URL field auto-detection
//   ★ File watcher now watches for both .csv AND .json
//   ★ loadDatasetFile() dispatched to CSV or JSON parser
//   ★ Memory guard (MAX_ROWS + MAX_TOTAL_ROWS)
//   ★ Bug fix: notes field crash on null in alert escalation
//
// SUPPORTED JSON FORMATS:
//   1. Array of objects:
//      [{"url":"http://...","label":"phishing"}, ...]
//
//   2. Wrapped array (any wrapper key):
//      {"data":[...]} or {"emails":[...]} or {"results":[...]}
//
//   3. JSONL / Newline-delimited JSON:
//      {"url":"http://...","label":"phishing"}
//      {"url":"http://...","label":"legitimate"}
//
//   4. Single object with arrays per field:
//      {"urls":["http://...","http://..."],"labels":[1,0]}
// ================================================================

"use strict";
const fs      = require("fs");
const path    = require("path");
const crypto  = require("crypto");

const DATASETS_DIR  = path.join(__dirname, "../datasets");
const MODEL_OUT     = path.join(__dirname, "phishing_model_v3.json");
const TRAIN_LOG     = path.join(__dirname, "training_log.json");
const DEBOUNCE_MS   = 8000;
const MAX_ROWS      = 10000;   // ★ FIX: was 50000 — reduced to prevent OOM crash
const MAX_TOTAL_ROWS= 25000;   // ★ NEW: hard cap across all files combined
const EPOCHS        = 100;     // ★ FIX: was 150 — faster training
const LR            = 0.05;

let   synaptic, mlModule;
let   trainingStatus = {
  state: "idle", startedAt: null, completedAt: null,
  accuracy: null, f1: null, samples: 0,
  datasetsUsed: [], error: null, modelVersion: "v3",
};
let debounceTimer = null;

function getSynaptic() {
  if (!synaptic) synaptic = require("synaptic");
  return synaptic;
}

// ════════════════════════════════════════════════════════════════
// CSV HELPERS (unchanged from original)
// ════════════════════════════════════════════════════════════════

function parseCSVLine(line) {
  const out = []; let cur = ""; let q = false;
  for (const ch of line) {
    if (ch === '"') { q = !q; continue; }
    if (ch === "," && !q) { out.push(cur.trim()); cur = ""; continue; }
    cur += ch;
  }
  out.push(cur.trim());
  return out;
}

function detectSchema(headers, firstRow) {
  const h = headers.map(x => x.toLowerCase().trim().replace(/[^a-z0-9_]/g, ""));
  const urlFeatureCols = ["nb_dots","nb_hyphens","length_url","numdots","urllength","numdashs","pathlevel","subdomainlevel"];
  if (urlFeatureCols.filter(c => h.includes(c)).length >= 3) return "url_features";
  const hasUrlCol   = h.some(c => c.match(/^urls?$|^links?$|^domain/));
  const hasLabelCol = h.some(c => c.match(/^labels?$|^class$|^y$|^target$|^types?$|^status$/));
  if (hasUrlCol && hasLabelCol) return "url_label";
  const hasTextCol = h.some(c => c.match(/text|content|message|body|email|sms|v[12]/));
  const hasTypCol  = h.some(c => c.match(/type|spam|phish|label|class|result|tag/));
  if (hasTextCol) {
    if (hasTypCol) return "email_text_labeled";
    const vals = Object.values(firstRow || {}).join(" ");
    if (vals.length > 200) return "email_text_unlabeled";
    return "email_text_labeled";
  }
  if (h.includes("compound") || h.includes("neg")) return "sentiment_text";
  return "unknown";
}

function normalizeLabel(raw) {
  if (raw === null || raw === undefined) return null;
  const v = String(raw).trim().toLowerCase();
  if (v === "1" || v === "1.0") return 1;
  if (v === "0" || v === "0.0") return 0;
  if (/^phishing|^bad$|^spam$|^fraud|^malicious|^credential|^romance|^social_eng|^financial/.test(v)) return 1;
  if (/^legitimate|^safe$|^ham$|^benign|^good$|^clean$|^legit$|^not.spam|^not.phishing/.test(v)) return 0;
  const n = parseFloat(v);
  if (!isNaN(n)) return n > 0 ? 1 : 0;
  return null;
}

const VECTOR_SIZE = 64;
function padVector(v) {
  if (v.length >= VECTOR_SIZE) return v.slice(0, VECTOR_SIZE);
  return [...v, ...new Array(VECTOR_SIZE - v.length).fill(0)];
}
function clamp(v, max = 1) {
  const n = parseFloat(v);
  return isNaN(n) ? 0 : Math.min(Math.max(n / max, 0), 1);
}
const bool = v => (v === "1" || v === 1 || v === "true" || v === true) ? 1 : 0;

function extractURLFeatures(row, headers) {
  const h = headers.map(x => x.toLowerCase().trim());
  const g = (name) => row[headers[h.indexOf(name)]] ?? "0";
  const isPhishDataset = h.includes("nb_dots");
  if (isPhishDataset) {
    return padVector([
      clamp(g("length_url"), 200), bool(g("ip")),
      clamp(g("nb_dots"), 10),     clamp(g("nb_hyphens"), 10),
      bool(g("nb_at")),            bool(g("nb_qm")),
      bool(g("nb_and")),           clamp(g("nb_eq"), 5),
      clamp(g("nb_underscore"), 5),clamp(g("nb_slash"), 15),
      clamp(g("nb_percent"), 5),   bool(g("nb_www")),
      bool(g("nb_com")),           bool(g("https_token")),
      clamp(g("ratio_digits_url"), 1), clamp(g("ratio_digits_host"), 1),
      bool(g("punycode")),         bool(g("port")),
      bool(g("tld_in_path")),      bool(g("tld_in_subdomain")),
      bool(g("abnormal_subdomain")),clamp(g("nb_subdomains"), 5),
      bool(g("prefix_suffix")),    bool(g("random_domain")),
      bool(g("shortening_service")),bool(g("path_extension")),
      clamp(g("nb_redirection"), 5), clamp(g("nb_external_redirection"), 5),
      clamp(g("phish_hints"), 5),  bool(g("domain_in_brand")),
      bool(g("brand_in_subdomain")),bool(g("brand_in_path")),
      bool(g("suspecious_tld")),   bool(g("login_form")),
      bool(g("iframe")),           bool(g("popup_window")),
      bool(g("safe_anchor")),      bool(g("onmouseover")),
      bool(g("right_clic")),       bool(g("empty_title")),
      bool(g("domain_in_title")),  bool(g("whois_registered_domain")),
      clamp(g("domain_registration_length"), 3650), bool(g("dns_record")),
      bool(g("google_index")),     clamp(g("page_rank"), 10),
    ]);
  }
  return padVector([
    clamp(g("urllength"), 200),   clamp(g("numdots"), 10),
    clamp(g("pathLevel"), 10),    clamp(g("numdashs"), 10),
    bool(g("AtSymbol")),          bool(g("TildeSymbol")),
    bool(g("NumUnderscore")),     clamp(g("NumQueryComponents"), 5),
    bool(g("IsHTTPS")),           bool(g("SubdomainLevel")),
    bool(g("NumSensitiveWords")), bool(g("EmbeddedBrandName")),
    bool(g("PctExtResourceUrls")), bool(g("ExtFavicon")),
    bool(g("InsecureForms")),     bool(g("RelativeFormAction")),
    bool(g("ExtFormAction")),     bool(g("AbnormalFormAction")),
    bool(g("PctNullSelfRedirectHyperlinks")), bool(g("FrequentDomainNameMismatch")),
    bool(g("FakeLinkInStatusBar")),bool(g("RightClickDisabled")),
    bool(g("PopUpWindow")),       bool(g("SubmitInfoToEmail")),
    bool(g("IframeOrFrame")),     bool(g("MissingTitle")),
    bool(g("ImagesOnlyInForm")),  bool(g("SubdomainLevelRT")),
    bool(g("UrlLengthRT")),       bool(g("PctExtResourceUrlsRT")),
  ]);
}

function extractURLLabelFeatures(url) {
  if (!url) return padVector([]);
  const u = url.toLowerCase();
  let domain = u;
  try { domain = new URL(u.startsWith("http") ? u : `https://${u}`).hostname.replace(/^www\./, ""); } catch {}
  const HIGH_ABUSE_TLDS = [".tk",".ml",".ga",".cf",".gq",".top",".xyz",".icu",".sbs",".cfd",".click",".vip",".men",".work"];
  const SHORT_SERVICES  = ["bit.ly","tinyurl","t.co","goo.gl","ow.ly","rb.gy","is.gd","buff.ly","cutt.ly"];
  const PHISH_KEYWORDS  = ["login","verify","secure","account","update","confirm","paypal","google","apple","amazon","microsoft","bank","signin","password","credential","auth","wallet","recover","suspended"];
  const SUSPICIOUS_PATTERNS = [/-secure-|-login-|-verify-|-update-|-confirm-/i, /\d{3,}\.\d{3,}/];
  const tld       = "." + domain.split(".").pop();
  return padVector([
    Math.min(url.length / 200, 1),
    Math.min((url.match(/\./g) || []).length / 10, 1),
    Math.min((url.match(/-/g)  || []).length / 10, 1),
    Math.min((url.match(/\//g) || []).length / 15, 1),
    (url.match(/\d/g) || []).length / Math.max(url.length, 1),
    /((\d{1,3}\.){3}\d{1,3})/.test(url) ? 1 : 0,
    url.startsWith("https") ? 1 : 0,
    HIGH_ABUSE_TLDS.includes(tld) ? 1 : 0,
    SHORT_SERVICES.some(s => domain.includes(s)) ? 1 : 0,
    Math.min(PHISH_KEYWORDS.filter(k => u.includes(k)).length / 5, 1),
    SUSPICIOUS_PATTERNS.some(p => p.test(url)) ? 1 : 0,
    Math.min((domain.split(".").length - 2), 5) / 5,
    url.includes("@") ? 1 : 0,
    (url.match(/\/\//g) || []).length > 1 ? 1 : 0,
    domain.startsWith("xn--") ? 1 : 0,
    Math.min(((url.match(/\//g) || []).length - 2), 10) / 10,
  ]);
}

function extractTextFeatures(text) {
  if (!text || typeof text !== "string") return padVector([]);
  const t  = text.toLowerCase();
  const wc = t.split(/\s+/).length;
  const countKW = (list) => Math.min(list.filter(w => t.includes(w)).length / 5, 1);
  const anyKW   = (list) => list.some(w => t.includes(w)) ? 1 : 0;
  const URGENCY    = ["urgent","immediately","verify","confirm","expire","expires","suspended","act now","limited time","within 24","deadline","final notice","last chance"];
  const CREDENTIAL = ["password","username","login","signin","credential","otp","pin","ssn","verify your","enter your","update your","click here","confirm your","account has"];
  const FINANCIAL  = ["bank account","wire transfer","gift card","bitcoin","western union","moneygram","refund","invoice","payment","transfer funds","routing number"];
  const BRAND      = ["paypal","google","microsoft","apple","amazon","facebook","netflix","instagram","twitter","linkedin","chase","wellsfargo","coinbase","binance"];
  const GOVT       = ["irs","hmrc","tax refund","government","social security","medicare","unemployment","stimulus","department of"];
  const TECH_SCAM  = ["tech support","microsoft support","windows defender","apple support","virus detected","your computer","hacker","compromised your"];
  const PRIZE      = ["you won","winner","congratulations","selected","prize","lottery","claim your","free gift","reward"];
  const GIFT_CARD  = ["amazon gift","google play","itunes","walmart gift","best buy","target gift","prepaid card"];
  const WIRE       = ["wire transfer","bank transfer","swift code","iban","routing","wiring instructions"];
  const OTP        = ["verification code","one-time","2fa","two factor","authentication code","security code","enter the code","otp"];
  const DEADLINE   = ["within 24 hours","within 48 hours","before it expires","respond immediately","action required","no later than"];
  const SAFE       = ["unsubscribe","view in browser","privacy policy","terms of service","copyright","all rights reserved"];
  return padVector([
    Math.min(wc / 500, 1),
    Math.min((t.match(/https?:\/\//g) || []).length / 5, 1),
    Math.min(text.length / 5000, 1),
    countKW(URGENCY), countKW(CREDENTIAL), countKW(FINANCIAL),
    anyKW(BRAND), anyKW(GOVT), anyKW(TECH_SCAM),
    anyKW(PRIZE), anyKW(GIFT_CARD), anyKW(WIRE),
    anyKW(OTP), anyKW(DEADLINE), anyKW(SAFE),
    Math.min(((text.match(/[A-Z]/g) || []).length / Math.max(text.length, 1)) * 10, 1),
    Math.min((text.match(/!/g) || []).length / 10, 1),
    Math.min((text.match(/\?/g) || []).length / 5, 1),
    t.includes("dear customer") ? 1 : 0,
    t.includes("dear user") ? 1 : 0,
    /https?:\/\/[a-z0-9]{6,14}\.(tk|ml|top|xyz|icu|sbs)/.test(t) ? 1 : 0,
    /bit\.ly|tinyurl|t\.co|rb\.gy|is\.gd/.test(t) ? 1 : 0,
    anyKW(["attachment","see attached","open file","open document"]),
    anyKW(["romance","lonely","dating","relationship","interested in you"]),
  ]);
}

// ════════════════════════════════════════════════════════════════
// ★ NEW: JSON SCHEMA DETECTION
// Figures out the structure of a JSON dataset file
// Returns one of:
//   "json_array"        → [{url, label}, ...]
//   "json_array_text"   → [{text/body/message, label}, ...]
//   "json_array_url"    → [{url, label}, ...]
//   "json_parallel"     → {urls:[...], labels:[...]}
//   "jsonl"             → newline-delimited JSON objects
//   "unknown"
// ════════════════════════════════════════════════════════════════
function detectJSONSchema(parsed) {
  // JSONL was already parsed as array by the loader
  if (!parsed) return "unknown";

  // ── Case 1: Top-level array ──
  if (Array.isArray(parsed)) {
    if (parsed.length === 0) return "unknown";
    const sample = parsed[0];
    if (typeof sample !== "object" || sample === null) return "unknown";
    const keys = Object.keys(sample).map(k => k.toLowerCase());

    // URL + label
    const hasURL   = keys.some(k => /^url$|^link$|^domain$|^website$|^href$/.test(k));
    const hasLabel = keys.some(k => /^label$|^class$|^target$|^type$|^status$|^tag$|^y$|^is_phishing$|^phishing$|^spam$/.test(k));
    const hasText  = keys.some(k => /^text$|^body$|^content$|^message$|^email$|^subject$|^email_text$|^email_body$|^sms$/.test(k));

    if (hasURL  && hasLabel) return "json_array_url";
    if (hasText && hasLabel) return "json_array_text";
    if (hasLabel)            return "json_array_url"; // try URL anyway
    // No label column — check for common field combeds
    if (hasURL)  return "json_array_url_unlabeled";
    if (hasText) return "json_array_text_unlabeled";
    return "json_array_unknown";
  }

  // ── Case 2: Wrapped object {"data":[...]} or {"emails":[...]} ──
  if (typeof parsed === "object") {
    for (const [key, val] of Object.entries(parsed)) {
      if (Array.isArray(val) && val.length > 0) {
        // Recurse into the array
        return detectJSONSchema(val);
      }
    }
    // ── Case 3: Parallel arrays {"urls":[...],"labels":[...]} ──
    const keys = Object.keys(parsed).map(k => k.toLowerCase());
    const hasURLArr   = keys.some(k => /urls?|links?|domains?/.test(k));
    const hasLabelArr = keys.some(k => /labels?|class|targets?|types?/.test(k));
    const hasTextArr  = keys.some(k => /texts?|bodies|messages?|emails?|contents?/.test(k));
    if ((hasURLArr || hasTextArr) && hasLabelArr) return "json_parallel";
    if (hasURLArr)  return "json_parallel_url";
    if (hasTextArr) return "json_parallel_text";
  }

  return "unknown";
}

// ════════════════════════════════════════════════════════════════
// ★ NEW: JSON FIELD FINDER
// Finds the actual key name for a given role in a JSON object
// ════════════════════════════════════════════════════════════════
function findJSONField(obj, role) {
  if (!obj || typeof obj !== "object") return null;
  const keys = Object.keys(obj);

  const PATTERNS = {
    label:   /^label$|^class$|^target$|^type$|^status$|^tag$|^y$|^is_phishing$|^phishing$|^spam$|^result$|^verdict$/i,
    url:     /^url$|^link$|^domain$|^website$|^href$|^address$|^site$/i,
    text:    /^text$|^body$|^content$|^message$|^email$|^subject$|^email_text$|^email_body$|^sms$|^mail$/i,
    subject: /^subject$|^email_subject$|^subj$|^title$/i,
    sender:  /^sender$|^from$|^from_address$|^email_from$|^source$/i,
    urgency: /^urgency$|^urgency_flag$|^is_urgent$|^urgent$/i,
    hasLink: /^has_link$|^has_url$|^contains_link$|^link_present$/i,
    hasAtch: /^has_attachment$|^attachment$|^has_attach$/i,
  };

  const pattern = PATTERNS[role];
  if (!pattern) return null;

  // Exact match first
  for (const k of keys) {
    if (pattern.test(k)) return k;
  }
  return null;
}

// ════════════════════════════════════════════════════════════════
// ★ NEW: JSON FILE PARSER
// Handles all 4 JSON formats and returns [{features, label}]
// ════════════════════════════════════════════════════════════════
function parseJSONFile(content, filename) {
  // ── Try to parse as JSON array / object ──
  let parsed;
  try {
    parsed = JSON.parse(content);
  } catch {
    // ── Try JSONL (newline-delimited JSON) ──
    const lines = content.split(/\r?\n/).filter(l => l.trim().startsWith("{"));
    if (lines.length === 0) return { data: [], schema: "invalid_json" };
    try {
      parsed = lines.map(l => JSON.parse(l));
    } catch {
      return { data: [], schema: "invalid_json" };
    }
  }

  const schema = detectJSONSchema(parsed);
  if (schema === "unknown" || schema.includes("unknown")) {
    return { data: [], schema };
  }

  const data = [];

  // ── Extract the actual array to iterate ──
  let rows = null;

  if (Array.isArray(parsed)) {
    rows = parsed;
  } else if (typeof parsed === "object") {
    // Wrapped object — find the array
    for (const val of Object.values(parsed)) {
      if (Array.isArray(val) && val.length > 0) {
        rows = val;
        break;
      }
    }

    // Parallel arrays {"urls":[...],"labels":[...]}
    if (!rows && schema.includes("parallel")) {
      const keys    = Object.keys(parsed);
      const urlKey  = keys.find(k => /urls?|links?|domains?/i.test(k));
      const textKey = keys.find(k => /texts?|bodies|messages?|emails?|contents?/i.test(k));
      const lblKey  = keys.find(k => /labels?|class|targets?|types?/i.test(k));

      const dataKey = urlKey || textKey;
      if (dataKey && lblKey) {
        const dataArr = parsed[dataKey];
        const lblArr  = parsed[lblKey];
        const len = Math.min(dataArr.length, lblArr.length, MAX_ROWS);
        for (let i = 0; i < len; i++) {
          const label = normalizeLabel(lblArr[i]);
          if (label === null) continue;
          const features = urlKey
            ? extractURLLabelFeatures(String(dataArr[i]))
            : extractTextFeatures(String(dataArr[i]));
          data.push({ features, label });
        }
        return { data, schema: `json_parallel (${len} rows)` };
      }
    }
  }

  if (!rows || rows.length === 0) return { data: [], schema };

  // ── Process each row object ──
  const limit = Math.min(rows.length, MAX_ROWS);
  let schemaType = schema;

  for (let i = 0; i < limit; i++) {
    const row = rows[i];
    if (!row || typeof row !== "object") continue;

    // Find label
    const labelKey = findJSONField(row, "label");
    const rawLabel = labelKey ? row[labelKey] : null;
    const label    = normalizeLabel(rawLabel);
    if (label === null) continue;

    // Find input data — prioritize URL, then text
    const urlKey  = findJSONField(row, "url");
    const textKey = findJSONField(row, "text");
    const subjKey = findJSONField(row, "subject");
    const sendrKey= findJSONField(row, "sender");
    const urgKey  = findJSONField(row, "urgency");
    const linkKey = findJSONField(row, "hasLink");
    const atchKey = findJSONField(row, "hasAtch");

    let features;

    if (urlKey && row[urlKey]) {
      // URL-based row
      schemaType = "json_array_url";
      features = extractURLLabelFeatures(String(row[urlKey]));
    } else if (textKey || subjKey || sendrKey) {
      // Text/email-based row — combine all text fields
      schemaType = "json_array_text";
      const parts = [];
      if (subjKey  && row[subjKey])  parts.push(`Subject: ${row[subjKey]}`);
      if (sendrKey && row[sendrKey]) parts.push(`From: ${row[sendrKey]}`);
      if (textKey  && row[textKey])  parts.push(String(row[textKey]));
      const combined = parts.join("\n");

      // Base text features
      const textFeats = extractTextFeatures(combined);

      // ★ Dataset-specific boolean signals (JSON datasets often have these)
      const urgencyBonus = (urgKey && bool(row[urgKey])) ? 0.3 : 0;
      const linkBonus    = (linkKey && bool(row[linkKey])) ? 0.1 : 0;
      const atchBonus    = (atchKey && bool(row[atchKey])) ? 0.1 : 0;

      // Inject bonuses into first 3 spare slots
      textFeats[60] = Math.min(urgencyBonus, 1);
      textFeats[61] = Math.min(linkBonus,    1);
      textFeats[62] = Math.min(atchBonus,    1);

      features = textFeats;
    } else {
      // No recognizable content key — skip row
      continue;
    }

    data.push({ features, label });
  }

  return { data, schema: `${schemaType} (${data.length} rows)` };
}

// ════════════════════════════════════════════════════════════════
// UNIFIED DATASET LOADER — dispatches CSV or JSON
// ════════════════════════════════════════════════════════════════
function loadDatasetFile(filePath) {
  const filename = path.basename(filePath);
  const ext      = path.extname(filename).toLowerCase();

  try {
    const content = fs.readFileSync(filePath, "utf8");

    // ── JSON file ──
    if (ext === ".json" || ext === ".jsonl") {
      const result = parseJSONFile(content, filename);
      return { filename, data: result.data, schema: result.schema, total: result.data.length };
    }

    // ── CSV file (original logic) ──
    const lines   = content.split(/\r?\n/).filter(l => l.trim());
    if (lines.length < 5) return { filename, data: [], schema: "too_small" };

    const headers   = parseCSVLine(lines[0]);
    const firstVals = parseCSVLine(lines[1]);
    const firstRow  = {};
    headers.forEach((h, i) => { firstRow[h] = firstVals[i] || ""; });

    const schema = detectSchema(headers, firstRow);
    if (schema === "unknown") return { filename, data: [], schema };

    const hLow = headers.map(h => h.toLowerCase().trim());

    const labelColIdx = (() => {
      const candidates = ["label","email type","type","status","v1","class","y","target","classification","phishing_type","result","spam","tag"];
      for (const c of candidates) {
        const idx = hLow.findIndex(h => h.replace(/[^a-z0-9]/g,"") === c.replace(/[^a-z0-9]/g,""));
        if (idx >= 0) return idx;
      }
      return headers.length - 1;
    })();

    const textColIdx = (() => {
      const candidates = ["email text","text","email_content","message","v2","url","content","body"];
      for (const c of candidates) {
        const idx = hLow.findIndex(h => h.replace(/[^a-z]/g,"") === c.replace(/[^a-z]/g,""));
        if (idx >= 0) return idx;
      }
      return -1;
    })();

    const data    = [];
    const maxLine = Math.min(lines.length, MAX_ROWS + 1);

    for (let i = 1; i < maxLine; i++) {
      const cols     = parseCSVLine(lines[i]);
      if (cols.length < 2) continue;
      const rawLabel = cols[labelColIdx];
      const label    = normalizeLabel(rawLabel);
      if (label === null) continue;

      let features;
      if (schema === "url_features") {
        const row = {};
        headers.forEach((h, idx) => { row[h] = cols[idx] || "0"; });
        features = extractURLFeatures(row, headers);
      } else if (schema === "url_label") {
        features = extractURLLabelFeatures(cols[textColIdx >= 0 ? textColIdx : 0]);
      } else if (schema === "email_text_labeled" || schema === "email_text_unlabeled") {
        features = extractTextFeatures(cols[textColIdx >= 0 ? textColIdx : 0]);
      } else if (schema === "sentiment_text") {
        const msg      = cols[0] || "";
        const compound = parseFloat(cols[1] || "0");
        const neg      = parseFloat(cols[2] || "0");
        const pos      = parseFloat(cols[4] || "0");
        features = padVector([
          ...extractTextFeatures(msg).slice(0, 60),
          Math.min(Math.max(-compound, 0), 1),
          Math.min(neg, 1), Math.min(pos, 1), 0,
        ]);
      } else { continue; }

      data.push({ features, label });
    }

    return { filename, data, schema, total: data.length };
  } catch (err) {
    return { filename, data: [], schema: "error", error: err.message };
  }
}

// ════════════════════════════════════════════════════════════════
// TRAINING — loads all datasets, trains, hot-swaps model
// ════════════════════════════════════════════════════════════════
function shuffle(arr) {
  for (let i = arr.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [arr[i], arr[j]] = [arr[j], arr[i]];
  }
  return arr;
}

async function trainFromAllDatasets() {
  if (trainingStatus.state === "training") return;
  trainingStatus = {
    state: "training", startedAt: new Date().toISOString(),
    completedAt: null, accuracy: null, f1: null,
    samples: 0, datasetsUsed: [], error: null, modelVersion: "v3",
  };
  console.log("\n🧠 PhishNetra Auto-Trainer — scanning datasets/...");

  if (!fs.existsSync(DATASETS_DIR)) {
    trainingStatus.state = "failed";
    trainingStatus.error = "datasets/ folder not found";
    return;
  }

  // ★ Accept both CSV and JSON files
  const allFiles = fs.readdirSync(DATASETS_DIR).filter(f => {
    const lower = f.toLowerCase();
    return (lower.endsWith(".csv") || lower.endsWith(".json") || lower.endsWith(".jsonl"))
      && !f.startsWith("_");
  });

  if (!allFiles.length) {
    trainingStatus.state = "failed";
    trainingStatus.error = "No CSV or JSON files in datasets/";
    return;
  }

  let allData = [];
  const usedDatasets = [];

  for (const file of allFiles) {
    const filePath = path.join(DATASETS_DIR, file);
    const result   = loadDatasetFile(filePath);
    if (result.data.length === 0) {
      console.log(`  ⚠ ${file}: ${result.schema} — skipped (${result.error || "no usable data"})`);
      continue;
    }
    console.log(`  ✅ ${file}: ${result.data.length} samples [schema: ${result.schema}]`);
    allData = allData.concat(result.data);
    usedDatasets.push({ file, samples: result.data.length, schema: result.schema });

    // ★ FIX: Check total after each file — stop before OOM
    if (allData.length >= MAX_TOTAL_ROWS) {
      console.warn(`  ⚠ Total rows hit MAX_TOTAL_ROWS (${MAX_TOTAL_ROWS}) — stopping file loading`);
      break;
    }
  }

  if (allData.length < 100) {
    trainingStatus.state = "failed";
    trainingStatus.error = `Only ${allData.length} training samples — need at least 100`;
    return;
  }

  // ★ FIX: Memory guard
  const memMB = Math.round(process.memoryUsage().heapUsed / 1024 / 1024);
  console.log(`\n💾 Heap before training: ${memMB}MB — ${allData.length} samples`);
  if (memMB > 1500) {
    trainingStatus.state = "failed";
    trainingStatus.error = "Training aborted — heap > 1.5GB. Reduce MAX_ROWS.";
    console.error("❌ " + trainingStatus.error);
    return;
  }

  // Balance classes
  const phishing = allData.filter(d => d.label === 1);
  const safe     = allData.filter(d => d.label === 0);
  const minority = Math.min(phishing.length, safe.length);
  const finalData = shuffle([
    ...shuffle(phishing).slice(0, minority * 2),
    ...shuffle(safe).slice(0, minority * 2),
  ]);

  const phCount = finalData.filter(d => d.label === 1).length;
  const saCount = finalData.filter(d => d.label === 0).length;
  console.log(`\n📊 Training set: ${finalData.length} samples (${phCount} phishing, ${saCount} safe)`);
  console.log(`   Datasets: ${usedDatasets.length} files`);

  const { Architect } = getSynaptic();
  const network      = new Architect.Perceptron(VECTOR_SIZE, 48, 32, 16, 1);
  const trainingSet  = finalData.map(d => ({ input: d.features, output: [d.label] }));

  console.log(`\n🏃 Training ${EPOCHS} epochs (lr=${LR}, ${VECTOR_SIZE} features)...`);
  const t0 = Date.now();
  let lastMSE = 1;

  for (let epoch = 1; epoch <= EPOCHS; epoch++) {
    const sh = shuffle([...trainingSet]);
    let total = 0;
    for (const s of sh) {
      network.activate(s.input);
      network.propagate(LR, s.output);
      const pred = network.activate(s.input)[0];
      total += (pred - s.output[0]) ** 2;
    }
    lastMSE = total / sh.length;
    if (epoch % 25 === 0 || epoch === 1 || epoch === EPOCHS) {
      console.log(`   Epoch ${String(epoch).padStart(3)}/${EPOCHS} — MSE: ${lastMSE.toFixed(5)} (${((Date.now()-t0)/1000).toFixed(1)}s)`);
    }
  }

  // Evaluate
  let tp=0, fp=0, tn=0, fn=0;
  for (const s of trainingSet) {
    const p = network.activate(s.input)[0] >= 0.5 ? 1 : 0;
    const a = s.output[0];
    if (p===1&&a===1) tp++; else if (p===1&&a===0) fp++;
    else if (p===0&&a===0) tn++; else fn++;
  }
  const acc  = ((tp+tn)/trainingSet.length*100).toFixed(2);
  const prec = tp ? (tp/(tp+fp)*100).toFixed(2) : "0";
  const rec  = tp ? (tp/(tp+fn)*100).toFixed(2) : "0";
  const f1   = (prec&&rec&&(parseFloat(prec)+parseFloat(rec))>0)
    ? (2*parseFloat(prec)*parseFloat(rec)/(parseFloat(prec)+parseFloat(rec))).toFixed(2)
    : "0";

  console.log(`\n📈 Results — Accuracy: ${acc}%  Precision: ${prec}%  Recall: ${rec}%  F1: ${f1}%`);
  console.log(`   TP:${tp}  FP:${fp}  TN:${tn}  FN:${fn}  MSE:${lastMSE.toFixed(5)}`);

  // Save model
  const modelJSON = network.toJSON();
  modelJSON._meta = {
    version: "v3", trainedAt: new Date().toISOString(),
    samples: finalData.length, phishingSamples: phCount, safeSamples: saCount,
    epochs: EPOCHS, learningRate: LR, finalMSE: lastMSE,
    accuracy: parseFloat(acc), precision: parseFloat(prec),
    recall:   parseFloat(rec), f1: parseFloat(f1),
    architecture: `${VECTOR_SIZE}→48→32→16→1`,
    datasetsUsed: usedDatasets, featureSize: VECTOR_SIZE,
    trainingMs: Date.now() - t0,
    // ★ Track JSON vs CSV dataset counts
    jsonDatasets: usedDatasets.filter(d => d.file.endsWith(".json") || d.file.endsWith(".jsonl")).length,
    csvDatasets:  usedDatasets.filter(d => d.file.endsWith(".csv")).length,
  };
  fs.writeFileSync(MODEL_OUT, JSON.stringify(modelJSON));

  // Hot-swap
  if (!mlModule) { try { mlModule = require("./mlModel"); } catch {} }
  if (mlModule?.hotSwapModel) {
    mlModule.hotSwapModel(network, modelJSON._meta);
    console.log("🔄 Model hot-swapped in mlModel.js — no restart needed");
  }

  trainingStatus = {
    state: "ready", startedAt: trainingStatus.startedAt,
    completedAt: new Date().toISOString(),
    accuracy:    parseFloat(acc), f1: parseFloat(f1),
    precision:   parseFloat(prec), recall: parseFloat(rec),
    samples:     finalData.length, datasetsUsed: usedDatasets,
    error:       null, modelVersion: "v3",
    trainingMs:  Date.now() - t0,
  };
  fs.writeFileSync(TRAIN_LOG, JSON.stringify(trainingStatus, null, 2));
  console.log(`\n✅ Training complete in ${((Date.now()-t0)/1000).toFixed(1)}s\n`);
}

// ════════════════════════════════════════════════════════════════
// FILE WATCHER — now watches .csv AND .json AND .jsonl
// ════════════════════════════════════════════════════════════════
function watchDatasets() {
  if (!fs.existsSync(DATASETS_DIR)) {
    fs.mkdirSync(DATASETS_DIR, { recursive: true });
  }

  // ★ Now tracks JSON files too
  const isDatasetFile = (f) => {
    const lower = f?.toLowerCase() || "";
    return lower.endsWith(".csv") || lower.endsWith(".json") || lower.endsWith(".jsonl");
  };

  const knownFiles = new Set(
    fs.readdirSync(DATASETS_DIR).filter(isDatasetFile)
  );
  console.log(`👁  Watching datasets/ for NEW CSV/JSON files (${knownFiles.size} existing files ignored)...`);

  try {
    fs.watch(DATASETS_DIR, { persistent: false }, (eventType, filename) => {
      if (!isDatasetFile(filename)) return;
      if (eventType !== "rename") return;
      if (knownFiles.has(filename)) return;
      const fullPath = path.join(DATASETS_DIR, filename);
      if (!fs.existsSync(fullPath)) return;

      knownFiles.add(filename);
      const ext = path.extname(filename).toUpperCase();
      console.log(`📂 New ${ext} dataset detected: ${filename} — auto-training in ${DEBOUNCE_MS/1000}s...`);

      clearTimeout(debounceTimer);
      debounceTimer = setTimeout(() => {
        console.log(`🧠 Auto-training triggered by: ${filename}`);
        trainFromAllDatasets().catch(err => {
          trainingStatus.state = "failed";
          trainingStatus.error = err.message;
          console.error("Auto-training failed:", err.message);
        });
      }, DEBOUNCE_MS);
    });
  } catch {
    console.warn("⚠ fs.watch unavailable — auto-retrain on new file drop disabled");
  }
}

// ════════════════════════════════════════════════════════════════
// PUBLIC API
// ════════════════════════════════════════════════════════════════
function getTrainingStatus() { return { ...trainingStatus }; }

function triggerRetrain() {
  clearTimeout(debounceTimer);
  return trainFromAllDatasets().catch(err => {
    trainingStatus.state = "failed";
    trainingStatus.error = err.message;
  });
}

setImmediate(() => {
  if (fs.existsSync(MODEL_OUT)) {
    try {
      const meta = JSON.parse(fs.readFileSync(MODEL_OUT, "utf8"))._meta || {};
      const ageH = meta.trainedAt
        ? ((Date.now() - new Date(meta.trainedAt).getTime()) / 3600000).toFixed(1) : "?";
      console.log(`🧠 ML Model v3 loaded (${ageH}h old) — accuracy: ${meta.accuracy}%  F1: ${meta.f1}%  samples: ${meta.samples?.toLocaleString()}`);
      console.log(`   CSV datasets: ${meta.csvDatasets || "?"}  JSON datasets: ${meta.jsonDatasets || "?"}`);
      console.log(`   To retrain: Dashboard → Train, or drop CSV/JSON into datasets/`);
      trainingStatus = {
        state: "ready", startedAt: meta.trainedAt || null,
        completedAt: meta.trainedAt || null,
        accuracy: meta.accuracy || null, f1: meta.f1 || null,
        precision: meta.precision || null, recall: meta.recall || null,
        samples: meta.samples || 0, datasetsUsed: meta.datasetsUsed || [],
        error: null, modelVersion: "v3",
      };
    } catch {
      console.log("🧠 ML Model v3 found (metadata unreadable) — press Train to rebuild");
      trainingStatus.state = "ready";
    }
  } else {
    console.log("⚠️  No ML model found (phishing_model_v3.json missing)");
    console.log("   Drop a CSV or JSON dataset into datasets/ and it will auto-train");
    trainingStatus.state = "idle";
    trainingStatus.error = "No trained model — drop a dataset into datasets/ to train";
  }
  watchDatasets();
});

module.exports = { getTrainingStatus, triggerRetrain, parseJSONFile, detectJSONSchema };