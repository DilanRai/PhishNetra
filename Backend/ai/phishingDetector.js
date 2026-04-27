// ============================================================
// FILE: backend/ai/phishingDetector.js  (FULL REPLACEMENT)
// Detection Engine v3.0 — Rule-Based + Neural Network Hybrid
// ============================================================

// ── ML model (loaded once at startup) ──
const { hybridScore } = require("./mlModel");

// ─────────────────────────────────────────────────────────────
// DATASET 1 — SAFE/TRUSTED DOMAINS
// ─────────────────────────────────────────────────────────────
const SAFE_DOMAINS = new Set([
  "google.com", "gmail.com", "googlemail.com", "bing.com", "yahoo.com", "duckduckgo.com",
  "facebook.com", "instagram.com", "twitter.com", "x.com", "linkedin.com",
  "reddit.com", "tiktok.com", "snapchat.com", "pinterest.com", "tumblr.com",
  "microsoft.com", "apple.com", "github.com", "gitlab.com", "stackoverflow.com",
  "adobe.com", "oracle.com", "ibm.com", "intel.com", "nvidia.com",
  "youtube.com", "netflix.com", "twitch.tv", "spotify.com", "hulu.com",
  "disneyplus.com", "hbomax.com", "primevideo.com",
  "amazon.com", "ebay.com", "paypal.com", "stripe.com", "shopify.com",
  "dropbox.com", "zoom.us", "slack.com", "notion.so", "trello.com",
  "salesforce.com", "atlassian.com", "asana.com",
  "wikipedia.org", "britannica.com", "bbc.com", "reuters.com", "apnews.com",
]);

// ─────────────────────────────────────────────────────────────
// DATASET 2 — BRAND IMPERSONATION PATTERNS
// ─────────────────────────────────────────────────────────────
const BRAND_IMPERSONATION = [
  {
    brand: "PayPal", domains: ["paypal.com"],
    fakes: ["paypa1", "paypa-l", "paypai", "paypalll", "paypal-secure", "paypals",
      "pay-pal", "paypa1.com", "paypal-login", "secure-paypal", "paypal-update",
      "paypal-confirm", "paypalverify"],
  },
  {
    brand: "Google", domains: ["google.com", "gmail.com"],
    fakes: ["g00gle", "googIe", "google-login", "gooogle", "googgle", "google-verify",
      "google-security", "google-accounts-verify", "accounts-google", "gmail-security"],
  },
  {
    brand: "Amazon", domains: ["amazon.com"],
    fakes: ["amaz0n", "amazon-secure", "arnazon", "amazoon", "amazon-verify", "amazon-login",
      "amazon-update", "amazonn", "amaz0n-prime", "amazon-security", "amazon-billing"],
  },
  {
    brand: "Apple", domains: ["apple.com", "icloud.com"],
    fakes: ["app1e", "apple-id", "applelogin", "apple-secure", "apple-verify", "icloud-verify",
      "appleid-login", "apple-support-id", "apple-account-locked", "applecare-billing"],
  },
  {
    brand: "Microsoft", domains: ["microsoft.com", "outlook.com", "live.com"],
    fakes: ["micros0ft", "microsofft", "microsoft-secure", "microsft", "microsoft-login",
      "office-365-verify", "outlook-security", "microsoft-account-verify", "ms-login"],
  },
  {
    brand: "Netflix", domains: ["netflix.com"],
    fakes: ["netf1ix", "netflixx", "netflix-login", "netflixs", "netflix-billing",
      "netflix-update", "netfl1x", "netflix-account-hold", "netflix-payment"],
  },
  {
    brand: "Facebook", domains: ["facebook.com", "fb.com"],
    fakes: ["faceb00k", "facebok", "facebook-login", "faceboook", "facebook-security",
      "fb-verify", "facebook-verify", "facebook-account-locked", "meta-security"],
  },
  {
    brand: "Instagram", domains: ["instagram.com"],
    fakes: ["instagr4m", "instagram-secure", "instagramm", "instagram-verify",
      "insta-login", "instagram-support"],
  },
  {
    brand: "Bank of America", domains: ["bankofamerica.com"],
    fakes: ["bankofamerica-secure", "bankofamerica-verify", "bofa-login",
      "bankamerica-secure", "bank-of-america-login"],
  },
  {
    brand: "Chase", domains: ["chase.com"],
    fakes: ["chase-verify", "chase-login", "chase-secure", "chase-banking",
      "chaseonline-verify", "chase-account-locked"],
  },
  {
    brand: "Wells Fargo", domains: ["wellsfargo.com"],
    fakes: ["wellsfargo-login", "wellsfargo-secure", "wells-fargo-verify", "wellsfargoonline-verify"],
  },
  {
    brand: "DHL", domains: ["dhl.com"],
    fakes: ["dhl-delivery", "dhl-tracking-verify", "dhl-parcel-notify", "dhl-express-verify"],
  },
  {
    brand: "FedEx", domains: ["fedex.com"],
    fakes: ["fedex-tracking", "fedex-delivery-notify", "fedex-shipment-verify"],
  },
  {
    brand: "IRS", domains: ["irs.gov"],
    fakes: ["irs-gov-refund", "irs-tax-refund", "irs-verify", "irs-payment-portal"],
  },
];

// ─────────────────────────────────────────────────────────────
// DATASET 3 — HIGH-CONFIDENCE PHISHING PHRASES
// ─────────────────────────────────────────────────────────────
const HIGH_CONFIDENCE_PHRASES = [
  "enter your password", "enter your otp", "enter your pin",
  "provide your credentials", "enter your bank details",
  "confirm your credit card", "verify your card number",
  "enter your social security", "provide your ssn",
  "confirm your date of birth", "enter your full name and address",
  "your account has been suspended", "your account will be closed",
  "your account has been compromised", "unauthorized access detected",
  "your account has been locked", "we detected suspicious login",
  "your password has expired", "your account has been flagged",
  "immediate action required to restore", "failure to verify will result",
  "you have been selected", "you have won", "claim your reward",
  "claim your prize", "you are our lucky winner", "congratulations you won",
  "wire transfer required", "send gift cards", "pay via western union",
  "your package could not be delivered", "delivery attempt failed",
  "reschedule your delivery", "confirm delivery address",
  "your shipment is on hold", "customs fee required",
];

// ─────────────────────────────────────────────────────────────
// DATASET 4 — MEDIUM-CONFIDENCE PHRASES
// ─────────────────────────────────────────────────────────────
const MEDIUM_CONFIDENCE_PHRASES = [
  "act now", "act immediately", "respond immediately", "urgent action required",
  "limited time offer", "offer expires", "today only", "last chance",
  "don't delay", "time is running out", "expires in 24 hours",
  "within 24 hours", "within 48 hours", "respond within",
  "verify your account", "verify your identity", "confirm your identity",
  "confirm your email", "confirm your account", "validate your account",
  "update your information", "update your details", "login to verify",
  "click to verify", "click the link below",
  "security alert", "security notice", "unusual activity",
  "suspicious activity detected", "login attempt from new device",
  "dear customer", "dear valued customer", "dear account holder",
  "as per our records", "kindly provide", "kindly click",
  "we noticed that", "we have detected",
];

// ─────────────────────────────────────────────────────────────
// DATASET 5 — OTP & CREDENTIAL PATTERNS
// ─────────────────────────────────────────────────────────────
const OTP_CREDENTIAL_PATTERNS = [
  /enter.*otp/i, /provide.*otp/i, /share.*otp/i,
  /otp.*\d{4,8}/,
  /one.?time.?password/i,
  /enter.*pin/i, /provide.*pin/i, /your.*pin.*is/i,
  /enter.*cvv/i, /card.*verification.*value/i,
  /share.*password/i, /send.*password/i, /reply.*with.*password/i,
  /enter.*mother.*maiden/i, /what.*mother.*maiden/i,
  /enter.*passport/i, /provide.*aadhar/i, /enter.*pan.*number/i,
];

// ─────────────────────────────────────────────────────────────
// DATASET 6 — SOCIAL ENGINEERING PATTERNS
// ─────────────────────────────────────────────────────────────
const SOCIAL_ENGINEERING_PATTERNS = [
  /from.*irs/i, /from.*fbi/i, /from.*police/i, /from.*government/i,
  /your.*tax.*refund/i, /income.*tax.*department/i,
  /legal.*action.*will.*be.*taken/i, /you.*will.*be.*arrested/i,
  /warrant.*issued/i, /law.*enforcement/i,
  /account.*will.*be.*deleted/i, /account.*will.*be.*terminated/i,
  /service.*will.*be.*suspended/i, /you.*will.*lose.*access/i,
  /data.*will.*be.*lost/i,
  /i.*fell.*in.*love/i, /stranded.*need.*money/i,
  /send.*money.*western.*union/i, /this.*is.*your.*bank/i,
  /calling.*on.*behalf.*of/i,
];

// ─────────────────────────────────────────────────────────────
// DATASET 7 — SUSPICIOUS URL PATTERNS
// ─────────────────────────────────────────────────────────────
const SUSPICIOUS_URL_PATTERNS = [
  { pattern: /\.php\?.*=.*http/i, score: 20, issue: "Open redirect parameter detected in URL" },
  { pattern: /redirect.*=.*http/i, score: 20, issue: "Redirect parameter in URL — possible open redirect" },
  { pattern: /url=http/i, score: 15, issue: "URL forwarding parameter detected" },
  { pattern: /base64/i, score: 15, issue: "Base64 encoding in URL — obfuscation technique" },
  { pattern: /%[0-9a-f]{2}/i, score: 10, issue: "URL encoding detected — content may be obfuscated" },
  { pattern: /data:text\/html/i, score: 40, issue: "Data URI scheme — classic phishing technique" },
  { pattern: /javascript:/i, score: 50, issue: "JavaScript URI — extremely dangerous" },
  { pattern: /\.exe$|\.bat$|\.sh$/i, score: 40, issue: "Executable file download link detected" },
  { pattern: /\d{4,}\.[a-z]{2,4}$/i, score: 20, issue: "Numerically named domain — common in phishing" },
];

// ─────────────────────────────────────────────────────────────
// DATASET 8 — MALICIOUS ATTACHMENT PATTERNS
// ─────────────────────────────────────────────────────────────
const MALICIOUS_ATTACHMENT_PATTERNS = [
  /attached.*invoice/i, /invoice.*attached/i,
  /see.*attached.*document/i, /open.*the.*attachment/i,
  /download.*the.*file/i,
  /\.zip.*password.*protected/i, /password.*for.*the.*zip/i,
  /enable.*macros/i, /enable.*editing/i,
];

// ─────────────────────────────────────────────────────────────
// DATASET 9 — TLDs & SHORTENERS
// ─────────────────────────────────────────────────────────────
const HIGH_RISK_TLDS = new Set([".tk", ".ml", ".ga", ".cf", ".gq"]);
const MEDIUM_RISK_TLDS = new Set([".xyz", ".top", ".click", ".loan", ".work", ".men", ".download", ".accountant", ".stream", ".cam", ".icu", ".cfd", ".monster", ".vip", ".fun", ".buzz", ".live"]);
const URL_SHORTENERS = new Set(["bit.ly", "tinyurl.com", "t.co", "ow.ly", "goo.gl", "short.io", "rb.gy", "cutt.ly", "is.gd", "tiny.cc", "lnkd.in", "buff.ly", "adf.ly", "bit.do"]);

// ─────────────────────────────────────────────────────────────
// DATASET 10 — EMAIL_KEYWORDS (Important Code from v1/v2)
// ─────────────────────────────────────────────────────────────
const EMAIL_KEYWORDS = [
  "urgent",
  "verify",
  "account suspended",
  "click here",
  "login now"
];

// ─────────────────────────────────────────────────────────────
// HELPERS
// ─────────────────────────────────────────────────────────────
function detectInputType(input) {
  const t = input.trim();
  if (/^https?:\/\//i.test(t) || /^www\./i.test(t) || /^[a-z0-9-]+\.[a-z]{2,}(\/|$)/i.test(t)) return "url";
  if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(t)) return "email";
  return "text";
}

function extractDomain(url) {
  try {
    const withProtocol = url.startsWith("http") ? url : `https://${url}`;
    return new URL(withProtocol).hostname.replace(/^www\./, "").toLowerCase();
  } catch {
    return url.toLowerCase();
  }
}

function levenshtein(a, b) {
  const m = [];
  for (let i = 0; i <= b.length; i++) m[i] = [i];
  for (let j = 0; j <= a.length; j++) m[0][j] = j;
  for (let i = 1; i <= b.length; i++)
    for (let j = 1; j <= a.length; j++)
      m[i][j] = b[i - 1] === a[j - 1] ? m[i - 1][j - 1]
        : Math.min(m[i - 1][j - 1] + 1, m[i][j - 1] + 1, m[i - 1][j] + 1);
  return m[b.length][a.length];
}

// ─────────────────────────────────────────────────────────────
// ENGINE 1 — URL ANALYSIS (16 checks)
// ─────────────────────────────────────────────────────────────
function analyzeURL(url) {
  let score = 0;
  const issues = [];
  const lower = url.toLowerCase();
  const domain = extractDomain(url);

  // 1. HTTPS
  if (!lower.startsWith("https://") && !lower.startsWith("http://localhost")) {
    score += 10; issues.push("No HTTPS — connection is not encrypted");
  }

  // 2. Whitelist
  const isWhitelisted = SAFE_DOMAINS.has(domain) || [...SAFE_DOMAINS].some((s) => domain.endsWith(`.${s}`));
  if (isWhitelisted) return { score: 0, issues: [] };

  // 3. IP address as domain
  if (/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/.test(domain)) {
    score += 35; issues.push("IP address used as domain — legitimate sites never do this");
  }

  // 4. URL length
  if (url.length > 75) { score += 10; issues.push("Unusually long URL — common phishing obfuscation"); }
  if (url.length > 120) { score += 10; }

  // 5. @ symbol
  if (url.includes("@")) { score += 25; issues.push("'@' symbol in URL — browser ignores everything before '@'"); }

  // 6. Hyphens
  const hyphens = (url.match(/-/g) || []).length;
  if (hyphens > 4) { score += 20; issues.push(`${hyphens} hyphens in URL — domain spoofing signal`); }
  else if (hyphens > 2) score += 10;

  // 7. Subdomain depth
  const subCount = domain.split(".").length - 2;
  if (subCount > 3) { score += 25; issues.push("Deep subdomain nesting — used to embed brand names in fake URLs"); }
  else if (subCount > 1) { score += 12; issues.push("Multiple subdomains — common brand impersonation trick"); }

  // 8. Brand impersonation (exact list)
  let brandMatched = false;
  for (const { brand, domains, fakes } of BRAND_IMPERSONATION) {
    if (fakes.some((f) => domain.includes(f))) {
      score += 40; issues.push(`Brand spoofing detected — domain impersonates ${brand}`); brandMatched = true; break;
    }
    for (const rd of domains) {
      const bn = rd.split(".")[0];
      if (domain.includes(bn) && !domains.includes(domain) && !SAFE_DOMAINS.has(domain)) {
        score += 28; issues.push(`Possible ${brand} impersonation — brand name in suspicious domain`); brandMatched = true; break;
      }
    }
    if (brandMatched) break;
  }

  // 9. Levenshtein typosquatting
  if (!brandMatched) {
    const brands = ["paypal", "google", "amazon", "apple", "microsoft", "netflix", "facebook", "instagram", "twitter", "linkedin"];
    const base = domain.split(".")[0];
    for (const brand of brands) {
      const dist = levenshtein(base, brand);
      if (dist > 0 && dist <= 2 && base.length >= brand.length - 1) {
        score += 30; issues.push(`Typosquatting — "${base}" closely resembles "${brand}"`); break;
      }
    }
  }

  // 10. Homoglyphs
  const homoglyphMap = { "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "rn": "m", "vv": "w" };
  let normalized = domain;
  for (const [fake, real] of Object.entries(homoglyphMap)) normalized = normalized.replaceAll(fake, real);
  if (normalized !== domain) { score += 15; issues.push("Homoglyph characters in domain — look-alike characters to deceive"); }

  // 11. TLD risk
  if ([...HIGH_RISK_TLDS].some((t) => domain.endsWith(t))) { score += 25; issues.push("High-risk free TLD (.tk/.ml/.ga) — massively abused for phishing"); }
  else if ([...MEDIUM_RISK_TLDS].some((t) => domain.endsWith(t))) { score += 15; issues.push("Suspicious TLD — associated with high phishing activity"); }

  // 12. URL shortener
  if ([...URL_SHORTENERS].some((s) => domain === s || domain.endsWith(`.${s}`))) {
    score += 20; issues.push("URL shortener — hides the true destination of the link");
  }

  // 13. Path keywords
  const pathKw = ["login", "signin", "verify", "account", "secure", "update", "confirm", "banking", "password", "credential", "authenticate", "wallet", "recover", "unlock"];
  const foundKw = pathKw.filter((k) => lower.includes(k));
  if (foundKw.length >= 3) { score += 25; issues.push(`Credential-harvesting keywords in URL: "${foundKw.slice(0, 3).join('", "')}"`); }
  else if (foundKw.length > 0) { score += foundKw.length * 8; issues.push(`Suspicious URL keyword: "${foundKw.join('", "')}"`); }

  // 14. Advanced patterns
  for (const { pattern, score: s, issue } of SUSPICIOUS_URL_PATTERNS) {
    if (pattern.test(url)) { score += s; issues.push(issue); }
  }

  // 15. Punycode
  if (domain.startsWith("xn--")) { score += 30; issues.push("Punycode/IDN domain — visually identical fake domain technique"); }

  // 16. Double extension
  if (/\.[a-z]{2,4}\.(exe|bat|sh|js|vbs|ps1|jar)$/i.test(url)) {
    score += 45; issues.push("Double file extension — classic malware delivery trick");
  }

  return { score: Math.min(Math.round(score), 100), issues };
}

// ─────────────────────────────────────────────────────────────
// ENGINE 2 — TEXT / EMAIL CONTENT ANALYSIS (15 checks)
// ─────────────────────────────────────────────────────────────
function analyzeText(text) {
  let score = 0;
  const issues = [];
  const lower = text.toLowerCase();

  // 1. High-confidence phrases
  const foundHigh = HIGH_CONFIDENCE_PHRASES.filter((p) => lower.includes(p));
  if (foundHigh.length > 0) {
    score += Math.min(foundHigh.length * 20, 50);
    issues.push(`High-risk phishing phrases: "${foundHigh.slice(0, 2).join('", "')}"`);
  }

  // 2. Medium-confidence phrases
  const foundMedium = MEDIUM_CONFIDENCE_PHRASES.filter((p) => lower.includes(p));
  if (foundMedium.length >= 3) { score += 25; issues.push(`Multiple social engineering phrases: "${foundMedium.slice(0, 3).join('", "')}"`); }
  else if (foundMedium.length > 0) { score += foundMedium.length * 8; issues.push(`Suspicious phrase: "${foundMedium[0]}"`); }

  // 3. OTP / credential harvest
  const otpMatches = OTP_CREDENTIAL_PATTERNS.filter((p) => p.test(text));
  if (otpMatches.length > 0) { score += 40; issues.push("OTP/credential request — legitimate services NEVER ask for this via message"); }

  // 4. Social engineering
  const seMatches = SOCIAL_ENGINEERING_PATTERNS.filter((p) => p.test(text));
  if (seMatches.length >= 2) { score += 35; issues.push("Multiple social engineering tactics — authority impersonation or fear manipulation"); }
  else if (seMatches.length === 1) { score += 20; issues.push("Social engineering tactic — possible authority impersonation"); }

  // 5. Attachment indicators
  const attachMatches = MALICIOUS_ATTACHMENT_PATTERNS.filter((p) => p.test(text));
  if (attachMatches.length > 0) { score += 30; issues.push("Malicious attachment indicator — enable macros / suspicious file"); }

  // 6. Embedded URL analysis
  const urlsInText = text.match(/https?:\/\/[^\s<>"]+/g) || [];
  const uniqueUrls = [...new Set(urlsInText)];
  for (const u of uniqueUrls.slice(0, 5)) {
    const { score: us, issues: ui } = analyzeURL(u);
    if (us > 0) { score += Math.round(us * 0.6); issues.push(...ui.map((i) => `[Embedded URL] ${i}`)); }
  }
  if (uniqueUrls.length > 5) { score += 15; issues.push(`${uniqueUrls.length} URLs in message — link-heavy messages are suspicious`); }

  // 7. Urgency scoring
  const urgencyGroups = [
    { words: ["immediately", "right now", "asap"], s: 15 },
    { words: ["urgent", "emergency", "critical"], s: 12 },
    { words: ["24 hours", "today only", "expires"], s: 10 },
    { words: ["last warning", "final notice"], s: 20 },
    { words: ["act now", "don't delay"], s: 10 },
  ];
  let urgencyScore = 0; const urgencyFound = [];
  for (const { words, s } of urgencyGroups) {
    const m = words.filter((w) => lower.includes(w));
    if (m.length > 0) { urgencyScore += s; urgencyFound.push(...m); }
  }
  if (urgencyScore > 0) { score += Math.min(urgencyScore, 30); issues.push(`Urgency manipulation: "${urgencyFound.slice(0, 3).join('", "')}"`); }

  // 8. Generic greetings
  const genericGreetings = ["dear customer", "dear user", "dear account holder", "dear valued member", "dear client", "hello user", "greetings from", "dear friend"];
  const gFound = genericGreetings.filter((g) => lower.includes(g));
  if (gFound.length > 0) { score += 15; issues.push(`Generic greeting "${gFound[0]}" — real companies use your actual name`); }

  // 9. ALL-CAPS words
  const words = text.split(/\s+/);
  const allCaps = words.filter((w) => w.length > 3 && w === w.toUpperCase() && /[A-Z]/.test(w));
  if (allCaps.length >= 3) { score += 12; issues.push(`${allCaps.length} ALL-CAPS words — panic/pressure tactic`); }

  // 10. Excessive punctuation
  if ((text.match(/!/g) || []).length > 3) { score += 10; issues.push("Excessive exclamation marks — emotional manipulation"); }
  if ((text.match(/\?/g) || []).length > 5) { score += 8; issues.push("Excessive question marks — anxiety-inducing tactic"); }

  // 11. Financial bait
  const financialBait = [
    { p: /\$[\d,]+/, l: "Dollar amount lure" }, { p: /£[\d,]+/, l: "Pound amount lure" },
    { p: /€[\d,]+/, l: "Euro amount lure" }, { p: /₹[\d,]+/, l: "Rupee amount lure" },
    { p: /free money/i, l: "Free money offer" }, { p: /wire transfer/i, l: "Wire transfer" },
    { p: /gift card/i, l: "Gift card request" }, { p: /bitcoin|crypto.*payment/i, l: "Crypto payment" },
    { p: /lottery.*win/i, l: "Lottery scam" }, { p: /inheritance.*fund/i, l: "Advance-fee fraud" },
  ];
  const fFound = financialBait.filter((f) => f.p.test(text));
  if (fFound.length > 0) { score += Math.min(fFound.length * 15, 35); issues.push(`Financial lure: ${fFound.map((f) => f.l).join(", ")}`); }

  // 12. Deliberate misspellings
  const misspellings = [/y0ur/i, /acc0unt/i, /verif1cation/i, /1mportant/i, /p4ssword/i, /c1ick/i, /l0gin/i];
  if (misspellings.some((p) => p.test(text))) { score += 20; issues.push("Deliberate character substitution — filter-evasion technique"); }

  // 13. Subject line analysis
  const subjectMatch = text.match(/subject:\s*(.+)/i);
  if (subjectMatch) {
    const subj = subjectMatch[1].toLowerCase();
    const riskSubjects = ["your account", "action required", "security alert", "verify", "suspended", "locked", "urgent", "winner", "prize", "invoice", "payment", "delivery failed"];
    const hits = riskSubjects.filter((s) => subj.includes(s));
    if (hits.length >= 2) { score += 20; issues.push(`High-risk subject line: "${subjectMatch[1].trim()}"`); }
    else if (hits.length === 1) { score += 10; issues.push(`Suspicious subject: "${subjectMatch[1].trim()}"`); }
  }

  // 14. Reply-To mismatch
  const fromMatch = text.match(/from:\s*(.+)/i);
  const replyMatch = text.match(/reply-to:\s*(.+)/i);
  if (fromMatch && replyMatch) {
    const fromDom = (fromMatch[1].match(/@([^\s>]+)/) || [])[1] || "";
    const replyDom = (replyMatch[1].match(/@([^\s>]+)/) || [])[1] || "";
    if (fromDom && replyDom && fromDom !== replyDom) {
      score += 40; issues.push(`Reply-To mismatch — From: "${fromDom}" but Reply-To: "${replyDom}" (classic spoofing)`);
    }
  }

  // 15. Display name spoofing
  const displayMatch = fromMatch ? fromMatch[1].match(/([^<]+)<([^>]+)>/) : null;
  if (displayMatch) {
    const displayName = displayMatch[1].trim().toLowerCase();
    const actualEmail = displayMatch[2].trim().toLowerCase();
    const majorBrands = ["paypal", "google", "amazon", "apple", "microsoft", "netflix", "bank", "chase", "irs"];
    const brandInDisplay = majorBrands.find((b) => displayName.includes(b));
    if (brandInDisplay && !actualEmail.includes(brandInDisplay)) {
      score += 45; issues.push(`Display name spoofing — claims to be "${displayMatch[1].trim()}" but sent from "${actualEmail}"`);
    }
  }

  return { score: Math.min(Math.round(score), 100), issues };
}

// ─────────────────────────────────────────────────────────────
// ENGINE 3 — EMAIL ADDRESS ANALYSIS
// ─────────────────────────────────────────────────────────────
function analyzeEmailAddress(email) {
  let score = 0;
  const issues = [];
  const [localPart, domainPart] = email.toLowerCase().split("@");

  if (!domainPart) return { score: 50, issues: ["Invalid email format"] };

  const { score: domainScore, issues: domainIssues } = analyzeURL(`https://${domainPart}`);
  score += domainScore * 0.7;
  issues.push(...domainIssues.map((i) => `[Sender domain] ${i}`));

  if (/no.?reply/i.test(localPart) && domainScore > 20) {
    score += 10; issues.push("No-reply address from suspicious domain");
  }
  if (/security|alert|verify|support|admin|helpdesk/i.test(localPart)) {
    score += 15; issues.push(`Suspicious sender name "${localPart}" — impersonates official support`);
  }
  if (/\d{4,}/.test(localPart)) {
    score += 10; issues.push("Many numbers in email local part — often auto-generated phishing addresses");
  }

  return { score: Math.min(Math.round(score), 100), issues };
}

// ─────────────────────────────────────────────────────────────
// STRONG SCORING ENGINE (Important Code from v1/v2)
// ─────────────────────────────────────────────────────────────
function runStrongScoring(input, inputType, issues) {
  let score = 0;
  const lower = input.toLowerCase();

  // Signal Detection
  const hasSuspiciousDomain = issues.some(i =>
    i.toLowerCase().includes("domain") ||
    i.toLowerCase().includes("impersonat") ||
    i.toLowerCase().includes("spoof")
  );

  const hasUrgencyWords = issues.some(i =>
    i.toLowerCase().includes("urgency") ||
    i.toLowerCase().includes("immediately") ||
    i.toLowerCase().includes("act now")
  ) || EMAIL_KEYWORDS.some(k => lower.includes(k.toLowerCase()));

  const hasLinks = /https?:\/\/[^\s]+/.test(input) ||
    issues.some(i => i.toLowerCase().includes("link") || i.toLowerCase().includes("url")) ||
    lower.includes("click here");

  const hasEmailPatterns = inputType === "email" ||
    /from:|subject:|to:|reply-to:/i.test(input) ||
    /@[a-z0-9.-]+\.[a-z]{2,}/i.test(input);

  // Scoring Logic (requested)
  if (hasSuspiciousDomain) score += 40;
  if (hasUrgencyWords) score += 20;
  if (hasLinks) score += 20;
  if (hasEmailPatterns) score += 20;

  return {
    score: Math.min(score, 100),
    indicators: {
      hasSuspiciousDomain,
      hasUrgencyWords,
      hasLinks,
      hasEmailPatterns
    }
  };
}

// ─────────────────────────────────────────────────────────────
// FEATURE EXTRACTOR — builds 18-feature vector for ML model
// ─────────────────────────────────────────────────────────────
function extractFeatureVector(input, inputType, ruleScore, issues) {
  const lower = input.toLowerCase();
  return {
    inputLength: Math.min(input.length / 500, 1),
    urlCount: Math.min((input.match(/https?:\/\//g) || []).length / 10, 1),
    hasHttps: /^https:\/\//i.test(input) ? 1 : 0,
    hasHttp: /^http:\/\//i.test(input) && !/^https:\/\//i.test(input) ? 1 : 0,
    issueCount: Math.min(issues.length / 10, 1),
    urgencyWordCount: Math.min((lower.match(/urgent|immediately|asap|expires|warning|right now/g) || []).length / 5, 1),
    credentialWordCount: Math.min((lower.match(/password|otp|pin|cvv|verify|login|credential|signin/g) || []).length / 8, 1),
    financialWordCount: Math.min((lower.match(/\$|£|€|₹|bitcoin|wire transfer|gift card|lottery/gi) || []).length / 5, 1),
    hasBrandSpoof: issues.some((i) => i.toLowerCase().includes("impersonat") || i.toLowerCase().includes("spoofing")) ? 1 : 0,
    hasOtpRequest: issues.some((i) => i.toLowerCase().includes("otp")) ? 1 : 0,
    hasUrgency: issues.some((i) => i.toLowerCase().includes("urgency")) ? 1 : 0,
    hasSocialEngineering: issues.some((i) => i.toLowerCase().includes("social engineering")) ? 1 : 0,
    hasFinancialLure: issues.some((i) => i.toLowerCase().includes("financial lure")) ? 1 : 0,
    hasAttachment: issues.some((i) => i.toLowerCase().includes("attachment")) ? 1 : 0,
    hasSuspiciousTLD: issues.some((i) => i.toLowerCase().includes("tld")) ? 1 : 0,
    hasIPAddress: issues.some((i) => i.toLowerCase().includes("ip address")) ? 1 : 0,
    isURL: inputType === "url" ? 1 : 0,
    isText: inputType === "text" ? 1 : 0,
  };
}

// ─────────────────────────────────────────────────────────────
// MAIN EXPORT — analyzeInput v3.0
// Rule engines → feature vector → hybrid ML+rule score → verdict
// ─────────────────────────────────────────────────────────────
async function analyzeInput(input) {
  const trimmed = input.trim();
  const inputType = detectInputType(trimmed);

  let ruleScore = 0;
  let issues = [];

  if (inputType === "url") {
    const r = analyzeURL(trimmed); ruleScore = r.score; issues = r.issues;
  } else if (inputType === "email") {
    const r = analyzeEmailAddress(trimmed); ruleScore = r.score; issues = r.issues;
  } else {
    const r = analyzeText(trimmed); ruleScore = r.score; issues = r.issues;
  }

  // Run Strong Scoring System (Categorical Email Detection Logic)
  const strongScoring = runStrongScoring(trimmed, inputType, issues);
  // Blend with existing score (ensures the requested engine contributes)
  ruleScore = Math.max(ruleScore, strongScoring.score);

  // Build feature vector for ML
  const features = extractFeatureVector(trimmed, inputType, ruleScore, issues);

  // Hybrid score: ML neural network + rule engine
  const hybrid = hybridScore(ruleScore, features);
  const finalScore = hybrid.finalScore;

  // Verdict
  const finalScoreResult = Math.min(finalScore, 100) || 0;
  let finalStatus = "safe";

  if (finalScoreResult > 70) finalStatus = "phishing";
  else if (finalScoreResult > 30) finalStatus = "suspicious";

  // Multi-factor confidence
  const corroborating = [
    features.hasBrandSpoof, features.hasOtpRequest, features.hasSocialEngineering,
    features.hasFinancialLure, features.hasIPAddress, features.hasSuspiciousTLD,
  ].reduce((a, b) => a + b, 0);

  let confidence;
  if (finalScoreResult >= 75 && corroborating >= 2) confidence = "high";
  else if (finalScoreResult >= 75 && corroborating < 2) confidence = "medium";
  else if (finalScoreResult >= 40 && corroborating >= 1) confidence = "medium";
  else if (finalScoreResult <= 20 && corroborating === 0) confidence = "high";
  else confidence = "low";

  // Prioritize issues: most critical first
  const unique = [...new Set(issues)];
  const detectedIssues = [
    ...unique.filter((i) => /spoof|otp|impersonat|social engineering|display name/i.test(i)),
    ...unique.filter((i) => !/spoof|otp|impersonat|social engineering|display name/i.test(i)),
  ].slice(0, 10);


  return {
    status: finalStatus,
    riskScore: finalScoreResult,
    issues: detectedIssues || [],
    inputType,
    confidence,
    detectionVersion: "3.0",
    mlEnabled: hybrid.hybridMode,
    mlScore: hybrid.mlScore,
    ruleScore: hybrid.ruleScore,
    features,
    categoricalScore: strongScoring.score,
    indicators: strongScoring.indicators,
  };
}

module.exports = { analyzeInput, detectInputType, runStrongScoring };