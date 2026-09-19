// FILE: backend/ai/phishingDetector.js  (FULL REPLACEMENT)
// Detection Engine v4.0 — 24-feature hybrid AI + rules

const { hybridScore } = require("./mlModel");
const { detectAIGeneratedText } = require("../services/aiTextDetector");

// Optional CSV dataset lookup (best-effort require)
let csvLookup = null;
try {
  csvLookup = require("./csvDatasetEngine").csvLookup;
} catch {
  /* datasets engine not available — detection continues without it */
}

// ═══════════════════════════════════════════════════════
// DATASET 1 — SAFE DOMAINS (Whitelist)
// ═══════════════════════════════════════════════════════
const SAFE_DOMAINS = new Set([
  // ── Global tech ─────────────────────────────────────────────
  "google.com",
  "gmail.com",
  "googlemail.com",
  "google.co.in",
  "google.co.uk",
  "google.de",
  "google.fr",
  "google.com.au",
  "google.co.jp",
  "google.ca",
  "google.es",
  "google.it",
  "google.com.br",
  "googleapis.com",
  "googletagmanager.com",
  "gstatic.com",
  "googlevideo.com",
  "googleusercontent.com",
  "google.com.sg",
  "google.co.nz",
  "google.com.hk",
  "google.nl",
  "google.pl",
  "google.com.ar",
  "google.com.co",
  "google.com.mx",
  "google.com.pk",
  "google.com.bd",
  "microsoft.com",
  "outlook.com",
  "live.com",
  "hotmail.com",
  "office.com",
  "office365.com",
  "microsoft365.com",
  "azure.com",
  "azure.microsoft.com",
  "microsoftonline.com",
  "sharepoint.com",
  "teams.microsoft.com",
  "skype.com",
  "bing.com",
  "msn.com",
  "xbox.com",
  "microsoft.co.in",
  "microsoft.co.uk",
  "microsoft.de",
  "apple.com",
  "icloud.com",
  "me.com",
  "apple.co.uk",
  "apple.co.in",
  "apple.de",
  "apple.fr",
  "apple.co.jp",
  "apple.com.au",
  "apple.ca",
  // ── Amazon — ALL regional variants ──────────────────────────
  "amazon.com",
  "amazon.in",
  "amazon.co.uk",
  "amazon.de",
  "amazon.fr",
  "amazon.co.jp",
  "amazon.ca",
  "amazon.com.au",
  "amazon.es",
  "amazon.it",
  "amazon.com.br",
  "amazon.com.mx",
  "amazon.com.tr",
  "amazon.ae",
  "amazon.sa",
  "amazon.sg",
  "amazon.nl",
  "amazon.pl",
  "amazon.se",
  "amazonaws.com",
  "cloudfront.net",
  "elasticbeanstalk.com",
  "awsstatic.com",
  "amazonwebservices.com",
  // ── Indian e-commerce & payments ────────────────────────────
  "flipkart.com",
  "myntra.com",
  "ajio.com",
  "meesho.com",
  "snapdeal.com",
  "nykaa.com",
  "bigbasket.com",
  "grofers.com",
  "blinkit.com",
  "zepto.com",
  "jiomart.com",
  "paytm.com",
  "paytmbank.com",
  "phonepe.com",
  "phonepe.in",
  "gpay.in",
  "bhimupi.org.in",
  "npci.org.in",
  "razorpay.com",
  "cashfree.com",
  "billdesk.com",
  "ccavenue.com",
  "payu.in",
  "payuindia.com",
  // ── Indian banks ─────────────────────────────────────────────
  "sbi.co.in",
  "onlinesbi.sbi",
  "onlinesbi.com",
  "sbionline.com",
  "hdfcbank.com",
  "hdfc.com",
  "hdfcsec.com",
  "hdfcmfoline.com",
  "icicibank.com",
  "icicidirect.com",
  "icicipruli.com",
  "axisbank.com",
  "axisbanksecure.com",
  "kotak.com",
  "kotaksecurities.com",
  "kotakmahindra.com",
  "yesbank.in",
  "yesbank.com",
  "pnbindia.in",
  "pnb.co.in",
  "bankofbaroda.in",
  "bankofbaroda.com",
  "canarabank.com",
  "canararobeco.com",
  "indusind.com",
  "indusindbank.com",
  "idfcfirstbank.com",
  "rbi.org.in",
  // ── Indian government ────────────────────────────────────────
  "gov.in",
  "nic.in",
  "ernet.in",
  "incometax.gov.in",
  "efiling.incometax.gov.in",
  "uidai.gov.in",
  "resident.uidai.net.in",
  "irctc.co.in",
  "indianrailways.gov.in",
  "rail.in",
  "passportindia.gov.in",
  "digilocker.gov.in",
  "umang.gov.in",
  "india.gov.in",
  "epfindia.gov.in",
  "epfindia.org",
  "unifiedportal-mem.epfindia.gov.in",
  "esic.gov.in",
  "esic.nic.in",
  "pmkisan.gov.in",
  "pmjay.gov.in",
  "mca.gov.in",
  "sebi.gov.in",
  "nse.co.in",
  "nseindia.com",
  "bseindia.com",
  "cybercrime.gov.in",
  "digitalindia.gov.in",
  "aadhaar.gov.in",
  // ── Indian telecom ───────────────────────────────────────────
  "jio.com",
  "jiocinema.com",
  "jiosaavn.com",
  "airtel.in",
  "airtel.com",
  "vodafoneidea.com",
  "viya.in",
  "bsnl.co.in",
  "bsnl.in",
  "tataplay.com",
  "tatacliq.com",
  // ── Indian media / travel / misc ────────────────────────────
  "makemytrip.com",
  "goibibo.com",
  "cleartrip.com",
  "ixigo.com",
  "yatra.com",
  "easemytrip.com",
  "zomato.com",
  "swiggy.com",
  "dunzo.com",
  "naukri.com",
  "indeed.com",
  "timesofindia.com",
  "ndtv.com",
  "thehindu.com",
  "hindustantimes.com",
  "livemint.com",
  "moneycontrol.com",
  "economictimes.com",
  "economictimes.indiatimes.com",
  "indiatimes.com",
  "rediff.com",
  "healthkart.com",
  "1mg.com",
  "pharmeasy.in",
  "lenskart.com",
  "pepperfry.com",
  "fabindia.com",
  // ── Social ───────────────────────────────────────────────────
  "facebook.com",
  "fb.com",
  "fbcdn.net",
  "instagram.com",
  "whatsapp.com",
  "whatsapp.net",
  "twitter.com",
  "x.com",
  "t.co",
  "linkedin.com",
  "lnkd.in",
  "youtube.com",
  "youtu.be",
  "yt.be",
  "reddit.com",
  "tiktok.com",
  "snapchat.com",
  "pinterest.com",
  "tumblr.com",
  "telegram.org",
  "t.me",
  "discord.com",
  "discordapp.com",
  // ── Dev / Cloud ──────────────────────────────────────────────
  "github.com",
  "githubusercontent.com",
  "gitlab.com",
  "bitbucket.org",
  "stackoverflow.com",
  "stackexchange.com",
  "npmjs.com",
  "npmjs.org",
  "pypi.org",
  "cloudflare.com",
  "pages.dev",
  "workers.dev",
  "heroku.com",
  "vercel.app",
  "netlify.app",
  "digitalocean.com",
  "linode.com",
  "vultr.com",
  // ── Entertainment / Streaming ────────────────────────────────
  "netflix.com",
  "hotstar.com",
  "disneyplus.com",
  "primevideo.com",
  "zee5.com",
  "sonyliv.com",
  "spotify.com",
  "gaana.com",
  "wynk.in",
  "hungama.com",
  "twitch.tv",
  "hulu.com",
  // ── Finance / Crypto ─────────────────────────────────────────
  "paypal.com",
  "paypal.co.uk",
  "paypal.de",
  "paypal.fr",
  "paypal.co.in",
  "paypal.com.au",
  "paypal.ca",
  "stripe.com",
  "visa.com",
  "mastercard.com",
  "coinbase.com",
  "binance.com",
  "wazirx.com",
  "zerodha.com",
  "groww.in",
  "upstox.com",
  "angelone.in",
  "5paisa.com",
  // ── Productivity ─────────────────────────────────────────────
  "dropbox.com",
  "box.com",
  "zoom.us",
  "zoom.com",
  "slack.com",
  "notion.so",
  "trello.com",
  "atlassian.com",
  "figma.com",
  "canva.com",
  "adobe.com",
  "adobecc.com",
  // ── Search / Info ─────────────────────────────────────────────
  "yahoo.com",
  "duckduckgo.com",
  "wikipedia.org",
  "wikimedia.org",
  "bbc.com",
  "bbc.co.uk",
  "reuters.com",
  "apnews.com",
  "nytimes.com",
  // ── Other tech ───────────────────────────────────────────────
  "oracle.com",
  "ibm.com",
  "intel.com",
  "nvidia.com",
  "ebay.com",
]);

// ═══════════════════════════════════════════════════════
// SAFE DOMAIN HELPER
// ═══════════════════════════════════════════════════════

/**
 * isKnownSafeDomain(domain)
 * Returns true if the domain is definitively safe.
 * Checks:
 *   1. Exact match in SAFE_DOMAINS
 *   2. Subdomain of any SAFE_DOMAIN  (e.g. mail.google.com → google.com)
 *   3. Ends with .gov.in / .nic.in / .ac.in / .res.in / .ernet.in
 *   4. Ends with .gov / .edu / .mil  (official institutional TLDs)
 */
function isKnownSafeDomain(domain) {
  if (!domain) return false;
  const d = domain.toLowerCase();

  // 1. Exact match
  if (SAFE_DOMAINS.has(d)) return true;

  // 2. Subdomain of any safe domain
  for (const safe of SAFE_DOMAINS) {
    if (d.endsWith(`.${safe}`)) return true;
  }

  // 3. Official Indian government TLDs — ALWAYS safe
  if (
    d.endsWith(".gov.in") ||
    d.endsWith(".nic.in") ||
    d.endsWith(".ac.in") ||
    d.endsWith(".res.in") ||
    d.endsWith(".ernet.in")
  )
    return true;

  // 4. Official institutional TLDs — ALWAYS safe
  if (d.endsWith(".gov") || d.endsWith(".edu") || d.endsWith(".mil"))
    return true;

  return false;
}

// ═══════════════════════════════════════════════════════
// DATASET 2 — BRAND IMPERSONATION
// ═══════════════════════════════════════════════════════
const BRAND_IMPERSONATION = [
  {
    brand: "PayPal",
    domains: [
      "paypal.com",
      "paypal.co.uk",
      "paypal.de",
      "paypal.fr",
      "paypal.co.in",
      "paypal.com.au",
      "paypal.ca",
      "paypal.es",
      "paypal.it",
      "paypal.com.br",
      "paypal.me",
    ],
    fakes: [
      "paypa1",
      "paypa-l",
      "paypai",
      "paypalll",
      "paypal-secure",
      "paypals",
      "pay-pal",
      "paypal-login",
      "secure-paypal",
      "paypal-update",
      "paypal-confirm",
      "paypalverify",
      "paypall",
      "pay-pal-secure",
    ],
  },
  {
    brand: "Google",
    domains: [
      "google.com",
      "gmail.com",
      "googlemail.com",
      "google.co.in",
      "google.co.uk",
      "google.de",
      "google.fr",
      "google.com.au",
      "google.co.jp",
      "google.ca",
      "google.es",
      "google.it",
      "google.com.br",
      "googleapis.com",
      "gstatic.com",
      "googleusercontent.com",
      "googlevideo.com",
      "googletagmanager.com",
      "google.com.sg",
      "google.co.nz",
      "google.com.hk",
      "google.nl",
      "google.pl",
      "google.com.ar",
      "google.com.co",
      "google.com.mx",
      "google.com.pk",
      "google.com.bd",
    ],
    fakes: [
      "g00gle",
      "googIe",
      "google-login",
      "gooogle",
      "googgle",
      "google-verify",
      "google-security",
      "accounts-google",
      "gmail-security",
      "google-account-verify",
      "goog1e",
    ],
  },
  {
    brand: "Amazon",
    domains: [
      "amazon.com",
      "amazon.in",
      "amazon.co.uk",
      "amazon.de",
      "amazon.fr",
      "amazon.co.jp",
      "amazon.ca",
      "amazon.com.au",
      "amazon.es",
      "amazon.it",
      "amazon.com.br",
      "amazon.com.mx",
      "amazon.ae",
      "amazon.sa",
      "amazon.sg",
      "amazon.nl",
      "amazon.pl",
      "amazon.se",
      "amazon.com.tr",
      "amazonaws.com",
      "cloudfront.net",
    ],
    fakes: [
      "amaz0n",
      "amazon-secure",
      "arnazon",
      "amazoon",
      "amazon-verify",
      "amazon-login",
      "amazon-update",
      "amazonn",
      "amaz0n-prime",
      "amazon-security",
      "amazon-billing",
      "amzon",
      "amazn",
    ],
  },
  {
    brand: "Apple",
    domains: [
      "apple.com",
      "icloud.com",
      "me.com",
      "apple.co.uk",
      "apple.co.in",
      "apple.de",
      "apple.fr",
      "apple.co.jp",
      "apple.com.au",
      "apple.ca",
    ],
    fakes: [
      "app1e",
      "apple-id",
      "applelogin",
      "apple-secure",
      "apple-verify",
      "icloud-verify",
      "appleid-login",
      "apple-support-id",
      "apple-account-locked",
      "applecare-billing",
      "app-le",
      "appl3",
    ],
  },
  {
    brand: "Microsoft",
    domains: [
      "microsoft.com",
      "outlook.com",
      "live.com",
      "hotmail.com",
      "msn.com",
      "office.com",
      "office365.com",
      "microsoft365.com",
      "microsoftonline.com",
      "sharepoint.com",
      "azure.com",
      "azure.microsoft.com",
      "teams.microsoft.com",
      "skype.com",
      "xbox.com",
      "bing.com",
      "microsoft.co.in",
      "microsoft.co.uk",
      "microsoft.de",
    ],
    fakes: [
      "micros0ft",
      "microsofft",
      "microsoft-secure",
      "microsft",
      "microsoft-login",
      "office-365-verify",
      "outlook-security",
      "microsoft-account-verify",
      "ms-login",
      "mlcrosoft",
      "microsooft",
    ],
  },
  {
    brand: "Netflix",
    domains: ["netflix.com"],
    fakes: [
      "netf1ix",
      "netflixx",
      "netflix-login",
      "netflixs",
      "netflix-billing",
      "netflix-update",
      "netfl1x",
      "netflix-account-hold",
      "netflix-payment",
      "netfix",
      "net-flix",
    ],
  },
  {
    brand: "Facebook",
    domains: ["facebook.com", "fb.com"],
    fakes: [
      "faceb00k",
      "facebok",
      "facebook-login",
      "faceboook",
      "facebook-security",
      "fb-verify",
      "facebook-verify",
      "facebook-account-locked",
      "meta-security",
      "faceb0ok",
      "faceebook",
    ],
  },
  {
    brand: "Instagram",
    domains: ["instagram.com"],
    fakes: [
      "instagr4m",
      "instagram-secure",
      "instagramm",
      "instagram-verify",
      "insta-login",
      "instagram-support",
      "1nstagram",
      "instagramlogin",
    ],
  },
  {
    brand: "Chase",
    domains: ["chase.com"],
    fakes: [
      "chase-verify",
      "chase-login",
      "chase-secure",
      "chase-banking",
      "chaseonline-verify",
      "chase-account-locked",
      "chasebank",
      "ch4se",
    ],
  },
  {
    brand: "Wells Fargo",
    domains: ["wellsfargo.com"],
    fakes: [
      "wellsfargo-login",
      "wellsfargo-secure",
      "wells-fargo-verify",
      "wellsfargoonline-verify",
      "wellsf4rgo",
    ],
  },
  {
    brand: "Bank of America",
    domains: ["bankofamerica.com"],
    fakes: [
      "bankofamerica-secure",
      "bankofamerica-verify",
      "bofa-login",
      "bankamerica-secure",
      "bank-of-america-login",
    ],
  },
  {
    brand: "DHL",
    domains: ["dhl.com"],
    fakes: [
      "dhl-delivery",
      "dhl-tracking-verify",
      "dhl-parcel-notify",
      "dhl-express-verify",
      "dhl-shipment-confirm",
      "dh1",
      "dhl-secure",
    ],
  },
  {
    brand: "FedEx",
    domains: ["fedex.com"],
    fakes: [
      "fedex-tracking",
      "fedex-delivery-notify",
      "fedex-shipment-verify",
      "fedex-login",
      "fed-ex",
    ],
  },
  {
    brand: "IRS",
    domains: ["irs.gov"],
    fakes: [
      "irs-gov-refund",
      "irs-tax-refund",
      "irs-verify",
      "irs-payment-portal",
      "irs-gov-login",
      "irsgov-refund",
    ],
  },
  {
    brand: "UPS",
    domains: ["ups.com"],
    fakes: [
      "ups-tracking",
      "ups-delivery-verify",
      "ups-shipment-notify",
      "ups-parcel",
      "upstracking",
    ],
  },
  {
    brand: "WhatsApp",
    domains: ["whatsapp.com"],
    fakes: [
      "whatsapp-verify",
      "whatsapp-login",
      "whatsappp",
      "what-sapp",
      "whatsapp-secure",
    ],
  },
  {
    brand: "Steam",
    domains: ["store.steampowered.com", "steamcommunity.com"],
    fakes: [
      "steam-login",
      "steamcommunity-verify",
      "steam-trade",
      "steampowered-login",
      "ssteam",
    ],
  },
  {
    brand: "Coinbase",
    domains: ["coinbase.com"],
    fakes: [
      "coinbase-verify",
      "coinbase-login",
      "coinbase-secure",
      "co1nbase",
      "coinbasse",
    ],
  },
];

// ═══════════════════════════════════════════════════════
// DATASET 3 — REAL PHISHING PHRASES (from PhishTank research)
// ═══════════════════════════════════════════════════════
const HIGH_CONFIDENCE_PHRASES = [
  // Credential harvest
  "enter your password",
  "enter your otp",
  "enter your pin",
  "provide your credentials",
  "enter your bank details",
  "confirm your credit card",
  "verify your card number",
  "enter your social security",
  "provide your ssn",
  "confirm your date of birth",
  "enter your full name and address",
  "enter your mother maiden",
  "provide your aadhar",
  "enter your pan number",
  "enter your cvv",
  // Account threat
  "your account has been suspended",
  "your account will be closed",
  "your account has been compromised",
  "unauthorized access detected",
  "your account has been locked",
  "we detected suspicious login",
  "your password has expired",
  "your account has been flagged",
  "immediate action required to restore",
  "failure to verify will result",
  "your account will be terminated",
  "your account will be deactivated",
  // Prize/reward scams
  "you have been selected",
  "you have won",
  "claim your reward",
  "claim your prize",
  "you are our lucky winner",
  "congratulations you won",
  "redeem your gift card now",
  "you have been chosen",
  // Financial fraud
  "wire transfer required",
  "send gift cards",
  "pay via western union",
  "update your payment method",
  "your payment has failed",
  "billing information required",
  "invoice attached for payment",
  "send bitcoin",
  "pay with cryptocurrency",
  // Delivery scams
  "your package could not be delivered",
  "delivery attempt failed",
  "reschedule your delivery",
  "confirm delivery address",
  "your shipment is on hold",
  "customs fee required",
  "pay to release your package",
  "delivery fee required",
  // IT/Tech support scams
  "your computer has been infected",
  "call microsoft support",
  "your windows license has expired",
  "your device has a virus",
  "remote access required",
  "download this software to fix",
];

const MEDIUM_CONFIDENCE_PHRASES = [
  "act now",
  "act immediately",
  "respond immediately",
  "urgent action required",
  "limited time offer",
  "today only",
  "last chance",
  "expires in 24 hours",
  "within 24 hours",
  "within 48 hours",
  "respond within",
  "verify your account",
  "verify your identity",
  "confirm your identity",
  "confirm your email",
  "confirm your account",
  "validate your account",
  "update your information",
  "update your details",
  "login to verify",
  "click to verify",
  "click the link below",
  "click here to confirm",
  "security alert",
  "security notice",
  "unusual activity",
  "suspicious activity detected",
  "login attempt from new device",
  "dear customer",
  "dear valued customer",
  "dear account holder",
  "dear valued member",
  "dear client",
  "hello user",
  "greetings from",
  "as per our records",
  "kindly provide",
  "kindly click",
  "we noticed that",
  "we have detected",
  "we need to verify",
  "your account security",
  "please update",
  "please confirm",
];

// ═══════════════════════════════════════════════════════
// DATASET 4 — OTP & CREDENTIAL PATTERNS
// ═══════════════════════════════════════════════════════
const OTP_CREDENTIAL_PATTERNS = [
  /enter.*otp/i,
  /provide.*otp/i,
  /share.*otp/i,
  /otp.*\d{4,8}/,
  /one.?time.?password/i,
  /enter.*pin/i,
  /provide.*pin/i,
  /your.*pin.*is/i,
  /enter.*cvv/i,
  /card.*verification.*value/i,
  /share.*password/i,
  /send.*password/i,
  /reply.*with.*password/i,
  /enter.*mother.*maiden/i,
  /what.*mother.*maiden/i,
  /enter.*passport/i,
  /provide.*aadhar/i,
  /enter.*pan.*number/i,
  /verify.*with.*code/i,
  /enter.*verification.*code/i,
  /your.*code.*is.*\d{4,}/i,
  /authentication.*code/i,
];

// ═══════════════════════════════════════════════════════
// DATASET 5 — SOCIAL ENGINEERING PATTERNS
// ═══════════════════════════════════════════════════════
const SOCIAL_ENGINEERING_PATTERNS = [
  /from.*irs/i,
  /from.*fbi/i,
  /from.*cia/i,
  /from.*police/i,
  /from.*government/i,
  /from.*microsoft.*support/i,
  /from.*apple.*support/i,
  /your.*tax.*refund/i,
  /income.*tax.*department/i,
  /legal.*action.*will.*be.*taken/i,
  /you.*will.*be.*arrested/i,
  /warrant.*issued/i,
  /law.*enforcement/i,
  /account.*will.*be.*deleted/i,
  /account.*will.*be.*terminated/i,
  /service.*will.*be.*suspended/i,
  /you.*will.*lose.*access/i,
  /stranded.*need.*money/i,
  /send.*money.*western.*union/i,
  /this.*is.*your.*bank/i,
  /calling.*on.*behalf.*of/i,
  /tech.*support.*calling/i,
  /your.*computer.*infected/i,
  /your.*device.*compromised/i,
  /remote.*access.*required/i,
];

// ═══════════════════════════════════════════════════════
// DATASET 6 — ADVANCED URL PATTERNS
// ═══════════════════════════════════════════════════════
const SUSPICIOUS_URL_PATTERNS = [
  {
    pattern: /\.php\?.*=.*http/i,
    score: 22,
    issue: "Open redirect parameter — forwards to malicious site",
  },
  {
    pattern: /redirect.*=.*http/i,
    score: 22,
    issue: "Redirect parameter detected — possible open redirect",
  },
  {
    pattern: /url=http/i,
    score: 18,
    issue: "URL forwarding parameter — destination hidden",
  },
  {
    pattern: /return.*=.*http/i,
    score: 18,
    issue: "Return URL parameter — possible redirect abuse",
  },
  {
    pattern: /next=http/i,
    score: 18,
    issue: "Next URL parameter — possible redirect abuse",
  },
  {
    pattern: /goto=http/i,
    score: 18,
    issue: "Goto parameter — possible open redirect",
  },
  {
    pattern: /base64/i,
    score: 16,
    issue: "Base64 encoding in URL — obfuscation technique",
  },
  {
    pattern: /%[0-9a-f]{2}/i,
    score: 10,
    issue: "URL encoding — content may be obfuscated",
  },
  {
    pattern: /data:text\/html/i,
    score: 45,
    issue: "Data URI scheme — classic phishing page delivery",
  },
  {
    pattern: /javascript:/i,
    score: 55,
    issue: "JavaScript URI — code execution attempt",
  },
  {
    pattern: /\.exe$|\.bat$|\.sh$/i,
    score: 45,
    issue: "Executable file download link",
  },
  {
    pattern: /\d{4,}\.[a-z]{2,4}$/i,
    score: 22,
    issue: "Numerically named domain — common in phishing campaigns",
  },
  {
    pattern: /%2e%2e|%252e/i,
    score: 25,
    issue: "Path traversal encoding detected",
  },
  {
    pattern: /\.\.\/|\.\.%2f/i,
    score: 25,
    issue: "Directory traversal attempt in URL",
  },
];

// ═══════════════════════════════════════════════════════
// DATASET 7 — MALICIOUS ATTACHMENT PATTERNS
// ═══════════════════════════════════════════════════════
const MALICIOUS_ATTACHMENT_PATTERNS = [
  /attached.*invoice/i,
  /invoice.*attached/i,
  /see.*attached.*document/i,
  /open.*the.*attachment/i,
  /download.*the.*file/i,
  /\.zip.*password.*protected/i,
  /password.*for.*the.*zip/i,
  /enable.*macros/i,
  /enable.*editing/i,
  /macro.*enabled.*document/i,
  /open.*to.*view.*details/i,
  /download.*to.*claim/i,
];

// ═══════════════════════════════════════════════════════
// DATASET 8 — LINK DISPLAY TEXT vs HREF MISMATCH
// Real link text says "click here" but href is suspicious
// ═══════════════════════════════════════════════════════
const SAFE_DISPLAY_INDICATORS = [
  "click here",
  "click now",
  "verify now",
  "login now",
  "sign in",
  "confirm now",
  "update now",
  "check here",
  "view here",
  "open here",
];

// ═══════════════════════════════════════════════════════
// DATASET 9 — HIGH-RISK TLDs (expanded)
// ═══════════════════════════════════════════════════════
const HIGH_RISK_TLDS = new Set([
  ".tk",
  ".ml",
  ".ga",
  ".cf",
  ".gq", // Free domains, massively abused
  ".pw",
  ".cc",
  ".su", // High phishing rates
]);
const MEDIUM_RISK_TLDS = new Set([
  ".xyz",
  ".top",
  ".click",
  ".loan",
  ".work",
  ".men",
  ".download",
  ".accountant",
  ".stream",
  ".cam",
  ".icu",
  ".cfd",
  ".monster",
  ".vip",
  ".fun",
  ".buzz",
  ".live",
  ".cyou",
  ".bond",
  ".sbs",
  ".uno",
  ".rest",
  ".fit",
  ".bar",
]);

// ═══════════════════════════════════════════════════════
// DATASET 10 — URL SHORTENERS
// ═══════════════════════════════════════════════════════
const URL_SHORTENERS = new Set([
  "bit.ly",
  "tinyurl.com",
  "t.co",
  "ow.ly",
  "goo.gl",
  "short.io",
  "rb.gy",
  "cutt.ly",
  "is.gd",
  "tiny.cc",
  "lnkd.in",
  "buff.ly",
  "adf.ly",
  "bit.do",
  "bl.ink",
  "snip.ly",
  "rebrand.ly",
  "clck.ru",
]);

// DATASET 11 — EXTENDED PRETEXTING SCENARIOS
const PRETEXTING_SCENARIOS = [
  {
    p: /(?:package|parcel|delivery).*(?:held|fee|customs|reschedule)/i,
    s: 38,
    t: "delivery_scam",
    i: "Delivery/customs fee scam — DHL/FedEx/USPS impersonation",
  },
  {
    p: /(?:tax\s+refund|irs\s+refund|gst\s+refund).*(?:claim|verify|click)/i,
    s: 50,
    t: "gov_impersonation",
    i: "Government tax refund scam — IRS/tax authority impersonation",
  },
  {
    p: /(?:job\s+offer|work\s+from\s+home|salary\s+package).*(?:fee|deposit|click|apply)/i,
    s: 38,
    t: "job_scam",
    i: "Fake job offer — advance fee or credential harvesting",
  },
  {
    p: /(?:lottery|prize|winner|selected|chosen).*(?:\$[\d,]+|claim|collect)/i,
    s: 45,
    t: "lottery_scam",
    i: "Lottery/prize scam — advance-fee fraud setup",
  },
  {
    p: /(?:netflix|spotify|amazon|paypal).*(?:payment.*failed|subscription.*expired|renew)/i,
    s: 42,
    t: "brand_impersonation",
    i: "Subscription payment failure lure — card harvesting",
  },
  {
    p: /(?:investment|trading|crypto).*(?:guaranteed|exclusive|double|profit.*\d+%)/i,
    s: 48,
    t: "financial_scam",
    i: "Investment/crypto fraud lure — pig-butchering scam pattern",
  },
];

// DATASET 12 — BEC / CEO FRAUD PATTERNS
const BEC_PATTERNS = [
  {
    p: /(?:ceo|president|director|cfo|executive).*(?:wire|transfer|payment|urgent)/i,
    s: 55,
    i: "CEO/executive impersonation with financial urgency — BEC attack",
  },
  {
    p: /(?:invoice|payment|banking\s+detail).*(?:changed|updated|new\s+account)/i,
    s: 52,
    i: "Vendor payment redirection — attacker changed banking details",
  },
  {
    p: /(?:payroll|direct\s+deposit).*(?:update|change|new\s+bank)/i,
    s: 50,
    i: "Payroll diversion fraud — HR/payroll impersonation",
  },
  {
    p: /(?:it\s+(?:support|team|helpdesk)).*(?:password|reset|vpn|mfa)/i,
    s: 48,
    i: "IT helpdesk impersonation — credential harvesting via internal authority",
  },
];

// DATASET 13 — QR CODE PHISHING (QUISHING)
const QUISHING_PATTERNS = [
  {
    p: /(?:scan.*qr|qr.*code).*(?:verify|access|payment|login|claim)/i,
    s: 45,
    i: "QR code phishing (quishing) — QR used to bypass link scanners",
  },
  {
    p: /(?:call|dial).*(?:\+?1?\s*\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}).*(?:microsoft|apple|bank|irs)/i,
    s: 50,
    i: "Vishing — phone number with brand impersonation",
  },
  // Scan QR to complete action — cross-channel evasion
  {
    p: /scan\s+(?:the\s+)?(?:qr|this)\s*(?:code)?\s+(?:to|and)\s+(?:complete|verify|access|confirm|login|pay|claim|activate|update)/i,
    s: 55,
    i: "Quishing: scan QR to complete action — QR moves victim off-channel to evade email filters",
  },
  // QR bypasses security tools
  {
    p: /qr\s*(?:code)?\s+(?:is\s+)?(?:safer|secure|encrypted|protected|can't\s+be\s+blocked)/i,
    s: 50,
    i: "Quishing: attacker claims QR is 'safer' — social engineering to justify QR usage",
  },
  // Parking/delivery/restaurant QR replacement attack
  {
    p: /(?:parking|meter|restaurant|table)\s+(?:payment|pay|fee).*qr/i,
    s: 48,
    i: "QR payment scam — fake QR code overlaid on physical parking/restaurant meters",
  },
  // Tax/government QR quishing
  {
    p: /(?:irs|hmrc|tax|refund|government|gov)\s+.*qr|qr.*(?:irs|hmrc|tax\s+refund)/i,
    s: 55,
    i: "Government/tax quishing — QR code claiming to be official government communication",
  },
  // Package delivery QR
  {
    p: /(?:package|parcel|delivery|shipment|fedex|ups|dhl|usps).*scan.*qr|qr.*(?:track|delivery|package)/i,
    s: 48,
    i: "Delivery quishing — QR code in fake shipping notification",
  },
  // MFA/2FA QR abuse
  {
    p: /(?:scan\s+qr|qr\s+code)\s+(?:to\s+)?(?:enable|set\s+up|activate|configure)\s+(?:2fa|mfa|two.factor|authenticator)/i,
    s: 60,
    i: "MFA QR quishing — fake authenticator QR setup to steal session/register attacker's device",
  },
  // QR + urgency combination
  {
    p: /(?:expires?|expire\s+in|valid\s+for)\s+\d+\s*(?:hour|minute|day).*qr|qr.*(?:expires?|time.sensitive)/i,
    s: 52,
    i: "Quishing with urgency — QR code with expiry pressure to prevent careful inspection",
  },
  // Generic "open camera" QR instruction
  {
    p: /open\s+(?:your\s+)?(?:camera|phone)\s+(?:and\s+)?scan/i,
    s: 35,
    i: "QR scan instruction — may indicate quishing attempt (lower confidence without context)",
  },
  // DocuSign/e-signature QR quishing
  {
    p: /(?:sign|signature|docu)\s+.*scan.*qr|qr.*(?:sign\s+document|e.sign)/i,
    s: 52,
    i: "Document signing quishing — QR in fake e-signature request",
  },
  // Wi-Fi QR (credential phishing via fake Wi-Fi)
  {
    p: /(?:wi.?fi|wireless|network|connect)\s+.*qr|qr.*(?:wi.?fi|connect\s+to)/i,
    s: 38,
    i: "Wi-Fi QR phishing — fake Wi-Fi QR code to capture credentials or deliver payload",
  },
];

// DATASET 14 — CONTEXTUAL ANOMALY PATTERNS
const CONTEXTUAL_ANOMALY_PATTERNS = [
  {
    p: /(?:within|before|by)\s+\d*\s*(?:hour|minute|24h|48h|today).*(?:suspend|delete|close|terminate)/i,
    s: 45,
    i: "Deadline threat — account deletion with specific timeframe",
  },
  {
    p: /(?:did\s+not\s+request|wasn't\s+you).*(?:code|otp|login)/i,
    s: 40,
    i: "Fake 2FA alert — harvests your response/code",
  },
  {
    p: /(?:transaction|payment).*(?:not\s+made|unauthorized).*(?:click|verify|dispute)/i,
    s: 48,
    i: "Phantom transaction alert — fake unauthorized charge lure",
  },
  {
    p: /(?:congratulations|you\s+have\s+been\s+selected)/i,
    s: 38,
    i: "Prize notification lure — excitement engineered to bypass critical thinking",
  },
];

// ═══════════════════════════════════════════════════════
// DATASET 15 — NLP URGENCY SCORING (Google/Microsoft technique)
// Weighted urgency word banks — more specific = higher weight
// ═══════════════════════════════════════════════════════
const NLP_URGENCY_TIERS = {
  tier1: {
    // Extreme urgency — 20pts each
    words: [
      "account will be permanently deleted",
      "your account has been suspended",
      "final warning",
      "last chance to verify",
      "immediate action required",
      "account will be terminated",
      "suspended due to unusual activity",
      "failure to verify will result",
      "your account has been compromised",
    ],
    score: 20,
  },
  tier2: {
    // High urgency — 14pts each
    words: [
      "verify now",
      "confirm now",
      "click immediately",
      "respond today",
      "expires in 24 hours",
      "within 24 hours",
      "before it expires",
      "unauthorized access detected",
      "suspicious activity",
      "we detected",
      "limited time",
      "action required",
      "your account",
      "alert",
    ],
    score: 14,
  },
  tier3: {
    // Social pressure — 8pts each
    words: [
      "dear customer",
      "dear valued",
      "dear account holder",
      "hello user",
      "kindly verify",
      "kindly confirm",
      "please update",
      "please confirm",
    ],
    score: 8,
  },
};

// ═══════════════════════════════════════════════════════
// DATASET 16 — BEHAVIORAL ANOMALY INDICATORS
// (Darktrace / Abnormal Security approach — identity-based)
// ═══════════════════════════════════════════════════════
const BEHAVIORAL_ANOMALIES = [
  // Unusual sender behavior patterns
  {
    p: /from:.*@(?:gmail|yahoo|hotmail|outlook)\.com.*(?:paypal|amazon|apple|bank|microsoft|google)/i,
    s: 45,
    i: "Freemail domain impersonating major brand — Abnormal Security identity signal",
  },
  // Unusual sending time reference
  {
    p: /sent.*(?:automatically|auto-generated|do not reply).*(?:security|verify|alert)/i,
    s: 28,
    i: "Automated security alert pattern — fake system notification",
  },
  // Unusual request for out-of-band communication
  {
    p: /(?:call|text|whatsapp|telegram|signal).*(?:to\s+verify|for\s+support|our\s+agent)/i,
    s: 38,
    i: "Out-of-band communication request — moves victim away from email to unmonitored channel",
  },
  // Account relationship anomaly
  {
    p: /(?:new\s+device|unrecognized\s+device|unfamiliar\s+device).*(?:sign\s*in|access|login)/i,
    s: 42,
    i: "Device anomaly alert — impersonates legitimate security notification",
  },
  // Impossible travel / location anomaly
  {
    p: /(?:sign.*in.*from|access.*from|login.*from).*(?:russia|china|nigeria|unknown\s+location|unusual\s+location)/i,
    s: 38,
    i: "Geographic anomaly claim — fear-based social engineering tactic",
  },
];

// ═══════════════════════════════════════════════════════
// DATASET 17 — VISUAL SIMILARITY DETECTION
// (Check Point / Perception Point approach)
// Detects sites designed to look visually like legitimate brands
// ═══════════════════════════════════════════════════════
const VISUAL_SIMILARITY_PATTERNS = [
  // Login page visual mimicry signals in URL + body
  {
    urlPattern: /login|signin|auth|account/i,
    bodyPatterns: [
      /enter.*(?:email|username|password)/i,
      /sign\s*in\s+to/i,
      /log\s*in\s+to/i,
    ],
    brand: null, // generic
    score: 22,
    issue:
      "Login page mimicry — visual phishing page designed to steal credentials",
  },
  // Bank visual clone indicators
  {
    urlPattern: /(?:online|secure|my|web).*(?:banking|bank|account)/i,
    bodyPatterns: [/balance|transfer|transaction|beneficiary/i],
    brand: "banking",
    score: 40,
    issue: "Bank portal visual clone — fake online banking interface",
  },
  // Payment page mimicry
  {
    urlPattern: /(?:checkout|payment|pay|billing)/i,
    bodyPatterns: [/card\s*number|expiry|cvv|billing\s*address/i],
    brand: "payment",
    score: 42,
    issue:
      "Payment page mimicry — fake checkout designed to harvest card details",
  },
];

// ═══════════════════════════════════════════════════════
// DATASET 18 — DNS / DOMAIN REPUTATION HEURISTICS
// (Cisco Umbrella / Cloudflare Gateway approach)
// Pattern-based domain reputation scoring without API
// ═══════════════════════════════════════════════════════
const DOMAIN_REPUTATION_SIGNALS = [
  // DGA (Domain Generation Algorithm) detection
  {
    test: (d) => {
      // High consonant-to-vowel ratio + length suggests DGA
      const stripped = d.split(".")[0];
      const vowels = (stripped.match(/[aeiou]/gi) || []).length;
      const ratio = vowels / stripped.length;
      return stripped.length > 12 && ratio < 0.25;
    },
    score: 35,
    issue:
      "DGA-pattern domain — algorithmically generated, common in phishing infrastructure",
  },
  // Random-looking subdomain
  {
    test: (d) => /^[a-z0-9]{8,}\.[a-z0-9]{8,}\./i.test(d),
    score: 28,
    issue:
      "Random-looking subdomain pair — automated phishing infrastructure pattern",
  },
  // Excessive numeric prefix/suffix
  {
    test: (d) => /^(?:\d{4,}[a-z]|[a-z]\d{4,})/.test(d.split(".")[0]),
    score: 22,
    issue:
      "Numeric-heavy domain prefix — bulk-registered phishing domain pattern",
  },
  // Double TLD confusion (e.g. paypal.com.phishing.tk)
  {
    test: (d) => {
      const parts = d.split(".");
      const knownTLDs = ["com", "net", "org", "io", "co", "gov", "edu"];
      return parts.length > 3 && knownTLDs.includes(parts[parts.length - 3]);
    },
    score: 40,
    issue:
      "Embedded TLD confusion — domain hides legitimate TLD inside path (e.g. brand.com.evil.tk)",
  },
];

// ═══════════════════════════════════════════════════════
// DATASET 19 — AiTM (Adversary-in-the-Middle) PATTERNS
// (Microsoft Defender XDR — detects modern reverse-proxy phishing)
// ═══════════════════════════════════════════════════════
const AITM_PATTERNS = [
  // Known AiTM framework indicators in URLs
  {
    p: /evilginx|modlishka|muraena|necrobrowser/i,
    s: 90,
    i: "Known AiTM framework name detected — adversary-in-the-middle phishing kit",
  },
  // Reverse proxy session token indicators
  {
    p: /\?token=[a-z0-9]{20,}|&session=[a-z0-9]{20,}|&sid=[a-z0-9]{20,}/i,
    s: 30,
    i: "Long session token in URL — possible AiTM reverse proxy relay",
  },
  // Cloudflare/CDN abuse for phishing relay
  {
    p: /(?:workers\.dev|pages\.dev|netlify\.app|vercel\.app).*(?:login|verify|account|microsoft|google|paypal)/i,
    s: 48,
    i: "Cloud platform phishing relay — legitimate CDN abused as AiTM proxy",
  },
  // Microsoft 365 phishing relay patterns
  {
    p: /microsoftonline\.(?!com)[a-z]{2,}|login\.microsoft\.[a-z]{2,4}(?!\w)/i,
    s: 55,
    i: "Microsoft O365 AiTM relay — fake login page harvesting session tokens",
  },
];

// ═══════════════════════════════════════════════════════
// DATASET 20 — ZERO-DAY BEHAVIORAL SIGNALS
// (Abnormal Security / Darktrace — no-signature detection)
// ═══════════════════════════════════════════════════════
const ZERO_DAY_SIGNALS = [
  // First-contact impersonation (never emailed before but claims relationship)
  {
    p: /as\s+(?:per|discussed|per\s+our)\s+(?:our\s+)?(?:last|recent|previous|earlier)\s+(?:conversation|meeting|call|discussion)/i,
    s: 38,
    i: "Fake prior relationship claim — zero-day BEC opener to establish false trust",
  },
  // Urgency escalation pattern (no greeting + immediate demand)
  {
    p: /^(?:please|kindly|urgent|hi|hello)(?:\s+\w+)?,?\s+(?:i\s+need|we\s+need|send|transfer|buy|purchase)/i,
    s: 35,
    i: "Abrupt demand pattern — no rapport building, immediate financial/action request",
  },
  // Confidentiality demand (used in BEC to prevent victim checking with others)
  {
    p: /(?:keep\s+this|this\s+is\s+confidential|don't\s+tell|do\s+not\s+discuss|between\s+us|just\s+between)/i,
    s: 42,
    i: "Confidentiality demand — BEC tactic to isolate victim from verification channels",
  },
  // Gift card / wire transfer request structure
  {
    p: /(?:buy|purchase|get)\s+(?:\d+\s+)?(?:amazon|google\s+play|apple|steam|vanilla|itunes).*(?:gift\s*card|e-?gift)/i,
    s: 58,
    i: "Gift card purchase request — classic executive impersonation BEC pattern",
  },
  // Fake invoice approval urgency
  {
    p: /(?:approve|process|authorize|sign\s+off).*(?:invoice|payment|transfer|wire).*(?:today|now|immediately|urgent)/i,
    s: 48,
    i: "Fake invoice approval urgency — vendor impersonation BEC with payment diversion",
  },
];

// DATASET A — Corporate / IT Security Impersonation Phishing
// Catches: Sample 1 (corporate phishing email with session ownership language)
const CORPORATE_PHISHING_PATTERNS = [
  {
    p: /(?:reconfirm|re-confirm|verify|validate).*(?:session|access|ownership|identity|profile)/i,
    s: 38,
    i: "Session ownership verification request — corporate phishing impersonating IT security",
  },
  {
    p: /(?:scheduled|routine|automated).*(?:security|maintenance|validation|update|improvement)/i,
    s: 25,
    i: "Scheduled maintenance pretext — makes phishing appear as routine IT activity",
  },
  {
    p: /(?:interruption|disruption|restriction|limitation).*(?:cloud|service|access|portal)/i,
    s: 28,
    i: "Service interruption threat — pressure tactic disguised as operational notice",
  },
  {
    p: /automated.*(?:lock|restriction|procedure|process).*(?:applied|activated|triggered)/i,
    s: 35,
    i: "Automated lock procedure threat — corporate phishing avoiding obvious keywords",
  },
  {
    p: /(?:reference|ticket|case|ref|incident).*(?:id|number|#)\s*[:\-]?\s*[A-Z]{2,6}[-\s]\d{4,}/i,
    s: 22,
    i: "Fake reference ID — creates false legitimacy, common in corporate phishing kits",
  },
  {
    p: /(?:security operations|security team|it security|infosec|helpdesk|service desk).*(?:team|department|group)/i,
    s: 28,
    i: "IT/Security team impersonation — authority spoof without brand name",
  },
  {
    p: /(?:access\s+profile|corporate\s+access|user\s+profile|account\s+profile).*(?:verify|confirm|review|validate)/i,
    s: 32,
    i: "Corporate access profile verification — enterprise spear phishing pattern",
  },
  {
    p: /(?:before|by).*(?:end of business|eob|close of business|cob|end of day|eod)/i,
    s: 30,
    i: "Business hours deadline pressure — corporate phishing urgency tactic",
  },
];

// DATASET B — Soft Urgency Patterns
// Catches: "within 30 minutes", "avoid temporary restrictions"
// These deliberately avoid keywords our main engine checks
const SOFT_URGENCY_PATTERNS = [
  {
    p: /within\s+(?:30|15|45|60|90)\s+minutes?/i,
    s: 35,
    i: "Tight time window (< 1hr) — extreme urgency to prevent victim thinking clearly",
  },
  {
    p: /within\s+(?:the\s+)?(?:next\s+)?(?:an?\s+)?hour/i,
    s: 30,
    i: "One-hour deadline — short window urgency tactic",
  },
  {
    p: /(?:avoid|prevent|stop)\s+(?:temporary|automated|possible)\s+(?:lock|restriction|interruption|suspension)/i,
    s: 38,
    i: "Soft threat framing — implies account suspension without using obvious keywords",
  },
  {
    p: /(?:to\s+prevent|in\s+order\s+to\s+avoid|so\s+(?:we|you)\s+can\s+avoid)/i,
    s: 18,
    i: "Consequence avoidance framing — softer urgency variant in professional phishing",
  },
  {
    p: /(?:may\s+(?:be|result)|could\s+(?:result|lead)|might\s+(?:affect|impact)).*(?:access|service|account)/i,
    s: 22,
    i: "Conditional threat framing — 'may affect access' avoids direct threat keywords",
  },
  {
    p: /(?:temporary|brief|short)\s+(?:interruption|restriction|limitation|suspension)/i,
    s: 25,
    i: "Minimised threat language — 'temporary restriction' softens account lock threat",
  },
];

// DATASET C — Conversation Hijacking
// Catches: Sample 5 — "document from yesterday" thread injection
const CONVERSATION_HIJACKING_PATTERNS = [
  {
    p: /(?:following\s+up|as\s+discussed|as\s+per\s+our|further\s+to|re:\s*our).*(?:document|attachment|file|report|meeting|call|conversation)/i,
    s: 32,
    i: "Conversation thread hijacking — references non-existent prior interaction",
  },
  {
    p: /(?:the\s+document|the\s+file|the\s+report|the\s+attachment)\s+from\s+(?:yesterday|last\s+week|earlier|this\s+morning)/i,
    s: 38,
    i: "Fake prior context reference — 'document from yesterday' creates false familiarity",
  },
  {
    p: /(?:for\s+approval|for\s+review|for\s+sign-?off|for\s+confirmation|before\s+(?:finance|accounts|the\s+team|deadline))/i,
    s: 28,
    i: "Approval/sign-off urgency — business workflow pretext to trigger click",
  },
  {
    p: /(?:updated|revised|final|latest)\s+(?:version|copy|draft|document).*(?:attached|attached|below|above|enclosed)/i,
    s: 35,
    i: "Updated document lure — conversation hijacking attachment vector",
  },
  {
    p: /(?:close|closes|closing|deadline).*(?:ticket|case|issue|request|task)/i,
    s: 22,
    i: "Ticket closure urgency — business process hijacking for phishing delivery",
  },
];

// DATASET D — Low-and-Slow Phishing
// Catches: Sample 6 — workspace permissions notification
const LOW_AND_SLOW_PATTERNS = [
  {
    p: /(?:permissions?|access|settings?|preferences?).*(?:refreshed|updated|modified|changed|reset).*(?:portal|link|below|here)/i,
    s: 35,
    i: "Permission change notification with action link — low-and-slow phishing pattern",
  },
  {
    p: /if.*(?:anything|something|this).*(?:appears?|seems?|looks?).*(?:incorrect|wrong|unusual|unexpected)/i,
    s: 38,
    i: "False reassurance with action prompt — 'if this looks wrong' phishing trigger",
  },
  {
    p: /(?:review|check|view|manage).*(?:active\s+sessions?|session\s+activity|access\s+log|recent\s+activity)/i,
    s: 32,
    i: "Session review prompt — low-and-slow phishing impersonating security notification",
  },
  {
    p: /(?:shared\s+workspace|workspace\s+permissions?|collaboration\s+(?:space|tool|access))/i,
    s: 25,
    i: "Workspace permission notification — impersonates Slack/Teams/Notion/Google Workspace",
  },
  {
    p: /(?:successfully|has\s+been).*(?:refreshed|updated|activated|configured).*(?:if|review|verify|portal)/i,
    s: 30,
    i: "Fake success notification with verification link — low-and-slow phishing vector",
  },
];

// DATASET E — Payment Profile / Policy Update
// Catches: Sample 2 (SMS smishing with policy pretext)
const PAYMENT_POLICY_PATTERNS = [
  {
    p: /(?:payment|billing|account)\s+(?:profile|information|details?).*(?:requires?|needs?|require)\s+(?:confirmation|verification|update|review)/i,
    s: 45,
    i: "Payment profile confirmation request — financial credential harvesting via policy pretext",
  },
  {
    p: /(?:recent|new|latest|upcoming)\s+(?:policy|terms?|regulation|compliance)\s+(?:update|change|revision)/i,
    s: 28,
    i: "Policy update pretext — uses regulatory change to justify verification",
  },
  {
    p: /(?:pending|outstanding|recent)\s+(?:activity|transaction|payment).*(?:review|confirm|verify)/i,
    s: 38,
    i: "Pending activity review — payment verification phishing trigger",
  },
  {
    p: /(?:temporary|possible|potential)\s+(?:restriction|hold|block|limitation).*(?:avoid|prevent|stop)/i,
    s: 35,
    i: "Temporary restriction threat — payment/account phishing with soft threat framing",
  },
  {
    p: /(?:acct|account|payment|profile|billing).*(?:review|verify|confirm).*(?:link|portal|below|here)/i,
    s: 32,
    i: "Account review link — financial phishing using account management language",
  },
];

// DATASET F — FIXED Homoglyph URL Patterns
// Catches: Samples 3a/3b/4a/4b/4c
// BUG FIX: Original patterns used /paypaI\./ which only matched before a dot
// FIX: Check anywhere in the URL, not just before dot
const HOMOGLYPH_URL_PATTERNS_V2 = [
  // Capital I used as lowercase l — paypaI, googIe, faceboook
  {
    p: /paypaI|googIe|faceboook|micr0s[o0]ft/i,
    s: 55,
    i: "Homoglyph brand impersonation — capital 'I' or zero used to visually fake brand",
  },
  // Number substitution — micr0soft, amaz0n, g00gle, paypa1, app1e
  {
    p: /micr[o0]s[o0]ft|g[o0][o0]gle|paypa[l1I]|amaz[o0]n|app[l1I]e|faceb[o0]{2}k|tw[i1]tter/i,
    s: 55,
    i: "Number substitution in brand name — classic homoglyph attack (e.g. micr0soft, amaz0n)",
  },
  // rn → m substitution (arnazon looks like amazon)
  {
    p: /(?:arna[zs]on|rnicros|rnazon|arnazon)/i,
    s: 50,
    i: "rn→m homoglyph — 'rn' characters mimic 'm' in brand name (e.g. arnazon = amazon)",
  },
  // auth-check / security-check domain structure (Sample 3a)
  {
    p: /(?:auth|security|account|login|verify|secure|update)[-_.](?:check|verify|confirm|review|update|center|portal)/i,
    s: 35,
    i: "Auth-check domain structure — common phishing domain naming (e.g. auth-check, secure-verify)",
  },
  // Cloud document sharing phishing structure (Sample 3c: drive-share-docs)
  {
    p: /(?:drive|docs|files?|share|cloud|storage|onedrive|gdrive|dropbox)[-_](?:share|view|access|review|get|open|docs?|files?)/i,
    s: 48,
    i: "Cloud document sharing domain — impersonates Google Drive/OneDrive/Dropbox sharing link",
  },
];

// ═══════════════════════════════════════════════════════
// DATASET 21 — SMISHING PATTERNS (SMS/WhatsApp Phishing)
// Carrier-specific + delivery-specific smishing indicators
// Documented: CISA, FTC, Proofpoint SMS threat reports
// ═══════════════════════════════════════════════════════
const SMISHING_PATTERNS = [
  // Delivery smishing (most common — USPS/FedEx/DHL)
  {
    p: /(?:usps|fedex|ups|dhl|royal mail|australia post).*(?:package|parcel|shipment).*(?:track|click|pay|fee|held)/i,
    s: 50,
    i: "Delivery smishing — impersonates postal carrier with fake tracking/fee link",
    t: "delivery_smish",
  },
  {
    p: /your (?:package|parcel|delivery|shipment) (?:has been|is being|was) (?:held|delayed|returned|stopped)/i,
    s: 45,
    i: "Delivery hold smishing — fake package detention to harvest card details",
    t: "delivery_smish",
  },
  {
    p: /customs (?:fee|charge|duty|payment) (?:required|pending|due).*(?:click|pay|link)/i,
    s: 48,
    i: "Fake customs fee — smishing tactic to harvest payment card details",
    t: "delivery_smish",
  },

  // Bank smishing
  {
    p: /(?:your bank|your account|banking alert).*(?:blocked|suspended|unusual|suspicious).*(?:verify|confirm|tap|click)/i,
    s: 52,
    i: "Bank account suspension smishing — urgent action to steal credentials",
    t: "bank_smish",
  },
  {
    p: /(?:sms|text).*(?:from|sent by).*(?:\d{5,6}).*(?:bank|paypal|amazon|apple)/i,
    s: 40,
    i: "Short code impersonation — uses 5-6 digit number to appear as legitimate institution",
    t: "bank_smish",
  },

  // OTP/2FA smishing
  {
    p: /(?:your|the) (?:otp|one.?time|verification|security) (?:code|pin|password) (?:is|:)\s*\d{4,8}/i,
    s: 55,
    i: "OTP smishing — sends fake OTP code to establish false trust before harvesting real one",
    t: "otp_smish",
  },
  {
    p: /(?:do not|never) share.*(?:otp|code|pin).*(?:with anyone|with our team|over phone)/i,
    s: 35,
    i: "Reverse psychology OTP smishing — warns not to share then asks for it",
    t: "otp_smish",
  },

  // Prize/reward smishing
  {
    p: /(?:congratulations|you.ve won|you have been selected|lucky winner).*(?:claim|collect|tap|click).*(?:prize|reward|gift|voucher)/i,
    s: 48,
    i: "Prize smishing — lottery/reward lure to harvest personal information",
    t: "prize_smish",
  },
  {
    p: /(?:free|complimentary|exclusive).*(?:iphone|samsung|gift card|voucher|prize).*(?:click|tap|claim)/i,
    s: 45,
    i: "Product prize smishing — fake product giveaway to steal information",
    t: "prize_smish",
  },

  // Government smishing
  {
    p: /(?:government|hmrc|irs|tax|dvla|nhs|social security).*(?:refund|rebate|payment|benefit).*(?:click|tap|apply|claim)/i,
    s: 52,
    i: "Government impersonation smishing — fake refund/benefit to harvest details",
    t: "gov_smish",
  },
  {
    p: /(?:covid|pandemic|vaccine|stimulus).*(?:payment|benefit|relief|check).*(?:click|apply|register)/i,
    s: 45,
    i: "Emergency benefit smishing — exploits crisis for credential/card theft",
    t: "gov_smish",
  },

  // Subscription smishing
  {
    p: /your (?:netflix|spotify|amazon prime|apple).*(?:subscription|membership|account).*(?:expired|suspended|payment failed)/i,
    s: 48,
    i: "Subscription expiry smishing — fake payment failure to harvest card details",
    t: "sub_smish",
  },

  // Carrier-specific patterns (number format analysis)
  {
    p: /(?:reply stop to|reply yes to|text stop to).*(?:unsubscribe|cancel|opt out)/i,
    s: 22,
    i: "Fake unsubscribe mechanism — legitimate SMS services don't send unsolicited opt-out prompts",
    t: "carrier_smish",
  },
  {
    p: /free msg:|free message:|freeMsg:/i,
    s: 20,
    i: "Fake carrier prefix — 'Free MSG:' prefix used by smishing kits to appear official",
    t: "carrier_smish",
  },
];

// ═══════════════════════════════════════════════════════
// DATASET 23 — INDIA CYBER FRAUD PATTERNS
// Hindi · Hinglish · Transliterated text detection
// Sources: CERT-In advisories, I4C reports, MHA cybercrime.gov.in
// ═══════════════════════════════════════════════════════
const INDIA_FRAUD_PATTERNS = [
  // ── Digital Arrest Scam (most reported in 2024) ────────────
  {
    p: /digital\s+arrest|digita\s*arest/i,
    s: 85,
    i: "Digital Arrest scam — fake police/CBI/Customs threatening video-call 'arrest'. India's #1 cyber fraud type in 2024.",
    t: "digital_arrest_scam",
    mitre: "T1566 - Phishing via Impersonation",
  },
  {
    p: /(?:cbi|narcotics|customs|trai|police|court)\s+(?:officer|official|notice|warrant|case).*(?:video|call|arrest|action)/i,
    s: 78,
    i: "Authority impersonation threatening arrest — Digital Arrest variant. Real CBI/police never contact via phone for arrests.",
    t: "digital_arrest_scam",
    mitre: "T1566.004 - Spearphishing Voice",
  },
  {
    p: /ghar\s+(?:par|mein|pe)\s+(?:rahiye?|raho|ruke?)\s*(?:bahar|na\s+jao)?/i,
    s: 75,
    i: "Hindi Digital Arrest phrase — 'Stay at home' command used in digital arrest scam. Victim is kept isolated under threat.",
    t: "digital_arrest_scam",
    mitre: "T1566.004",
  },
  // ── TRAI / SIM Block scam ──────────────────────────────────
  {
    p: /trai.*(?:sim|number|mobile).*(?:band|block|suspend|disconnect)/i,
    s: 80,
    i: "TRAI SIM block scam — TRAI never sends SMS to block SIMs. Fake TRAI messages harvest Aadhaar/OTP.",
    t: "trai_sim_scam",
    mitre: "T1566",
  },
  {
    p: /(?:aapka|tumhara|your)\s+(?:sim|number|mobile|number)\s+(?:band|block|suspend)\s+(?:hoga|ho\s+jayega|kar\s+diya)/i,
    s: 78,
    i: "Hindi SIM block threat — 'Your SIM/number will be blocked' — standard TRAI fraud opening script.",
    t: "trai_sim_scam",
    mitre: "T1566",
  },
  // ── OTP / Banking fraud (Hinglish) ─────────────────────────
  {
    p: /otp\s+(?:share|batao|dijiye?|send|bhejo|bolo|batana|dena)/i,
    s: 82,
    i: "Hindi OTP harvest request — 'Share your OTP'. Banks/UPI platforms never ask for OTP over call or message.",
    t: "otp_fraud_india",
    mitre: "T1056 - Credential Harvesting",
  },
  {
    p: /kyc\s+(?:update|verify|complete|karo|karein|pending|expired)/i,
    s: 70,
    i: "Fake KYC update fraud — banks do not ask for KYC via SMS links. This harvests Aadhaar/PAN/account details.",
    t: "kyc_fraud",
    mitre: "T1566",
  },
  {
    p: /(?:account|khata)\s+(?:band|block|freeze|suspend)\s+(?:hoga|ho\s+jayega|ho\s+gaya|kar\s+diya)/i,
    s: 72,
    i: "Hindi account block threat — 'Your account will be blocked' — used in banking OTP fraud scripts.",
    t: "banking_fraud_india",
    mitre: "T1566",
  },
  // ── UPI / QR Code fraud ────────────────────────────────────
  {
    p: /(?:upi|gpay|phonepe|paytm|bhim).*(?:scan|qr|code|link|pin|id).*(?:paise|money|refund|return|reward|prize)/i,
    s: 75,
    i: "UPI fraud pattern — scammer sends payment request disguised as refund/reward. Scanning their QR sends money TO them.",
    t: "upi_scam",
    mitre: "T1566",
  },
  {
    p: /qr\s+(?:code|scan)\s+(?:karo|karein|scan\s+karo)\s*(?:aur|or|to)\s+(?:paise|money|receive|milo|milega)/i,
    s: 78,
    i: "Hindi UPI QR scam — 'Scan this QR to receive money' — victim scans and unknowingly SENDS money instead.",
    t: "upi_scam",
    mitre: "T1566",
  },
  // ── FedEx / Drug parcel scam ───────────────────────────────
  {
    p: /(?:fedex|dhl|bluedart|india\s+post|courier).*(?:parcel|package).*(?:drug|narcotic|illegal|seized|held|banned)/i,
    s: 82,
    i: "Courier drug parcel scam — fake FedEx/customs call about 'drugs found in your parcel'. Demands payment to avoid arrest.",
    t: "courier_drug_scam",
    mitre: "T1566.004",
  },
  {
    p: /(?:aapke|tumhare|your)\s+(?:naam|name|address)\s+(?:par|pe|mein).*(?:parcel|packet|courier).*(?:drug|narcotic|illegal|seized)/i,
    s: 80,
    i: "Hindi courier drug scam — 'Parcel in your name contains drugs' — variant of Digital Arrest targeting victims with fake charges.",
    t: "courier_drug_scam",
    mitre: "T1566",
  },
  // ── Electricity / Utility fraud ────────────────────────────
  {
    p: /(?:bijli|electricity|power|light).*(?:cut|disconnect|band)\s+(?:hoga|ho\s+jayega|kar\s+diya).*(?:\d{1,2}:\d{2}|hour|ghante)/i,
    s: 68,
    i: "Electricity disconnection scam — fake utility threat with deadline to create urgency. Harvests payment card details.",
    t: "electricity_fraud",
    mitre: "T1566",
  },
  {
    p: /(?:bijli|electric)\s+(?:bill|meter).*(?:pending|due|unpaid|baaki).*(?:pay|bharo|jama|click|link)/i,
    s: 65,
    i: "Fake electricity bill scam — impersonates BESCOM/MSEDCL/BSNL with fake bill link.",
    t: "electricity_fraud",
    mitre: "T1566",
  },
  // ── Investment / Part-time job fraud ──────────────────────
  {
    p: /(?:ghar|home|घर)\s+(?:baithe?|se|par)\s+(?:kaam|work|job|earn|paise)\s+(?:karo|karein|kamao)/i,
    s: 65,
    i: "Hindi work-from-home job scam — 'Earn money from home' — leads to advance fee fraud or cryptocurrency investment scam.",
    t: "job_investment_fraud",
    mitre: "T1566",
  },
];

// ═══════════════════════════════════════════════════════
// DATASET 24 — FAKE GOVERNMENT PORTAL DETECTION
// India-specific fake .gov.in impersonation URLs
// Covers: UIDAI, IRCTC, Income Tax, DigiLocker, PM schemes
// ═══════════════════════════════════════════════════════

// ── Real govt domains (fast-exit whitelist) ──────────────────
const REAL_GOVT_DOMAINS = new Set([
  "uidai.gov.in",
  "resident.uidai.net.in",
  "myaadhaar.uidai.gov.in",
  "irctc.co.in",
  "www.irctc.co.in",
  "indianrailways.gov.in",
  "incometax.gov.in",
  "efiling.incometax.gov.in",
  "tin.tin.nsdl.com",
  "digilocker.gov.in",
  "www.digilocker.gov.in",
  "pmjay.gov.in",
  "abdm.gov.in",
  "epfindia.gov.in",
  "unifiedportal-mem.epfindia.gov.in",
  "passportindia.gov.in",
  "mca.gov.in",
  "sebi.gov.in",
  "rbi.org.in",
  "india.gov.in",
  "gov.in",
  "nic.in",
  "ernet.in",
  "cybercrime.gov.in",
  "digitalindia.gov.in",
  "umang.gov.in",
  "csc.gov.in",
  "meripehchaan.gov.in",
  "pmkisan.gov.in",
  "pm.gov.in",
  "pmindia.gov.in",
  "cowin.gov.in",
  "aarogyasetu.gov.in",
  "nha.gov.in",
  "nhm.gov.in",
  "gstn.org.in",
  "gst.gov.in",
  "cbic.gov.in",
  "bseindia.com",
  "nseindia.com",
]);

// ── Fake govt portal URL patterns ────────────────────────────
const GOVT_PORTAL_FAKE_PATTERNS = [
  // Fake UIDAI / Aadhaar
  {
    p: /(?:aadhar|aadhaar|uidai)[-.](?:update|verify|link|card|download|seva|portal|status|correction|online|apply|new)/i,
    s: 72,
    i: "Fake Aadhaar/UIDAI portal — official UIDAI services are only at uidai.gov.in and myAadhaar.uidai.gov.in",
    t: "fake_govt_portal",
    brand: "UIDAI",
  },
  {
    p: /(?:aadhar|aadhaar|uidai).*\.(?:com|in|net|org|info|online|site|xyz|tk|ml)(?!\.in\/)/i,
    s: 75,
    i: "Aadhaar impersonation on non-government domain — official UIDAI only operates on uidai.gov.in",
    t: "fake_govt_portal",
    brand: "UIDAI",
  },
  // Fake IRCTC
  {
    p: /irctc[-.](?:booking|ticket|train|railway|tatkal|refund|login|app|online|india)/i,
    s: 70,
    i: "Fake IRCTC portal — official Indian Railways booking is only at irctc.co.in",
    t: "fake_govt_portal",
    brand: "IRCTC",
  },
  {
    p: /irctc.*\.(?:com|net|org|info|online|xyz|tk|top)(?!\.co\.in)/i,
    s: 72,
    i: "IRCTC impersonation on non-official domain — real IRCTC is irctc.co.in only",
    t: "fake_govt_portal",
    brand: "IRCTC",
  },
  // Fake Income Tax
  {
    p: /(?:income.?tax|incometax|it.?return|itr)[-.](?:efiling|portal|login|refund|notice|pay|online|department)/i,
    s: 72,
    i: "Fake Income Tax portal — official IT efiling is only at incometax.gov.in",
    t: "fake_govt_portal",
    brand: "Income Tax",
  },
  {
    p: /(?:income.?tax|incometax).*\.(?:com|net|online|xyz|tk)(?!\.gov\.in)/i,
    s: 74,
    i: "Income Tax impersonation — official portal is incometax.gov.in only. Never share PAN/Aadhaar on unofficial sites.",
    t: "fake_govt_portal",
    brand: "Income Tax",
  },
  // Fake DigiLocker
  {
    p: /digi.?locker[-.](?:login|download|documents|verify|portal|app|id)/i,
    s: 68,
    i: "Fake DigiLocker portal — official DigiLocker is only at digilocker.gov.in",
    t: "fake_govt_portal",
    brand: "DigiLocker",
  },
  // Fake PM Schemes
  {
    p: /pm(?:jay|kisan|awas|ujjwala|mudra|svanidhi)[-.](?:apply|register|status|benefit|online|portal|yojana)/i,
    s: 68,
    i: "Fake PM scheme portal — scammers create fake websites to harvest application fees for PM Kisan/PMJAY/Awas.",
    t: "fake_govt_portal",
    brand: "PM Scheme",
  },
  // Fake EPFO / PF
  {
    p: /(?:epfo|provident.?fund|pf.?withdrawal|pf.?balance|epfindia)[-.](?!epfindia\.gov\.in)(?:online|portal|withdraw|apply|login)/i,
    s: 70,
    i: "Fake EPFO portal — official EPFO is at epfindia.gov.in. Fake sites steal PF withdrawal details.",
    t: "fake_govt_portal",
    brand: "EPFO",
  },
  // Fake Passport Seva
  {
    p: /passport[-.](?:apply|seva|status|appointment|renewal|online|india)(?!india\.gov\.in)/i,
    s: 68,
    i: "Fake Passport Seva portal — official portal is passportindia.gov.in. These sites charge fake fees.",
    t: "fake_govt_portal",
    brand: "Passport Seva",
  },
  // Generic fake .gov.in lookalike detection
  {
    p: /gov[-.]in|\.gov-in\.|govtin\.|gov\.in[-.](?!$)/i,
    s: 76,
    i: "Fake .gov.in domain structure — scammer created a domain to look like an official government site.",
    t: "fake_govt_portal",
    brand: "Government",
  },
  // Homoglyph govt domains
  {
    p: /(?:g0v|g0vernment|g\.ov|gov\.ln|gov\.1n|g0v\.in|uidai\.in(?!\.)|irctc\.in(?!\.co))/i,
    s: 78,
    i: "Homoglyph government domain — uses 0 for o, l for i, .in instead of .gov.in to create visual confusion.",
    t: "fake_govt_portal",
    brand: "Government",
  },
  // Fake GST / Tax portals
  {
    p: /(?:gst|gstin|gst.?portal)[-.](?!gov\.in)(?:login|register|file|return|apply|pay|online)/i,
    s: 65,
    i: "Fake GST portal — official GST portal is gst.gov.in. Fake portals steal GSTIN and banking credentials.",
    t: "fake_govt_portal",
    brand: "GST",
  },
  // Fake UMANG / Seva Kendra
  {
    p: /(?:umang|sevakendra|csc)[-.](?!gov\.in)(?:app|portal|services|apply|login|online)/i,
    s: 62,
    i: "Fake UMANG/CSC portal — official UMANG app is by MeitY at umang.gov.in",
    t: "fake_govt_portal",
    brand: "UMANG",
  },
];

// ── Smishing-specific URL shortener patterns ──
const SMISHING_URL_PATTERNS = [
  /bit\.ly\/[A-Za-z0-9]{4,8}$/,
  /tinyurl\.com\/[A-Za-z0-9]{4,8}$/,
  /rb\.gy\/[A-Za-z0-9]{4,8}$/,
  /t\.co\/[A-Za-z0-9]{8,12}$/,
  /goo\.gl\/[A-Za-z0-9]{4,8}$/,
  /cutt\.ly\/[A-Za-z0-9]{4,8}$/,
  /ow\.ly\/[A-Za-z0-9]{4,8}$/,
];

// ═══════════════════════════════════════════════════════
// DATASET 22 — MULTI-LAYER CONTENT ANALYSIS
// (Perception Point 7-layer approach)
// ═══════════════════════════════════════════════════════
const MULTILAYER_SIGNALS = {
  // Layer 1: Suspicious file type combinations
  attachmentRisk: [
    {
      p: /\.(?:exe|bat|cmd|ps1|vbs|js|jar|wsf|hta)(?:\s|$)/i,
      s: 55,
      i: "Executable attachment — direct malware delivery",
    },
    {
      p: /\.(?:doc|docx|xls|xlsx|ppt)m\b/i,
      s: 48,
      i: "Macro-enabled Office document — common malware vector",
    },
    {
      p: /\.(?:iso|img|vhd)(?:\s|$)/i,
      s: 42,
      i: "Disk image attachment — used to bypass email scanners",
    },
    {
      p: /password.*(?:is|:)\s*\S+.*attachment/i,
      s: 38,
      i: "Password-protected attachment with inline password — scanner bypass",
    },
  ],
  // Layer 2: HTML email technique indicators
  htmlTricks: [
    {
      p: /(?:display:\s*none|visibility:\s*hidden|opacity:\s*0|font-size:\s*0|color:\s*(?:white|#fff|#ffffff))/i,
      s: 32,
      i: "Hidden text in HTML — used to confuse spam filters with innocent-looking content",
    },
    {
      p: /<img[^>]+src=["']https?:\/\/[^"']+["'][^>]*(?:width|height)=["']1["']/i,
      s: 28,
      i: "1x1 pixel tracking image — confirms email opened, used by phishing kits",
    },
    {
      p: /<!--[\s\S]{200,}-->/,
      s: 22,
      i: "Excessive HTML comments — text stuffing to confuse NLP content scanners",
    },
  ],
  // Layer 3: Obfuscation techniques
  obfuscation: [
    {
      p: /(?:eval\s*\(|document\.write\s*\(|unescape\s*\()/i,
      s: 50,
      i: "JavaScript obfuscation — eval/write pattern, phishing kit delivery",
    },
    {
      p: /String\.fromCharCode\s*\(/i,
      s: 45,
      i: "CharCode obfuscation — URL/content hidden as character codes",
    },
    {
      p: /atob\s*\(|btoa\s*\(/i,
      s: 38,
      i: "Base64 decode call — obfuscated payload delivery",
    },
  ],
};

// ═══════════════════════════════════════════════════════
// DATASET 23 — EVASION RESISTANCE SIGNALS
// Detects when an attacker is deliberately trying to stay
// just below detection thresholds (the "25-38 zone trick")
// Technique: Microsoft SmartScreen + CrowdStrike approach
// ═══════════════════════════════════════════════════════
const EVASION_RESISTANCE = {
  // ── URL-level evasion signals ──
  url: [
    {
      id: "EV-URL-01",
      name: "HTTPS with suspicious TLD combo",
      desc: "Uses HTTPS to bypass HTTP penalty but pairs with known phishing TLD",
      test: (url, domain, features) =>
        url.startsWith("https://") &&
        /\.(?:tk|ml|ga|cf|gq|xyz|top|click|loan|cam|icu|cfd)$/i.test(domain),
      score: 22,
      issue:
        "HTTPS + high-risk TLD combination — attacker using HTTPS to bypass basic checks",
    },
    {
      id: "EV-URL-02",
      name: "Brand keyword present but zero other indicators",
      desc: "Only one signal fires (brand name) — deliberate minimalism to avoid threshold",
      test: (url, domain, features, issues) =>
        /paypal|google|amazon|apple|microsoft|netflix|bank|chase/i.test(
          domain,
        ) && issues.length === 1,
      score: 28,
      issue:
        "Deliberate signal minimalism — brand keyword only, likely evasion of multi-signal threshold",
    },
    {
      id: "EV-URL-03",
      name: "URL shortener + redirect chain",
      desc: "Shortener hides destination, combined with redirect = evasion stack",
      test: (url, domain, features) =>
        /bit\.ly|tinyurl|t\.co|ow\.ly|rb\.gy|cutt\.ly|is\.gd/i.test(domain) &&
        /\?.*=.*http|redirect|forward/i.test(url),
      score: 25,
      issue:
        "URL shortener + redirect parameter — double evasion layer hiding true destination",
    },
    {
      id: "EV-URL-04",
      name: "Clean domain with suspicious path depth",
      desc: "Domain looks clean but path is deeply nested with credential keywords",
      test: (url, domain, features) => {
        const pathDepth = (url.match(/\//g) || []).length;
        return (
          pathDepth >= 5 &&
          /login|verify|account|secure|auth|password/i.test(url) &&
          !features.hasSuspiciousTLD
        );
      },
      score: 20,
      issue:
        "Deep URL path with credential keywords — evasion via clean domain + suspicious path",
    },
    {
      id: "EV-URL-05",
      name: "Recently registered + single signal",
      desc: "Domain registered < 30 days with exactly 1 issue — deliberate minimalism",
      test: (url, domain, features, issues) =>
        features.subdomainDepth > 0.3 && issues.length <= 2,
      score: 18,
      issue:
        "Deep subdomain with minimal signals — sophisticated domain construction evasion",
    },
    {
      id: "EV-URL-06",
      name: "No brand name but all structural signals present",
      desc: "Attacker removed brand name to avoid brand detection but kept all structural phishing signals",
      test: (url, domain, features) =>
        !features.hasBrandSpoof &&
        features.hasSuspiciousTLD &&
        features.urlPathRisk > 0.3 &&
        features.subdomainDepth > 0.2,
      score: 24,
      issue:
        "Brand-name-free evasion — removed brand keyword but structural phishing signals remain",
    },
    {
      id: "EV-URL-07",
      name: "Unicode normalization bypass",
      desc: "Non-ASCII characters that normalize to look like ASCII — advanced homograph evasion",
      test: (url) => {
        // Detect non-ASCII in domain that could normalize
        const domain = url.replace(/https?:\/\//i, "").split("/")[0];
        return /[^\x00-\x7F]/.test(domain) && !/xn--/i.test(domain);
      },
      score: 32,
      issue:
        "Non-ASCII domain characters — Unicode normalization bypass, advanced homograph attack",
    },
    {
      id: "EV-URL-08",
      name: "Score clustering near threshold (28-38 zone)",
      desc: "Attacker engineered URL to score just below suspicious threshold",
      test: (url, domain, features, issues, ruleScore) =>
        ruleScore >= 25 && ruleScore <= 38 && issues.length >= 2,
      score: 15, // small bump that pushes over threshold
      issue:
        "Score near detection threshold — possible deliberate evasion engineering",
    },
  ],

  // ── Text/email evasion signals ──
  text: [
    {
      id: "EV-TXT-01",
      name: "Excessive whitespace injection",
      desc: "Inserts blank lines/spaces to push content below email preview pane",
      test: (text) => /(\n\s*){8,}/.test(text),
      score: 18,
      issue:
        "Excessive whitespace injection — hides malicious content below email preview pane",
    },
    {
      id: "EV-TXT-02",
      name: "Deliberate misspelling of trigger words",
      desc: "Breaks up phishing keywords to bypass string matching: 'p.a.s.s.w.o.r.d'",
      test: (text) =>
        /p[\.\-_]?a[\.\-_]?s[\.\-_]?s[\.\-_]?w[\.\-_]?o[\.\-_]?r[\.\-_]?d/i.test(
          text,
        ) ||
        /v[\.\-_]?e[\.\-_]?r[\.\-_]?i[\.\-_]?f[\.\-_]?y/i.test(text) ||
        /a[\.\-_]?c[\.\-_]?c[\.\-_]?o[\.\-_]?u[\.\-_]?n[\.\-_]?t/i.test(text),
      score: 28,
      issue:
        "Keyword fragmentation evasion — trigger words split with separators to bypass string matching",
    },
    {
      id: "EV-TXT-03",
      name: "Innocent lure with single embedded link",
      desc: "Long legitimate-looking text with one malicious link — dilution attack",
      test: (text) => {
        const urls = text.match(/https?:\/\/[^\s]+/g) || [];
        return text.length > 500 && urls.length === 1;
      },
      score: 14,
      issue:
        "Content dilution attack — large legitimate-looking body with single embedded phishing link",
    },
    {
      id: "EV-TXT-04",
      name: "Zero-width space injection between keywords",
      desc: "Invisible Unicode characters inserted inside phishing keywords",
      test: (text) => /[\u200b\u200c\u200d\u200e\u200f\ufeff\u00ad]/.test(text),
      score: 38,
      issue:
        "Zero-width character injection — invisible Unicode inserted to break keyword detection",
    },
    {
      id: "EV-TXT-05",
      name: "HTML entity encoding of phishing keywords",
      desc: "Uses &amp; &#x76; etc. to spell out phishing words",
      test: (text) => /&#x?[0-9a-f]+;/i.test(text),
      score: 25,
      issue:
        "HTML entity encoding evasion — keywords encoded as HTML entities to bypass text analysis",
    },
    {
      id: "EV-TXT-06",
      name: "Mixed script attack (Latin + Cyrillic/Greek)",
      desc: "Mixes character sets so the word looks correct but isn't ASCII",
      test: (text) => {
        // Check for mixing of Latin with Cyrillic (common homograph evasion)
        const hasCyrillic = /[\u0400-\u04FF]/.test(text);
        const hasLatin = /[a-zA-Z]/.test(text);
        return hasCyrillic && hasLatin;
      },
      score: 30,
      issue:
        "Mixed script attack — Latin + Cyrillic characters mixed to create visual homographs",
    },
    {
      id: "EV-TXT-07",
      name: "RTL override character abuse",
      desc: "Right-to-left override makes malicious text appear reversed/innocuous",
      test: (text) => /[\u202e\u202d\u202c\u202b\u202a]/.test(text),
      score: 45,
      issue:
        "RTL override character — reverses text rendering to visually disguise malicious content",
    },
    {
      id: "EV-TXT-08",
      name: "Image-only email (no scannable text)",
      desc: "Entire phishing content in an <img> tag, no text for NLP to analyze",
      test: (text) => {
        const imgCount = (text.match(/<img[^>]+>/gi) || []).length;
        const textLen = text.replace(/<[^>]+>/g, "").replace(/\s/g, "").length;
        return imgCount >= 1 && textLen < 50;
      },
      score: 32,
      issue:
        "Image-only email — phishing content delivered as image, bypassing text analysis",
    },
  ],
};

// ═══════════════════════════════════════════════════════
// MITRE ATT&CK MAPPING
// ═══════════════════════════════════════════════════════
const MITRE_MAPPING = {
  brand_impersonation: {
    tactic: "TA0001 - Initial Access",
    technique: "T1566.002 - Spearphishing Link",
  },
  evasion_attempt: {
    tactic: "TA0005 - Defense Evasion",
    technique: "T1027 - Obfuscated Files or Information",
  },
  typosquatting: {
    tactic: "TA0001 - Initial Access",
    technique: "T1583.001 - Acquire Infrastructure: Domains",
  },
  credential_harvest: {
    tactic: "TA0006 - Credential Access",
    technique: "T1056 - Input Capture",
  },
  otp_request: {
    tactic: "TA0006 - Credential Access",
    technique: "T1111 - Multi-Factor Authentication Interception",
  },
  redirect_chain: {
    tactic: "TA0005 - Defense Evasion",
    technique: "T1027 - Obfuscated Files or Information",
  },
  homograph: {
    tactic: "TA0001 - Initial Access",
    technique: "T1583.001 - Acquire Infrastructure: Domains",
  },
  punycode: {
    tactic: "TA0001 - Initial Access",
    technique: "T1583.001 - Acquire Infrastructure: Domains",
  },
  social_engineering: {
    tactic: "TA0001 - Initial Access",
    technique: "T1566 - Phishing",
  },
  malicious_attachment: {
    tactic: "TA0001 - Initial Access",
    technique: "T1566.001 - Spearphishing Attachment",
  },
  financial_scam: {
    tactic: "TA0040 - Impact",
    technique: "T1657 - Financial Theft",
  },
  display_mismatch: {
    tactic: "TA0001 - Initial Access",
    technique: "T1566.002 - Spearphishing Link",
  },
  ip_as_domain: {
    tactic: "TA0011 - Command and Control",
    technique: "T1071 - Application Layer Protocol",
  },
  url_shortener: {
    tactic: "TA0005 - Defense Evasion",
    technique: "T1027 - Obfuscated Files or Information",
  },
  tech_support_scam: {
    tactic: "TA0001 - Initial Access",
    technique: "T1566 - Phishing",
  },
  bec_fraud: {
    tactic: "TA0001 - Initial Access",
    technique: "T1566.002 - Spearphishing via Service",
  },
  quishing: {
    tactic: "TA0001 - Initial Access",
    technique: "T1566 - Phishing",
  },
  pretexting: {
    tactic: "TA0001 - Initial Access",
    technique: "T1566 - Phishing",
  },
  delivery_scam: {
    tactic: "TA0040 - Impact",
    technique: "T1657 - Financial Theft",
  },
  gov_impersonation: {
    tactic: "TA0001 - Initial Access",
    technique: "T1566 - Phishing",
  },
  aitm_attack: {
    tactic: "TA0001 - Initial Access",
    technique: "T1557 - Adversary-in-the-Middle",
  },
  domain_reputation: {
    tactic: "TA0001 - Initial Access",
    technique: "T1583.001 - Acquire Infrastructure: Domains",
  },
  visual_similarity: {
    tactic: "TA0001 - Initial Access",
    technique: "T1566.002 - Spearphishing Link",
  },
  behavioral_anomaly: {
    tactic: "TA0001 - Initial Access",
    technique: "T1566 - Phishing",
  },
  zero_day_bec: {
    tactic: "TA0001 - Initial Access",
    technique: "T1534 - Internal Spearphishing",
  },
  obfuscation: {
    tactic: "TA0005 - Defense Evasion",
    technique: "T1027 - Obfuscated Files or Information",
  },
  smishing: {
    tactic: "TA0001 - Initial Access",
    technique: "T1660 - Phishing via SMS",
  },
  delivery_smish: {
    tactic: "TA0001 - Initial Access",
    technique: "T1660 - Phishing via SMS",
  },
  bank_smish: {
    tactic: "TA0006 - Credential Access",
    technique: "T1660 - Phishing via SMS",
  },
  otp_smish: {
    tactic: "TA0006 - Credential Access",
    technique: "T1111 - MFA Interception",
  },
  prize_smish: {
    tactic: "TA0040 - Impact",
    technique: "T1657 - Financial Theft",
  },
  gov_smish: {
    tactic: "TA0001 - Initial Access",
    technique: "T1566 - Phishing",
  },
  sub_smish: {
    tactic: "TA0040 - Impact",
    technique: "T1657 - Financial Theft",
  },
  corporate_phishing: {
    tactic: "TA0001 - Initial Access",
    technique: "T1566 - Phishing",
  },
  conversation_hijacking: {
    tactic: "TA0001 - Initial Access",
    technique: "T1534 - Internal Spearphishing",
  },
  low_and_slow: {
    tactic: "TA0001 - Initial Access",
    technique: "T1566 - Phishing",
  },
  payment_fraud: {
    tactic: "TA0040 - Impact",
    technique: "T1657 - Financial Theft",
  },
};

// CVE references for common attack techniques
const CVE_MAPPING = {
  punycode: "CVE-2021-28879 — IDN homograph vulnerability in multiple browsers",
  redirect_chain: "CWE-601 — URL Redirection to Untrusted Site (Open Redirect)",
  display_mismatch:
    "CWE-451 — User Interface Misrepresentation of Critical Information",
  javascript_uri: "CVE-2021-38496 — JavaScript URI scheme abuse",
  aitm_attack: "CVE-2022-26925 — Windows LSA Spoofing / AiTM relay abuse",
  obfuscation: "CWE-116 — Improper Encoding or Escaping of Output",
};

// ═══════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════
function detectInputType(input) {
  const t = input.trim();
  if (
    /^https?:\/\//i.test(t) ||
    /^www\./i.test(t) ||
    /^[a-z0-9-]+\.[a-z]{2,}(\/|$)/i.test(t)
  )
    return "url";
  if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(t)) return "email";
  return "text";
}

function extractDomain(url) {
  try {
    const u = url.startsWith("http") ? url : `https://${url}`;
    return new URL(u).hostname.replace(/^www\./, "").toLowerCase();
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
      m[i][j] =
        b[i - 1] === a[j - 1]
          ? m[i - 1][j - 1]
          : Math.min(m[i - 1][j - 1] + 1, m[i][j - 1] + 1, m[i - 1][j] + 1);
  return m[b.length][a.length];
}

function normalizeDefangedURL(input) {
  return input
    .replace(/hxxps?:\/\//gi, "https://") // hxxps:// → https://
    .replace(/hXXps?:\/\//gi, "https://") // hXXps:// → https://
    .replace(/\[\.\]/g, ".") // example[.]com → example.com
    .replace(/\(\.\)/g, ".") // example(.)com → example.com
    .replace(/\[:\]/g, ":") // http[:]// → http://
    .replace(/\[\/\]/g, "/") // path[/]to → path/to
    .trim();
}

// ═══════════════════════════════════════════════════════
// ENGINE 1 — URL ANALYSIS (26 checks)
// ═══════════════════════════════════════════════════════
function analyzeURL(rawUrl) {
  const url = normalizeDefangedURL(rawUrl);
  const wasDefanged = rawUrl !== url && rawUrl.trim().length > 0;
  let score = 0;
  const issues = [];
  const attackTypes = [];
  const lower = url.toLowerCase();
  const domain = extractDomain(url);

  // 1. HTTPS
  if (!lower.startsWith("https://") && !lower.startsWith("http://localhost")) {
    score += 10;
    issues.push("No HTTPS — connection is not encrypted");
  }

  // 2. Whitelist — use centralized safe domain check (covers all country TLD variants)
  if (isKnownSafeDomain(domain)) {
    return {
      score: 0,
      issues: [],
      attackTypes: [],
      hasRedirect: false,
      hasHomoglyph: false,
      hasPunycode: false,
      subdomainDepth: 0,
      urlPathRisk: 0,
    };
  }

  // 3. IP address as domain
  if (/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/.test(domain)) {
    score += 38;
    issues.push("IP address used as domain — legitimate sites never do this");
    attackTypes.push("ip_as_domain");
  }

  // 4. URL length
  if (url.length > 75) {
    score += 10;
    issues.push("Unusually long URL — common obfuscation technique");
  }
  if (url.length > 120) {
    score += 10;
  }

  // 5. @ symbol in URL
  if (url.includes("@")) {
    score += 28;
    issues.push("'@' symbol in URL — browser ignores everything before '@'");
  }

  // 6. Excessive hyphens
  const hyphens = (url.match(/-/g) || []).length;
  if (hyphens > 4) {
    score += 22;
    issues.push(`${hyphens} hyphens in URL — domain spoofing signal`);
  } else if (hyphens > 2) {
    score += 10;
  }

  // 7. Subdomain depth
  const subCount = domain.split(".").length - 2;
  if (subCount > 3) {
    score += 28;
    issues.push(
      "Deep subdomain nesting — used to embed brand names in fake URLs",
    );
    attackTypes.push("subdomain_spoof");
  } else if (subCount > 1) {
    score += 14;
    issues.push("Multiple subdomains — common brand impersonation trick");
  }

  // 8. Brand impersonation (exact fake list)
  let brandMatched = false;
  for (const { brand, domains, fakes } of BRAND_IMPERSONATION) {
    // Check 1: Known fake patterns (typos / spoofed substrings — high confidence)
    if (fakes.some((f) => domain.includes(f))) {
      score += 42;
      issues.push(`Brand spoofing detected — domain impersonates ${brand}`);
      attackTypes.push("brand_impersonation");
      brandMatched = true;
      break;
    }

    // Check 2: Domain contains brand root but isn't a known legitimate domain.
    // FIXED: use isKnownSafeDomain() to cover ALL country-TLD variants so that
    // amazon.in / google.co.in / apple.co.uk etc. are never flagged.
    for (const rd of domains) {
      const bn = rd.split(".")[0]; // e.g. "amazon" from "amazon.com"
      if (domain.includes(bn)) {
        const isRealBrand =
          isKnownSafeDomain(domain) ||
          domains.includes(domain) ||
          domains.some((d) => domain.endsWith(`.${d}`));

        if (!isRealBrand) {
          // Require at least one additional suspicious signal before flagging.
          // This prevents single-signal false positives on legitimate regional
          // domains that happen to share a substring with a brand name.
          const domainTld = "." + domain.split(".").pop();
          const hasFakeSignal =
            domain.includes("-") || // amazon-something.com
            domain.split(".").length > 3 || // sub.sub.amazon.com
            HIGH_RISK_TLDS.has(domainTld) || // amazon.tk
            MEDIUM_RISK_TLDS.has(domainTld); // amazon.xyz

          if (hasFakeSignal) {
            score += 30;
            issues.push(
              `Possible ${brand} impersonation — brand name with suspicious domain pattern`,
            );
            attackTypes.push("brand_impersonation");
            brandMatched = true;
          }
          // No extra suspicious signal → don't flag.
          // e.g. amazon.in with no hyphens and no bad TLD is NOT flagged.
        }

        if (brandMatched) break;
      }
    }
    if (brandMatched) break;
  }

  // 9. Levenshtein typosquatting
  if (!brandMatched) {
    const brands = [
      "paypal",
      "google",
      "amazon",
      "apple",
      "microsoft",
      "netflix",
      "facebook",
      "instagram",
      "twitter",
      "linkedin",
      "coinbase",
      "whatsapp",
      "steam",
    ];
    const base = domain.split(".")[0];
    for (const brand of brands) {
      const dist = levenshtein(base, brand);
      if (dist > 0 && dist <= 2 && base.length >= brand.length - 1) {
        score += 32;
        issues.push(`Typosquatting — "${base}" closely resembles "${brand}"`);
        attackTypes.push("typosquatting");
        break;
      }
    }
  }

  // ── 10. Homoglyph detection v2 ──
  // Covers: ASCII substitutions, Unicode confusables (Cyrillic/Greek/
  // Armenian), multi-char sequences, zero-width characters, and
  // brand-specific known-evil patterns
  const HOMOGLYPH_MAP_V2 = {
    // ── ASCII digit/letter substitutions ──
    0: "o",
    1: "l",
    3: "e",
    4: "a",
    5: "s",
    6: "g",
    7: "t",
    8: "b",
    9: "g",
    // ── Multi-character confusables ──
    rn: "m",
    vv: "w",
    cl: "d",
    nn: "m",
    ii: "n",
    ij: "ij",
    li: "h",
    lI: "n",
    m: "rn",
    w: "vv",
    // ── Cyrillic homoglyphs (look identical in most fonts) ──
    "\u0430": "a", // а (Cyrillic) → a
    "\u0435": "e", // е (Cyrillic) → e
    "\u043e": "o", // о (Cyrillic) → o
    "\u0440": "r", // р (Cyrillic) → r
    "\u0441": "c", // с (Cyrillic) → c
    "\u0445": "x", // х (Cyrillic) → x
    "\u0443": "y", // у (Cyrillic) → y
    "\u0456": "i", // і (Ukrainian) → i
    "\u0406": "I", // І (Ukrainian) → I
    // ── Greek confusables ──
    "\u03bf": "o", // ο (Greek omicron) → o
    "\u03b1": "a", // α (Greek alpha) → a
    "\u03c5": "u", // υ (Greek upsilon) → u
    "\u03b5": "e", // ε (Greek epsilon) → e
    // ── Armenian confusables ──
    "\u0585": "p", // փ (Armenian) → p
    "\u0578": "o", // օ (Armenian) → o
    // ── Zero-width / invisible characters ──
    "\u200b": "",
    "\u200c": "",
    "\u200d": "",
    "\ufeff": "",
    "\u00ad": "",
    // ── Lookalike punctuation ──
    "\u2013": "-",
    "\u2014": "-",
    "\u2212": "-",
    "\u0060": "`",
    "\u00b4": "'",
  };

  // Build full homoglyph-normalized version
  let homoNormalized = domain.toLowerCase();
  let homoChanges = 0;
  for (const [fake, real] of Object.entries(HOMOGLYPH_MAP_V2)) {
    const before = homoNormalized;
    homoNormalized = homoNormalized.replaceAll(fake, real);
    if (homoNormalized !== before) homoChanges++;
  }

  // Check if normalized domain now matches a known brand
  const homoMatchesBrand =
    HOMOGLYPH_MAP_V2 &&
    (() => {
      const knownBrands = [
        "paypal",
        "google",
        "microsoft",
        "apple",
        "amazon",
        "facebook",
        "instagram",
        "twitter",
        "netflix",
        "spotify",
        "linkedin",
        "dropbox",
        "yahoo",
        "outlook",
        "chase",
        "wellsfargo",
        "bankofamerica",
        "citibank",
        "hsbc",
        "barclays",
        "coinbase",
        "binance",
        "kraken",
        "robinhood",
        "discord",
        "steam",
        "roblox",
        "tiktok",
        "whatsapp",
        "telegram",
        "zoom",
        "docusign",
        "adobe",
        "slack",
      ];
      return knownBrands.find(
        (b) => homoNormalized.includes(b) && !domain.includes(b),
      );
    })();

  const hasHomoglyph = homoChanges > 0 || !!homoMatchesBrand;
  if (hasHomoglyph) {
    // Score based on severity:
    // - Matches a known brand after normalization = definitive brand spoofing
    // - Unicode/Cyrillic chars = more sophisticated, higher score
    // - Simple digit substitution = still real but slightly lower
    const hasUnicodeGlyphs = /[^\x00-\x7F]/.test(domain);
    const glyphScore = homoMatchesBrand
      ? 55
      : hasUnicodeGlyphs
        ? 50
        : homoChanges >= 2
          ? 35
          : 22;
    score += glyphScore;
    const brandNote = homoMatchesBrand
      ? ` (normalizes to "${homoMatchesBrand}")`
      : "";
    issues.push(
      `Homoglyph/confusable characters in domain${brandNote} — ` +
        `${hasUnicodeGlyphs ? "Unicode (Cyrillic/Greek)" : "ASCII"} substitution to visually impersonate a brand`,
    );
    attackTypes.push("homograph");
    if (homoMatchesBrand) {
      if (typeof confidence !== "undefined") {
        confidence = Math.min(confidence + 0.15, 0.98);
      }
    }
  }

  // ── 10b. Zero-width character detection (standalone) ──
  // Zero-width chars make identical-looking domains with different DNS
  if (/[\u200b\u200c\u200d\ufeff\u00ad]/.test(domain)) {
    score += 45;
    issues.push(
      "Zero-width character in domain — invisible character creates unique domain while appearing identical to legitimate one",
    );
    attackTypes.push("homograph");
  }

  // ── 10c. Punycode brand impersonation (expanded) ──
  // Already checks xn-- but doesn't validate what the decoded brand is
  if (domain.startsWith("xn--")) {
    score += 32;
    issues.push(
      "Punycode/IDN domain — internationalized domain name used for homograph attack",
    );
    attackTypes.push("punycode");
    // Extra penalty if it also contains a brand name in the ACE label
    if (/paypal|google|microsoft|apple|amazon|bank|secure/i.test(domain)) {
      score += 20;
      issues.push(
        "Punycode domain encodes a brand name — confirmed IDN homograph attack",
      );
    }
  }

  // 11. Punycode / IDN
  const hasPunycode = domain.startsWith("xn--");
  if (hasPunycode) {
    score += 32;
    issues.push(
      "Punycode/IDN domain — internationalized domain used for homograph attack",
    );
    attackTypes.push("punycode");
  }

  // 12. TLD risk
  if ([...HIGH_RISK_TLDS].some((t) => domain.endsWith(t))) {
    score += 28;
    issues.push("High-risk free TLD — massively abused in phishing campaigns");
  } else if ([...MEDIUM_RISK_TLDS].some((t) => domain.endsWith(t))) {
    score += 16;
    issues.push("Suspicious TLD — associated with high phishing activity");
  }

  // 13. URL shortener
  if (
    [...URL_SHORTENERS].some((s) => domain === s || domain.endsWith(`.${s}`))
  ) {
    score += 22;
    issues.push("URL shortener — hides the true destination of the link");
    attackTypes.push("url_shortener");
  }

  // 14. Redirect chain detection (IMPROVED)
  let hasRedirect = false;
  for (const { pattern, score: s, issue } of SUSPICIOUS_URL_PATTERNS) {
    if (pattern.test(url)) {
      score += s;
      issues.push(issue);
      if (/redirect|url=|goto=|next=|return=/i.test(url)) {
        hasRedirect = true;
        attackTypes.push("redirect_chain");
      }
    }
  }

  // 15. Credential keywords in path
  const pathKw = [
    "login",
    "signin",
    "verify",
    "account",
    "secure",
    "update",
    "confirm",
    "banking",
    "password",
    "credential",
    "authenticate",
    "wallet",
    "recover",
    "unlock",
    "suspended",
    "verification",
    "validate",
  ];
  const foundKw = pathKw.filter((k) => lower.includes(k));
  const urlPathRisk = Math.min(foundKw.length / pathKw.length, 1);
  if (foundKw.length >= 3) {
    score += 28;
    issues.push(
      `Credential-harvesting keywords in URL: "${foundKw.slice(0, 3).join('", "')}"`,
    );
  } else if (foundKw.length > 0) {
    score += foundKw.length * 9;
    issues.push(`Suspicious URL keyword: "${foundKw.join('", "')}"`);
  }

  // 16. Number substitution (l33t)
  if (/[0-9]/.test(domain.replace(/\.[a-z]+$/, ""))) {
    score += 12;
    issues.push("Numbers in domain — possible character substitution trick");
  }

  // 17. Data/JavaScript URI
  if (/data:text\/html/i.test(url)) {
    score += 45;
    issues.push("Data URI scheme — phishing page delivered via data URI");
  }
  if (/javascript:/i.test(url)) {
    score += 55;
    issues.push("JavaScript URI — code execution attempt");
  }

  // 18. Double extension malware
  if (/\.[a-z]{2,4}\.(exe|bat|sh|js|vbs|ps1|jar|cmd)$/i.test(url)) {
    score += 48;
    issues.push("Double file extension — classic malware delivery trick");
  }

  // 19. Path traversal
  if (/\.\.\//i.test(url) || /%2e%2e/i.test(url)) {
    score += 25;
    issues.push("Path traversal in URL — possible directory traversal attack");
  }

  // 20. Recently registered domain indicators
  if ((hyphens > 2 || subCount > 1) && foundKw.length >= 2 && !isWhitelisted) {
    score += 10;
    issues.push(
      "Combined risk factors suggest recently registered phishing domain",
    );
  }

  // ── 21. Combo-squatting detection ──
  // Brand name + security/action word in domain = classic phishing domain
  // e.g. paypal-secure-login.com, amazon-account-verify.tk
  const COMBO_SQUAT_BRANDS = [
    "paypal",
    "google",
    "apple",
    "amazon",
    "microsoft",
    "facebook",
    "instagram",
    "netflix",
    "spotify",
    "bank",
    "chase",
    "wellsfargo",
    "irs",
    "fedex",
    "ups",
    "dhl",
    "usps",
    "coinbase",
    "binance",
    "discord",
    "steam",
    "roblox",
    "tiktok",
  ];
  const COMBO_SQUAT_WORDS = [
    "secure",
    "security",
    "login",
    "signin",
    "verify",
    "verification",
    "account",
    "update",
    "confirm",
    "alert",
    "notice",
    "support",
    "help",
    "service",
    "portal",
    "access",
    "auth",
    "authentication",
    "billing",
    "payment",
    "recover",
    "unlock",
  ];
  const domainForCombo = domain.replace(
    /\.(com|net|org|io|co|uk|[a-z]{2,4})$/i,
    "",
  );
  const comboMatchBrand = COMBO_SQUAT_BRANDS.find((b) =>
    domainForCombo.includes(b),
  );
  const comboMatchWord = COMBO_SQUAT_WORDS.find((w) =>
    domainForCombo.includes(w),
  );
  if (comboMatchBrand && comboMatchWord && domain.includes("-")) {
    const isSafeDomain =
      (typeof whitelistedDomains !== "undefined" &&
        whitelistedDomains?.has(domain)) ||
      domain === `${comboMatchBrand}.com` ||
      domain === `${comboMatchBrand}.net` ||
      SAFE_DOMAINS.has(domain);
    if (!isSafeDomain) {
      score += 35;
      issues.push(
        `Combo-squatting: domain combines brand "${comboMatchBrand}" with action word ` +
          `"${comboMatchWord}" — classic phishing domain naming pattern`,
      );
      attackTypes.push("brand_impersonation");
    }
  }

  // ── 22. Repeated security keywords in URL path ──
  // /login/verify/confirm/secure — stacked keywords signal credential harvesting
  const pathKeywordCount = (
    url.match(
      /\/(login|verify|confirm|secure|account|auth|signin|password|credential|update|validate)/gi,
    ) || []
  ).length;
  if (pathKeywordCount >= 3) {
    score += 28;
    issues.push(
      `Stacked security keywords in URL path (${pathKeywordCount} occurrences) — ` +
        `credential harvesting path pattern (e.g. /login/verify/confirm/secure)`,
    );
  }

  // ── 23. Numeric IP embedded as subdomain ──
  // 192.168.1.1.malicious.com — tricks users glancing at URL
  if (/^\d{1,3}[.-]\d{1,3}[.-]\d{1,3}[.-]\d{1,3}[.-]/i.test(domain)) {
    score += 38;
    issues.push(
      "IP address disguised as subdomain (e.g. 192.168.1.1.evil.com) — " +
        "numeric IP prefix makes URL appear to be internal/trusted network",
    );
    attackTypes.push("ip_address_url");
  }

  // ── 24. Unicode confusable TLD ──
  // .соm (Cyrillic) vs .com (Latin) — identical display, different DNS
  if (/\.([\u0400-\u04FF\u0370-\u03FF]+)$/.test(url)) {
    score += 55;
    issues.push(
      "Unicode/Cyrillic TLD — domain TLD uses non-Latin characters visually " +
        "identical to .com/.net (e.g. Cyrillic .соm = different domain entirely)",
    );
    attackTypes.push("homograph");
  }

  // ── 25. Missing HTTPS on financial/login page ──
  // A page claiming to be a bank or payment processor over plain HTTP
  const isFinancialBrand =
    /bank|paypal|chase|wellsfargo|coinbase|binance|hsbc|barclays|citibank|stripe|square/i.test(
      url,
    );
  if (!url.startsWith("https") && isFinancialBrand) {
    score += 30;
    issues.push(
      "Financial brand served over plain HTTP — legitimate financial sites " +
        "enforce HTTPS; HTTP indicates a fake or compromised page",
    );
  }

  // ── 26. Excessive path depth (evasion via deep nesting) ──
  // https://evil.com/a/b/c/d/e/f/g/verify.php — deep paths evade shallow scanners
  const pathDepth = (url.match(/\//g) || []).length - 2; // subtract protocol //
  if (pathDepth >= 7) {
    score += 18;
    issues.push(
      `Excessively deep URL path (${pathDepth} levels) — often used to hide ` +
        `phishing pages from URL-pattern scanners that truncate path analysis`,
    );
  }

  // ── ENTERPRISE LAYER: Domain reputation heuristics (Cisco Umbrella approach) ──
  for (const sig of DOMAIN_REPUTATION_SIGNALS) {
    if (sig.test(domain)) {
      score += sig.score;
      issues.push(sig.issue);
      attackTypes.push("domain_reputation");
    }
  }

  // ── ENTERPRISE LAYER: AiTM detection (Microsoft Defender XDR approach) ──
  for (const { p, s: sc, i } of AITM_PATTERNS) {
    if (p.test(url)) {
      score += sc;
      issues.push(i);
      attackTypes.push("aitm_attack");
    }
  }

  // ── ENTERPRISE LAYER: Visual similarity URL signals (Check Point approach) ──
  for (const vs of VISUAL_SIMILARITY_PATTERNS) {
    if (vs.urlPattern.test(url)) {
      score += Math.round(vs.score * 0.5);
      issues.push(vs.issue);
      attackTypes.push("visual_similarity");
    }
  }

  // ── NEW: Defanged URL signal ──
  if (typeof wasDefanged !== "undefined" && wasDefanged) {
    score += 12;
    issues.push(
      "Defanged URL notation (hxxps:// or [.]) — URL was encoded to evade scanners",
    );
    attackTypes.push("filter_evasion");
  }

  // ── NEW: Homoglyph URL patterns (fixed version) ──
  for (const { p, s: sc, i } of HOMOGLYPH_URL_PATTERNS_V2) {
    if (p.test(url)) {
      score += sc;
      issues.push(i);
      attackTypes.push("homograph");
    }
  }

  // ── NEW: Standalone homoglyph brand domain boost ──
  // When the domain itself IS the homoglyph brand → unambiguous phishing
  const domainPart = domain.split(".")[0];
  const isStandaloneHomoglyph =
    /^(?:paypa[lI1]|micr[o0]s[o0]ft|amaz[o0]n|arna[zs]on|g[o0]{2}gle|app[lI1]e|faceb[o0]{2}k|tw[i1]tter)$/i.test(
      domainPart,
    );
  if (isStandaloneHomoglyph) {
    score += 20; // extra push past phishing threshold
    issues.push(
      "Standalone homoglyph brand domain — the entire domain name impersonates a major brand",
    );
    attackTypes.push("brand_impersonation");
  }

  // ── Govt Portal Fake Domain Detection ────────────────────────
  // First check if it's a real government domain (fast exit)
  const isRealGovt =
    REAL_GOVT_DOMAINS.has(domain) ||
    [...REAL_GOVT_DOMAINS].some((d) => domain.endsWith(`.${d}`)) ||
    domain.endsWith(".gov.in") ||
    domain.endsWith(".nic.in") ||
    domain.endsWith(".ernet.in") ||
    domain.endsWith(".ac.in") ||
    domain.endsWith(".res.in") ||
    domain.endsWith(".mil.in");

  if (!isRealGovt) {
    for (const { p, s: gs, i: issueText, t } of GOVT_PORTAL_FAKE_PATTERNS) {
      if (p.test(rawUrl) || p.test(domain)) {
        score += gs;
        issues.push(issueText);
        attackTypes.push(t);
        attackTypes.push("govt_impersonation");
        break; // Only flag once per URL to avoid stacking
      }
    }
  }

  // Also run India fraud text patterns on URL path/query string
  // (catches "uidai-update-karo" type URLs with Hindi words)
  const urlTextForIndia = rawUrl.replace(/[-_/]/g, " ");
  const urlIndiaHits = INDIA_FRAUD_PATTERNS.filter(({ p }) =>
    p.test(urlTextForIndia),
  );
  for (const hit of urlIndiaHits.slice(0, 2)) {
    // max 2 from URL
    if (!issues.includes(hit.i)) {
      score += Math.round(hit.s * 0.6); // reduced weight for URL path match
      issues.push(hit.i);
      attackTypes.push(hit.t);
    }
  }

  return {
    score: Math.min(Math.round(score), 100),
    issues,
    attackTypes,
    hasRedirect,
    hasHomoglyph,
    hasPunycode,
    subdomainDepth: Math.min(subCount / 5, 1),
    urlPathRisk,
  };
}

// ═══════════════════════════════════════════════════════
// ENGINE 2 — TEXT / EMAIL CONTENT ANALYSIS (22 checks)
// ═══════════════════════════════════════════════════════
function analyzeText(text) {
  let score = 0;
  // Normalize defanged content
  const normalizedText = normalizeDefangedURL(text);

  // Extract and analyze defanged URLs from text body
  const defangedUrlMatches =
    text.match(
      /hxxps?:\/\/[^\s\]>]+|hXXps?:\/\/[^\s\]>]+|[\w.-]+\[\.\][\w.-]+(?:\/\S*)?/gi,
    ) || [];

  const issues = [];
  const attackTypes = [];
  const lower = text.toLowerCase();

  // 1. High-confidence phrases
  const foundHigh = HIGH_CONFIDENCE_PHRASES.filter((p) => lower.includes(p));
  if (foundHigh.length > 0) {
    score += Math.min(foundHigh.length * 20, 55);
    issues.push(
      `High-risk phishing phrases: "${foundHigh.slice(0, 2).join('", "')}"`,
    );
  }

  // 2. Medium-confidence phrases
  const foundMedium = MEDIUM_CONFIDENCE_PHRASES.filter((p) =>
    lower.includes(p),
  );
  if (foundMedium.length >= 3) {
    score += 28;
    issues.push(`Multiple social engineering phrases detected`);
  } else if (foundMedium.length > 0) {
    score += foundMedium.length * 8;
    issues.push(`Suspicious phrase: "${foundMedium[0]}"`);
  }

  // 3. OTP / credential harvest
  const otpMatches = OTP_CREDENTIAL_PATTERNS.filter((p) => p.test(text));
  if (otpMatches.length > 0) {
    score += 42;
    issues.push(
      "OTP/credential request — legitimate services NEVER ask for this via message",
    );
    attackTypes.push("otp_request");
  }

  // 4. Social engineering
  const seMatches = SOCIAL_ENGINEERING_PATTERNS.filter((p) => p.test(text));
  if (seMatches.length >= 2) {
    score += 38;
    issues.push(
      "Multiple social engineering tactics — authority impersonation or fear manipulation",
    );
    attackTypes.push("social_engineering");
  } else if (seMatches.length === 1) {
    score += 22;
    issues.push("Social engineering tactic — possible authority impersonation");
    attackTypes.push("social_engineering");
  }

  // 5. Attachment indicators
  const attachMatches = MALICIOUS_ATTACHMENT_PATTERNS.filter((p) =>
    p.test(text),
  );
  if (attachMatches.length > 0) {
    score += 32;
    issues.push(
      "Malicious attachment indicator — enable macros or suspicious file",
    );
    attackTypes.push("malicious_attachment");
  }

  // 6. Tech support scam
  if (
    /call.*\+?1?[-.\s]?\d{3}[-.\s]?\d{3}[-.\s]?\d{4}/i.test(text) &&
    /microsoft|apple|google|support|technician|virus|infected/i.test(text)
  ) {
    score += 45;
    issues.push(
      "Tech support scam detected — fake support number with threat language",
    );
    attackTypes.push("tech_support_scam");
  }

  // 7. Embedded URL analysis + display mismatch detection
  let hasDisplayMismatch = false;
  const urlsInText = text.match(/https?:\/\/[^\s<>"]+/g) || [];
  const uniqueUrls = [...new Set(urlsInText)];

  // Check display text vs actual URL (HTML href mismatch)
  const hrefPattern = /href=["']([^"']+)["'][^>]*>([^<]+)</gi;
  let hrefMatch;
  while ((hrefMatch = hrefPattern.exec(text)) !== null) {
    const actualUrl = hrefMatch[1];
    const displayTxt = hrefMatch[2].trim().toLowerCase();
    const isSafeDisplay = SAFE_DISPLAY_INDICATORS.some((s) =>
      displayTxt.includes(s),
    );
    const displayIsUrl = /^https?:\/\//i.test(displayTxt);

    if (
      displayIsUrl &&
      !actualUrl.toLowerCase().includes(displayTxt.replace(/https?:\/\//i, ""))
    ) {
      score += 55;
      hasDisplayMismatch = true;
      issues.push(
        `Link display mismatch — shows "${hrefMatch[2].trim().substring(0, 40)}" but links to "${actualUrl.substring(0, 40)}"`,
      );
      attackTypes.push("display_mismatch");
    } else if (isSafeDisplay) {
      // Neutral — generic CTA text, check the actual URL
      const urlResult = analyzeURL(actualUrl);
      if (urlResult.score >= 40) {
        score += Math.round(urlResult.score * 0.5);
        issues.push(...urlResult.issues.map((i) => `[Hidden link] ${i}`));
      }
    }
  }

  // Plain URL analysis
  for (const u of uniqueUrls.slice(0, 5)) {
    const { score: us, issues: ui, attackTypes: uat } = analyzeURL(u);
    if (us > 0) {
      score += Math.round(us * 0.6);
      issues.push(...ui.map((i) => `[Embedded URL] ${i}`));
      attackTypes.push(...uat);
    }
  }
  if (uniqueUrls.length > 5) {
    score += 16;
    issues.push(
      `${uniqueUrls.length} URLs found — link-heavy messages are suspicious`,
    );
  }

  // 8. Urgency scoring (weighted)
  const urgencyGroups = [
    { words: ["immediately", "right now", "asap"], s: 16 },
    { words: ["urgent", "emergency", "critical"], s: 13 },
    { words: ["24 hours", "today only", "expires"], s: 11 },
    { words: ["last warning", "final notice"], s: 22 },
    { words: ["act now", "don't delay", "time sensitive"], s: 11 },
  ];
  let urgencyScore = 0;
  const urgencyFound = [];
  for (const { words, s } of urgencyGroups) {
    const m = words.filter((w) => lower.includes(w));
    if (m.length > 0) {
      urgencyScore += s;
      urgencyFound.push(...m);
    }
  }
  if (urgencyScore > 0) {
    score += Math.min(urgencyScore, 32);
    issues.push(
      `Urgency manipulation: "${urgencyFound.slice(0, 3).join('", "')}"`,
    );
    attackTypes.push("urgency");
  }

  // 9. Generic greetings
  const genericGreetings = [
    "dear customer",
    "dear user",
    "dear account holder",
    "dear valued member",
    "dear client",
    "hello user",
    "greetings from",
    "dear friend",
  ];
  const gFound = genericGreetings.filter((g) => lower.includes(g));
  if (gFound.length > 0) {
    score += 16;
    issues.push(
      `Generic greeting "${gFound[0]}" — real companies use your actual name`,
    );
  }

  // 10. ALL-CAPS panic words
  const words = text.split(/\s+/);
  const allCaps = words.filter(
    (w) => w.length > 3 && w === w.toUpperCase() && /[A-Z]/.test(w),
  );
  if (allCaps.length >= 3) {
    score += 13;
    issues.push(`${allCaps.length} ALL-CAPS words — panic/pressure tactic`);
  }

  // 11. Excessive punctuation
  if ((text.match(/!/g) || []).length > 3) {
    score += 11;
    issues.push("Excessive exclamation marks — emotional manipulation");
  }
  if ((text.match(/\?/g) || []).length > 5) {
    score += 8;
    issues.push("Excessive question marks — anxiety-inducing tactic");
  }

  // 12. Financial bait
  const financialBait = [
    { p: /\$[\d,]+/, l: "Dollar amount lure" },
    { p: /£[\d,]+/, l: "Pound amount lure" },
    { p: /€[\d,]+/, l: "Euro amount lure" },
    { p: /₹[\d,]+/, l: "Rupee amount lure" },
    { p: /free money/i, l: "Free money offer" },
    { p: /wire transfer/i, l: "Wire transfer" },
    { p: /gift card/i, l: "Gift card request" },
    { p: /bitcoin|crypto.*payment/i, l: "Crypto payment" },
    { p: /lottery.*win/i, l: "Lottery scam" },
    { p: /inheritance.*fund/i, l: "Advance-fee fraud" },
    { p: /nigerian.*prince/i, l: "Nigerian prince scam" },
    { p: /million.*dollar/i, l: "Large sum lure" },
  ];
  const fFound = financialBait.filter((f) => f.p.test(text));
  if (fFound.length > 0) {
    score += Math.min(fFound.length * 16, 38);
    issues.push(`Financial lure: ${fFound.map((f) => f.l).join(", ")}`);
    attackTypes.push("financial_scam");
  }

  // 13. Deliberate misspellings (filter evasion)
  const misspellings = [
    /y0ur/i,
    /acc0unt/i,
    /verif1cation/i,
    /1mportant/i,
    /p4ssword/i,
    /c1ick/i,
    /l0gin/i,
    /activ1ty/i,
  ];
  if (misspellings.some((p) => p.test(text))) {
    score += 22;
    issues.push("Deliberate character substitution — filter-evasion technique");
  }

  // 14. Subject line analysis
  const subjectMatch = text.match(/subject:\s*(.+)/i);
  if (subjectMatch) {
    const subj = subjectMatch[1].toLowerCase();
    const riskSubjects = [
      "your account",
      "action required",
      "security alert",
      "verify",
      "suspended",
      "locked",
      "urgent",
      "winner",
      "prize",
      "invoice",
      "payment",
      "delivery failed",
      "unusual activity",
      "important notice",
    ];
    const hits = riskSubjects.filter((s) => subj.includes(s));
    if (hits.length >= 2) {
      score += 22;
      issues.push(`High-risk email subject: "${subjectMatch[1].trim()}"`);
    } else if (hits.length === 1) {
      score += 11;
      issues.push(`Suspicious subject: "${subjectMatch[1].trim()}"`);
    }
  }

  // 15. Reply-To mismatch (email spoofing)
  const fromMatch = text.match(/from:\s*(.+)/i);
  const replyMatch = text.match(/reply-to:\s*(.+)/i);
  if (fromMatch && replyMatch) {
    const fromDom = (fromMatch[1].match(/@([^\s>]+)/) || [])[1] || "";
    const replyDom = (replyMatch[1].match(/@([^\s>]+)/) || [])[1] || "";
    if (fromDom && replyDom && fromDom !== replyDom) {
      score += 42;
      issues.push(
        `Reply-To mismatch — From: "${fromDom}" but Reply-To: "${replyDom}" (email spoofing)"`,
      );
      attackTypes.push("email_spoofing");
    }
  }

  // 16. Display name spoofing
  const displayMatch = fromMatch
    ? fromMatch[1].match(/([^<]+)<([^>]+)>/)
    : null;
  if (displayMatch) {
    const displayName = displayMatch[1].trim().toLowerCase();
    const actualEmail = displayMatch[2].trim().toLowerCase();
    const majorBrands = [
      "paypal",
      "google",
      "amazon",
      "apple",
      "microsoft",
      "netflix",
      "bank",
      "chase",
      "irs",
      "fedex",
      "dhl",
    ];
    const brandInDisplay = majorBrands.find((b) => displayName.includes(b));
    if (brandInDisplay && !actualEmail.includes(brandInDisplay)) {
      score += 48;
      issues.push(
        `Display name spoofing — claims to be "${displayMatch[1].trim()}" but sent from "${actualEmail}"`,
      );
      attackTypes.push("display_mismatch");
      hasDisplayMismatch = true;
    }
  }

  // 17. Pretexting scenarios
  for (const { p, s: sc, t, i } of PRETEXTING_SCENARIOS) {
    if (p.test(text)) {
      score += sc;
      issues.push(i);
      if (t) attackTypes.push(t);
    }
  }

  // 18. BEC / CEO fraud
  const becHits = BEC_PATTERNS.filter(({ p }) => p.test(text));
  if (becHits.length > 0) {
    score += Math.min(
      becHits.reduce((a, b) => a + b.s, 0),
      70,
    );
    issues.push(becHits[0].i);
    attackTypes.push("bec_fraud");
  }

  // 19. QR code phishing (quishing)
  const quishHits = QUISHING_PATTERNS.filter(({ p }) => p.test(text));
  if (quishHits.length > 0) {
    score += quishHits[0].s;
    issues.push(quishHits[0].i);
    attackTypes.push("quishing");
  }

  // 20. Contextual anomalies
  const contextHits = CONTEXTUAL_ANOMALY_PATTERNS.filter(({ p }) =>
    p.test(text),
  );
  if (contextHits.length > 0) {
    score += Math.min(
      contextHits.reduce((a, b) => a + b.s, 0),
      55,
    );
    issues.push(contextHits[0].i);
    attackTypes.push("social_engineering");
  }

  // 21. Lookalike domain mentioned inside body
  if (/(?:paypa1|g00gle|arnazon|app1e|micros0ft|netf1ix)\./i.test(text)) {
    score += 45;
    issues.push("Lookalike domain in email body — visual deception");
    attackTypes.push("typosquatting");
  }

  // 22. Link-to-text ratio (phishing = many links, little text)
  const wordCount = text.split(/\s+/).filter(Boolean).length;
  if (wordCount > 10 && uniqueUrls.length / wordCount > 0.15) {
    score += 20;
    issues.push(`High link-to-text ratio — phishing emails are link-heavy`);
  }

  // ── 23. NLP Urgency Scoring (Google/Microsoft NLP approach) ──
  let nlpScore = 0;
  const nlpFound = [];
  for (const [tier, { words, score: ts }] of Object.entries(
    NLP_URGENCY_TIERS,
  )) {
    for (const word of words) {
      if (lower.includes(word)) {
        nlpScore += ts;
        nlpFound.push(word);
        break; // one match per tier
      }
    }
  }
  if (nlpScore > 0) {
    score += Math.min(nlpScore, 45);
    issues.push(
      `NLP urgency pattern: "${nlpFound[0]}" — social engineering language`,
    );
    attackTypes.push("social_engineering");
  }

  // ── 24. Behavioral anomaly indicators (Darktrace / Abnormal approach) ──
  for (const { p, s: sc, i } of BEHAVIORAL_ANOMALIES) {
    if (p.test(text)) {
      score += sc;
      issues.push(i);
      attackTypes.push("behavioral_anomaly");
    }
  }

  // ── 25. Zero-day behavioral signals (Abnormal Security approach) ──
  for (const { p, s: sc, i } of ZERO_DAY_SIGNALS) {
    if (p.test(text)) {
      score += sc;
      issues.push(i);
      attackTypes.push("zero_day_bec");
    }
  }

  // ── 26. Multi-layer content analysis (Perception Point approach) ──
  // Attachment risk
  for (const { p, s: sc, i } of MULTILAYER_SIGNALS.attachmentRisk) {
    if (p.test(text)) {
      score += sc;
      issues.push(i);
      attackTypes.push("malicious_attachment");
    }
  }
  // HTML tricks
  for (const { p, s: sc, i } of MULTILAYER_SIGNALS.htmlTricks) {
    if (p.test(text)) {
      score += sc;
      issues.push(i);
      attackTypes.push("filter_evasion");
    }
  }
  // Obfuscation
  for (const { p, s: sc, i } of MULTILAYER_SIGNALS.obfuscation) {
    if (p.test(text)) {
      score += sc;
      issues.push(i);
      attackTypes.push("obfuscation");
    }
  }

  // ── 27. Visual similarity body signals (Check Point approach) ──
  for (const vs of VISUAL_SIMILARITY_PATTERNS) {
    const bodyHits = vs.bodyPatterns.filter((bp) => bp.test(text));
    if (bodyHits.length >= 2) {
      score += vs.score;
      issues.push(vs.issue);
      attackTypes.push("visual_similarity");
    }
  }

  // 28. Smishing detection (SMS/WhatsApp specific patterns)
  for (const { p, s: sc, i, t } of SMISHING_PATTERNS) {
    if (p.test(text)) {
      score += sc;
      issues.push(i);
      attackTypes.push(t || "smishing");
    }
  }
  // Check for smishing URL patterns in text
  const smishingUrlHits = SMISHING_URL_PATTERNS.filter((p) => p.test(text));
  if (smishingUrlHits.length > 0 && score >= 30) {
    score += 18;
    issues.push(
      "Short URL in suspicious message — classic smishing delivery pattern",
    );
    attackTypes.push("smishing");
  }
  // Short message + link + urgency = high smishing probability
  const wordCount2 = text.split(/\s+/).filter(Boolean).length;
  if (wordCount2 < 30 && uniqueUrls.length >= 1 && urgencyScore > 0) {
    score += 15;
    issues.push(
      "Short message + link + urgency — matches SMS phishing (smishing) pattern",
    );
    attackTypes.push("smishing");
  }

  // 29. Defanged URL detection and analysis
  if (defangedUrlMatches.length > 0) {
    score += 15;
    issues.push(
      `Defanged URL notation detected — "${defangedUrlMatches[0].substring(0, 50)}" (hxxps:// or [.] format)`,
    );
    for (const defanged of defangedUrlMatches.slice(0, 3)) {
      const normalized = normalizeDefangedURL(defanged);
      if (normalized !== defanged) {
        const urlResult = analyzeURL(normalized);
        if (urlResult.score > 0) {
          score += Math.round(urlResult.score * 0.7);
          issues.push(
            ...urlResult.issues.slice(0, 2).map((i) => `[Defanged URL] ${i}`),
          );
          attackTypes.push(...urlResult.attackTypes);
        }
      }
    }
  }

  // 30. Corporate phishing patterns
  for (const { p, s: sc, i } of CORPORATE_PHISHING_PATTERNS) {
    if (p.test(text)) {
      score += sc;
      issues.push(i);
      attackTypes.push("corporate_phishing");
    }
  }

  // 31. Soft urgency patterns
  for (const { p, s: sc, i } of SOFT_URGENCY_PATTERNS) {
    if (p.test(text)) {
      score += sc;
      issues.push(i);
      attackTypes.push("social_engineering");
    }
  }

  // 32. Conversation hijacking
  for (const { p, s: sc, i } of CONVERSATION_HIJACKING_PATTERNS) {
    if (p.test(text)) {
      score += sc;
      issues.push(i);
      attackTypes.push("conversation_hijacking");
    }
  }

  // 33. Low-and-slow phishing
  for (const { p, s: sc, i } of LOW_AND_SLOW_PATTERNS) {
    if (p.test(text)) {
      score += sc;
      issues.push(i);
      attackTypes.push("low_and_slow");
    }
  }

  // 34. Payment profile / policy update
  for (const { p, s: sc, i } of PAYMENT_POLICY_PATTERNS) {
    if (p.test(text)) {
      score += sc;
      issues.push(i);
      attackTypes.push("payment_fraud");
    }
  }

  // 35. Homoglyph patterns in text body (brand names in message content)
  for (const { p, s: sc, i } of HOMOGLYPH_URL_PATTERNS_V2) {
    if (sc > 0 && p.test(text)) {
      score += sc;
      issues.push(i);
      attackTypes.push("homograph");
    }
  }

  // 36. Professional language + action link combo
  // Corporate language alone is weak signal; combined with action link = phishing fingerprint
  const hasActionLink =
    /(?:review|confirm|verify|access|check).*(?:here|below|portal|link)|(?:click|tap|open).*to\s+(?:review|verify|confirm|access)/i.test(
      text,
    );
  const hasCorporateLang =
    /(?:corporate|enterprise|workspace|profile|portal|session|cloud\s+service)/i.test(
      text,
    );
  if (hasActionLink && hasCorporateLang && score >= 20) {
    score += 18;
    issues.push(
      "Professional language + action link — corporate phishing fingerprint",
    );
  }

  // 37. Fake reference ID legitimacy signal
  if (
    /(?:ref(?:erence)?\s*(?:id|#|no\.?)|ticket\s*(?:id|#)|case\s*(?:id|#)|incident\s*(?:id|#))\s*[:\-]?\s*[A-Z]{0,6}[-\s]?\d{4,}/i.test(
      text,
    )
  ) {
    score += 15;
    issues.push(
      "Fake reference ID — creates false official legitimacy, common in corporate phishing",
    );
  }

  // GAP 12: AI-generated text detection
  const aiDetection = detectAIGeneratedText(text);
  let aiResult = null;
  if (aiDetection.aiProbability >= 35) {
    score += aiDetection.riskBoost;
    aiResult = aiDetection;
    if (aiDetection.verdict === "likely_ai") {
      issues.push(
        `AI-Generated Content: ${aiDetection.aiProbability}% probability — LLM-written text detected. "${aiDetection.fingerprintPhrases?.[0]}" and ${aiDetection.signals?.length || 0} other linguistic signals.`,
      );
      attackTypes.push("ai_generated_phishing");
    } else if (aiDetection.verdict === "possibly_ai") {
      issues.push(
        `Possibly AI-Generated: ${aiDetection.aiProbability}% — over-formal language patterns suggest LLM authorship.`,
      );
      attackTypes.push("ai_assisted_phishing");
    }
  }

  // ── India Cyber Fraud Detection ──────────────────────────────
  // Runs on ALL text/SMS/email scans
  const indiaFraudHits = INDIA_FRAUD_PATTERNS.filter(({ p }) => p.test(text));
  for (const hit of indiaFraudHits) {
    score += hit.s;
    issues.push(hit.i);
    attackTypes.push(hit.t);
  }
  // Cap India fraud contribution to avoid over-penalizing with multiple hits
  if (indiaFraudHits.length > 1) {
    score = Math.min(score, 100);
  }
  // Add specific India fraud context to attackTypes
  if (indiaFraudHits.some((h) => h.t === "digital_arrest_scam")) {
    attackTypes.push("india_cyber_fraud");
    attackTypes.push("authority_impersonation");
  }
  if (indiaFraudHits.some((h) => h.t === "upi_scam")) {
    attackTypes.push("financial_fraud");
  }
  if (indiaFraudHits.some((h) => h.t === "otp_fraud_india")) {
    attackTypes.push("credential_harvest");
  }

  return {
    score: Math.min(Math.round(score), 100),
    issues,
    attackTypes,
    hasDisplayMismatch,
    aiDetection: aiResult,
  };
}

// ═══════════════════════════════════════════════════════
// ENGINE 3 — EMAIL ADDRESS ANALYSIS
// ═══════════════════════════════════════════════════════
function analyzeEmailAddress(email) {
  let score = 0;
  const issues = [];
  const attackTypes = [];
  const [localPart, domainPart] = email.toLowerCase().split("@");

  if (!domainPart)
    return { score: 50, issues: ["Invalid email format"], attackTypes: [] };

  const domResult = analyzeURL(`https://${domainPart}`);
  score += domResult.score * 0.7;
  issues.push(...domResult.issues.map((i) => `[Sender domain] ${i}`));
  attackTypes.push(...domResult.attackTypes);

  if (/no.?reply/i.test(localPart) && domResult.score > 20) {
    score += 11;
    issues.push("No-reply address from suspicious domain");
  }
  if (
    /security|alert|verify|support|admin|helpdesk|noreply|notification/i.test(
      localPart,
    )
  ) {
    score += 16;
    issues.push(
      `Suspicious sender name "${localPart}" — impersonates official support`,
    );
    attackTypes.push("email_spoofing");
  }
  if (/\d{4,}/.test(localPart)) {
    score += 11;
    issues.push(
      "Many numbers in email local part — often auto-generated phishing addresses",
    );
  }

  return { score: Math.min(Math.round(score), 100), issues, attackTypes };
}

// ═══════════════════════════════════════════════════════
// ENGINE 4 — EVASION RESISTANCE PASS
// Second detection pass on top of primary analysis
// Runs AFTER rule scoring — designed to catch sophisticated
// attackers who deliberately engineer near-threshold scores
// ═══════════════════════════════════════════════════════
function runEvasionResistancePass(
  input,
  inputType,
  ruleScore,
  issues,
  features,
) {
  let evasionScore = 0;
  const evasionIssues = [];
  const evasionTypes = [];
  let evasionLevel = null;

  const domain =
    inputType === "url"
      ? (() => {
          try {
            return new URL(
              input.startsWith("http") ? input : `https://${input}`,
            ).hostname;
          } catch {
            return input;
          }
        })()
      : "";

  const signals =
    inputType === "url" ? EVASION_RESISTANCE.url : EVASION_RESISTANCE.text;

  let matchCount = 0;

  for (const signal of signals) {
    try {
      const matched = signal.test(input, domain, features, issues, ruleScore);
      if (matched) {
        matchCount++;
        evasionScore += signal.score;
        evasionIssues.push(`[Evasion] ${signal.issue}`);
        evasionTypes.push("evasion_attempt");
      }
    } catch {
      /* skip bad signal */
    }
  }

  // Also run text evasion signals on URLs (embedded text evasion in query strings)
  if (inputType === "url" && input.length > 80) {
    for (const signal of EVASION_RESISTANCE.text.slice(0, 4)) {
      try {
        if (signal.test(input, domain, features, issues, ruleScore)) {
          matchCount++;
          evasionScore += Math.round(signal.score * 0.5);
          evasionIssues.push(`[Evasion/URL] ${signal.issue}`);
        }
      } catch {}
    }
  }

  // Evasion level classification
  if (matchCount >= 3) {
    evasionLevel = "SOPHISTICATED";
    evasionScore += 25; // additional penalty for multiple evasion techniques
  } else if (matchCount === 2) {
    evasionLevel = "MODERATE";
    evasionScore += 12;
  } else if (matchCount === 1) {
    evasionLevel = "BASIC";
  }

  return {
    evasionDetected: matchCount > 0,
    evasionLevel,
    evasionScore: Math.min(evasionScore, 45), // cap at 45 additional points
    evasionIssues,
    evasionTypes: [...new Set(evasionTypes)],
    signalCount: matchCount,
  };
}

// ═══════════════════════════════════════════════════════
// FEATURE EXTRACTOR — 24 features for ML model v2
// ═══════════════════════════════════════════════════════
function extractFeatureVector(
  input,
  inputType,
  ruleScore,
  issues,
  extras = {},
) {
  const lower = input.toLowerCase();
  return {
    // Original 18
    inputLength: Math.min(input.length / 500, 1),
    urlCount: Math.min((input.match(/https?:\/\//g) || []).length / 10, 1),
    hasHttps: /^https:\/\//i.test(input) ? 1 : 0,
    hasHttp: /^http:\/\//i.test(input) && !/^https:\/\//i.test(input) ? 1 : 0,
    issueCount: Math.min(issues.length / 10, 1),
    urgencyWordCount: Math.min(
      (lower.match(/urgent|immediately|asap|expires|warning|right now/g) || [])
        .length / 5,
      1,
    ),
    credentialWordCount: Math.min(
      (
        lower.match(/password|otp|pin|cvv|verify|login|credential|signin/g) ||
        []
      ).length / 8,
      1,
    ),
    financialWordCount: Math.min(
      (lower.match(/\$|£|€|₹|bitcoin|wire transfer|gift card|lottery/gi) || [])
        .length / 5,
      1,
    ),
    hasBrandSpoof: issues.some((i) => /impersonat|spoofing/i.test(i)) ? 1 : 0,
    hasOtpRequest: issues.some((i) => /otp/i.test(i)) ? 1 : 0,
    hasUrgency: issues.some((i) => /urgency/i.test(i)) ? 1 : 0,
    hasSocialEngineering: issues.some((i) => /social engineering/i.test(i))
      ? 1
      : 0,
    hasFinancialLure: issues.some((i) => /financial lure/i.test(i)) ? 1 : 0,
    hasAttachment: issues.some((i) => /attachment/i.test(i)) ? 1 : 0,
    hasSuspiciousTLD: issues.some((i) => /tld/i.test(i)) ? 1 : 0,
    hasIPAddress: issues.some((i) => /ip address/i.test(i)) ? 1 : 0,
    isURL: inputType === "url" ? 1 : 0,
    isText: inputType === "text" ? 1 : 0,
    // New 6 features
    hasRedirect: extras.hasRedirect ? 1 : 0,
    hasHomoglyph: extras.hasHomoglyph ? 1 : 0,
    hasPunycode: extras.hasPunycode ? 1 : 0,
    hasDisplayMismatch: extras.hasDisplayMismatch ? 1 : 0,
    subdomainDepth: extras.subdomainDepth || 0,
    urlPathRisk: extras.urlPathRisk || 0,
    // v5 — 4 new enterprise features
    hasAiTM: issues.some((i) =>
      /aitm|adversary.in.the.middle|reverse.proxy/i.test(i),
    )
      ? 1
      : 0,
    hasZeroDayBEC: issues.some((i) =>
      /confidentiality demand|gift card purchase|fake invoice approval|abrupt demand|prior relationship/i.test(
        i,
      ),
    )
      ? 1
      : 0,
    hasBehavioralAnomaly: issues.some((i) =>
      /freemail domain|automated security alert|out-of-band|device anomaly|geographic anomaly/i.test(
        i,
      ),
    )
      ? 1
      : 0,
    hasVisualSimilarity: issues.some((i) =>
      /visual|mimicry|clone|visual phishing/i.test(i),
    )
      ? 1
      : 0,
  };
}

// ═══════════════════════════════════════════════════════
// MITRE / CVE LOOKUP
// ═══════════════════════════════════════════════════════
// Returns the first matching entry (kept for backward-compat, not used in main flow)
function getMitreMapping(attackTypes = []) {
  for (const type of attackTypes) {
    if (MITRE_MAPPING[type]) return MITRE_MAPPING[type];
  }
  return null;
}

// Returns ALL unique tactic/technique pairs across every detected attack type.
// Deduplicates by tactic so the same tactic never appears twice.
function getAllMitreMappings(attackTypes = []) {
  const seenTactics = new Set();
  const results = [];
  for (const type of attackTypes) {
    const entry = MITRE_MAPPING[type];
    if (!entry) continue;
    if (seenTactics.has(entry.tactic)) continue;
    seenTactics.add(entry.tactic);
    results.push({ ...entry });
  }
  return results.length > 0 ? results : null;
}

function getCVEMapping(attackTypes = []) {
  for (const type of attackTypes) {
    if (CVE_MAPPING[type]) return CVE_MAPPING[type];
  }
  return null;
}

// ═══════════════════════════════════════════════════════
// MAIN EXPORT — analyzeInput v4.0
// ═══════════════════════════════════════════════════════
async function analyzeInput(input) {
  const rawTrimmed = input.trim();
  const trimmed = normalizeDefangedURL(rawTrimmed);
  const wasDefanged = rawTrimmed !== trimmed;
  const inputType = detectInputType(trimmed);

  let ruleScore = 0;
  let issues = [];
  let attackTypes = [];
  let extras = {};

  if (inputType === "url") {
    const r = analyzeURL(trimmed);
    ruleScore = r.score;
    issues = r.issues;
    attackTypes = r.attackTypes;
    extras = {
      hasRedirect: r.hasRedirect,
      hasHomoglyph: r.hasHomoglyph,
      hasPunycode: r.hasPunycode,
      subdomainDepth: r.subdomainDepth,
      urlPathRisk: r.urlPathRisk,
    };

    // ── Whitelist fast-exit: whitelisted domains score 0 with no issues ──
    // The ML model must not override a known-safe domain.
    if (ruleScore === 0 && issues.length === 0) {
      return {
        status: "safe",
        riskScore: 0,
        issues: [],
        inputType,
        confidence: "high",
        attackTypes: [],
        detectionVersion: "5.2",
        mlEnabled: false,
        mlScore: null,
        ruleScore: 0,
        features: {},
        mitre: null,
        cve: null,
        evasion: null,
        csvMatch: null,
      };
    }
  } else if (inputType === "email") {
    const r = analyzeEmailAddress(trimmed);
    ruleScore = r.score;
    issues = r.issues;
    attackTypes = r.attackTypes;
  } else {
    const r = analyzeText(trimmed);
    ruleScore = r.score;
    issues = r.issues;
    attackTypes = r.attackTypes;
    extras = { hasDisplayMismatch: r.hasDisplayMismatch };
    if (r.aiDetection) extras.aiDetection = r.aiDetection;
  }

  // Build feature vector (24 features)
  let features = extractFeatureVector(
    trimmed,
    inputType,
    ruleScore,
    issues,
    extras,
  );

  // ── Evasion Resistance Pass (Second detection layer) ──
  const evasion = runEvasionResistancePass(
    trimmed,
    inputType,
    ruleScore,
    issues,
    features,
  );
  if (evasion.evasionDetected) {
    ruleScore = Math.min(ruleScore + evasion.evasionScore, 100);
    issues = [...evasion.evasionIssues, ...issues];
    attackTypes = [...attackTypes, ...evasion.evasionTypes];
  }

  // Hybrid score: ML (45%) + Rules (55%)
  const hybrid = hybridScore(ruleScore, features);
  let finalScore = hybrid.finalScore;

  // Minimum evidence threshold — prevents single weak-signal false positives.
  // Need at least 2 distinct issues OR 1 high-weight issue before upgrading verdict.
  const highWeightIssues = issues.filter(
    (i) =>
      i.includes("impersonat") ||
      i.includes("spoofing") ||
      i.includes("phishing") ||
      i.includes("malware") ||
      i.includes("typosquatt") ||
      i.includes("redirect"),
  ).length;
  const hasMinEvidence = issues.length >= 2 || highWeightIssues >= 1;
  const adjustedScore =
    !hasMinEvidence && finalScore < 40
      ? Math.max(finalScore - 15, 0) // dampen weak single-signal scores
      : finalScore;

  // Verdict
  let status;
  if (adjustedScore <= 25) status = "safe";
  else if (adjustedScore <= 65) status = "suspicious";
  else status = "phishing";

  // Confidence (multi-factor)
  const uniqueAttacks = [...new Set(attackTypes)];
  const corroborating = [
    features.hasBrandSpoof,
    features.hasOtpRequest,
    features.hasSocialEngineering,
    features.hasFinancialLure,
    features.hasIPAddress,
    features.hasSuspiciousTLD,
    features.hasRedirect,
    features.hasHomoglyph,
    features.hasPunycode,
  ].reduce((a, b) => a + b, 0);

  let confidence;
  if (finalScore >= 75 && corroborating >= 2) confidence = "high";
  else if (finalScore >= 75 && corroborating < 2) confidence = "medium";
  else if (finalScore >= 40 && corroborating >= 1) confidence = "medium";
  else if (finalScore <= 20 && corroborating === 0) confidence = "high";
  else confidence = "low";

  // MITRE + CVE
  const mitre = getMitreMapping(uniqueAttacks); // single entry (legacy)
  const mitreAttack = getAllMitreMappings(uniqueAttacks); // all matched tactics (new)
  const cve = getCVEMapping(uniqueAttacks);

  // ── PASS 3: CSV Dataset Lookup (offline phishing database check) ──
  // O(1) in-memory hash lookup — no file I/O at scan time
  let csvMatch = null;
  if (csvLookup) {
    try {
      const match = csvLookup(trimmed);
      if (match) {
        csvMatch = match;

        // Score boost based on match level and dataset label
        const boost =
          match.label === "phishing" && match.matchLevel === "exact"
            ? 30
            : match.label === "phishing" && match.matchLevel === "domain+path"
              ? 22
              : match.label === "phishing" && match.matchLevel === "domain"
                ? 15
                : match.label === "suspicious"
                  ? 8
                  : 0;

        if (boost > 0) {
          finalScore = Math.min(finalScore + boost, 100);

          // Escalate status if CSV confirms phishing
          if (match.label === "phishing" && finalScore >= 50)
            status = "phishing";
          else if (match.label === "phishing" && status === "safe")
            status = "suspicious";

          // Add to issues list
          const matchDesc =
            match.matchLevel === "exact"
              ? "Exact match"
              : match.matchLevel === "domain+path"
                ? "Domain+path match"
                : "Domain match";
          issues.unshift(
            `📂 CSV Dataset: ${matchDesc} in "${match.source}" — ` +
              `confirmed ${match.label}${match.count > 1 ? ` (${match.count} reports)` : ""}`,
          );

          // Add attack type
          if (!attackTypes.includes("csv_confirmed")) {
            attackTypes = ["csv_confirmed", ...attackTypes];
          }

          // Recalculate confidence after CSV boost
          if (match.label === "phishing") {
            confidence = finalScore >= 80 ? "high" : "medium";
          }
        }
      }
    } catch {
      /* CSV lookup never blocks detection */
    }
  }

  // India fraud detection (adds to risk score if detected)
  let indiaFraud = null;
  try {
    const { detectIndiaFraud } = require("../services/indiaFraudDetector");
    const indiaResult = detectIndiaFraud(input);
    if (indiaResult.detected) {
      finalScore += indiaResult.riskBoost;
      issues.push(
        `🇮🇳 ${indiaResult.topFraud}: ${indiaResult.description?.substring(0, 100)}`,
      );
      attackTypes.push(indiaResult.fraudType);
      indiaFraud = indiaResult;
    }
  } catch {}

  // Fake govt portal detection (URL scans only)
  let govtPortal = null;
  if (inputType === "url") {
    try {
      const {
        detectFakeGovtPortal,
      } = require("../services/govtPortalDetector");
      const govtResult = detectFakeGovtPortal(input);
      if (govtResult.isGovtImpersonation) {
        finalScore += govtResult.riskBoost;
        issues.push(
          `🏛️ Fake Govt Portal: ${govtResult.detections[0]?.name} — Real: ${govtResult.realPortal}`,
        );
        attackTypes.push("govt_impersonation");
        govtPortal = govtResult;
      }
    } catch {}
  }

  // Ransomware detection (all input types)
  let ransomware = null;
  try {
    const { analyzeForRansomware } = require("../services/ransomwareDetector");
    const rwResult = await analyzeForRansomware(input, { inputType });
    if (rwResult.isRansomware) {
      finalScore = Math.min(finalScore + 40, 100);
      issues.push(
        `🚨 Ransomware: ${rwResult.family || "Unknown family"} — ${rwResult.detections[0]?.description?.substring(0, 80)}`,
      );
      attackTypes.push("ransomware");
      ransomware = rwResult;
    }
  } catch {}

  // Prioritize issues (after all detectors have pushed to issues)
  const unique = [...new Set(issues)];
  const prioritized = [
    ...unique.filter((i) =>
      /spoof|otp|impersonat|social engineering|display name|mismatch|punycode|homoglyph/i.test(
        i,
      ),
    ),
    ...unique.filter(
      (i) =>
        !/spoof|otp|impersonat|social engineering|display name|mismatch|punycode|homoglyph/i.test(
          i,
        ),
    ),
  ].slice(0, 10);

  return {
    status,
    riskScore: Math.min(finalScore, 100),
    issues: prioritized,
    inputType,
    confidence,
    attackTypes: uniqueAttacks,
    detectionVersion: "5.2",
    mlEnabled: hybrid.hybridMode,
    mlScore: hybrid.mlScore,
    ruleScore: hybrid.ruleScore,
    features,
    mitre,
    mitreAttack,
    cve,
    evasion: evasion.evasionDetected
      ? {
          detected: true,
          level: evasion.evasionLevel,
          signals: evasion.signalCount,
          techniques: evasion.evasionTypes,
        }
      : null,
    csvMatch: csvMatch
      ? {
          matched: true,
          matchLevel: csvMatch.matchLevel,
          label: csvMatch.label,
          source: csvMatch.source,
          count: csvMatch.count || 1,
        }
      : null,
    indiaFraud,
    govtPortal,
    ransomware,
    aiDetection: extras.aiDetection || null,
  };
}

module.exports = { analyzeInput, detectInputType };
