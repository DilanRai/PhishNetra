// FILE: backend/ai/emailHeaderAnalyzer.js
// Parses raw email headers and detects spoofing/forgery

"use strict";
const http = require("http");
const dns = require("dns").promises;
const { checkIPReputation } = require("../services/ipReputationEngine");
const { validateMXAndSPF } = require("../services/mxValidationEngine");
const { buildAttributionScore } = require("../services/attributionEngine");
const { detectAIGeneratedText } = require("../services/aiTextDetector");

// ── Domain intel cache (15 min TTL) ──────────────────────────
const DOMAIN_CACHE = new Map();
const DOMAIN_CACHE_TTL = 15 * 60 * 1000;

// ── High-abuse TLDs (free / commonly used for phishing) ──────
const HIGH_RISK_TLDS = new Map([
  // Risk score per TLD (0-100)
  [".tk", 90],
  [".ml", 88],
  [".ga", 88],
  [".cf", 88],
  [".gq", 88],
  [".xyz", 55],
  [".top", 55],
  [".icu", 60],
  [".sbs", 65],
  [".vip", 50],
  [".club", 45],
  [".online", 45],
  [".site", 40],
  [".store", 40],
  [".fun", 40],
  [".click", 55],
  [".link", 55],
  [".live", 40],
  [".world", 35],
  [".space", 40],
  [".info", 30],
  [".biz", 25],
  [".name", 25],
  [".mobi", 25],
  // High-abuse ccTLDs
  [".pw", 60],
  [".ru", 35],
  [".cn", 30],
  [".in", 20],
  [".br", 20],
]);

// ── Known free email providers (not suspicious alone, but flag if impersonating) ──
const FREE_EMAIL_PROVIDERS = new Set([
  "gmail.com",
  "yahoo.com",
  "yahoo.in",
  "yahoo.co.in",
  "hotmail.com",
  "outlook.com",
  "live.com",
  "rediffmail.com",
  "ymail.com",
  "icloud.com",
  "protonmail.com",
  "tutanota.com",
  "gmx.com",
  "mail.com",
  "aol.com",
  "zoho.com",
  "fastmail.com",
  "yandex.com",
  "yandex.ru",
  "mailinator.com",
  "guerrillamail.com",
  "tempmail.com",
  "10minutemail.com",
  "throwam.com",
]);

// ── Known legitimate MX providers (if sender domain MX matches → legit) ──
const LEGIT_MX_PROVIDERS = [
  "google.com",
  "googlemail.com",
  "gmail.com", // Google Workspace
  "outlook.com",
  "hotmail.com",
  "protection.outlook.com",
  "mail.protection.outlook.com", // Microsoft 365
  "amazonses.com",
  "amazon.com",
  "amazonaws.com", // Amazon SES
  "sendgrid.net",
  "sendgrid.com", // SendGrid
  "mailgun.org",
  "mailgun.net", // Mailgun
  "zoho.com",
  "zohomail.com", // Zoho
  "protonmail.ch",
  "proton.me", // ProtonMail
  "mimecast.com",
  "mimecast.org", // Mimecast
  "barracudanetworks.com",
  "pphosted.com", // Barracuda, Proofpoint
];

// ── Known brands for lookalike detection ──────────────────────
const MAJOR_BRANDS = [
  "paypal",
  "amazon",
  "google",
  "microsoft",
  "apple",
  "netflix",
  "facebook",
  "instagram",
  "whatsapp",
  "twitter",
  "linkedin",
  "dropbox",
  "docusign",
  "zoom",
  "teams",
  "office365",
  "outlook",
  "onedrive",
  "sharepoint",
  "sbi",
  "icici",
  "hdfc",
  "axis",
  "kotak",
  "paytm",
  "phonepe",
  "gpay",
  "irctc",
  "aadhaar",
  "uidai",
  "incometax",
  "digilocker",
  "pmjay",
  "fedex",
  "dhl",
  "usps",
  "bluedart",
  "indiapost",
  "flipkart",
  "amazon",
  "meesho",
  "olx",
  "quikr",
];

// ── Freenom nameservers (free domains = disposable = suspicious) ──
const FREENOM_NS_PATTERNS = [
  "freenom.com",
  "dns-parking.com",
  "privatedns.org",
  "parkpage.net",
  "sedoparking.com",
  "above.com",
];

// ── Known disposable/suspicious NS providers ──────────────────
const SUSPICIOUS_NS = [
  "afraid.org",
  "changeip.com",
  "dnsmadeeasy.com",
  "he.net",
  "hurricane.net",
  "duckdns.org",
];

// ════════════════════════════════════════════════════════════════
// MAIN FUNCTION — Domain Intelligence Analysis
// ════════════════════════════════════════════════════════════════
async function analyzeDomainIntel(domain) {
  if (!domain) return null;

  // Cache check
  const cached = DOMAIN_CACHE.get(domain);
  if (cached && Date.now() - cached.ts < DOMAIN_CACHE_TTL) return cached.data;

  const result = {
    domain,
    // DNS data
    mxRecords: [],
    nsRecords: [],
    txtRecords: [],
    hasMX: false,
    hasNS: false,
    // TLD analysis
    tld: extractTLD(domain),
    tldRisk: 0,
    isHighRiskTLD: false,
    isFreeTLD: false,
    // Provider analysis
    isFreeEmailProvider: FREE_EMAIL_PROVIDERS.has(domain),
    mxProvider: null, // "google", "microsoft", "sendgrid" etc.
    isLegitMXProvider: false,
    // Lookalike detection
    lookalikeBrand: null,
    lookalikeTechnique: null,
    // Pattern analysis
    hasNumericSub: false, // paypa1, g00gle
    hasExcessiveHyphens: false, // pay-pal-secure-login
    subdomainDepth: 0, // mail.secure.login.paypal-fake.com = 3
    domainLength: domain.length,
    isVeryLong: domain.length > 40,
    // NS fingerprinting
    registrarHint: null,
    isFreenomDomain: false,
    isSuspiciousNS: false,
    // Risk assessment
    domainAnomalies: [],
    domainRiskScore: 0,
  };

  // ── 1. DNS lookups (parallel, with timeouts) ──────────────────
  const [mxResult, nsResult, txtResult] = await Promise.allSettled([
    dns.resolveMx(domain),
    dns.resolveNs(domain),
    dns.resolveTxt(domain),
  ]);

  if (mxResult.status === "fulfilled") {
    result.mxRecords = mxResult.value.map((r) => r.exchange).sort();
    result.hasMX = result.mxRecords.length > 0;
  }
  if (nsResult.status === "fulfilled") {
    result.nsRecords = nsResult.value;
    result.hasNS = result.nsRecords.length > 0;
  }
  if (txtResult.status === "fulfilled") {
    result.txtRecords = txtResult.value.map((r) => r.join("")).slice(0, 5);
  }

  // ── 2. TLD risk scoring ───────────────────────────────────────
  const tld = result.tld;
  if (tld && HIGH_RISK_TLDS.has(tld)) {
    result.tldRisk = HIGH_RISK_TLDS.get(tld);
    result.isHighRiskTLD = true;
    result.isFreeTLD = [".tk", ".ml", ".ga", ".cf", ".gq"].includes(tld);
  }

  // ── 3. MX provider identification ────────────────────────────
  if (result.hasMX) {
    const firstMX = result.mxRecords[0]?.toLowerCase() || "";
    for (const provider of LEGIT_MX_PROVIDERS) {
      if (firstMX.includes(provider)) {
        result.mxProvider = provider;
        result.isLegitMXProvider = true;
        break;
      }
    }
    // Classify provider type
    if (firstMX.includes("google") || firstMX.includes("gmail"))
      result.mxProvider = "Google Workspace";
    else if (firstMX.includes("outlook") || firstMX.includes("microsoft"))
      result.mxProvider = "Microsoft 365";
    else if (firstMX.includes("amazonses") || firstMX.includes("amazonaws"))
      result.mxProvider = "Amazon SES";
    else if (firstMX.includes("sendgrid")) result.mxProvider = "SendGrid";
    else if (firstMX.includes("mailgun")) result.mxProvider = "Mailgun";
    else if (firstMX.includes("zoho")) result.mxProvider = "Zoho Mail";
    else if (firstMX.includes("mimecast")) result.mxProvider = "Mimecast";
  }

  // ── 4. NS fingerprinting (registrar hint) ────────────────────
  if (result.hasNS) {
    const nsStr = result.nsRecords.join(" ").toLowerCase();
    // Freenom free domain NS
    if (FREENOM_NS_PATTERNS.some((p) => nsStr.includes(p))) {
      result.isFreenomDomain = true;
      result.registrarHint = "Freenom (free domain — disposable)";
    }
    // Other suspicious NS
    else if (SUSPICIOUS_NS.some((p) => nsStr.includes(p))) {
      result.isSuspiciousNS = true;
      result.registrarHint = "Suspicious/free DNS provider";
    }
    // Legit registrars
    else if (nsStr.includes("cloudflare"))
      result.registrarHint = "Cloudflare DNS";
    else if (nsStr.includes("godaddy")) result.registrarHint = "GoDaddy";
    else if (nsStr.includes("namecheap")) result.registrarHint = "Namecheap";
    else if (nsStr.includes("google")) result.registrarHint = "Google Domains";
    else if (nsStr.includes("awsdns")) result.registrarHint = "AWS Route53";
    else if (nsStr.includes("azure")) result.registrarHint = "Azure DNS";
  }

  // ── 5. Domain pattern analysis ───────────────────────────────
  const domainBase = domain.split(".")[0].toLowerCase();

  // Numeric substitution (pay pa1, g00gle, micros0ft)
  if (/[0-9]/.test(domainBase)) {
    const COMMON_SUBS = {
      0: "o",
      1: "i",
      3: "e",
      4: "a",
      5: "s",
      6: "g",
      7: "t",
      8: "b",
      9: "g",
    };
    let desubstituted = domainBase;
    for (const [num, letter] of Object.entries(COMMON_SUBS)) {
      desubstituted = desubstituted.replaceAll(num, letter);
    }
    // Check if desubstituted matches a brand
    const matchedBrand = MAJOR_BRANDS.find((b) => desubstituted.includes(b));
    if (matchedBrand) {
      result.hasNumericSub = true;
      result.lookalikeBrand = matchedBrand;
      result.lookalikeTechnique = "numeric_substitution";
    }
  }

  // Excessive hyphens (pay-pal-secure-login.com)
  const hyphenCount = (domain.match(/-/g) || []).length;
  if (hyphenCount >= 2) {
    result.hasExcessiveHyphens = true;
    // Check if brand name is in the hyphenated domain
    const domainNoHyphens = domain.replace(/-/g, "").toLowerCase();
    const matchedBrand = MAJOR_BRANDS.find((b) => domainNoHyphens.includes(b));
    if (matchedBrand && !result.lookalikeBrand) {
      result.lookalikeBrand = matchedBrand;
      result.lookalikeTechnique = "hyphen_injection";
    }
  }

  // Subdomain depth (secure.login.paypal-fake.com = depth 2)
  result.subdomainDepth = domain.split(".").length - 2;

  // Lookalike by Levenshtein-style check (contains brand + extra chars)
  if (!result.lookalikeBrand) {
    for (const brand of MAJOR_BRANDS) {
      if (
        domain.includes(brand) &&
        !domain.endsWith(`.${brand}.com`) &&
        domain !== `${brand}.com`
      ) {
        result.lookalikeBrand = brand;
        result.lookalikeTechnique = "brand_in_subdomain_or_path";
        break;
      }
    }
  }

  // Very long domain
  result.isVeryLong = domain.length > 40;

  // ── 6. Anomaly scoring ────────────────────────────────────────
  const add = (anomaly) => {
    result.domainAnomalies.push(anomaly);
    result.domainRiskScore += anomaly.risk;
  };

  // No MX records = domain can't receive email = suspicious sender
  if (!result.hasMX) {
    add({
      type: "no_mx_records",
      label: "No MX records",
      detail: `Domain "${domain}" has no MX records — cannot legitimately send or receive email. Likely a freshly registered phishing domain.`,
      risk: 35,
    });
  }

  // No NS records = domain not configured
  if (!result.hasNS) {
    add({
      type: "no_ns_records",
      label: "No DNS configuration",
      detail: `Domain "${domain}" has no NS records — domain is not configured. Highly suspicious for an email sender.`,
      risk: 40,
    });
  }

  // High-risk TLD
  if (result.isHighRiskTLD) {
    add({
      type: "high_risk_tld",
      label: `High-abuse TLD (${tld})`,
      detail: `TLD "${tld}" is heavily abused for phishing and cybercrime. Risk score: ${result.tldRisk}/100.`,
      risk: Math.round(result.tldRisk * 0.4), // cap contribution
    });
  }

  // Free TLD (Freenom .tk/.ml/.ga/.cf/.gq)
  if (result.isFreeTLD) {
    add({
      type: "free_tld",
      label: "Free domain TLD",
      detail: `"${tld}" domains are available for free via Freenom — attackers register thousands for one-time phishing campaigns.`,
      risk: 20,
    });
  }

  // Lookalike brand
  if (result.lookalikeBrand) {
    const techLabel =
      {
        numeric_substitution: `numeric character substitution (e.g. "1" for "l", "0" for "o")`,
        hyphen_injection: `hyphen injection to break brand name`,
        brand_in_subdomain_or_path: `brand name embedded in subdomain or domain path`,
      }[result.lookalikeTechnique] || "lookalike domain";
    add({
      type: "brand_lookalike",
      label: `Lookalike: ${result.lookalikeBrand}`,
      detail: `Domain "${domain}" impersonates "${result.lookalikeBrand}" using ${techLabel}. Classic phishing/BEC technique.`,
      risk: 40,
    });
  }

  // Freenom domain
  if (result.isFreenomDomain) {
    add({
      type: "freenom_domain",
      label: "Freenom disposable domain",
      detail: `NS records indicate this is a Freenom free domain — typically used for short-term phishing campaigns.`,
      risk: 25,
    });
  }

  // Excessive hyphens (without brand match)
  if (result.hasExcessiveHyphens && !result.lookalikeBrand) {
    add({
      type: "excessive_hyphens",
      label: `Hyphen-heavy domain (${hyphenCount} hyphens)`,
      detail: `"${domain}" uses ${hyphenCount} hyphens — legitimate organizations rarely use hyphenated domains for email.`,
      risk: 15,
    });
  }

  // Very long domain
  if (result.isVeryLong) {
    add({
      type: "very_long_domain",
      label: "Unusually long domain",
      detail: `Domain is ${domain.length} characters — legitimate business domains are almost always under 30 characters.`,
      risk: 15,
    });
  }

  // Deep subdomain (secure.login.mail.paypal-fake.com)
  if (result.subdomainDepth > 2) {
    add({
      type: "deep_subdomain",
      label: `Deep subdomain (${result.subdomainDepth} levels)`,
      detail: `Domain has ${result.subdomainDepth} subdomain levels — attackers use this to put a legitimate-looking name at the start.`,
      risk: 20,
    });
  }

  // Cap domain risk at 80 to not overwhelm other signals
  result.domainRiskScore = Math.min(result.domainRiskScore, 80);

  DOMAIN_CACHE.set(domain, { ts: Date.now(), data: result });
  return result;
}

function extractTLD(domain) {
  if (!domain) return null;
  const parts = domain.split(".");
  if (parts.length < 2) return null;
  // Handle two-part TLDs like .co.in, .co.uk
  if (
    ["in", "uk", "au", "nz", "jp", "br", "za", "id"].includes(
      parts[parts.length - 1],
    ) &&
    parts.length >= 3 &&
    ["co", "com", "net", "org", "gov", "ac"].includes(parts[parts.length - 2])
  ) {
    return `.${parts[parts.length - 2]}.${parts[parts.length - 1]}`;
  }
  return `.${parts[parts.length - 1]}`;
}

// ── In-memory geo cache (30 min TTL) ─────────────────────────
const GEO_CACHE = new Map();
const GEO_CACHE_TTL = 30 * 60 * 1000; // 30 minutes

// Known datacenter/hosting ASN prefixes (free check, no API needed)
const DATACENTER_ASNS = new Set([
  "AS14061",
  "AS16509",
  "AS15169",
  "AS396982", // DigitalOcean, AWS, Google Cloud
  "AS14618",
  "AS16276",
  "AS63949",
  "AS20473", // AWS alt, OVH, Linode, Vultr
  "AS13335",
  "AS209242",
  "AS8075",
  "AS8011", // Cloudflare, AWS alt, Microsoft, Akamai
  "AS136907",
  "AS9808",
  "AS45090", // Huawei, China Mobile, Tencent
  "AS7552",
  "AS45899",
  "AS55836",
  "AS132203", // VN ISPs commonly used for relay abuse
]);

// Known TOR exit node indicator (simplified — check hostname/org string)
const TOR_INDICATORS = [
  "torservers",
  "tor-exit",
  "exit-node",
  "tor.node",
  "torexit",
  "dan.me.uk",
];
// Known VPN provider keywords in org name
const VPN_INDICATORS = [
  "nordvpn",
  "expressvpn",
  "mullvad",
  "protonvpn",
  "hidemyass",
  "cyberghost",
  "ipvanish",
  "privateinternetaccess",
  "pia",
  "surfshark",
  "windscribe",
  "vyprvpn",
  "tunnelbear",
  "strongvpn",
  "torguard",
  "ivpn",
  "perfect-privacy",
];

// RFC1918 + loopback private IP check
function isPrivateIP(ip) {
  if (!ip) return true;
  return (
    /^10\./.test(ip) ||
    /^172\.(1[6-9]|2\d|3[01])\./.test(ip) ||
    /^192\.168\./.test(ip) ||
    /^127\./.test(ip) ||
    /^::1$/.test(ip) ||
    /^fc00:/i.test(ip) ||
    /^fe80:/i.test(ip)
  );
}

function buildGeoFallback(ip) {
  return {
    ip,
    country: null,
    countryCode: null,
    region: null,
    city: null,
    isp: null,
    org: null,
    asn: null,
    asnCode: null,
    isVPN: false,
    isTor: false,
    isDatacenter: false,
    isProxy: false,
    isMobile: false,
    isPrivate: false,
    abuseRisk: "unknown",
    geoSource: "unavailable",
  };
}

// ── IP Geolocation via ip-api.com (free, 45 req/min, no key) ──
async function emailIPGeolocate(ip) {
  if (!ip || ip === "unknown" || isPrivateIP(ip)) {
    return {
      ip,
      country: null,
      countryCode: null,
      region: null,
      city: null,
      isp: null,
      org: null,
      asn: null,
      isVPN: false,
      isTor: false,
      isDatacenter: false,
      isPrivate: isPrivateIP(ip),
      abuseRisk: "none",
      geoSource: "private_or_unknown",
    };
  }

  // Check cache
  const cached = GEO_CACHE.get(ip);
  if (cached && Date.now() - cached.ts < GEO_CACHE_TTL) return cached.data;

  return new Promise((resolve) => {
    const url = `http://ip-api.com/json/${ip}?fields=status,country,countryCode,region,regionName,city,zip,lat,lon,isp,org,as,proxy,hosting,mobile&lang=en`;

    const req = http.get(url, (res) => {
      let body = "";
      res.on("data", (c) => (body += c));
      res.on("end", () => {
        try {
          const d = JSON.parse(body);
          if (d.status !== "success") return resolve(buildGeoFallback(ip));

          const asnStr = d.as || "";
          const asnCode = asnStr.split(" ")[0]; // e.g. "AS14061"
          const orgLower = (d.org || "").toLowerCase();
          const ispLower = (d.isp || "").toLowerCase();

          const isDatacenter =
            d.hosting === true || DATACENTER_ASNS.has(asnCode);
          const isTor = TOR_INDICATORS.some(
            (t) => orgLower.includes(t) || ispLower.includes(t),
          );
          const isVPN =
            d.proxy === true ||
            VPN_INDICATORS.some(
              (v) => orgLower.includes(v) || ispLower.includes(v),
            );

          // Determine abuse risk label
          let abuseRisk = "low";
          if (isTor) abuseRisk = "critical";
          else if (isVPN) abuseRisk = "high";
          else if (isDatacenter) abuseRisk = "medium";
          else if (d.mobile === true) abuseRisk = "low"; // mobile IPs are normal

          const result = {
            ip,
            country: d.country || null,
            countryCode: d.countryCode || null,
            region: d.regionName || null,
            city: d.city || null,
            lat: d.lat || null,
            lon: d.lon || null,
            isp: d.isp || null,
            org: d.org || null,
            asn: asnStr || null,
            asnCode,
            isVPN,
            isTor,
            isDatacenter,
            isMobile: d.mobile || false,
            isProxy: d.proxy || false,
            isPrivate: false,
            abuseRisk,
            geoSource: "ip-api.com",
            cachedAt: new Date().toISOString(),
          };

          GEO_CACHE.set(ip, { ts: Date.now(), data: result });
          resolve(result);
        } catch {
          resolve(buildGeoFallback(ip));
        }
      });
    });

    req.on("error", () => resolve(buildGeoFallback(ip)));
    req.setTimeout(4000, () => {
      req.destroy();
      resolve(buildGeoFallback(ip));
    });
  });
}

/**
 * parseRelayChain(rawHeaders)
 * Parses all "Received:" headers from a raw email header block.
 * Returns structured relay hops ordered oldest → newest (origin first).
 */
function parseRelayChain(rawHeaders) {
  const empty = { hops: [], anomalies: [], relayRiskBoost: 0 };
  if (!rawHeaders || typeof rawHeaders !== "string") return empty;

  // Extract all Received headers (multi-line headers are joined)
  // Received headers are stacked newest-first (last hop at top)
  const receivedBlocks = [];
  const lines = rawHeaders.split(/\r?\n/);
  let current = null;

  for (const line of lines) {
    if (/^Received:/i.test(line)) {
      if (current) receivedBlocks.push(current);
      current = line;
    } else if (current && /^\s+/.test(line)) {
      current += " " + line.trim();
    } else {
      if (current) {
        receivedBlocks.push(current);
        current = null;
      }
    }
  }
  if (current) receivedBlocks.push(current);

  if (!receivedBlocks.length) return empty;

  const hops = receivedBlocks.map((block, index) => {
    const hop = {
      hopNumber: receivedBlocks.length - index, // newest = highest number
      raw: block,
      fromHost: null,
      fromIP: null,
      byHost: null,
      byIP: null,
      protocol: null,
      timestamp: null,
      timestampMs: null,
      delayMs: null,
      delayFormatted: null,
      isLocalhost: false,
      isPrivateIP: false,
      anomalies: [],
    };

    const fromMatch = block.match(/from\s+([^\s(]+)(?:\s+\(([^)]+)\))?/i);
    if (fromMatch) {
      hop.fromHost = fromMatch[1] || null;
      const parenContent = fromMatch[2] || "";
      const ipInParen = parenContent.match(/\[([^\]]+)\]/);
      hop.fromIP = ipInParen?.[1] || extractIPFromString(parenContent) || null;
    }

    const byMatch = block.match(/by\s+([^\s(]+)(?:\s+\([^)]*\))?/i);
    if (byMatch) hop.byHost = byMatch[1] || null;

    const byIPMatch = block.match(/by\s+\S+\s+\(([^)]+\[([^\]]+)\])/i);
    if (byIPMatch) hop.byIP = byIPMatch[2] || null;

    const protoMatch = block.match(/with\s+(E?SMTPS?A?|LMTP|HTTP|HTTPS)/i);
    if (protoMatch) hop.protocol = protoMatch[1].toUpperCase();

    const tsMatch = block.match(/;\s*(.+)$/);
    if (tsMatch) {
      const tsStr = tsMatch[1].trim();
      hop.timestamp = tsStr;
      const parsed = new Date(tsStr);
      if (!isNaN(parsed.getTime())) hop.timestampMs = parsed.getTime();
    }

    if (hop.fromHost && /^localhost$/i.test(hop.fromHost))
      hop.isLocalhost = true;
    if (hop.fromIP && isPrivateIP(hop.fromIP)) hop.isPrivateIP = true;

    return hop;
  });

  hops.reverse();

  const anomalies = [];
  let relayRiskBoost = 0;

  for (let i = 0; i < hops.length; i++) {
    const hop = hops[i];
    const prev = i > 0 ? hops[i - 1] : null;

    if (prev?.timestampMs && hop.timestampMs) {
      hop.delayMs = hop.timestampMs - prev.timestampMs;
      hop.delayFormatted = formatDelay(hop.delayMs);

      if (hop.delayMs < -60000) {
        hop.anomalies.push({
          type: "time_travel",
          label: "Timestamp goes backwards",
          detail: `Hop ${i + 1} timestamp is ${formatDelay(Math.abs(hop.delayMs))} EARLIER than hop ${i}. This indicates a forged Received header.`,
          risk: 35,
        });
        relayRiskBoost += 35;
      }

      if (hop.delayMs > 2 * 60 * 60 * 1000) {
        hop.anomalies.push({
          type: "suspicious_delay",
          label: "Unusual hop delay",
          detail: `${formatDelay(hop.delayMs)} delay between hops — email may have been held in a queue or relay server for delayed delivery (common in phishing campaigns).`,
          risk: 10,
        });
        relayRiskBoost += 10;
      }
    }

    if (i > 0 && hop.isLocalhost) {
      hop.anomalies.push({
        type: "localhost_injection",
        label: "localhost in mid-chain",
        detail: `"from localhost" appearing at hop ${i + 1} (not the first hop) indicates a forged Received header was injected by the attacker.`,
        risk: 40,
      });
      relayRiskBoost += 40;
    }

    if (!hop.fromHost && !hop.fromIP && i === 0) {
      hop.anomalies.push({
        type: "missing_from",
        label: "No originating host",
        detail:
          "First Received header has no 'from' clause — the sending server intentionally omitted its identity.",
        risk: 20,
      });
      relayRiskBoost += 20;
    }

    if (hop.fromHost && hop.fromIP && !hop.isPrivateIP) {
      const ipInHostname = hop.fromHost.match(
        /(\d{1,3}[.-]\d{1,3}[.-]\d{1,3}[.-]\d{1,3})/,
      );
      if (ipInHostname) {
        hop.anomalies.push({
          type: "ip_hostname_mismatch",
          label: "Reverse-DNS hostname pattern",
          detail: `Sending hostname "${hop.fromHost}" appears to be a dynamic/residential IP reverse DNS — not a dedicated mail server.`,
          risk: 10,
        });
        relayRiskBoost += 10;
      }
    }

    anomalies.push(...hop.anomalies);
  }

  return { hops, anomalies, relayRiskBoost };
}

function formatDelay(ms) {
  if (ms < 0) return `${Math.abs(Math.round(ms / 1000))}s (negative)`;
  if (ms < 60000) return `${Math.round(ms / 1000)}s`;
  if (ms < 3600000) return `${Math.round(ms / 60000)}m`;
  const h = Math.floor(ms / 3600000);
  const m = Math.round((ms % 3600000) / 60000);
  return m > 0 ? `${h}h ${m}m` : `${h}h`;
}

function extractIPFromString(str) {
  const match = str?.match(/\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/);
  return match?.[1] || null;
}

function parseHeaders(raw) {
  const headers = {};
  const lines = raw.replace(/\r\n/g, "\n").split("\n");
  let current = "";

  for (const line of lines) {
    if (/^\s/.test(line) && current) {
      headers[current] += " " + line.trim();
    } else {
      const m = line.match(/^([^:]+):\s*(.*)$/);
      if (m) {
        current = m[1].toLowerCase().trim();
        headers[current] = m[2].trim();
      }
    }
  }
  return headers;
}

function extractIP(str) {
  const m = str?.match(/\b(\d{1,3}(?:\.\d{1,3}){3})\b/);
  return m ? m[1] : null;
}

function extractDomain(email) {
  const m = (email || "").match(/@([^\s>]+)/);
  return m ? m[1].toLowerCase() : null;
}

async function analyzeEmailHeaders(rawHeaders) {
  const issues = [];
  const signals = [];
  let score = 0;

  const h = parseHeaders(rawHeaders);

  // ── 1. SPF check ──
  const spf = h["received-spf"] || h["authentication-results"] || "";
  if (/spf=fail/i.test(spf)) {
    score += 40;
    issues.push("SPF FAIL — sender IP not authorized to send for this domain");
    signals.push({ label: "SPF", value: "FAIL", color: "#ff4444" });
  } else if (/spf=softfail/i.test(spf)) {
    score += 20;
    issues.push("SPF SoftFail — sender may not be authorized");
    signals.push({ label: "SPF", value: "SOFTFAIL", color: "#f5a623" });
  } else if (/spf=pass/i.test(spf)) {
    signals.push({ label: "SPF", value: "PASS", color: "#00ff88" });
  } else {
    score += 10;
    signals.push({ label: "SPF", value: "NONE", color: "#8b95a8" });
  }

  // ── 2. DKIM check ──
  const dkim = h["authentication-results"] || "";
  if (/dkim=fail/i.test(dkim)) {
    score += 35;
    issues.push("DKIM FAIL — email signature invalid, message may be tampered");
    signals.push({ label: "DKIM", value: "FAIL", color: "#ff4444" });
  } else if (/dkim=pass/i.test(dkim)) {
    signals.push({ label: "DKIM", value: "PASS", color: "#00ff88" });
  } else {
    score += 8;
    signals.push({ label: "DKIM", value: "NONE", color: "#8b95a8" });
  }

  // ── 3. DMARC check ──
  if (/dmarc=fail/i.test(dkim)) {
    score += 30;
    issues.push("DMARC FAIL — email fails domain alignment policy");
    signals.push({ label: "DMARC", value: "FAIL", color: "#ff4444" });
  } else if (/dmarc=pass/i.test(dkim)) {
    signals.push({ label: "DMARC", value: "PASS", color: "#00ff88" });
  } else {
    signals.push({ label: "DMARC", value: "NONE", color: "#8b95a8" });
  }

  // ── 4. From vs Reply-To mismatch ──
  const fromDomain = extractDomain(h["from"] || "");
  const replyToDomain = extractDomain(h["reply-to"] || "");
  if (fromDomain && replyToDomain && fromDomain !== replyToDomain) {
    score += 35;
    issues.push(
      `Reply-To mismatch — From: ${fromDomain} → Reply-To: ${replyToDomain}`,
    );
  }

  // ── 5. Display name spoofing ──
  const fromField = h["from"] || "";
  const displayMatch = fromField.match(/^"?([^"<]+)"?\s*</);
  const majorBrands = [
    "paypal",
    "google",
    "amazon",
    "apple",
    "microsoft",
    "netflix",
    "bank",
    "irs",
    "chase",
  ];
  if (displayMatch) {
    const display = displayMatch[1].toLowerCase();
    if (
      majorBrands.some((b) => display.includes(b)) &&
      fromDomain &&
      !majorBrands.some((b) => fromDomain.includes(b))
    ) {
      score += 45;
      issues.push(
        `Display name spoofing — claims to be "${displayMatch[1].trim()}" but domain is "${fromDomain}"`,
      );
    }
  }

  // ── 6. Originating IP extraction ──
  const originatingIP = extractIP(h["x-originating-ip"] || "");
  const receivedIP = extractIP(h["received"] || "");
  const sourceIP = originatingIP || receivedIP;

  // ── Geolocate the originating IP ─────────────────────────────
  const sourceGeo = await emailIPGeolocate(sourceIP);
  const ipReputation = await checkIPReputation(sourceIP, {
    geoData: sourceGeo,
    senderDomain: fromDomain,
  }).catch(() => null);

  // Add reputation-based risk
  if (ipReputation) {
    if (ipReputation.isTorExitNode) {
      score += 50;
      issues.push(
        `Source IP ${sourceIP} is a confirmed TOR exit node — sender is anonymizing origin. Attribution nearly impossible.`,
      );
      signals.push({ label: "TOR", value: "EXIT NODE", color: "#ff0000" });
    } else if (ipReputation.isBotnet) {
      score += 40;
      issues.push(
        `Source IP ${sourceIP} is in ${ipReputation.dnsblHits[0]?.list} as a botnet-infected host — email likely sent from compromised machine.`,
      );
      signals.push({
        label: "BOTNET",
        value: "INFECTED HOST",
        color: "#f87171",
      });
    } else if (ipReputation.isKnownSpamSource) {
      score += 30;
      issues.push(
        `Source IP ${sourceIP} is blacklisted by ${ipReputation.dnsblHits.map((h) => h.list).join(", ")} as a known spam source.`,
      );
      signals.push({
        label: "DNSBL",
        value: `BLACKLISTED x${ipReputation.dnsblHits.length}`,
        color: "#f87171",
      });
    }
    if (ipReputation.seenInScans > 5) {
      score += 15;
      issues.push(
        `Repeat offender: IP ${sourceIP} has appeared in ${ipReputation.seenInScans} PhishNetra scans — persistent threat actor.`,
      );
    }
  }

  // High-risk country signal (common phishing origins — add/remove as needed)
  const HIGH_RISK_COUNTRIES = new Set([
    "NG",
    "RO",
    "UA",
    "RU",
    "CN",
    "VN",
    "PH",
    "ID",
    "TR",
    "PK",
  ]);
  if (
    sourceGeo.countryCode &&
    HIGH_RISK_COUNTRIES.has(sourceGeo.countryCode) &&
    !sourceGeo.isPrivate
  ) {
    // Only flag if SPF also failed (don't flag just for country alone)
    const spfFailed = signals.some(
      (s) => s.label === "SPF" && s.value === "FAIL",
    );
    if (spfFailed) {
      score += 10;
      issues.push(
        `Email origin country (${sourceGeo.country}) combined with SPF failure raises risk`,
      );
    }
  }

  // ── Domain Intelligence Check ────────────────────────────────
  const domainIntel = await analyzeDomainIntel(fromDomain);
  if (domainIntel) {
    score += domainIntel.domainRiskScore;
    for (const anomaly of domainIntel.domainAnomalies) {
      issues.push(`Domain intel: ${anomaly.label} — ${anomaly.detail}`);
    }
    if (domainIntel.lookalikeBrand) {
      signals.push({
        label: "LOOKALIKE",
        value: domainIntel.lookalikeBrand.toUpperCase(),
        color: "#f87171",
      });
    }
    if (domainIntel.isHighRiskTLD) {
      signals.push({
        label: "TLD",
        value: `HIGH RISK ${domainIntel.tld}`,
        color: "#fb923c",
      });
    }
  }

  // ── 7. Full relay chain reconstruction ───────────────────────
  const {
    hops: relayHops,
    anomalies: relayAnomalies,
    relayRiskBoost,
  } = parseRelayChain(rawHeaders);

  // ── GAP 5: MX Record Validation + Live SPF Cross-Check ───────
  const mxValidation = await validateMXAndSPF(
    fromDomain,
    sourceIP,
    relayHops || [],
  );
  if (mxValidation) {
    score += mxValidation.mxRiskScore;
    for (const anomaly of mxValidation.anomalies) {
      issues.push(`MX/SPF: ${anomaly.label} — ${anomaly.detail}`);
    }
    if (mxValidation.spfLiveResult === "fail") {
      // Override or reinforce the header-based SPF signal
      signals.push({ label: "SPF LIVE", value: "FAIL", color: "#ff0000" });
    } else if (mxValidation.spfLiveResult === "pass") {
      signals.push({ label: "SPF LIVE", value: "PASS", color: "#34d399" });
    }
  }
  const receivedHeaders = rawHeaders.match(/^Received:.*$/gim) || [];

  if (relayRiskBoost > 0) score += Math.min(relayRiskBoost, 50);

  if (relayHops.length > 8) {
    score += 15;
    issues.push(
      `Excessive relay hops (${relayHops.length}) — unusual routing, possible obfuscation`,
    );
  }

  for (const anomaly of relayAnomalies) {
    issues.push(`Relay chain: ${anomaly.label} — ${anomaly.detail}`);
  }

  // ── 8. Message-ID anomaly ──
  const msgId = h["message-id"] || "";
  if (!msgId) {
    score += 15;
    issues.push("Missing Message-ID — legitimate servers always add this");
  } else if (/^\d{10,}@/i.test(msgId.replace(/[<>]/g, ""))) {
    score += 10;
    issues.push("Auto-generated Message-ID pattern — possible bulk mailer");
  }

  // ── 9. Bulk mailer indicators ──
  if (
    h["x-mailer"]?.toLowerCase().includes("mass") ||
    h["precedence"] === "bulk"
  ) {
    score += 10;
    issues.push("Bulk mailer indicator in headers");
  }

  // ── 10. X-Spam header ──
  if (/yes/i.test(h["x-spam-status"] || "")) {
    score += 20;
    issues.push("X-Spam-Status: YES — marked as spam by receiving server");
  }

  // ── GAP 12: AI-generated text detection on subject + body snippet ──
  // Some headers carry a partial body (X-Original-Message, etc.).
  // Even subject-line analysis alone fires on over-formal AI phrasing.
  const subjectLine = h["subject"] || "";
  const bodySnippet =
    h["x-original-message"] ||
    h["x-ms-exchange-organization-originalarrivaltime"] ||
    h["x-original-body"] ||
    "";
  const textForAI = [subjectLine, bodySnippet].filter(Boolean).join("\n");
  const aiDetection =
    textForAI.length >= 80 ? detectAIGeneratedText(textForAI) : null;

  // Boost risk score if AI-generated phishing is likely
  if (aiDetection && aiDetection.aiProbability >= 35) {
    score += aiDetection.riskBoost;
    issues.push(
      `AI-Generated Content (${aiDetection.aiProbability}% — ${aiDetection.verdictLabel}): ` +
        `${aiDetection.signals?.filter((s) => s.weight > 0).length || 0} linguistic signals fired. ` +
        (aiDetection.fingerprintPhrases?.length
          ? `Phrases: "${aiDetection.fingerprintPhrases[0]}"`
          : ""),
    );
  }

  const finalScore = Math.min(score, 100);
  let status;
  if (finalScore >= 66) status = "phishing";
  else if (finalScore >= 30) status = "suspicious";
  else status = "safe";

  return {
    status,
    riskScore: finalScore,
    issues,
    signals, // SPF/DKIM/DMARC badges

    // ── Origin Intelligence (NEW) ──
    sourceIP,
    sourceGeo, // Full geo object: country, city, isp, isVPN, isTor etc.
    ipReputation, // Full IP reputation object with DNSBL hits
    domainIntel, // Full domain intelligence object
    mxValidation, // Full MX/SPF validation object
    originType: sourceGeo.isTor
      ? "tor"
      : sourceGeo.isVPN
        ? "vpn"
        : sourceGeo.isDatacenter
          ? "datacenter"
          : sourceGeo.isMobile
            ? "mobile"
            : sourceGeo.isPrivate
              ? "private_network"
              : "residential",

    // Attribution confidence (0-100) — multi-signal engine (GAP 10)
    attribution: buildAttributionScore({
      sourceIP,
      sourceGeo,
      ipReputation,
      domainIntel,
      mxValidation,
      relayAnomalies,
      fromDomain,
      replyToDomain,
      riskScore: finalScore,
      status,
    }),
    // Backwards-compatible simple field — now sourced from attribution engine
    attributionConfidence: null, // see attribution.confidence

    // ── GAP 12 ──
    aiDetection:
      aiDetection && aiDetection.aiProbability >= 35 ? aiDetection : null,

    // ── Existing fields ──
    fromDomain,
    replyToDomain,
    hops: relayHops.length || receivedHeaders.length,
    relayChain: relayHops,
    relayAnomalies,
    relayRiskBoost,
    headers: Object.keys(h).length,
    inputType: "email_header",
    confidence: finalScore >= 60 ? "high" : finalScore >= 30 ? "medium" : "low",
    detectionVersion: "5.2",
    mlEnabled: false,
    mlScore: null,
    ruleScore: finalScore,
  };
}

module.exports = {
  analyzeEmailHeaders,
  emailIPGeolocate,
  analyzeDomainIntel,
  isPrivateIP,
  validateMXAndSPF,
};
