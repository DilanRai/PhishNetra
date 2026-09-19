// FILE: backend/services/urlPreview.js — FULL REPLACEMENT
// Sandbox v2 — significantly expanded real-world phishing detection
// Added: TLS certificate inspection, JS obfuscation depth, HTML entropy,
//        full link extraction, credential-harvesting URL parameter detection,
//        IP geolocation anomaly, evasion detection, expanded kit signatures
// All passive analysis — no code execution, no form submission, no cookies

const axios  = require("axios");
const tls    = require("tls");
const crypto = require("crypto");
const geoip  = require("geoip-lite");

const { identifyKitFromHTML } = (() => {
  try { return require("./kitFingerprint"); }
  catch { return { identifyKitFromHTML: () => null }; }
})();

// ── Sandboxed request headers — minimal fingerprint ──
const SANDBOX_HEADERS = {
  "User-Agent":      "Mozilla/5.0 (compatible; PhishNetra/5.0; +https://PhishNetra.ai)",
  Accept:            "text/html,application/xhtml+xml,application/xml;q=0.9",
  "Accept-Language": "en-US,en;q=0.5",
  DNT:               "1",
  "Sec-Fetch-Mode":  "navigate",
  "Cache-Control":   "no-cache",
  Pragma:            "no-cache",
};

// ── Brand list — used for mismatch detection ──
const SAFE_BRANDS = [
  "paypal","google","amazon","apple","microsoft","netflix","facebook",
  "instagram","twitter","linkedin","bank","chase","wellsfargo","irs",
  "fedex","dhl","ups","whatsapp","coinbase","dropbox","spotify","youtube",
  "tiktok","hsbc","barclays","citibank","amex","americanexpress","usps",
  "usaa","schwab","fidelity","robinhood","binance","kraken","discord","steam",
  "epicgames","roblox","adobe","slack","shopify","ebay","airbnb","booking",
  "docusign","zoom","okta","salesforce","twilio",
];

// ── TLDs commonly abused for phishing (free/cheap) ──
const HIGH_ABUSE_TLDS = [
  ".tk",".ml",".ga",".cf",".gq",".top",".xyz",".icu",
  ".sbs",".cyou",".cfd",".click",".live",".vip",".men",
  ".work",".loan",".date",".faith",".party",".review",".win",
];

// ── URL shortener domains (redirect-chain evasion) ──
const URL_SHORTENERS = new Set([
  "bit.ly","tinyurl.com","t.co","goo.gl","ow.ly","is.gd",
  "buff.ly","rebrand.ly","rb.gy","short.io","soo.gd",
  "bl.ink","tiny.one","cutt.ly","shorturl.at","clck.ru",
  "qr.ae","yourls.org","v.gd","bitly.com",
]);

// ── Expanded technology + kit signatures ──
const TECH_SIGNATURES = [
  // Phishing kit markers
  { name:"16Shop Kit",           pattern:/16shop|apple-phish|iCloud_phish/i,                                    category:"phishing_kit",  risk:"critical" },
  { name:"EvilProxy",            pattern:/evilproxy|modlishka|evilginx/i,                                       category:"phishing_kit",  risk:"critical" },
  { name:"BlackHole Kit",        pattern:/blackhole|bhole_kit/i,                                                 category:"phishing_kit",  risk:"critical" },
  { name:"PHPMailer Exfil",      pattern:/PHPMailer|phpmailer|sendmail\.php/i,                                  category:"phishing_kit",  risk:"critical" },
  { name:"W3LL Panel",           pattern:/w3ll|W3LL|w3-panel/i,                                                 category:"phishing_kit",  risk:"critical" },
  { name:"Caffeine Kit",         pattern:/caffeine-phish|caff_kit/i,                                            category:"phishing_kit",  risk:"critical" },
  { name:"Telegram Bot Exfil",   pattern:/api\.telegram\.org\/bot[0-9]+:/i,                                     category:"phishing_kit",  risk:"critical" },
  { name:"Discord Webhook Exfil",pattern:/discord\.com\/api\/webhooks\/\d+\//i,                                 category:"phishing_kit",  risk:"critical" },

  // JavaScript obfuscation — expanded
  { name:"eval(unescape) Obfuscation",  pattern:/eval\(unescape/i,                                             category:"obfuscation",   risk:"high" },
  { name:"eval(atob) Obfuscation",      pattern:/eval\(atob/i,                                                 category:"obfuscation",   risk:"high" },
  { name:"Hex CharCode Array",          pattern:/String\.fromCharCode\(\d{2,3},\d{2,3},\d{2,3},\d{2,3}/i,     category:"obfuscation",   risk:"high" },
  { name:"_0x Hex Variable Encoding",   pattern:/_0x[0-9a-f]{4,}\s*[\(\[]/i,                                  category:"obfuscation",   risk:"high" },
  { name:"p,a,c,k,e,d Packer",         pattern:/\beval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k/i,  category:"obfuscation",   risk:"high" },
  { name:"document.write(unescape)",    pattern:/document\.write\s*\(\s*unescape\s*\(/i,                       category:"obfuscation",   risk:"high" },
  { name:"Base64 Payload Decode",       pattern:/atob\(['"][A-Za-z0-9+\/]{50,}['"]\)/i,                        category:"obfuscation",   risk:"high" },
  { name:"Large Obfuscated Array",      pattern:/var\s+\w+\s*=\s*\[(?:'[^']{0,5}',){30,}/i,                   category:"obfuscation",   risk:"high" },

  // Redirect signals
  { name:"window.location Redirect",    pattern:/<script[^>]*>[\s\S]{0,200}window\.location\s*=/i,            category:"redirect",      risk:"high" },
  { name:"Meta Refresh Redirect",       pattern:/<meta[^>]+http-equiv=['"]refresh['"]/i,                       category:"redirect",      risk:"medium" },
  { name:"location.replace Redirect",   pattern:/location\.replace\s*\(\s*['"]https?:/i,                      category:"redirect",      risk:"high" },
  { name:"document.location Redirect",  pattern:/document\.location\s*=\s*['"]https?:/i,                      category:"redirect",      risk:"high" },

  // Anti-analysis evasion
  { name:"Reverse Tabnabbing",          pattern:/target=['"]_blank['"][^>]*rel(?:=|=['"])[^>]*(?!noopener)/i, category:"evasion",       risk:"medium" },
  { name:"Right-Click Disable",         pattern:/oncontextmenu\s*=\s*['"]return\s+false/i,                    category:"evasion",       risk:"medium" },
  { name:"DevTools Detection",          pattern:/debugger\s*;[\s\S]{0,100}debugger\s*;/i,                     category:"evasion",       risk:"medium" },
  { name:"Headless Browser Detection",  pattern:/navigator\.webdriver|phantom|headless/i,                     category:"evasion",       risk:"high"   },
  { name:"Security Researcher Block",   pattern:/window\._phantom|callPhantom|__nightmare/i,                  category:"evasion",       risk:"high"   },
  { name:"Geofencing Detection",        pattern:/ip(?:info|api|stack)\.(?:io|com|net).*country/i,             category:"evasion",       risk:"medium" },
  { name:"Bot Detection",               pattern:/isBot|bot_detect|checkBot|botcheck/i,                        category:"evasion",       risk:"medium" },

  // Credential harvesting URL parameters (AiTM/kit patterns)
  { name:"Base64 Victim Email Param",   pattern:/[?&][a-z]{1,3}=[a-zA-Z0-9+\/]{30,}={0,2}(?:&|$)/,          category:"aitm",          risk:"critical" },
  { name:"Pre-filled Email Param",      pattern:/[?&](?:email|mail|user|login)=[^&]{6,}/i,                    category:"aitm",          risk:"high" },
  { name:"AiTM Session Token",          pattern:/[?&](?:session|token|sess|sid)=[a-zA-Z0-9]{25,}/i,           category:"aitm",          risk:"high" },

  // Legitimate tech (reduce false positives)
  { name:"WordPress",           pattern:/wp-content|wp-includes|wordpress/i,                                   category:"cms",           risk:"low" },
  { name:"Shopify",             pattern:/shopify|myshopify\.com/i,                                             category:"ecommerce",     risk:"low" },
  { name:"Bootstrap",           pattern:/bootstrap\.min\.css|cdn\.jsdelivr\.net\/npm\/bootstrap/i,             category:"framework",     risk:"low" },
  { name:"jQuery",              pattern:/jquery\.min\.js|jquery-\d+\.\d+/i,                                    category:"framework",     risk:"low" },
  { name:"React",               pattern:/react\.development|react\.production|__REACT/i,                       category:"framework",     risk:"low" },
  { name:"Cloudflare CDN",      pattern:/cloudflare|__cf_bm|cf-ray/i,                                         category:"cdn",           risk:"low" },
  { name:"Google Analytics",    pattern:/gtag\(|ga\('send'|google-analytics\.com/i,                           category:"analytics",     risk:"low" },
];

// ── Shannon entropy calculator ──
// High entropy = heavily obfuscated content
function calculateEntropy(str) {
  if (!str || str.length === 0) return 0;
  const freq = {};
  for (const c of str) freq[c] = (freq[c] || 0) + 1;
  const len = str.length;
  return -Object.values(freq).reduce((sum, f) => {
    const p = f / len;
    return sum + p * Math.log2(p);
  }, 0);
}

// Extract inline JS blocks and compute their entropy
// A legit site's JS has entropy ~3.5-4.5; obfuscated kit JS is often 5.0+
function analyzeJsEntropy(html) {
  const scripts = [];
  const scriptRegex = /<script[^>]*>([\s\S]*?)<\/script>/gi;
  let match;
  while ((match = scriptRegex.exec(html)) !== null) {
    const content = match[1].trim();
    if (content.length < 50) continue; // skip tiny event handlers
    const entropy = calculateEntropy(content);
    scripts.push({ length: content.length, entropy: parseFloat(entropy.toFixed(3)) });
  }
  if (scripts.length === 0) return { maxEntropy: 0, avgEntropy: 0, highEntropyBlocks: 0 };
  const entropies = scripts.map(s => s.entropy);
  const maxEntropy = Math.max(...entropies);
  const avgEntropy = entropies.reduce((a,b) => a+b,0) / entropies.length;
  const highEntropyBlocks = scripts.filter(s => s.entropy > 5.0).length;
  return {
    maxEntropy:        parseFloat(maxEntropy.toFixed(3)),
    avgEntropy:        parseFloat(avgEntropy.toFixed(3)),
    highEntropyBlocks,
    totalScriptBlocks: scripts.length,
  };
}

// ── Link extraction + analysis ──
function extractAndAnalyzeLinks(html, pageDomain) {
  const links = [];
  const srcHrefRegex = /(?:href|src|action)\s*=\s*['"]([^'"]{4,500})['"]/gi;
  let match;
  const seen = new Set();
  while ((match = srcHrefRegex.exec(html)) !== null) {
    const raw = match[1].trim();
    if (seen.has(raw) || raw.startsWith("#") || raw.startsWith("data:")) continue;
    seen.add(raw);
    let external = false;
    let domain = null;
    try {
      const base = raw.startsWith("http") ? raw : `https://${pageDomain}/${raw}`;
      domain = new URL(base).hostname.replace(/^www\./, "");
      external = domain !== pageDomain;
    } catch {}
    links.push({ url: raw.substring(0, 200), external, domain });
  }

  const externalLinks = links.filter(l => l.external);
  const externalDomains = [...new Set(externalLinks.map(l => l.domain).filter(Boolean))];
  const suspiciousDomains = externalDomains.filter(d =>
    HIGH_ABUSE_TLDS.some(tld => d.endsWith(tld)) ||
    URL_SHORTENERS.has(d)
  );

  return {
    totalLinks:       links.length,
    externalLinks:    externalLinks.length,
    externalDomains:  externalDomains.slice(0, 10),
    suspiciousDomains:suspiciousDomains.slice(0, 5),
    hasShortenerLink: externalDomains.some(d => URL_SHORTENERS.has(d)),
  };
}

// ── TLS certificate inspection ──
async function inspectTLSCertificate(hostname, port = 443) {
  return new Promise((resolve) => {
    const timeout = setTimeout(() => resolve(null), 5000);
    try {
      const socket = tls.connect(port, hostname, {
        servername:  hostname,
        rejectUnauthorized: false, // we want to inspect even bad certs
        timeout:     4000,
      }, () => {
        clearTimeout(timeout);
        try {
          const cert   = socket.getPeerCertificate(true);
          const cipher = socket.getCipher();
          socket.destroy();
          if (!cert || !cert.subject) return resolve(null);

          const now         = Date.now();
          const validFrom   = new Date(cert.valid_from).getTime();
          const validTo     = new Date(cert.valid_to).getTime();
          const daysOld     = Math.floor((now - validFrom)  / (1000 * 86400));
          const daysLeft    = Math.floor((validTo  - now)   / (1000 * 86400));
          const issuerOrg   = cert.issuer?.O || "";
          const subjectCN   = cert.subject?.CN || "";
          const subjectOrg  = cert.subject?.O || "";
          const isLE        = issuerOrg.toLowerCase().includes("let's encrypt") ||
                              issuerOrg.toLowerCase().includes("letsencrypt");
          const isSelfSigned= cert.issuer?.CN === cert.subject?.CN;

          // Brand name in cert CN that doesn't match the hostname = spoofing
          const brandInCert = SAFE_BRANDS.find(b =>
            subjectCN.toLowerCase().includes(b) || subjectOrg.toLowerCase().includes(b)
          );
          const certDomain  = subjectCN.replace(/^\*\./, "");
          const certMismatch= brandInCert &&
            !hostname.includes(certDomain) &&
            !certDomain.includes(hostname);

          // Very new cert (< 30 days old) on a non-well-known domain = likely fresh phishing site
          const isVeryNew = daysOld < 30;

          // Wildcard cert on a cheap TLD = evasion technique
          const wildcardOnAbuseTLD = subjectCN.startsWith("*") &&
            HIGH_ABUSE_TLDS.some(t => hostname.endsWith(t));

          const signals = [];
          if (isSelfSigned)         signals.push("Self-signed certificate — no CA validation");
          if (isLE && isVeryNew)    signals.push(`Let's Encrypt cert only ${daysOld} days old — freshly registered phishing site`);
          if (certMismatch)         signals.push(`Certificate issued for "${certDomain}" but page claims to be "${brandInCert}"`);
          if (wildcardOnAbuseTLD)   signals.push(`Wildcard cert (${subjectCN}) on high-abuse TLD`);
          if (daysLeft < 0)         signals.push("Certificate is EXPIRED");
          if (daysLeft < 7 && daysLeft >= 0) signals.push(`Certificate expires in ${daysLeft} days`);

          resolve({
            subject:        subjectCN,
            issuer:         issuerOrg,
            validFrom:      cert.valid_from,
            validTo:        cert.valid_to,
            daysOld,
            daysLeft,
            isLetEncrypt:   isLE,
            isSelfSigned,
            isVeryNew,
            certMismatch:   certMismatch || false,
            claimedBrand:   brandInCert || null,
            wildcardOnAbuseTLD,
            cipher:         cipher?.name || null,
            signals,
            riskScore: (isSelfSigned ? 35 : 0) +
                       (isVeryNew && isLE ? 20 : 0) +
                       (certMismatch ? 40 : 0) +
                       (wildcardOnAbuseTLD ? 25 : 0) +
                       (daysLeft < 0 ? 30 : 0),
          });
        } catch {
          socket.destroy();
          resolve(null);
        }
      });
      socket.on("error", () => { clearTimeout(timeout); resolve(null); });
    } catch { clearTimeout(timeout); resolve(null); }
  });
}

// ── IP geolocation & abuse check ──
function analyzeIPGeolocation(ip) {
  if (!ip || ip === "::1" || ip === "127.0.0.1") return null;
  try {
    const geo = geoip.lookup(ip);
    if (!geo) return null;
    // Countries with historically high phishing infrastructure concentration
    // (based on APWG, Spamhaus, and cybercrime statistics)
    const HIGH_ABUSE_COUNTRIES = new Set([
      "RU","CN","NG","UA","RO","BR","IN","VN","ID","PH","KE","GH","PK","BD"
    ]);
    const isHighAbuse = HIGH_ABUSE_COUNTRIES.has(geo.country);
    return {
      ip, country: geo.country, region: geo.region, city: geo.city,
      isHighAbuseRegion: isHighAbuse,
      signal: isHighAbuse
        ? `Hosting IP (${ip}) resolves to ${geo.city || geo.country} — region with elevated phishing infrastructure`
        : null,
    };
  } catch { return null; }
}

// ── Form analysis ──
function analyzeFormStructure(html) {
  const forms = [];
  const formRegex = /<form[^>]*>([\s\S]*?)<\/form>/gi;
  let formMatch;
  while ((formMatch = formRegex.exec(html)) !== null) {
    const formHtml  = formMatch[0];
    const formInner = formMatch[1];
    const action    = (formHtml.match(/action=['"]([^'"]*)['"]/i) || [])[1] || null;
    const method    = (formHtml.match(/method=['"]([^'"]*)['"]/i) || [])[1]?.toUpperCase() || "GET";
    const passwordFields  = (formInner.match(/type=['"]password['"]/gi) || []).length;
    const emailFields     = (formInner.match(/type=['"](?:email|text)['"]/gi) || []).length;
    const inputFields     = (formInner.match(/<input[^>]+>/gi) || []).length;
    const submitButtons   = (formInner.match(/type=['"]submit['"]/gi) || []).length;
    const sensitiveAttrs  = formInner.match(
      /(?:name|placeholder|id)=['"][^'"]*(?:password|passwd|pass|pwd|credential|otp|pin|card|cvv|ssn|social|secret|token|auth|mfa|2fa)[^'"]*['"]/gi
    ) || [];
    let externalAction = false;
    if (action && action.startsWith("http")) {
      try { externalAction = action; } catch {}
    }
    const isCredentialHarvester = passwordFields >= 1 || sensitiveAttrs.length >= 1 ||
      (emailFields >= 1 && submitButtons >= 1 && inputFields <= 4);
    if (isCredentialHarvester || inputFields >= 2) {
      forms.push({
        hasPasswordField: passwordFields > 0, hasEmailField: emailFields > 0,
        passwordFieldCount: passwordFields, inputFieldCount: inputFields,
        submitButtonCount: submitButtons, sensitiveFieldCount: sensitiveAttrs.length,
        formAction: action, formMethod: method, externalAction: externalAction || null,
        isCredentialHarvester,
        suspicionScore: passwordFields * 30 + sensitiveAttrs.length * 20 +
          (externalAction ? 25 : 0) + (method === "POST" && passwordFields > 0 ? 10 : 0),
      });
    }
  }
  return forms;
}

// ── Redirect chain tracker ──
async function trackRedirectChain(url, maxHops = 6) {
  const chain = [];
  let current = url;
  let resolvedIP = null;
  for (let i = 0; i < maxHops; i++) {
    try {
      const res = await axios.get(current, {
        headers: SANDBOX_HEADERS, timeout: 4000, maxRedirects: 0,
        validateStatus: (s) => s < 600, withCredentials: false,
      });
      // Capture server IP from response headers if available
      const serverIP = res.headers?.["x-real-ip"] || res.headers?.["x-forwarded-for"]?.split(",")[0]?.trim();
      if (serverIP && !resolvedIP) resolvedIP = serverIP;

      // Check if hop is a URL shortener
      let hopDomain = null;
      try { hopDomain = new URL(current).hostname; } catch {}
      const isShortener = hopDomain && URL_SHORTENERS.has(hopDomain);
      chain.push({ url: current, statusCode: res.status, hop: i + 1, isShortener });
      if (res.status >= 300 && res.status < 400) {
        const location = res.headers?.location;
        if (!location) break;
        current = location.startsWith("http") ? location : new URL(location, current).href;
      } else break;
    } catch (err) {
      chain.push({ url: current, statusCode: null, error: "Failed", hop: i + 1 });
      break;
    }
  }
  const hasShortener = chain.some(h => h.isShortener);
  const crossDomain  = chain.length > 1 && (() => {
    try {
      return new URL(chain[0].url).hostname !== new URL(chain[chain.length-1].url).hostname;
    } catch { return false; }
  })();
  return {
    hops: chain.length, chain,
    finalUrl: chain[chain.length-1]?.url || url,
    hasRedirects: chain.length > 1, crossDomain, hasShortener, resolvedIP,
  };
}

// ── Meta extraction ──
function extractMeta(html) {
  const get = (p) => (html.match(p) || [])[1]?.trim() || null;
  return {
    title:       get(/<title[^>]*>([^<]{1,200})<\/title>/i),
    description: get(/<meta[^>]+name=["']description["'][^>]+content=["']([^"']{1,300})["']/i) ||
                 get(/<meta[^>]+content=["']([^"']{1,300})["'][^>]+name=["']description["']/i),
    ogTitle:     get(/<meta[^>]+property=["']og:title["'][^>]+content=["']([^"']{1,200})["']/i),
    ogDesc:      get(/<meta[^>]+property=["']og:description["'][^>]+content=["']([^"']{1,300})["']/i),
    ogImage:     get(/<meta[^>]+property=["']og:image["'][^>]+content=["']([^"']{1,500})["']/i),
    favicon:     get(/<link[^>]+rel=["'](?:shortcut )?icon["'][^>]+href=["']([^"']{1,300})["']/i),
    keywords:    get(/<meta[^>]+name=["']keywords["'][^>]+content=["']([^"']{1,200})["']/i),
    generator:   get(/<meta[^>]+name=["']generator["'][^>]+content=["']([^"']{1,100})["']/i),
    charset:     get(/<meta[^>]+charset=["']([^"']{1,30})["']/i),
    csp:         get(/<meta[^>]+http-equiv=["']Content-Security-Policy["'][^>]+content=["']([^"']{1,400})["']/i),
  };
}

// ── Technology detection ──
function detectTechnologies(html) {
  const detected = [];
  for (const tech of TECH_SIGNATURES) {
    if (tech.pattern.test(html)) {
      detected.push({ name: tech.name, category: tech.category, risk: tech.risk });
    }
  }
  return detected;
}

// ── Brand mismatch detection ──
function detectBrandMismatch(domain, title, description, ogTitle) {
  const extractBrand = (text) => {
    if (!text) return null;
    return SAFE_BRANDS.find(b => text.toLowerCase().includes(b)) || null;
  };
  const urlBrand    = extractBrand(domain);
  const titleBrand  = extractBrand(title) || extractBrand(ogTitle);
  const claimedBrand= titleBrand || extractBrand(description);
  if (claimedBrand && urlBrand && claimedBrand !== urlBrand)
    return { found:true, urlBrand, claimedBrand,
      message:`Page claims to be "${claimedBrand}" but domain is "${domain}"`, severity:"critical" };
  if (claimedBrand && !urlBrand)
    return { found:true, urlBrand:"unknown", claimedBrand,
      message:`Page impersonates "${claimedBrand}" on non-official domain`, severity:"high" };
  return null;
}

// ── Domain age / abuse TLD check ──
function analyzeDomain(domain) {
  const signals = [];
  let score = 0;
  const tld = "." + domain.split(".").pop();
  if (HIGH_ABUSE_TLDS.includes(tld)) {
    score += 20;
    signals.push(`High-abuse TLD: ${tld}`);
  }
  // Suspicious subdomain patterns
  if (/^(?:secure|login|account|verify|update|confirm|pay|auth|signin|billing)-/.test(domain)) {
    score += 15;
    signals.push(`Suspicious subdomain prefix: ${domain.split(".")[0]}`);
  }
  // Very long domain (common in evasion)
  if (domain.length > 40) {
    score += 10;
    signals.push(`Unusually long domain (${domain.length} chars)`);
  }
  // Many hyphens (common in brand impersonation)
  const hyphenCount = (domain.match(/-/g) || []).length;
  if (hyphenCount >= 3) {
    score += 10;
    signals.push(`Many hyphens in domain (${hyphenCount}) — common brand impersonation pattern`);
  }
  return { score, signals };
}

// ── Master risk scorer ──
function scoreSandboxFindings(forms, technologies, brandMismatch, redirectChain,
                               statusCode, jsEntropy, linkAnalysis, tlsCert,
                               ipGeo, domainAnalysis) {
  let riskScore = 0;
  const signals = [];

  // Forms
  if (forms.length > 0) {
    const maxFormScore = Math.max(...forms.map(f => f.suspicionScore));
    riskScore += Math.min(maxFormScore, 55);
    const credForms = forms.filter(f => f.isCredentialHarvester);
    if (credForms.length > 0)
      signals.push(`${credForms.length} credential harvesting form${credForms.length>1?"s":""} detected`);
    if (forms.some(f => f.hasPasswordField))  signals.push("Password input field detected");
    if (forms.some(f => f.externalAction))     signals.push("Form submits to external domain");
  }

  // Technologies + kits
  const phishingKits  = technologies.filter(t => t.category === "phishing_kit");
  const obfuscation   = technologies.filter(t => t.category === "obfuscation");
  const evasion       = technologies.filter(t => t.category === "evasion");
  const aitm          = technologies.filter(t => t.category === "aitm");
  phishingKits.forEach(t  => { riskScore += 50; signals.push(`Phishing kit detected: ${t.name}`); });
  obfuscation.forEach(t   => { riskScore += 30; signals.push(`Obfuscation: ${t.name}`); });
  evasion.forEach(t       => { riskScore += 15; signals.push(`Evasion technique: ${t.name}`); });
  aitm.forEach(t          => { riskScore += 40; signals.push(`AiTM signal: ${t.name}`); });

  // JS entropy
  if (jsEntropy?.highEntropyBlocks > 0) {
    riskScore += Math.min(jsEntropy.highEntropyBlocks * 12, 35);
    signals.push(`${jsEntropy.highEntropyBlocks} high-entropy JS block${jsEntropy.highEntropyBlocks>1?"s":""} (max entropy: ${jsEntropy.maxEntropy}) — likely obfuscated`);
  }

  // Redirect chain
  if (redirectChain?.crossDomain)  { riskScore += 20; signals.push("Cross-domain redirect chain"); }
  if (redirectChain?.hops >= 3)    { riskScore += 15; signals.push(`${redirectChain.hops}-hop redirect chain`); }
  if (redirectChain?.hasShortener) { riskScore += 18; signals.push("URL shortener in redirect chain — destination concealed"); }

  // Brand mismatch
  if (brandMismatch?.found) {
    riskScore += brandMismatch.severity === "critical" ? 45 : 30;
    signals.push(brandMismatch.message);
  }

  // Link analysis
  if (linkAnalysis?.suspiciousDomains?.length > 0) {
    riskScore += Math.min(linkAnalysis.suspiciousDomains.length * 10, 25);
    signals.push(`${linkAnalysis.suspiciousDomains.length} suspicious external domain${linkAnalysis.suspiciousDomains.length>1?"s":""} linked: ${linkAnalysis.suspiciousDomains.join(", ")}`);
  }
  if (linkAnalysis?.hasShortenerLink) {
    riskScore += 12;
    signals.push("Page embeds URL shortener links — redirects to unknown destination");
  }

  // TLS certificate
  if (tlsCert?.signals?.length > 0) {
    riskScore += Math.min(tlsCert.riskScore, 40);
    tlsCert.signals.forEach(s => signals.push(`TLS: ${s}`));
  }

  // IP geolocation
  if (ipGeo?.isHighAbuseRegion && ipGeo.signal) {
    riskScore += 10;
    signals.push(ipGeo.signal);
  }

  // Domain analysis
  if (domainAnalysis?.score > 0) {
    riskScore += Math.min(domainAnalysis.score, 30);
    domainAnalysis.signals.forEach(s => signals.push(s));
  }

  // Status
  if (statusCode === 200)           signals.push("Page is live and accessible");
  if (!statusCode || statusCode >= 500) signals.push("Page returned server error");

  const riskLevel = riskScore >= 75 ? "critical" : riskScore >= 50 ? "high" :
                    riskScore >= 25 ? "medium"   : "low";
  return { riskScore: Math.min(riskScore, 100), riskLevel, signals };
}

// ── MAIN ──
async function getURLPreview(url) {
  const normalizedUrl = url.startsWith("http") ? url : `https://${url}`;
  let domain = "";
  try { domain = new URL(normalizedUrl).hostname.toLowerCase().replace(/^www\./, ""); }
  catch { return null; }

  // 1. Redirect chain
  let redirectChain = null;
  try { redirectChain = await trackRedirectChain(normalizedUrl); }
  catch { redirectChain = { hops:1, chain:[{url:normalizedUrl,statusCode:null,hop:1}],
    finalUrl:normalizedUrl, hasRedirects:false, crossDomain:false, hasShortener:false }; }

  // 2. TLS certificate (non-blocking, in parallel with HTML fetch)
  const tlsPromise = (() => {
    try {
      if (!normalizedUrl.startsWith("https")) return Promise.resolve(null);
      const finalDomain = (() => {
        try { return new URL(redirectChain.finalUrl || normalizedUrl).hostname; } catch { return domain; }
      })();
      return inspectTLSCertificate(finalDomain);
    } catch { return Promise.resolve(null); }
  })();

  // 3. Fetch final page HTML
  let html = "", statusCode = null, isLive = false, isTakenDown = false;
  try {
    const res = await axios.get(redirectChain.finalUrl || normalizedUrl, {
      headers: SANDBOX_HEADERS, timeout: 7000, maxRedirects: 3,
      maxContentLength: 1000 * 1024, responseType: "text",
      validateStatus: (s) => s < 600, withCredentials: false,
    });
    statusCode  = res.status;
    isLive      = res.status === 200;
    isTakenDown = res.status === 404 || res.status === 410;
    html        = typeof res.data === "string" ? res.data.substring(0, 100000) : "";
  } catch (err) {
    isTakenDown = err.code === "ECONNREFUSED" || err.code === "ENOTFOUND";
  }

  // 4. Wait for TLS result
  const tlsCert = await tlsPromise;

  // 5. All HTML analysis in parallel
  const meta            = extractMeta(html);
  const title           = meta.ogTitle || meta.title || null;
  const forms           = html ? analyzeFormStructure(html) : [];
  const technologies    = html ? detectTechnologies(html) : [];
  const jsEntropy       = html ? analyzeJsEntropy(html) : { maxEntropy:0, avgEntropy:0, highEntropyBlocks:0 };
  const linkAnalysis    = html ? extractAndAnalyzeLinks(html, domain) : null;
  const domainAnalysis  = analyzeDomain(domain);
  const ipGeo           = redirectChain.resolvedIP ? analyzeIPGeolocation(redirectChain.resolvedIP) : null;

  // Kit fingerprinting
  const htmlKitMatch = html ? identifyKitFromHTML(html) : null;
  if (htmlKitMatch) {
    technologies.push({
      name: `Phishing Kit: ${htmlKitMatch.kitName}`, category:"phishing_kit",
      risk:"critical", kitId:htmlKitMatch.kitId, confidence:htmlKitMatch.confidence,
    });
  }

  // 6. Brand mismatch
  const brandMismatch = detectBrandMismatch(domain, title, meta.description, meta.ogTitle);

  // 7. Master risk score
  const sandboxRisk = scoreSandboxFindings(
    forms, technologies, brandMismatch, redirectChain,
    statusCode, jsEntropy, linkAnalysis, tlsCert, ipGeo, domainAnalysis
  );

  // 8. Favicon
  let faviconUrl = meta.favicon;
  if (faviconUrl && !faviconUrl.startsWith("http")) {
    try {
      const base = new URL(normalizedUrl);
      faviconUrl = faviconUrl.startsWith("/")
        ? `${base.protocol}//${base.host}${faviconUrl}`
        : `${base.protocol}//${base.host}/${faviconUrl}`;
    } catch { faviconUrl = null; }
  }
  if (!faviconUrl) faviconUrl = `https://www.google.com/s2/favicons?domain=${domain}&sz=32`;

  const liveStatus = isTakenDown ? "TAKEN_DOWN" : isLive ? "LIVE" :
                     statusCode  ? "ERROR"       : "UNREACHABLE";

  return {
    // Basic metadata
    url: normalizedUrl, domain, title,
    description: meta.ogDesc || meta.description, ogImage: meta.ogImage,
    favicon: faviconUrl, generator: meta.generator,
    // Status
    statusCode, liveStatus, isLive, isTakenDown,
    // Redirect chain (now includes shortener and IP data)
    redirectChain: {
      hops: redirectChain.hops, hasRedirects: redirectChain.hasRedirects,
      crossDomain: redirectChain.crossDomain, finalUrl: redirectChain.finalUrl,
      hasShortener: redirectChain.hasShortener,
      chain: redirectChain.chain.map(c => ({
        url: c.url.substring(0, 120), statusCode: c.statusCode,
        hop: c.hop, isShortener: c.isShortener || false,
      })),
    },
    // Forms
    forms: {
      count: forms.length,
      hasCredentialForm: forms.some(f => f.isCredentialHarvester),
      hasPasswordField:  forms.some(f => f.hasPasswordField),
      hasExternalAction: forms.some(f => f.externalAction !== null),
      details: forms.slice(0, 3),
    },
    // Technologies (expanded)
    technologies: {
      detected: technologies,
      hasPhishingKit:   technologies.some(t => t.category === "phishing_kit"),
      hasObfuscation:   technologies.some(t => t.category === "obfuscation"),
      hasRedirectScript:technologies.some(t => t.category === "redirect"),
      hasEvasion:       technologies.some(t => t.category === "evasion"),
      hasAiTMSignal:    technologies.some(t => t.category === "aitm"),
    },
    // NEW: JS entropy analysis
    jsEntropy,
    // NEW: Link analysis
    linkAnalysis,
    // NEW: TLS certificate
    tlsCertificate: tlsCert ? {
      issuer:         tlsCert.issuer,
      subject:        tlsCert.subject,
      daysOld:        tlsCert.daysOld,
      daysLeft:       tlsCert.daysLeft,
      isLetEncrypt:   tlsCert.isLetEncrypt,
      isSelfSigned:   tlsCert.isSelfSigned,
      isVeryNew:      tlsCert.isVeryNew,
      certMismatch:   tlsCert.certMismatch,
      signals:        tlsCert.signals,
    } : null,
    // NEW: IP geolocation
    ipGeolocation: ipGeo,
    // NEW: Domain analysis
    domainAnalysis,
    // Risk
    brandMismatch,
    sandboxRisk,
    fetchedAt: new Date().toISOString(),
  };
}

module.exports = { getURLPreview };