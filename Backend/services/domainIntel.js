// FILE: backend/services/domainIntel.js
// Domain Intelligence — age, DNS, SSL, geo, blacklist check
// Uses only built-in Node.js modules + axios (already installed)

const https = require("https");
const dns = require("dns").promises;
const tls = require("tls");
const axios = require("axios");
const geoip = require("geoip-lite");

// ── Country flag emoji from code ──
function countryFlag(code) {
  if (!code || code.length !== 2) return "🌐";
  return String.fromCodePoint(
    ...code.toUpperCase().split("").map(c => 127397 + c.charCodeAt(0))
  );
}

// ── Extract clean domain ──
function extractDomain(url) {
  try {
    const u = url.startsWith("http") ? url : `https://${url}`;
    return new URL(u).hostname.replace(/^www\./, "").toLowerCase();
  } catch { return url.toLowerCase().trim(); }
}

// ── DNS lookup ──
async function getDNSInfo(domain) {
  try {
    const [addresses, mx] = await Promise.allSettled([
      dns.lookup(domain),
      dns.resolveMx(domain),
    ]);
    const ip = addresses.status === "fulfilled" ? addresses.value.address : null;
    const geo = ip ? geoip.lookup(ip) : null;
    return {
      ip,
      country: geo?.country || null,
      city: geo?.city || null,
      region: geo?.region || null,
      flag: geo?.country ? countryFlag(geo.country) : "🌐",
      hasMX: mx.status === "fulfilled" && mx.value.length > 0,
    };
  } catch {
    return { ip: null, country: null, city: null, flag: "🌐", hasMX: false };
  }
}

// ── SSL certificate check ──
async function getSSLInfo(domain) {
  return new Promise((resolve) => {
    const timeout = setTimeout(() => resolve({ valid: false, error: "Timeout", daysLeft: null }), 6000);
    try {
      const socket = tls.connect(443, domain, { servername: domain, rejectUnauthorized: false }, () => {
        clearTimeout(timeout);
        try {
          const cert = socket.getPeerCertificate(true);
          socket.destroy();
          if (!cert || !cert.valid_to) return resolve({ valid: false, error: "No certificate", daysLeft: null });
          const expiry = new Date(cert.valid_to);
          const daysLeft = Math.floor((expiry - Date.now()) / (1000 * 60 * 60 * 24));
          resolve({
            valid: daysLeft > 0,
            daysLeft,
            expiresAt: expiry.toISOString().split("T")[0],
            issuer: cert.issuer?.O || cert.issuer?.CN || "Unknown",
            subject: cert.subject?.CN || domain,
            selfSigned: cert.issuer?.CN === cert.subject?.CN,
          });
        } catch { resolve({ valid: false, error: "Parse error", daysLeft: null }); }
      });
      socket.on("error", (e) => { clearTimeout(timeout); resolve({ valid: false, error: e.message, daysLeft: null }); });
    } catch (e) { clearTimeout(timeout); resolve({ valid: false, error: e.message, daysLeft: null }); }
  });
}

// ── WHOIS-style domain age via RDAP (free, no key) ──
async function getDomainAge(domain) {
  const tld = domain.split(".").pop();
  // RDAP bootstrap — maps TLDs to RDAP servers
  const RDAP_SERVERS = {
    "com": "https://rdap.verisign.com/com/v1/domain/",
    "net": "https://rdap.verisign.com/net/v1/domain/",
    "org": "https://rdap.org/domain/",
    "io": "https://rdap.org/domain/",
    "co": "https://rdap.org/domain/",
    "tk": "https://rdap.org/domain/",
    "ml": "https://rdap.org/domain/",
    "ga": "https://rdap.org/domain/",
    "xyz": "https://rdap.org/domain/",
    "info": "https://rdap.org/domain/",
    "biz": "https://rdap.org/domain/",
  };
  const server = RDAP_SERVERS[tld] || "https://rdap.org/domain/";

  try {
    const res = await axios.get(`${server}${domain}`, {
      timeout: 6000,
      headers: { "User-Agent": "PhishNetra/3.0", Accept: "application/json" },
    });
    const events = res.data?.events || [];
    const regEvent = events.find(e => e.eventAction === "registration");
    const updEvent = events.find(e => e.eventAction === "last changed");
    const expEvent = events.find(e => e.eventAction === "expiration");

    const regDate = regEvent?.eventDate ? new Date(regEvent.eventDate) : null;
    const ageMs = regDate ? Date.now() - regDate.getTime() : null;
    const ageDays = ageMs ? Math.floor(ageMs / (1000 * 60 * 60 * 24)) : null;

    return {
      registeredAt: regDate ? regDate.toISOString().split("T")[0] : null,
      updatedAt: updEvent?.eventDate ? new Date(updEvent.eventDate).toISOString().split("T")[0] : null,
      expiresAt: expEvent?.eventDate ? new Date(expEvent.eventDate).toISOString().split("T")[0] : null,
      ageDays,
      ageLabel: ageDays !== null
        ? ageDays < 7 ? `${ageDays} days (⚠️ Very new)`
          : ageDays < 30 ? `${ageDays} days (⚠️ New)`
            : ageDays < 365 ? `${Math.floor(ageDays / 30)} months`
              : `${Math.floor(ageDays / 365)} year${Math.floor(ageDays / 365) > 1 ? "s" : ""}`
        : null,
      isNew: ageDays !== null && ageDays < 30,
      isSuspicious: ageDays !== null && ageDays < 7,
      status: res.data?.status || [],
      registrar: res.data?.entities?.find(e => e.roles?.includes("registrar"))?.vcardArray?.[1]
        ?.find((f) => f[0] === "fn")?.[3] || null,
    };
  } catch {
    return { registeredAt: null, ageDays: null, ageLabel: "Unavailable", isNew: false, isSuspicious: false };
  }
}

// ── Blacklist check via Google Safe Browsing-compatible feeds ──
async function checkBlacklists(domain, ip) {
  const results = {};

  // Check known free feeds we already cache in threatIntel.js
  try {
    const { checkThreatIntel } = require("./threatIntel");
    const intel = await checkThreatIntel(`https://${domain}`);
    results["PhishTank"] = intel.sources?.includes("PhishTank") || false;
    results["OpenPhish"] = intel.sources?.includes("OpenPhish") || false;
  } catch { /* not available */ }

  const found = Object.values(results).some(Boolean);
  return { results, found, count: Object.values(results).filter(Boolean).length };
}

// ── Risk scoring for domain intel ──
function scoreDomainIntel(age, ssl, dns, blacklist) {
  let riskSignals = [];
  let riskLevel = "low";
  let addScore = 0;

  if (age.isSuspicious) { riskSignals.push("Domain registered < 7 days ago"); addScore += 40; }
  else if (age.isNew) { riskSignals.push("Domain registered < 30 days ago"); addScore += 20; }

  if (ssl.valid === false && ssl.error !== "Timeout") {
    riskSignals.push("SSL certificate invalid or missing"); addScore += 25;
  } else if (ssl.selfSigned) {
    riskSignals.push("Self-signed SSL certificate"); addScore += 15;
  } else if (ssl.daysLeft !== null && ssl.daysLeft < 7) {
    riskSignals.push(`SSL expires in ${ssl.daysLeft} days`); addScore += 10;
  }

  if (blacklist.found) {
    riskSignals.push(`Blacklisted by: ${Object.entries(blacklist.results).filter(([, v]) => v).map(([k]) => k).join(", ")}`);
    addScore += 50;
  }

  // Suspicious country heuristic (not a moral judgment — purely statistical phishing source data)
  const HIGH_RISK_HOSTING = ["RU", "CN", "KP", "IR"];
  if (dns.country && HIGH_RISK_HOSTING.includes(dns.country) && addScore > 10) {
    riskSignals.push(`Server hosted in ${dns.country}`); addScore += 10;
  }

  if (addScore >= 50) riskLevel = "critical";
  else if (addScore >= 30) riskLevel = "high";
  else if (addScore >= 15) riskLevel = "medium";

  return { riskLevel, riskSignals, addScore };
}

// ── MAIN export ──
async function getDomainIntelligence(url) {
  const domain = extractDomain(url);
  if (!domain || domain.length < 3) return null;

  // Run all checks in parallel
  const [age, ssl, dnsInfo, blacklist] = await Promise.all([
    getDomainAge(domain),
    getSSLInfo(domain),
    getDNSInfo(domain),
    checkBlacklists(domain, null),
  ]);

  const risk = scoreDomainIntel(age, ssl, dnsInfo, blacklist);

  return {
    domain,
    age,
    ssl,
    dns: dnsInfo,
    blacklist,
    risk,
    fetchedAt: new Date().toISOString(),
  };
}

module.exports = { getDomainIntelligence, extractDomain };