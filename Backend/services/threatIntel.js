// FILE: backend/services/threatIntel.js
// Free threat intelligence feeds — no API key needed for PhishTank + OpenPhish

const axios = require("axios");

// In-memory cache (refresh every 2 hours, retry every 15m on failure)
let phishTankCache    = new Set();
let openPhishCache    = new Set();
let lastRefreshed     = 0;
let isRefreshing      = false;
const CACHE_TTL       = 2 * 60 * 60 * 1000; // 2 hours
const RETRY_DELAY     = 15 * 60 * 1000;    // 15 minutes

// ── Load PhishTank online valid feed ──
async function loadPhishTank() {
  try {
    const PHISHTANK_KEY = process.env.PHISHTANK_API_KEY;
    const phishTankUrl  = PHISHTANK_KEY
      ? `https://data.phishtank.com/data/${PHISHTANK_KEY}/online-valid.json`
      : "https://data.phishtank.com/data/online-valid.json";

    const res = await axios.get(phishTankUrl, {
      timeout: 30000,
      headers: { "User-Agent": "PhishNetra/3.0 (security-research)" },
    });
    
    const urls = (res.data || []).map((e) => {
      try { return new URL(e.url).hostname.toLowerCase(); }
      catch { return null; }
    }).filter(Boolean);
    phishTankCache = new Set(urls);
    console.log(`🔍 PhishTank: loaded ${phishTankCache.size} malicious domains`);
    return true;
  } catch (err) {
    if (err.response?.status === 429) {
      console.warn("⚠️  PhishTank rate limited (429). Using existing cache.");
    } else {
      console.warn("⚠️  PhishTank feed unavailable:", err.message);
    }
    return false;
  }
}

// ── Load OpenPhish feed ──
async function loadOpenPhish() {
  try {
    const res = await axios.get(
      "https://openphish.com/feed.txt",
      { timeout: 15000, headers: { "User-Agent": "PhishNetra/3.0" } }
    );
    const lines = (res.data || "").split("\n").filter(Boolean);
    const hosts = lines.map((url) => {
      try { return new URL(url.trim()).hostname.toLowerCase(); }
      catch { return null; }
    }).filter(Boolean);
    openPhishCache = new Set(hosts);
    console.log(`🔍 OpenPhish: loaded ${openPhishCache.size} malicious domains`);
    return true;
  } catch (err) {
    console.warn("⚠️  OpenPhish feed unavailable:", err.message);
    return false;
  }
}

// ── Refresh both feeds ──
async function refreshFeeds() {
  if (isRefreshing) return;
  isRefreshing = true;
  try {
    const [ptSuccess, opSuccess] = await Promise.all([loadPhishTank(), loadOpenPhish()]);
    
    // If successful, wait for full TTL. If failed, schedule a retry sooner.
    if (ptSuccess && opSuccess) {
      lastRefreshed = Date.now();
      console.log("✅ Threat Intel: Full refresh successful");
    } else {
      // Partial or total failure — we still update the timestamp but with a "penalty"
      // or we just let the next checkTrigger handle it with a retry.
      // Here we set lastRefreshed to a value that will trigger a retry after RETRY_DELAY
      lastRefreshed = Date.now() - (CACHE_TTL - RETRY_DELAY);
      console.log(`🕒 Threat Intel: Partial failure, will retry in ${RETRY_DELAY / 60000} minutes`);
    }
  } finally {
    isRefreshing = false;
  }
}

// ── Check a URL against all intel feeds ──
async function checkThreatIntel(url) {
  // Auto-refresh if cache is stale and not already refreshing
  if (Date.now() - lastRefreshed > CACHE_TTL && !isRefreshing) {
    refreshFeeds().catch(() => {}); // non-blocking
  }

  let domain = "";
  try {
    domain = new URL(url.startsWith("http") ? url : `https://${url}`)
      .hostname.toLowerCase().replace(/^www\./, "");
  } catch { return { found: false }; }

  const inPhishTank = phishTankCache.has(domain);
  const inOpenPhish = openPhishCache.has(domain);
  const found       = inPhishTank || inOpenPhish;

  return {
    found,
    domain,
    sources: [
      ...(inPhishTank ? ["PhishTank"] : []),
      ...(inOpenPhish ? ["OpenPhish"] : []),
    ],
    score:   found ? 40 : 0,
    label:   found ? "Confirmed by Threat Intelligence" : null,
  };
}

// Initial load on startup
refreshFeeds();

// Dynamic interval check
setInterval(() => {
  if (Date.now() - lastRefreshed > CACHE_TTL && !isRefreshing) {
    refreshFeeds();
  }
}, 60000); // Check every minute if we need to refresh

// ── Fast domain-only lookup (used by DNS log matching — Phase 2) ──
// Reuses the exact same in-memory caches already loaded for URL scanning.
// O(1) Set lookup — zero extra cost, zero extra API calls.
function isDomainMalicious(domain) {
  const clean = domain.toLowerCase().replace(/^www\./, "").trim();
  const inPhishTank = phishTankCache.has(clean);
  const inOpenPhish = openPhishCache.has(clean);
  return {
    found: inPhishTank || inOpenPhish,
    sources: [
      ...(inPhishTank ? ["PhishTank"] : []),
      ...(inOpenPhish ? ["OpenPhish"] : []),
    ],
  };
}

module.exports = { checkThreatIntel, refreshFeeds, isDomainMalicious };