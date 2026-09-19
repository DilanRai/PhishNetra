// FILE: backend/services/geolocate.js — FULL REPLACEMENT
// v2: adds DNS resolution for domain→IP, CIDR private-range detection,
//     caching so repeated domains don't re-resolve, and enriched output

const geoip = require("geoip-lite");
const dns = require("dns").promises;

// ── In-memory cache: domain/ip → geo result (TTL 30 min) ──
const cache = new Map();
const CACHE_TTL_MS = 30 * 60 * 1000;

function cacheGet(key) {
  const entry = cache.get(key);
  if (!entry) return undefined;
  if (Date.now() - entry.ts > CACHE_TTL_MS) {
    cache.delete(key);
    return undefined;
  }
  return entry.val;
}
function cacheSet(key, val) {
  cache.set(key, { val, ts: Date.now() });
}

// ── Private/reserved IP ranges ──
function isPrivateIP(ip) {
  if (!ip) return true;
  const clean = ip.replace(/^::ffff:/, "");
  return (
    clean === "127.0.0.1" ||
    clean === "::1" ||
    clean === "localhost" ||
    /^10\./.test(clean) ||
    /^192\.168\./.test(clean) ||
    /^172\.(1[6-9]|2\d|3[01])\./.test(clean) ||
    /^169\.254\./.test(clean) ||
    /^fc00:/i.test(clean) ||
    /^fe80:/i.test(clean) ||
    clean === "0.0.0.0" ||
    clean === "255.255.255.255"
  );
}

// ── Lookup by raw IP ──
function lookup(ip) {
  if (!ip || isPrivateIP(ip)) return null;
  const clean = ip.replace(/^::ffff:/, "");
  const cached = cacheGet(clean);
  if (cached !== undefined) return cached;

  const geo = geoip.lookup(clean);
  if (!geo || !geo.ll) {
    cacheSet(clean, null);
    return null;
  }

  const result = {
    ip: clean,
    country: geo.country || "Unknown",
    region: geo.region || "",
    city: geo.city || "",
    lat: geo.ll[0],
    lon: geo.ll[1],
    timezone: geo.timezone || "",
    org: geo.org || "",
  };
  cacheSet(clean, result);
  return result;
}

// ── Resolve domain → IP → geolocate (async) ──
async function lookupDomain(domain) {
  if (!domain) return null;

  // Strip protocol/path if accidentally passed a full URL
  try {
    if (domain.startsWith("http")) {
      domain = new URL(domain).hostname;
    }
  } catch {}
  domain = domain
    .replace(/^www\./, "")
    .toLowerCase()
    .trim();
  if (!domain || domain.length < 4) return null;

  const cached = cacheGet(`dom:${domain}`);
  if (cached !== undefined) return cached;

  try {
    // Try A record first (IPv4), fall back to AAAA
    const addresses = await dns
      .resolve4(domain)
      .catch(() => dns.resolve6(domain).catch(() => []));
    if (!addresses || addresses.length === 0) {
      cacheSet(`dom:${domain}`, null);
      return null;
    }

    // Pick first non-private address
    const publicIp = addresses.find((a) => !isPrivateIP(a));
    if (!publicIp) {
      cacheSet(`dom:${domain}`, null);
      return null;
    }

    const geo = geoip.lookup(publicIp);
    if (!geo || !geo.ll) {
      cacheSet(`dom:${domain}`, null);
      return null;
    }

    const result = {
      ip: publicIp,
      domain,
      country: geo.country || "Unknown",
      region: geo.region || "",
      city: geo.city || "",
      lat: geo.ll[0],
      lon: geo.ll[1],
      timezone: geo.timezone || "",
      org: geo.org || "",
    };
    cacheSet(`dom:${domain}`, result);
    return result;
  } catch {
    cacheSet(`dom:${domain}`, null);
    return null;
  }
}

// ── Enrich an event with geo from domain OR ip (tries both) ──
async function enrichEvent(event) {
  // Prefer target.domain geo (the phishing site's actual location)
  if (event?.target?.domain) {
    const geo = await lookupDomain(event.target.domain);
    if (geo) return geo;
  }
  // Fall back to source IP geo (scanner's IP — usually useless locally
  // but works when deployed or accessed remotely)
  if (event?.source?.ip) {
    return lookup(event.source.ip);
  }
  return null;
}

module.exports = { lookup, lookupDomain, enrichEvent, isPrivateIP };

// ── FIX ISSUE 8: Schedule weekly geoip-lite database refresh ──────────────
// geoip-lite bundles MaxMind GeoLite2 at install time and never auto-updates.
// This runs a check once per day; when a week has passed it re-runs the
// bundled update script and reloads the data into memory.
const WEEK_MS = 7 * 24 * 60 * 60 * 1000;
let lastGeoUpdate = Date.now(); // assume fresh on startup

function scheduleGeoUpdate() {
  setInterval(
    () => {
      if (Date.now() - lastGeoUpdate < WEEK_MS) return;

      console.log("[geoip-lite] Starting weekly database update...");
      try {
        require("child_process").exec(
          "node node_modules/geoip-lite/scripts/updatedb.js",
          { cwd: process.cwd() },
          (err) => {
            if (err) {
              console.warn("[geoip-lite] Update failed:", err.message);
            } else {
              geoip.reloadDataSync();
              cache.clear(); // invalidate cached lookups so new data is used
              lastGeoUpdate = Date.now();
              console.log("[geoip-lite] Database updated and reloaded.");
            }
          },
        );
      } catch (e) {
        console.warn("[geoip-lite] Update error:", e.message);
      }
    },
    24 * 60 * 60 * 1000,
  ); // check daily
}

scheduleGeoUpdate();
