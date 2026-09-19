// FILE: backend/middleware/ids.js
// Intrusion Detection System — sits before all routes

const { ingestEvent } = (() => {
  try { return require("../siem/eventEngine"); }
  catch { return { ingestEvent: null }; }
})();

// ── In-memory tracking (replace with Redis in production) ──
const ipTracker   = new Map(); // ip → { count, firstSeen, paths, agents }
const blockedIPs  = new Set();

const BLOCK_THRESHOLD     = 500; // requests per minute
const SCAN_BURST_THRESHOLD = 50; // /api/scan calls per minute
const PAYLOAD_PATTERNS = [
  { pattern: /<script[\s>]/i,          type: "XSS",           severity: 4 },
  { pattern: /;\s*drop\s+table/i,      type: "SQLi",          severity: 5 },
  { pattern: /union\s+select/i,        type: "SQLi",          severity: 5 },
  { pattern: /\.\.\//,                 type: "PathTraversal", severity: 4 },
  { pattern: /\/etc\/passwd/i,         type: "PathTraversal", severity: 5 },
  { pattern: /\/etc\/shadow/i,         type: "PathTraversal", severity: 5 },
  { pattern: /cmd\.exe|powershell/i,   type: "CMDInjection",  severity: 5 },
  { pattern: /`.*`|\$\(.*\)/,         type: "CMDInjection",  severity: 4 },
  { pattern: /onload=|onerror=|onclick=/i, type: "XSS",      severity: 4 },
  { pattern: /javascript:.*\(/i,       type: "XSS",           severity: 4 },
];

const SUSPICIOUS_AGENTS = [
  /sqlmap/i, /nikto/i, /masscan/i, /nmap/i, /zgrab/i,
  /dirbuster/i, /gobuster/i, /burpsuite/i, /hydra/i,
  /metasploit/i, /havij/i, /acunetix/i,
];

function getIP(req) {
  return req.headers["x-forwarded-for"]?.split(",")[0]?.trim() || req.ip || "unknown";
}

function track(ip, path) {
  const now = Date.now();
  if (!ipTracker.has(ip)) {
    ipTracker.set(ip, { count: 0, scanCount: 0, firstSeen: now, lastSeen: now, paths: new Set(), agents: new Set() });
  }
  const t = ipTracker.get(ip);

  // Reset window every 60s
  if (now - t.firstSeen > 60000) {
    t.count = 0; t.scanCount = 0; t.firstSeen = now; t.paths.clear();
  }
  t.count++;
  t.lastSeen = now;
  t.paths.add(path);
  if (path.includes("/api/scan")) t.scanCount++;
  return t;
}

async function fireIdsAlert(io, type, severity, ip, detail) {
  const event = {
    type:        "custom",
    category:    "reconnaissance",
    subcategory: type.toLowerCase().replace(" ", "_"),
    severity,
    title:       `IDS: ${type} from ${ip}`,
    description: detail,
    sourceType:  "ids",
    sourceIp:    ip,
    agent:       "SentinelCore IDS",
    rawData:     { type, ip, detail },
    tags:        ["ids", "intrusion"],
  };

  if (ingestEvent) {
    ingestEvent(event).catch(() => {});
  }

  if (io) {
    io.emit("ids_alert", { type, severity, ip, detail, timestamp: new Date().toISOString() });
  }
}

function idsMiddleware(req, res, next) {
  const ip    = getIP(req);
  const path  = req.path;
  const agent = req.headers["user-agent"] || "";
  const io    = req.app.get("io");

  // ── CHECK 1: Blocked IP ──
  if (blockedIPs.has(ip)) {
    return res.status(403).json({ error: "Access denied" });
  }

  // ── CHECK 2: Suspicious User-Agent ──
  if (SUSPICIOUS_AGENTS.some((p) => p.test(agent))) {
    fireIdsAlert(io, "Suspicious Scanner Detected", 4, ip, `Known scanner UA: "${agent.substring(0, 80)}"`);
  }

  // ── CHECK 3: Payload injection in body/query ──
  const bodyStr  = JSON.stringify(req.body  || "");
  const queryStr = JSON.stringify(req.query || "");
  const combined = bodyStr + queryStr;

  for (const { pattern, type, severity } of PAYLOAD_PATTERNS) {
    if (pattern.test(combined)) {
      fireIdsAlert(io, `${type} Injection Attempt`, severity, ip, `Payload pattern "${type}" in ${path}`);
      return res.status(400).json({ error: "Malicious payload detected" });
    }
  }

  // ── CHECK 4: Rate tracking ──
  const t = track(ip, path);

  // General rate limit
  if (t.count > BLOCK_THRESHOLD) {
    blockedIPs.add(ip);
    setTimeout(() => blockedIPs.delete(ip), 10 * 60 * 1000); // auto-unblock after 10min
    fireIdsAlert(io, "Rate Limit Exceeded — IP Blocked", 5, ip, `${t.count} requests/min — temporarily blocked`);
    return res.status(429).json({ error: "Rate limit exceeded" });
  }

  // Scan burst
  if (t.scanCount >= SCAN_BURST_THRESHOLD && t.scanCount % 25 === 0) {
    fireIdsAlert(io, "API Scan Burst", 4, ip, `${t.scanCount} /api/scan calls from ${ip} in 60s`);
  }

  // Payload variation attack (same IP, many different scan inputs)
  if (t.paths.size > 30 && t.count > 100) {
    fireIdsAlert(io, "Abnormal Scan Pattern", 3, ip, `${t.paths.size} unique paths — possible enumeration`);
  }

  next();
}

// ── Cleanup old entries every 5 min ──
setInterval(() => {
  const cutoff = Date.now() - 5 * 60 * 1000;
  for (const [ip, t] of ipTracker.entries()) {
    if (t.lastSeen < cutoff) ipTracker.delete(ip);
  }
}, 5 * 60 * 1000);

module.exports = { idsMiddleware };