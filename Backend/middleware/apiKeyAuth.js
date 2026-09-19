// FILE: backend/middleware/apiKeyAuth.js
// Validates X-API-Key header on /api/scan requests

const ApiKey = require("../models/ApiKey");

async function apiKeyMiddleware(req, res, next) {
  const apiKey = req.headers["x-phishnetra-key"] || req.headers["x-api-key"];

  // No API key — fall through to normal JWT auth
  if (!apiKey) return next();

  try {
    const key = await ApiKey.findOne({ key: apiKey, active: true });

    if (!key) {
      return res.status(401).json({ error: "Invalid or revoked API key" });
    }

    // Check expiry
    if (key.expiresAt && key.expiresAt < new Date()) {
      return res.status(401).json({ error: "API key expired" });
    }

    // Rate limiting — rolling 1-hour window
    const now = new Date();
    const windowMs = 60 * 60 * 1000; // 1 hour
    if (!key.windowStart || now - key.windowStart > windowMs) {
      // Reset window
      key.windowStart = now;
      key.windowCount = 0;
    }

    if (key.windowCount >= key.rateLimit) {
      return res.status(429).json({
        error: `API key rate limit exceeded (${key.rateLimit} req/hr)`,
        resetAt: new Date(key.windowStart.getTime() + windowMs).toISOString(),
      });
    }

    // Update usage
    key.windowCount++;
    key.usageCount++;
    // ── Zero-Trust trust score update ──
    key.totalScans++;
    if (!key.firstScan) key.firstScan = new Date();

    // Check for scan burst pattern
    if (key.windowCount >= key.rateLimit * 0.8) {
      key.scanBursts = (key.scanBursts || 0) + 1;
    }

    // Recalculate trust score
    let trustScore = 50; // neutral baseline
    if (key.totalScans >= 10) {
      const phishRate = key.phishingSubmitted / key.totalScans;
      // High phishing rate = probably under attack (boost trust)
      if (phishRate >= 0.4) {
        trustScore += 20;
        key.isUnderAttack = true;
      }
      // All safe = legitimate testing or low-risk usage
      if (phishRate === 0 && key.totalScans >= 20) trustScore += 15;
      // Known phishing hits = testing our detection (neutral)
      if (key.knownPhishingHits >= 5) {
        trustScore -= 5;
        key.isReconClient = true;
      }
      // Repeated scan bursts = API abuse signal
      if (key.scanBursts >= 3) trustScore -= 20;
      // Long usage history = established client
      if (key.totalScans >= 100) trustScore += 10;
      if (key.totalScans >= 500) trustScore += 10;
    }

    trustScore = Math.max(0, Math.min(100, trustScore));
    key.trustScore = trustScore;
    key.trustLevel =
      trustScore >= 75
        ? "trusted"
        : trustScore >= 40
          ? "neutral"
          : trustScore >= 20
            ? "suspicious"
            : "untrusted";
    key.lastUsed = now;
    await key.save();

    // Attach key info to request
    req.apiKeyUser = {
      id: key.userId,
      username: key.username,
      role: "analyst",
    };
    // Also populate req.user so requireAuth/requireRole middleware
    // treats this request as authenticated (API key bypasses JWT)
    req.user = {
      id: key.userId,
      username: key.username,
      role: "analyst",
    };
    next();
  } catch (err) {
    console.error("API key auth error:", err.message);
    res.status(500).json({ error: "API key validation failed" });
  }
}

module.exports = { apiKeyMiddleware };
