// FILE: backend/routes/apikeys.js

const express    = require("express");
const router     = express.Router();
const ApiKey     = require("../models/ApiKey");
const { requireAuth } = require("./auth");

// GET /api/keys — list user's keys
router.get("/", requireAuth, async (req, res) => {
  try {
    const keys = await ApiKey.find({ userId: req.user.id })
      .sort({ createdAt: -1 })
      .select("-__v")
      .lean();
    // Mask key — only show first 12 + last 4 chars
    res.json(keys.map(k => ({
      ...k,
      key: `${k.key.slice(0, 12)}...${k.key.slice(-4)}`,
      keyFull: undefined,
    })));
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch keys" });
  }
});

// POST /api/keys — create new key
router.post("/", requireAuth, async (req, res) => {
  try {
    const { name, rateLimit } = req.body;
    if (!name?.trim()) return res.status(400).json({ error: "Key name required" });

    // Max 5 keys per user
    const existing = await ApiKey.countDocuments({ userId: req.user.id, active: true });
    if (existing >= 5) return res.status(400).json({ error: "Maximum 5 active keys per user" });

    const key = new ApiKey({
      name:      name.trim(),
      userId:    req.user.id,
      username:  req.user.username,
      rateLimit: Math.min(rateLimit || 100, 1000),
    });
    await key.save();

    // Return full key ONCE on creation
    res.status(201).json({
      ...key.toObject(),
      message: "Save this key — it will not be shown again in full",
    });
  } catch (err) {
    res.status(500).json({ error: "Failed to create key" });
  }
});

// DELETE /api/keys/:keyId — revoke key
router.delete("/:keyId", requireAuth, async (req, res) => {
  try {
    const key = await ApiKey.findOneAndUpdate(
      { _id: req.params.keyId, userId: req.user.id },
      { active: false },
      { new: true }
    );
    if (!key) return res.status(404).json({ error: "Key not found" });
    res.json({ message: "Key revoked" });
  } catch (err) {
    res.status(500).json({ error: "Failed to revoke key" });
  }
});

router.delete("/:id/permanent", requireAuth, async (req, res) => {
  try {
    const ApiKey = require("../models/ApiKey");
    const key = await ApiKey.findOne({ _id: req.params.id, userId: req.user.id });
    if (!key) return res.status(404).json({ error: "Key not found" });
    await ApiKey.findByIdAndDelete(req.params.id);
    res.json({ message: "API key permanently deleted" });
  } catch (err) {
    res.status(500).json({ error: "Failed to delete key" });
  }
});

// GET /api/keys/:keyId/stats — usage stats
router.get("/:keyId/stats", requireAuth, async (req, res) => {
  try {
    const key = await ApiKey.findOne({ _id: req.params.keyId, userId: req.user.id });
    if (!key) return res.status(404).json({ error: "Key not found" });
    res.json({
      usageCount: key.usageCount,
      lastUsed:   key.lastUsed,
      rateLimit:  key.rateLimit,
      windowCount:key.windowCount,
      active:     key.active,
    });
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch stats" });
  }
});
// GET /api/keys/intelligence — API intelligence dashboard data
router.get("/intelligence", requireAuth, async (req, res) => {
  try {
    const ApiKey  = require("../models/ApiKey");
    const allKeys = await ApiKey.find({ active: true })
      .select("name username trustScore trustLevel totalScans phishingSubmitted safeSubmitted isUnderAttack isReconClient scanBursts firstScan lastUsed")
      .lean();
 
    const stats = {
      totalClients:      allKeys.length,
      trustedClients:    allKeys.filter(k => k.trustLevel === "trusted").length,
      suspiciousClients: allKeys.filter(k => k.trustLevel === "suspicious" || k.trustLevel === "untrusted").length,
      underAttack:       allKeys.filter(k => k.isUnderAttack).length,
      reconClients:      allKeys.filter(k => k.isReconClient).length,
      totalApiScans:     allKeys.reduce((s, k) => s + (k.totalScans || 0), 0),
    };
 
    const clients = allKeys.map(k => ({
      name:             k.name,
      username:         k.username,
      trustScore:       k.trustScore || 50,
      trustLevel:       k.trustLevel || "neutral",
      totalScans:       k.totalScans || 0,
      phishingRate:     k.totalScans > 0
        ? Math.round(((k.phishingSubmitted || 0) / k.totalScans) * 100) : 0,
      isUnderAttack:    k.isUnderAttack || false,
      isReconClient:    k.isReconClient || false,
      scanBursts:       k.scanBursts || 0,
      lastUsed:         k.lastUsed,
      firstScan:        k.firstScan,
      anomalies:        [
        k.isUnderAttack  ? "High phishing rate — org may be under attack" : null,
        k.isReconClient  ? "Scanning known phishing URLs — possible system testing" : null,
        (k.scanBursts || 0) >= 3 ? "Repeated scan bursts — possible API abuse" : null,
        (k.trustLevel === "untrusted") ? "Trust score critically low" : null,
      ].filter(Boolean),
    })).sort((a, b) => b.totalScans - a.totalScans);
 
    res.json({ stats, clients });
  } catch (err) {
    res.status(500).json({ error: "Intelligence data unavailable" });
  }
});

module.exports = router;