// FILE: backend/routes/auth.js

const express = require("express");
const router = express.Router();
const jwt = require("jsonwebtoken");
const User = require("../models/User");
const NotificationPrefs = (() => {
  try {
    return require("../models/NotificationPrefs");
  } catch {
    return null;
  }
})();

const JWT_SECRET =
  process.env.JWT_SECRET || "your-super-secret-key-change-this";
const JWT_EXPIRES = "24h";

// ── POST /api/auth/register ──
router.post("/register", async (req, res) => {
  try {
    const { username, password, role } = req.body;
    if (!username || !password) {
      return res.status(400).json({ error: "Username and password required" });
    }
    if (password.length < 8) {
      return res
        .status(400)
        .json({ error: "Password must be at least 8 characters" });
    }
    if (role && !["admin", "analyst", "viewer"].includes(role)) {
      return res.status(400).json({ error: "Invalid role selected" });
    }
    const existing = await User.findOne({ username });
    if (existing)
      return res.status(409).json({ error: "Username already exists" });

    const user = await User.create({
      username,
      password,
      role: role || "analyst",
    });
    const token = jwt.sign(
      { id: user._id, username: user.username, role: user.role },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRES },
    );

    res.status(201).json({
      token,
      user: { id: user._id, username: user.username, role: user.role },
    });
  } catch (err) {
    if (err?.name === "ValidationError") {
      return res.status(400).json({ error: err.message });
    }
    res.status(500).json({ error: "Registration failed" });
  }
});

// ── POST /api/auth/login ──
router.post("/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ error: "Username and password required" });
    }
    const user = await User.findOne({ username });
    if (!user) return res.status(401).json({ error: "Invalid credentials" });

    const valid = await user.comparePassword(password);
    if (!valid) return res.status(401).json({ error: "Invalid credentials" });

    user.lastLogin = new Date();
    await user.save();

    const token = jwt.sign(
      { id: user._id, username: user.username, role: user.role },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRES },
    );
    res.json({
      token,
      user: { id: user._id, username: user.username, role: user.role },
    });
  } catch (err) {
    res.status(500).json({ error: "Login failed" });
  }
});

// ── GET /api/auth/me ──
router.get("/me", requireAuth, (req, res) => {
  res.json({ user: req.user });
});

// GET /api/auth/notification-prefs
router.get("/notification-prefs", requireAuth, async (req, res) => {
  try {
    if (!NotificationPrefs)
      return res.json({
        channels: {},
        quietHours: { enabled: false },
        digestMode: false,
      });
    let prefs = await NotificationPrefs.findOne({ userId: req.user.id });
    if (!prefs) prefs = await NotificationPrefs.create({ userId: req.user.id });
    res.json(prefs);
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch prefs" });
  }
});

// PATCH /api/auth/notification-prefs
router.patch("/notification-prefs", requireAuth, async (req, res) => {
  try {
    if (!NotificationPrefs)
      return res.status(503).json({ error: "Prefs not available" });
    const prefs = await NotificationPrefs.findOneAndUpdate(
      { userId: req.user.id },
      { ...req.body, updatedAt: new Date() },
      { new: true, upsert: true },
    );
    res.json(prefs);
  } catch (err) {
    res.status(500).json({ error: "Failed to update prefs" });
  }
});

// ── Middleware: verify JWT ──
function requireAuth(req, res, next) {
  // Already authenticated via API key — skip JWT check
  if (req.user) return next();

  const header = req.headers.authorization;
  if (!header?.startsWith("Bearer ")) {
    return res.status(401).json({ error: "No token provided" });
  }
  try {
    req.user = jwt.verify(header.slice(7), JWT_SECRET);
    next();
  } catch (err) {
    const msg =
      err.name === "TokenExpiredError"
        ? "Token expired — please log in again"
        : err.name === "JsonWebTokenError"
          ? "Invalid token — please log in again"
          : "Invalid or expired token";
    res.status(401).json({ error: msg });
  }
}

function optionalAuth(req, res, next) {
  const header = req.headers.authorization;
  if (header?.startsWith("Bearer ")) {
    try {
      req.user = jwt.verify(header.slice(7), JWT_SECRET);
    } catch {}
  }
  if (!req.user) req.user = { role: "guest" };
  next();
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.user?.role)) {
      return res
        .status(403)
        .json({ error: `Requires role: ${roles.join(" or ")}` });
    }
    next();
  };
}

module.exports = { router, requireAuth, optionalAuth, requireRole };
