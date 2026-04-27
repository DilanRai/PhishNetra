// FILE: backend/server.js

require("dotenv").config();
const express  = require("express");
const cors     = require("cors");
const mongoose = require("mongoose");

const scanRoutes = require("./routes/scan");

// Lazy-load SIEM routes — won't crash if siem/ folder not yet added
let siemRoutes        = null;
let runCorrelation    = null;
try {
  siemRoutes     = require("./routes/siem");
  runCorrelation = require("./siem/correlationEngine").runCorrelation;
  console.log("🛡️  SentinelCore SIEM: routes loaded");
} catch {
  console.log("ℹ️  SentinelCore SIEM: routes not found — add siem/ folder to enable");
}

const app  = express();
const PORT = process.env.PORT || 5000;

// ── CORS ──
app.use(cors({
  origin:       process.env.FRONTEND_URL || "http://localhost:5173",
  methods:      ["GET", "POST", "PUT", "PATCH", "DELETE"],
  allowedHeaders: ["Content-Type"],
}));

// ── MongoDB ──
mongoose.connect(process.env.MONGODB_URI || "mongodb://127.0.0.1:27017/phishguard")
  .then(() => console.log("✅ MongoDB Connected"))
  .catch((err) => console.error("❌ MongoDB error:", err.message));

app.use(express.json());

// ── ROUTES ──
app.get("/", (req, res) => {
  res.json({
    message:     "🛡️ PhishGuard AI + SentinelCore SIEM",
    version:     "3.0",
    status:      "online",
    siemEnabled: !!siemRoutes,
    endpoints: {
      scan:       "POST /api/scan",
      health:     "GET  /api/health",
      stats:      "GET  /api/scan/stats",
      siemEvents: siemRoutes ? "POST /api/siem/event"  : "disabled",
      siemAlerts: siemRoutes ? "GET  /api/siem/alerts" : "disabled",
    },
  });
});

app.get("/api/health", (req, res) => {
  res.json({ status: "ok", uptime: process.uptime(), timestamp: new Date().toISOString() });
});

app.use("/api/scan", scanRoutes);

if (siemRoutes) {
  app.use("/api/siem", siemRoutes);
}

// ── 404 ──
app.use((req, res) => {
  res.status(404).json({ error: "Route not found", path: req.originalUrl });
});

// ── Global error handler ──
app.use((err, req, res, next) => {
  console.error("Server error:", err.message);
  res.status(500).json({ error: "Internal server error" });
});

// ── START ──
app.listen(PORT, () => {
  console.log("─────────────────────────────────────");
  console.log("🛡️  PhishGuard AI + SentinelCore SIEM");
  console.log(`🚀 Server: http://localhost:${PORT}`);
  if (siemRoutes) {
    console.log(`🔍 SIEM:   http://localhost:${PORT}/api/siem/stats`);
  }
  console.log("─────────────────────────────────────");
});

// ── Auto-correlation job (every 5 min) ──
if (runCorrelation) {
  setInterval(async () => {
    try {
      const result = await runCorrelation();
      if (result.chains > 0) {
        console.log(`🔗 SentinelCore: ${result.chains} attack chain(s) detected`);
      }
    } catch (err) {
      console.error("Auto-correlation error:", err.message);
    }
  }, 5 * 60 * 1000);
}