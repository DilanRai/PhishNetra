// ================================================================
// FILE: Backend/server.js — FULL REPLACE
// Fixes applied:
//   1. express-rate-limit on all routes (DDoS protection)
//   2. Helmet security headers
//   3. MongoDB URI in .env (was hardcoded)
//   4. Graceful shutdown (SIGINT/SIGTERM)
//   5. Uncaught exception handlers (prevent crash loops)
//   6. Alert escalation fix (notes field was string concat on null)
// ================================================================

require("dotenv").config();

// ── Crash protection — must be first ──
process.on("uncaughtException",  (err) => { console.error("💥 Uncaught:", err.message); });
process.on("unhandledRejection", (err) => { console.error("💥 Unhandled:", err?.message || err); });

const express    = require("express");
const cors       = require("cors");
const mongoose   = require("mongoose");
const http       = require("http");
const { Server } = require("socket.io");

// ── Security packages ──
let rateLimit, helmet;
try { rateLimit = require("express-rate-limit"); } catch { /* optional */ }
try { helmet    = require("helmet"); }             catch { /* optional */ }

const scanRoutes      = require("./routes/scan");
const feedRoutes      = require("./routes/threatfeed");
const { router: authRoutes } = require("./routes/auth");
const honeypotRoutes  = require("./routes/honeypot");
const bulkRoutes      = require("./routes/bulk");
const apiKeyRoutes    = require("./routes/apikeys");
const { apiKeyMiddleware } = require("./middleware/apiKeyAuth");
const threatShareRoutes = require("./routes/threatshare");
const logsRoutes      = require("./routes/logs");
const { idsMiddleware } = require("./middleware/ids");

// Auto ML training — watches datasets/ folder
require("./ai/autoTrainingEngine");

// Lazy-load optional modules safely
const safeRequire = (mod) => { try { return require(mod); } catch { return null; } };

const siemModule       = safeRequire("./routes/siem");
const correlationMod   = safeRequire("./siem/correlationEngine");
const anomalyMod       = safeRequire("./siem/anomalyBaseline");
const emailMod         = safeRequire("./ai/emailNotifier");
const featuresMod      = safeRequire("./routes/features");

const siemRoutes       = siemModule;
const runCorrelation   = correlationMod?.runCorrelation   || null;
const runAnomalyCheck  = anomalyMod?.runAnomalyCheck      || null;
const sendWeeklyDigest = emailMod?.sendWeeklyDigest        || null;

if (siemRoutes)      console.log("🛡️  SentinelCore SIEM: loaded");
if (runCorrelation)  console.log("🔗 Correlation Engine: loaded");
if (runAnomalyCheck) console.log("🧠 Anomaly Baseline: loaded");

// ── Express app ──
const app    = express();
const server = http.createServer(app);

// ── CORS ──
const allowedOrigins = [
  "http://localhost:5173",
  "http://127.0.0.1:5173",
  ...(process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(",") : []),
];
const corsOriginChecker = (origin, cb) => {
  if (!origin) return cb(null, true);
  if (allowedOrigins.includes(origin)) return cb(null, true);
  if (origin.startsWith("chrome-extension://")) return cb(null, true);
  return cb(new Error("Not allowed by CORS"));
};

// ── Security headers (if helmet installed) ──
if (helmet) {
  app.use(helmet({
    contentSecurityPolicy: false, // Disable for API server
    crossOriginEmbedderPolicy: false,
  }));
}

app.use(cors({
  origin:  corsOriginChecker,
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE"],
  allowedHeaders: ["Content-Type", "Authorization", "X-API-Key", "X-PhishNetra-Key"],
}));

// ── Rate limiting ──
if (rateLimit) {
  const limiter = rateLimit({
    windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000,
    max:      parseInt(process.env.RATE_LIMIT_MAX)        || 2000, // 2000 req per 15 min window
    message:  { error: "Too many requests — please try again later" },
    skip: (req) => req.path === "/api/health", // don't rate limit health check
  });
  const scanLimiter = rateLimit({
    windowMs: 60 * 1000,   // 1 minute
    max:      parseInt(process.env.SCAN_RATE_LIMIT_MAX)   || 120,  // 120 scans per minute per IP
    message:  { error: "Scan rate limit reached — max 120/min" },
  });
  app.use(limiter);
  app.use("/api/scan", scanLimiter);
  console.log("🔒 Rate limiting: enabled (global: 2000/15m, scan: 120/1m)");
} else {
  console.log("⚠️  Rate limiting: disabled (run: npm install express-rate-limit)");
}

// ── WebSocket ──
const io = new Server(server, {
  cors: { origin: corsOriginChecker, methods: ["GET", "POST"] },
});
app.set("io", io);

io.on("connection", (socket) => {
  console.log(`🔌 WS connected: ${socket.id}`);

  const viewingAlerts = {};

  socket.on("viewing_alert", ({ alertId, username }) => {
    if (!viewingAlerts[alertId]) viewingAlerts[alertId] = [];
    Object.keys(viewingAlerts).forEach(id => {
      viewingAlerts[id] = viewingAlerts[id].filter(v => v.socketId !== socket.id);
    });
    viewingAlerts[alertId].push({ socketId: socket.id, username });
    io.emit("alert_viewers", { alertId, viewers: viewingAlerts[alertId].map(v => v.username) });
  });

  socket.on("disconnect", () => {
    console.log(`🔌 WS disconnected: ${socket.id}`);
    Object.keys(viewingAlerts).forEach(alertId => {
      viewingAlerts[alertId] = viewingAlerts[alertId].filter(v => v.socketId !== socket.id);
    });
  });
});

// ── MongoDB ──
const MONGODB_URI = process.env.MONGODB_URI || "mongodb://127.0.0.1:27017/phishnetra";
mongoose.connect(MONGODB_URI)
  .then(() => console.log("✅ MongoDB Connected:", MONGODB_URI))
  .catch(err => console.error("❌ MongoDB:", err.message));

// ── Body parser ──
const jsonParser = express.json({ limit: "10mb" });
const formParser = express.urlencoded({ extended: true, limit: "10mb" });

app.use((req, res, next) => {
  if (req.originalUrl?.startsWith("/api/logs/ingest")) {
    return express.raw({
      type: ["application/json", "application/json; charset=utf-8"],
      limit: "10mb",
    })(req, res, next);
  }

  const ct = req.headers["content-type"] || "";
  if (ct.includes("application/x-www-form-urlencoded")) {
    return formParser(req, res, next);
  }

  return jsonParser(req, res, next);
});

// ── IDS Middleware ──
app.use(idsMiddleware);

// ── Health & Root ──
app.get("/", (req, res) => res.json({
  message: "🛡️ PhishNetra AI + SentinelCore SIEM",
  version: "3.0", status: "online",
  siemEnabled: !!siemRoutes,
}));

app.get("/api/health", (req, res) => res.json({
  status: "ok",
  uptime: Math.round(process.uptime()),
  timestamp: new Date().toISOString(),
  mongodb: mongoose.connection.readyState === 1 ? "connected" : "disconnected",
  siem: !!siemRoutes,
}));

// ── Routes ──
app.use("/api/scan",        apiKeyMiddleware);
app.use("/api/keys",        apiKeyRoutes);
app.use("/api/scan",        scanRoutes);
app.use("/api/auth",        authRoutes);
app.use("/api/feed",        feedRoutes);
app.use("/api/honeypot",    honeypotRoutes);
app.use("/api/bulk",        bulkRoutes);
app.use("/api/threatshare", threatShareRoutes);
app.use("/api/logs",        logsRoutes);
if (featuresMod) app.use("/api", featuresMod);
if (siemRoutes)  app.use("/api/siem", siemRoutes);

// ── 404 ──
app.use((req, res) => res.status(404).json({ error: "Route not found", path: req.originalUrl }));

// ── Global error handler ──
app.use((err, req, res, next) => {
  // Don't expose internal errors
  const isDev = process.env.NODE_ENV === "development";
  console.error("Server error:", err.message);
  res.status(500).json({ error: isDev ? err.message : "Internal server error" });
});

// ── Start ──
const PORT = parseInt(process.env.PORT) || 5000;
server.listen(PORT, () => {
  console.log("─────────────────────────────────────");
  console.log("🛡️  PhishNetra AI + SentinelCore SIEM");
  console.log(`🚀 Server: http://localhost:${PORT}`);
  console.log(`🗄️  DB:     ${MONGODB_URI}`);
  console.log("─────────────────────────────────────");
  console.log("⚠️  FIRST TIME? Run: node seed.js");
  console.log("─────────────────────────────────────");
});

// ── Graceful shutdown ──
const shutdown = async (signal) => {
  console.log(`\n${signal} received — shutting down...`);
  server.close();
  await mongoose.disconnect();
  console.log("✅ Clean shutdown");
  process.exit(0);
};
process.on("SIGINT",  () => shutdown("SIGINT"));
process.on("SIGTERM", () => shutdown("SIGTERM"));

// ── Background jobs ──

// Correlation: every 5 min
if (runCorrelation) {
  setInterval(async () => {
    try {
      const r = await runCorrelation();
      if (r?.chains > 0) console.log(`🔗 Correlation: ${r.chains} chain(s)`);
    } catch (e) { console.error("Correlation error:", e.message); }
  }, 5 * 60 * 1000);
}

// Anomaly check: every 15 min
if (runAnomalyCheck) {
  setInterval(async () => {
    try {
      const r = await runAnomalyCheck();
      if (r?.checked && r.anomalies > 0) {
        console.log(`🧠 Anomaly: ${r.anomalies} detected`);
        app.get("io")?.emit("anomaly_detected", {
          anomalies: r.anomalies,
          current:   r.current,
          baseline:  r.baseline,
          timestamp: new Date().toISOString(),
        });
      }
    } catch (e) { console.error("Anomaly error:", e.message); }
  }, 15 * 60 * 1000);
}

// Alert escalation: every 10 min — FIX: notes field null crash
setInterval(async () => {
  try {
    const Alert = safeRequire("./siem/models/Alert");
    if (!Alert) return;
    const { sendCriticalAlert } = emailMod || {};
    const cutoff = new Date(Date.now() - 60 * 60 * 1000);

    const stale = await Alert.find({
      severity:  5,
      status:    "open",
      firstSeen: { $lt: cutoff },
      escalated: { $ne: true },
    });

    for (const alert of stale) {
      // FIX: notes can be null — use String() to avoid crash
      const currentNotes = String(alert.notes || "");
      alert.notes = currentNotes + `\n[${new Date().toISOString()}] AUTO-ESCALATED — open > 1 hour`;
      alert.escalated = true;
      await alert.save();

      sendCriticalAlert?.({
        status: "phishing", riskScore: 100,
        input: `ESCALATED: ${alert.title}`,
        issues: ["Alert open > 1 hour — immediate attention required"],
      }).catch(() => {});

      app.get("io")?.emit("alert_escalated", {
        alertId:   alert.alertId,
        title:     alert.title,
        severity:  5,
        timestamp: new Date().toISOString(),
      });
      console.log(`🚨 Escalated: ${alert.alertId}`);
    }
  } catch (e) { console.error("Escalation error:", e.message); }
}, 10 * 60 * 1000);

// Weekly digest: every Monday 9am
if (sendWeeklyDigest) {
  const scheduleWeekly = () => {
    const now  = new Date();
    const next = new Date();
    next.setDate(now.getDate() + ((1 + 7 - now.getDay()) % 7 || 7));
    next.setHours(9, 0, 0, 0);
    setTimeout(async () => {
      try {
        const Scan   = require("./models/Scan");
        const since7 = new Date(Date.now() - 7 * 24 * 3600 * 1000);
        const [total, phishing, suspicious] = await Promise.all([
          Scan.countDocuments({ createdAt: { $gte: since7 } }),
          Scan.countDocuments({ createdAt: { $gte: since7 }, status: "phishing"   }),
          Scan.countDocuments({ createdAt: { $gte: since7 }, status: "suspicious" }),
        ]);
        await sendWeeklyDigest({ total, phishing, suspicious, safe: total - phishing - suspicious });
      } catch (e) { console.error("Weekly digest error:", e.message); }
      scheduleWeekly();
    }, next - now);
    console.log(`📧 Weekly digest: ${next.toLocaleString()}`);
  };
  scheduleWeekly();
}