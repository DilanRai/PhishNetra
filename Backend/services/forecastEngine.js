// FILE: backend/services/forecastEngine.js
// Proactive threat forecasting — predicts campaigns before they peak
// Extends predictiveEngine.js with campaign-level intelligence

const Scan = require("../models/Scan");
const geoip = require("geoip-lite");

// ── Weighted moving average (more weight to recent data) ──
function weightedMovingAverage(points, windowSize = 6) {
  if (points.length < windowSize) return points.map(p => p.y);
  return points.map((_, i) => {
    if (i < windowSize - 1) return points[i].y;
    const window = points.slice(i - windowSize + 1, i + 1);
    const weights = window.map((_, wi) => wi + 1);
    const wSum = weights.reduce((a, b) => a + b, 0);
    return window.reduce((s, p, wi) => s + p.y * weights[wi], 0) / wSum;
  });
}

// ── Detect emerging brand campaign spikes ──
async function detectEmergingCampaigns() {
  const since6h = new Date(Date.now() - 6 * 60 * 60 * 1000);
  const since24h = new Date(Date.now() - 24 * 60 * 60 * 1000);
  const since7d = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);

  // Current window brand hits
  const [recent, baseline] = await Promise.all([
    Scan.aggregate([
      {
        $match: {
          createdAt: { $gte: since6h }, status: "phishing",
          "dna.brand": { $nin: [null, "unknown"] }
        }
      },
      {
        $group: {
          _id: "$dna.brand", count: { $sum: 1 },
          techniques: { $addToSet: "$dna.technique" },
          fingerprints: { $addToSet: "$dna.fingerprint" }
        }
      },
      { $sort: { count: -1 } }, { $limit: 10 },
    ]),
    Scan.aggregate([
      {
        $match: {
          createdAt: { $gte: since7d, $lt: since24h },
          status: "phishing", "dna.brand": { $nin: [null, "unknown"] }
        }
      },
      {
        $group: {
          _id: "$dna.brand",
          avgPerHour: { $sum: { $divide: [1, 144] } }
        }
      }, // 144 = 7d*24h/day
    ]),
  ]);

  const baselineMap = {};
  baseline.forEach(b => { baselineMap[b._id] = b.avgPerHour * 6; }); // scale to 6h

  const emerging = recent.map(r => {
    const base = baselineMap[r._id] || 0.1;
    const spike = r.count / base;
    const confidence = Math.min(Math.round((spike / 10) * 100), 95);
    return {
      brand: r._id,
      currentHits: r.count,
      baseline: Math.round(base * 10) / 10,
      spikeRatio: Math.round(spike * 10) / 10,
      confidence,
      techniques: r.techniques.filter(Boolean),
      fingerprints: r.fingerprints.filter(Boolean).slice(0, 3),
      isEmerging: spike >= 3 && r.count >= 3,
      predictedPeak: spike >= 5 ? "next 2–4 hours" :
        spike >= 3 ? "next 4–8 hours" : "ongoing",
    };
  }).filter(e => e.isEmerging);

  return emerging;
}

// ── Honeypot correlation — IPs that hit honeypots ──
async function getHoneypotCorrelation() {
  // We store honeypot hits in memory (routes/honeypot.js)
  // This checks SIEM events for honeypot triggers
  try {
    const Event = require("../siem/models/Event");
    const since48h = new Date(Date.now() - 48 * 60 * 60 * 1000);
    const honeypotEvents = await Event.find({
      timestamp: { $gte: since48h },
      "rawData.type": "honeypot_triggered",
    }).lean();

    // Group by IP + count
    const ipHits = {};
    honeypotEvents.forEach(e => {
      const ip = e.source?.ip || e.rawData?.ip;
      if (ip) ipHits[ip] = (ipHits[ip] || 0) + 1;
    });

    const highRisk = Object.entries(ipHits)
      .filter(([, count]) => count >= 3)
      .map(([ip, count]) => {
        const geo = geoip.lookup(ip);
        return {
          ip, hits: count, country: geo?.country || "Unknown",
          threatLevel: count >= 5 ? "imminent_campaign" : "reconnaissance"
        };
      });

    return highRisk;
  } catch { return []; }
}

// ── Typosquatting pattern prediction ──
async function predictTyposquattingCampaign() {
  // Look at domain patterns from last 7 days
  const since7d = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
  const typos = await Scan.aggregate([
    {
      $match: {
        createdAt: { $gte: since7d }, status: "phishing",
        attackTypes: "typosquatting"
      }
    },
    {
      $group: {
        _id: "$dna.brand", count: { $sum: 1 },
        tlds: { $addToSet: "$dna.tld" }
      }
    },
    { $sort: { count: -1 } }, { $limit: 5 },
  ]);

  return typos.map(t => ({
    brand: t._id,
    variants: t.count,
    tlds: t.tlds.filter(Boolean),
    confidence: Math.min(t.count * 15, 85),
    prediction: t.count >= 4
      ? `Active typosquatting campaign against ${t._id} — ${t.count} variants detected`
      : `Emerging typosquatting pattern for ${t._id}`,
  })).filter(t => t.variants >= 2);
}

// ── Day/hour pattern for next 24h forecast ──
async function getNextDayForecast() {
  const since14d = new Date(Date.now() - 14 * 24 * 60 * 60 * 1000);
  const hourlyData = await Scan.aggregate([
    { $match: { createdAt: { $gte: since14d } } },
    {
      $group: {
        _id: { day: { $dayOfWeek: "$createdAt" }, hour: { $hour: "$createdAt" } },
        total: { $sum: 1 },
        phish: { $sum: { $cond: [{ $eq: ["$status", "phishing"] }, 1, 0] } },
      }
    },
  ]);

  // Build 7x24 matrix
  const matrix = Array(7).fill(null).map(() => Array(24).fill({ total: 0, phish: 0 }));
  hourlyData.forEach(d => {
    matrix[d._id.day - 1][d._id.hour] = { total: d.total, phish: d.phish };
  });

  // Next 12 hours prediction
  const now = new Date();
  const forecast = [];
  for (let i = 1; i <= 12; i++) {
    const futureTime = new Date(now.getTime() + i * 60 * 60 * 1000);
    const day = futureTime.getDay();
    const hour = futureTime.getHours();
    const cell = matrix[day][hour];
    const phishRate = cell.total > 0 ? (cell.phish / cell.total) * 100 : 0;
    forecast.push({
      hoursFromNow: i,
      hour: hour,
      label: futureTime.toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit", hour12: true }),
      predictedPhishRate: Math.round(phishRate),
      riskLevel: phishRate >= 60 ? "high" : phishRate >= 30 ? "medium" : "low",
    });
  }
  return forecast;
}

// ── MAIN: full campaign forecast ──
async function getCampaignForecast() {
  const [emerging, honeypots, typosquatting, hourForecast] = await Promise.all([
    detectEmergingCampaigns(),
    getHoneypotCorrelation(),
    predictTyposquattingCampaign(),
    getNextDayForecast(),
  ]);

  // Overall threat level
  const hasCritical = emerging.some(e => e.confidence >= 70) ||
    honeypots.some(h => h.threatLevel === "imminent_campaign");
  const threatLevel = hasCritical ? "HIGH" :
    (emerging.length > 0 || typosquatting.length > 0) ? "MEDIUM" : "LOW";

  // Composite confidence
  const confidence = emerging.length > 0
    ? Math.max(...emerging.map(e => e.confidence))
    : typosquatting.length > 0
      ? Math.max(...typosquatting.map(t => t.confidence))
      : 20;

  // Natural language summary
  let summary = "";
  if (emerging.length > 0) {
    const topBrand = emerging[0];
    summary = `Active ${topBrand.brand} campaign spike detected — ${topBrand.spikeRatio}x above baseline. Peak expected ${topBrand.predictedPeak}.`;
  } else if (honeypots.length > 0) {
    summary = `${honeypots[0].ip} has triggered honeypots ${honeypots[0].hits} times — mass campaign likely imminent.`;
  } else if (typosquatting.length > 0) {
    summary = `${typosquatting[0].variants} typosquatting variants targeting ${typosquatting[0].brand} — campaign building.`;
  } else {
    summary = "No immediate campaign threats detected. Monitoring active.";
  }

  return {
    threatLevel,
    confidence,
    summary,
    emergingCampaigns: emerging,
    honeypotAlerts: honeypots,
    typosquatting,
    hourForecast,
    indicators: emerging.length + honeypots.length + typosquatting.length,
    generatedAt: new Date().toISOString(),
  };
}

module.exports = { getCampaignForecast, detectEmergingCampaigns };