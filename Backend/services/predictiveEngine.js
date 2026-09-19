// FILE: backend/services/predictiveEngine.js
// Simple time-series regression on hourly scan data
// Predicts next spike without external ML libraries

const Scan = require("../models/Scan");

// ── Linear regression (least squares) ──
function linearRegression(points) {
  const n  = points.length;
  if (n < 2) return { slope: 0, intercept: points[0]?.y || 0, r2: 0 };
  const sumX  = points.reduce((s, p) => s + p.x, 0);
  const sumY  = points.reduce((s, p) => s + p.y, 0);
  const sumXY = points.reduce((s, p) => s + p.x * p.y, 0);
  const sumX2 = points.reduce((s, p) => s + p.x * p.x, 0);
  const slope     = (n * sumXY - sumX * sumY) / (n * sumX2 - sumX * sumX);
  const intercept = (sumY - slope * sumX) / n;
  // R² goodness of fit
  const meanY = sumY / n;
  const ssTot = points.reduce((s, p) => s + Math.pow(p.y - meanY, 2), 0);
  const ssRes = points.reduce((s, p) => s + Math.pow(p.y - (slope * p.x + intercept), 2), 0);
  const r2    = ssTot === 0 ? 1 : 1 - ssRes / ssTot;
  return { slope, intercept, r2 };
}

// ── Day-of-week pattern analysis ──
function dayOfWeekPattern(hourlyData) {
  const byDay = Array(7).fill(null).map(() => ({ total: 0, phishing: 0, count: 0 }));
  hourlyData.forEach(d => {
    const day = new Date(d._id).getDay(); // 0=Sun, 1=Mon...
    byDay[day].total    += d.total;
    byDay[day].phishing += d.phishing;
    byDay[day].count    += 1;
  });
  const DAY_NAMES = ["Sunday","Monday","Tuesday","Wednesday","Thursday","Friday","Saturday"];
  return byDay.map((d, i) => ({
    day:       DAY_NAMES[i],
    avgTotal:   d.count > 0 ? Math.round(d.total    / d.count) : 0,
    avgPhishing:d.count > 0 ? Math.round(d.phishing / d.count) : 0,
    rate:       d.total > 0  ? Math.round((d.phishing / d.total) * 100) : 0,
  }));
}

// ── Hour-of-day pattern (peak hours) ──
function hourOfDayPattern(hourlyData) {
  const byHour = Array(24).fill(null).map(() => ({ total: 0, phishing: 0, count: 0 }));
  hourlyData.forEach(d => {
    const hour = new Date(d._id).getHours();
    byHour[hour].total    += d.total;
    byHour[hour].phishing += d.phishing;
    byHour[hour].count    += 1;
  });
  return byHour.map((h, i) => ({
    hour:       i,
    avgTotal:   h.count > 0 ? Math.round(h.total    / h.count) : 0,
    avgPhishing:h.count > 0 ? Math.round(h.phishing / h.count) : 0,
  }));
}

// ── Main prediction engine ──
async function getPredictiveInsights() {
  const since14d = new Date(Date.now() - 14 * 24 * 60 * 60 * 1000);
  const since24h = new Date(Date.now() -      24 * 60 * 60 * 1000);

  // Hourly aggregation for last 14 days
  const hourlyData = await Scan.aggregate([
    { $match: { createdAt: { $gte: since14d } } },
    { $group: {
        _id:      { $dateToString: { format: "%Y-%m-%dT%H:00", date: "$createdAt" } },
        total:    { $sum: 1 },
        phishing: { $sum: { $cond: [{ $eq: ["$status","phishing"] }, 1, 0] } },
    }},
    { $sort: { _id: 1 } },
  ]);

  if (hourlyData.length < 6) {
    return { insufficient: true, reason: "Need at least 6 hours of data for predictions" };
  }

  // Build time-series points (x = hour index, y = phishing count)
  const points = hourlyData.map((d, i) => ({
    x:        i,
    y:        d.phishing,
    total:    d.total,
    hour:     d._id,
  }));

  // Linear trend
  const regression = linearRegression(points);

  // Next 6 hours prediction
  const lastIdx = points.length - 1;
  const predictions = Array.from({ length: 6 }, (_, i) => {
    const x = lastIdx + i + 1;
    const predicted = Math.max(0, Math.round(regression.slope * x + regression.intercept));
    const hourLabel = new Date(Date.now() + (i + 1) * 60 * 60 * 1000)
      .toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit", hour12: true });
    return { hoursFromNow: i + 1, label: hourLabel, predicted, confidence: Math.max(0, Math.round(regression.r2 * 100)) };
  });

  // Trend direction
  const recentPoints = points.slice(-6);
  const earlyPoints  = points.slice(0, 6);
  const recentAvg = recentPoints.reduce((s, p) => s + p.y, 0) / recentPoints.length;
  const earlyAvg  = earlyPoints.reduce((s,  p) => s + p.y, 0) / earlyPoints.length;
  const trendDir  = recentAvg > earlyAvg * 1.2 ? "rising"
                  : recentAvg < earlyAvg * 0.8 ? "falling" : "stable";

  // Day-of-week + hour patterns
  const dowPattern  = dayOfWeekPattern(hourlyData);
  const hourPattern = hourOfDayPattern(hourlyData);

  // Peak day and hour
  const peakDay  = dowPattern.reduce((a, b) => b.avgPhishing > a.avgPhishing ? b : a);
  const peakHour = hourPattern.reduce((a, b) => b.avgPhishing > a.avgPhishing ? b : a);

  // Current hour vs baseline
  const currentHourData = await Scan.aggregate([
    { $match: { createdAt: { $gte: since24h } } },
    { $group: {
        _id:      { $hour: "$createdAt" },
        phishing: { $sum: { $cond: [{ $eq: ["$status","phishing"] }, 1, 0] } },
    }},
  ]);
  const thisHour    = new Date().getHours();
  const thisHourVal = currentHourData.find(d => d._id === thisHour)?.phishing || 0;
  const baseline    = hourPattern[thisHour]?.avgPhishing || 0;
  const spikeRisk   = baseline > 0
    ? Math.round(((thisHourVal - baseline) / baseline) * 100)
    : 0;

  // Natural language insight
  let insight = "";
  if (trendDir === "rising") {
    insight = `Phishing activity is trending upward. Peak expected around ${predictions.reduce((a,b) => b.predicted > a.predicted ? b : a).label}.`;
  } else if (trendDir === "falling") {
    insight = `Phishing activity is declining from recent levels. Current trajectory is below baseline.`;
  } else {
    insight = `Activity is stable. ${peakDay.day} tends to see the highest phishing volume (avg ${peakDay.avgPhishing}/hr).`;
  }

  if (spikeRisk > 40) {
    insight += ` ⚠️ Current hour is ${spikeRisk}% above baseline — possible active campaign.`;
  }

  return {
    trend:       trendDir,
    trendSlope:  Math.round(regression.slope * 100) / 100,
    r2:          Math.round(regression.r2 * 100),
    predictions,
    peakDay,
    peakHour:    { hour: peakHour.hour, label: `${peakHour.hour}:00`, avgPhishing: peakHour.avgPhishing },
    dowPattern:  dowPattern.filter(d => d.avgTotal > 0),
    hourPattern: hourPattern.slice(6, 23), // 6am-11pm
    spikeRisk,
    insight,
    dataPoints:  hourlyData.length,
    since:       since14d.toISOString(),
  };
}

module.exports = { getPredictiveInsights };