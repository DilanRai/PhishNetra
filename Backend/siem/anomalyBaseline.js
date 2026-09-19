// FILE: backend/siem/anomalyBaseline.js
// Learns normal scan behavior and fires alerts when it deviates

const Scan = require("../models/Scan");
const { ingestEvent } = require("./eventEngine");

// ── Config ──
const WINDOW_HOURS   = 1;    // compare current hour vs baseline
const BASELINE_DAYS  = 7;    // learn from last 7 days
const SPIKE_THRESHOLD= 40;   // % above baseline triggers alert
const MIN_SCANS      = 5;    // min scans needed before anomaly fires

// ── Compute baseline: avg scans/hour over last N days ──
async function computeBaseline() {
  const since = new Date(Date.now() - BASELINE_DAYS * 24 * 60 * 60 * 1000);

  const hourlyData = await Scan.aggregate([
    { $match: { createdAt: { $gte: since } } },
    { $group: {
        _id: {
          day:  { $dayOfYear: "$createdAt" },
          hour: { $hour:      "$createdAt" },
        },
        total:         { $sum: 1 },
        phishingCount: { $sum: { $cond: [{ $eq: ["$status","phishing"] }, 1, 0] } },
    }},
  ]);

  if (hourlyData.length === 0) return null;

  const totalScans    = hourlyData.reduce((s, d) => s + d.total, 0);
  const totalPhishing = hourlyData.reduce((s, d) => s + d.phishingCount, 0);
  const hours         = hourlyData.length;

  return {
    avgScansPerHour:    totalScans    / hours,
    avgPhishingPerHour: totalPhishing / hours,
    avgPhishingRate:    totalScans > 0 ? (totalPhishing / totalScans) * 100 : 0,
    sampleHours:        hours,
    computedAt:         new Date(),
  };
}

// ── Get current hour's stats ──
async function getCurrentHourStats() {
  const since = new Date(Date.now() - WINDOW_HOURS * 60 * 60 * 1000);

  const [total, phishing, suspicious] = await Promise.all([
    Scan.countDocuments({ createdAt: { $gte: since } }),
    Scan.countDocuments({ createdAt: { $gte: since }, status: "phishing"   }),
    Scan.countDocuments({ createdAt: { $gte: since }, status: "suspicious" }),
  ]);

  return {
    total,
    phishing,
    suspicious,
    phishingRate: total > 0 ? Math.round((phishing / total) * 100) : 0,
  };
}

// ── Main: run anomaly check ──
async function runAnomalyCheck() {
  try {
    const [baseline, current] = await Promise.all([
      computeBaseline(),
      getCurrentHourStats(),
    ]);

    if (!baseline || current.total < MIN_SCANS) return { checked: false, reason: "Insufficient data" };

    const anomalies = [];

    // ── CHECK 1: Scan volume spike ──
    const volumeIncrease = baseline.avgScansPerHour > 0
      ? ((current.total - baseline.avgScansPerHour) / baseline.avgScansPerHour) * 100
      : 0;

    if (volumeIncrease >= SPIKE_THRESHOLD && current.total >= MIN_SCANS) {
      anomalies.push({
        type:        "volume_spike",
        metric:      "scan_volume",
        currentVal:  current.total,
        baselineVal: Math.round(baseline.avgScansPerHour),
        increasePC:  Math.round(volumeIncrease),
        severity:    volumeIncrease >= 200 ? 5 : volumeIncrease >= 100 ? 4 : 3,
        description: `Scan volume ${Math.round(volumeIncrease)}% above baseline (${current.total} scans vs avg ${Math.round(baseline.avgScansPerHour)}/hr)`,
      });
    }

    // ── CHECK 2: Phishing rate spike ──
    const rateIncrease = baseline.avgPhishingRate > 0
      ? ((current.phishingRate - baseline.avgPhishingRate) / baseline.avgPhishingRate) * 100
      : current.phishingRate > 20 ? 100 : 0;

    if (current.phishingRate > 30 && rateIncrease >= SPIKE_THRESHOLD) {
      anomalies.push({
        type:        "phishing_rate_spike",
        metric:      "phishing_rate",
        currentVal:  current.phishingRate,
        baselineVal: Math.round(baseline.avgPhishingRate),
        increasePC:  Math.round(rateIncrease),
        severity:    current.phishingRate >= 70 ? 5 : current.phishingRate >= 50 ? 4 : 3,
        description: `Phishing rate ${current.phishingRate}% (baseline: ${Math.round(baseline.avgPhishingRate)}%) — ${Math.round(rateIncrease)}% above normal`,
      });
    }

    // ── CHECK 3: Absolute phishing burst ──
    if (current.phishing >= 10 && baseline.avgPhishingPerHour < 5) {
      anomalies.push({
        type:        "phishing_burst",
        metric:      "phishing_count",
        currentVal:  current.phishing,
        baselineVal: Math.round(baseline.avgPhishingPerHour),
        increasePC:  null,
        severity:    current.phishing >= 20 ? 5 : 4,
        description: `Phishing burst detected — ${current.phishing} phishing scans in last hour (baseline avg: ${Math.round(baseline.avgPhishingPerHour)}/hr)`,
      });
    }

    // ── CHECK 4: Zero-to-suspicious (new activity after silence) ──
    if (baseline.avgScansPerHour < 1 && current.total >= MIN_SCANS && current.phishing >= 3) {
      anomalies.push({
        type:        "cold_start_threat",
        metric:      "activity_after_silence",
        currentVal:  current.phishing,
        baselineVal: 0,
        increasePC:  null,
        severity:    4,
        description: `Unusual activity after silence — ${current.phishing} phishing detections from inactive system`,
      });
    }

    // ── Ingest each anomaly as a SIEM event ──
    for (const anomaly of anomalies) {
      await ingestEvent({
        type:        "custom",
        category:    "anomaly",
        subcategory: anomaly.type,
        severity:    anomaly.severity,
        title:       `Behavioral Anomaly: ${anomaly.description}`,
        description: anomaly.description,
        sourceType:  "anomaly_engine",
        agent:       "SentinelCore Anomaly Baseline",
        rawData: {
          type:        anomaly.type,
          metric:      anomaly.metric,
          value:       anomaly.currentVal,
          baseline:    anomaly.baselineVal,
          increasePC:  anomaly.increasePC,
          threshold:   SPIKE_THRESHOLD,
          currentHour: current,
          baseline:    baseline,
        },
        tags: ["anomaly", "behavioral", "auto-detected"],
      });

      console.log(`🧠 Anomaly detected: ${anomaly.type} — ${anomaly.description}`);
    }

    return {
      checked:    true,
      anomalies:  anomalies.length,
      current,
      baseline: {
        avgScansPerHour:    Math.round(baseline.avgScansPerHour * 10) / 10,
        avgPhishingRate:    Math.round(baseline.avgPhishingRate * 10) / 10,
        sampleHours:        baseline.sampleHours,
      },
    };

  } catch (err) {
    console.error("Anomaly check error:", err.message);
    return { checked: false, error: err.message };
  }
}

module.exports = { runAnomalyCheck, computeBaseline, getCurrentHourStats };