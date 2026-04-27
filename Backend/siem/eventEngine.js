// ================================================================
// FILE: backend/siem/eventEngine.js
// SentinelCore Event Engine
// Ingests raw data → normalizes → runs rules → fires alerts
// ================================================================

const Event           = require("./models/Event");
const Alert           = require("./models/Alert");
const { matchRules, SEVERITY_LABELS } = require("./ruleEngine");

// ── Normalize incoming data into standard event shape ──
function normalizeEvent(raw) {
  const now = new Date();

  // Extract domain from URL
  const getDomain = (url) => {
    try { return new URL(url).hostname.replace(/^www\./, ""); }
    catch { return null; }
  };

  // Map PhishGuard scan result → SIEM event
  if (raw.type === "phishing_scan") {
    const scan = raw.data;
    return {
      category:    "phishing",
      subcategory: scan.status,
      severity:    scan.riskScore >= 75 ? 5
                 : scan.riskScore >= 50 ? 4
                 : scan.riskScore >= 30 ? 3 : 1,
      severityLabel: scan.riskScore >= 75 ? "CRITICAL"
                   : scan.riskScore >= 50 ? "HIGH"
                   : scan.riskScore >= 30 ? "MEDIUM" : "INFO",
      source: {
        type:  raw.sourceType || "scanner",
        ip:    raw.sourceIp   || null,
        agent: raw.agent      || "PhishGuard Scanner",
      },
      target: {
        url:    scan.inputType === "url" ? scan.input : null,
        domain: scan.inputType === "url" ? getDomain(scan.input) : null,
        email:  scan.inputType === "email" ? scan.input : null,
      },
      title:       `${scan.status.toUpperCase()} — ${scan.input?.substring(0, 60)}`,
      description: `PhishGuard detected ${scan.status} content. Risk score: ${scan.riskScore}/100`,
      riskScore:   scan.riskScore,
      rawData: {
        issues:    scan.issues || [],
        inputType: scan.inputType,
        mlScore:   scan.mlScore,
        ruleScore: scan.ruleScore,
        confidence: scan.confidence,
      },
      mitre: scan.riskScore >= 65
        ? { tactic: "TA0001 - Initial Access", technique: "T1566.002 - Spearphishing Link" }
        : {},
      compliance: scan.riskScore >= 65 ? ["PCI-DSS 6.4", "GDPR Art.32"] : [],
      timestamp: now,
    };
  }

  // Manual / custom event ingest
  if (raw.type === "custom") {
    const sev = Math.max(1, Math.min(5, raw.severity || 2));
    return {
      category:     raw.category || "system",
      subcategory:  raw.subcategory || "general",
      severity:     sev,
      severityLabel: SEVERITY_LABELS[sev],
      source: {
        type:  raw.sourceType || "manual",
        ip:    raw.sourceIp   || null,
        agent: raw.agent      || "Manual",
      },
      target: {
        url:    raw.url    || null,
        domain: raw.domain || (raw.url ? (() => { try { return new URL(raw.url).hostname; } catch { return null; } })() : null),
        ip:     raw.targetIp || null,
        email:  raw.email  || null,
      },
      title:       raw.title       || "Custom Security Event",
      description: raw.description || "",
      riskScore:   raw.riskScore   || null,
      rawData:     raw.rawData     || {},
      mitre:       raw.mitre       || {},
      compliance:  raw.compliance  || [],
      timestamp:   raw.timestamp ? new Date(raw.timestamp) : now,
      tags:        raw.tags || [],
    };
  }

  // Extension event (from Chrome extension)
  if (raw.type === "extension_scan") {
    const sev = raw.data?.riskScore >= 75 ? 5
              : raw.data?.riskScore >= 50 ? 4
              : raw.data?.riskScore >= 30 ? 3 : 1;
    return {
      category:     "phishing",
      subcategory:  raw.data?.status || "unknown",
      severity:     sev,
      severityLabel: SEVERITY_LABELS[sev],
      source: {
        type:  "extension",
        ip:    raw.sourceIp || null,
        agent: "PhishGuard Chrome Extension",
      },
      target: {
        url:    raw.data?.url || null,
        domain: raw.data?.url ? getDomain(raw.data.url) : null,
      },
      title:       `Extension: ${(raw.data?.status || "unknown").toUpperCase()} — ${raw.data?.url?.substring(0, 50)}`,
      description: `Chrome extension reported ${raw.data?.status} page`,
      riskScore:   raw.data?.riskScore || null,
      rawData:     raw.data || {},
      mitre:       {},
      compliance:  [],
      timestamp:   now,
      tags:        ["extension"],
    };
  }

  // Fallback
  return {
    category:     raw.category || "system",
    subcategory:  "unknown",
    severity:     raw.severity || 1,
    severityLabel: SEVERITY_LABELS[raw.severity || 1],
    source:       { type: "api" },
    target:       {},
    title:        raw.title || "Unknown Event",
    description:  raw.description || "",
    riskScore:    null,
    rawData:      raw,
    mitre:        {},
    compliance:   [],
    timestamp:    now,
    tags:         [],
  };
}

// ── Generate dedup key to prevent duplicate alerts ──
function getDedupKey(ruleId, event, windowMs) {
  const windowBucket = Math.floor(Date.now() / windowMs);
  const target = event.target?.domain || event.target?.url || event.target?.ip || "unknown";
  return `${ruleId}::${target}::${windowBucket}`;
}

// ── Core ingest pipeline ──
async function ingestEvent(rawData) {
  try {
    // 1. Normalize
    const normalized = normalizeEvent(rawData);

    // 2. Save event to DB
    const event = new Event(normalized);
    await event.save();

    // 3. Run rule engine
    const ruleMatches = matchRules({ ...normalized, rawData: normalized.rawData });

    // 4. Fire alerts for each matched rule
    const firedAlerts = [];
    for (const match of ruleMatches) {
      const dedupKey = getDedupKey(match.ruleId, normalized, match.dedupWindow);

      // Try to upsert alert (dedup by key)
      try {
        const existingAlert = await Alert.findOne({ dedupKey });

        if (existingAlert) {
          // Update existing alert
          existingAlert.lastSeen  = new Date();
          existingAlert.eventCount += 1;
          existingAlert.eventIds.push(event.eventId);
          await existingAlert.save();
          firedAlerts.push(existingAlert);
        } else {
          // Create new alert
          const alert = new Alert({
            title:         match.ruleName,
            description:   match.description,
            category:      match.category,
            ruleId:        match.ruleId,
            ruleName:      match.ruleName,
            severity:      match.severity,
            severityLabel: match.severityLabel,
            eventIds:      [event.eventId],
            eventCount:    1,
            target:        normalized.target,
            source:        normalized.source,
            mitre:         match.mitre,
            riskScore:     normalized.riskScore || 0,
            correlationId: normalized.correlationId || null,
            dedupKey,
            tags:          match.compliance.map((c) => `compliance:${c}`),
          });
          await alert.save();

          // Link event → alert
          event.alertId      = alert.alertId;
          event.status       = "alerted";
          event.ruleMatches  = ruleMatches.map((r) => r.ruleId);
          event.processed    = true;
          await event.save();

          firedAlerts.push(alert);
        }
      } catch (dedupErr) {
        if (dedupErr.code !== 11000) throw dedupErr; // ignore duplicate key errors
      }
    }

    if (ruleMatches.length === 0) {
      event.processed = true;
      event.status    = "suppressed";
      await event.save();
    }

    return {
      eventId:    event.eventId,
      alertsFired: firedAlerts.length,
      rulesMatched: ruleMatches.map((r) => r.ruleId),
      severity:   normalized.severity,
    };

  } catch (err) {
    console.error("SentinelCore ingest error:", err.message);
    throw err;
  }
}

// ── Auto-ingest from PhishGuard scan results ──
// Called internally whenever a scan completes
async function ingestFromScan(scanResult, input, meta = {}) {
  if (scanResult.status === "safe" && scanResult.riskScore < 20) return null; // Skip trivially safe
  return ingestEvent({
    type:       "phishing_scan",
    sourceType: meta.sourceType || "scanner",
    sourceIp:   meta.sourceIp   || null,
    agent:      meta.agent      || "PhishGuard Scanner",
    data: {
      ...scanResult,
      input,
      url: input,
    },
  });
}

module.exports = { ingestEvent, ingestFromScan, normalizeEvent };