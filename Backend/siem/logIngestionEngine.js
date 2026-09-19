// Processes incoming log events: brute force correlation, severity scoring,
// MITRE mapping. Mirrors your existing eventEngine.js pattern.

const crypto = require("crypto");
const LogEvent = require("./models/LogEvent");
const { isDomainMalicious } = require("../services/threatIntel");

// ── MITRE mapping for log-based attack types ──
const LOG_MITRE_MAP = {
  failed_login: {
    tactic: "TA0006 - Credential Access",
    technique: "T1110 - Brute Force",
  },
  multiple_login_attempts: {
    tactic: "TA0006 - Credential Access",
    technique: "T1110.001 - Password Guessing",
  },
  powershell_execution: {
    tactic: "TA0002 - Execution",
    technique: "T1059.001 - PowerShell",
  },
  suspicious_process: {
    tactic: "TA0002 - Execution",
    technique: "T1055 - Process Injection",
  },
  account_lockout: {
    tactic: "TA0006 - Credential Access",
    technique: "T1110 - Brute Force (Account Lockout)",
  },
  malware_detected: {
    tactic: "TA0002 - Execution",
    technique: "T1204.002 - User Execution: Malicious File",
  },
  application_error: {
    tactic: "TA0005 - Defense Evasion",
    technique: "T1055 - Process Injection (suspected)",
  },
  usb_activity: {
    tactic: "TA0010 - Exfiltration",
    technique: "T1052.001 - USB Exfiltration",
  },
  dns_malicious: {
    tactic: "TA0011 - Command and Control",
    technique: "T1071.004 - DNS",
  },
  browser_alert: {
    tactic: "TA0001 - Initial Access",
    technique: "T1566 - Phishing",
  },
};

// ── In-memory tracking for brute force detection ──
// Map<sourceIp+sourceUser, [{timestamp}]>
const failedLoginTracker = new Map();
const BRUTE_FORCE_WINDOW = 2 * 60 * 1000; // 2 minutes
const BRUTE_FORCE_THRESHOLD = 5; // 5+ failures = brute force

function cleanOldAttempts(key) {
  const now = Date.now();
  const attempts = failedLoginTracker.get(key) || [];
  const recent = attempts.filter((t) => now - t < BRUTE_FORCE_WINDOW);
  failedLoginTracker.set(key, recent);
  return recent;
}

// ── MAIN: ingest a log event ──
async function ingestLogEvent(data) {
  let { logType, description } = data;
  const { sourceHost, sourceIp, sourceUser, eventId, rawData } = data;

  let severity = data.severity || 2;
  let attackTypes = [];
  let correlationKey = null;

  // ── Brute force / multiple login attempt detection ──
  if (logType === "failed_login") {
    const key = `${sourceIp || "unknown"}:${sourceUser || "unknown"}`;
    const attempts = cleanOldAttempts(key);
    attempts.push(Date.now());
    failedLoginTracker.set(key, attempts);

    if (attempts.length >= BRUTE_FORCE_THRESHOLD) {
      // Escalate — this is now a brute force pattern, not just a failed login
      severity = 4;
      attackTypes.push("brute_force");
      correlationKey = key;

      // Log the escalated brute force event separately
      await LogEvent.create({
        logType: "multiple_login_attempts",
        sourceHost,
        sourceIp,
        sourceUser,
        severity: 4,
        description: `Brute force detected: ${attempts.length} failed login attempts for user "${sourceUser}" from ${sourceIp} within 2 minutes`,
        rawData: {
          attemptCount: attempts.length,
          windowMs: BRUTE_FORCE_WINDOW,
        },
        attackTypes: ["brute_force"],
        mitre: LOG_MITRE_MAP.multiple_login_attempts,
        correlationKey: key,
        collectedAt: new Date(),
        collectedBy: data.collectedBy || "system",
        integrityHash: crypto
          .createHash("sha256")
          .update(
            JSON.stringify({
              attemptCount: attempts.length,
              windowMs: BRUTE_FORCE_WINDOW,
            }),
          )
          .digest("hex"),
      });
    } else if (attempts.length >= 3) {
      severity = 3; // elevate slightly even before full threshold
    }
  }

  // ── PowerShell obfuscation detection ──
  if (logType === "powershell_execution" && rawData?.commandLine) {
    const cmd = rawData.commandLine.toLowerCase();
    if (
      /-encodedcommand|frombase64string|downloadstring|iex\s*\(|invoke-expression|-enc\s/i.test(
        cmd,
      )
    ) {
      severity = 5;
      attackTypes.push("obfuscated_powershell");
    } else if (/-windowstyle\s+hidden|-noprofile|bypass/i.test(cmd)) {
      severity = 4;
      attackTypes.push("suspicious_powershell_flags");
    }
  }

  // ── Suspicious process parent-child detection ──
  if (
    logType === "suspicious_process" &&
    rawData?.parentProcess &&
    rawData?.process
  ) {
    const parent = rawData.parentProcess.toLowerCase();
    const proc = rawData.process.toLowerCase();
    // Office app spawning shell = classic macro malware pattern
    const officeApps = [
      "winword.exe",
      "excel.exe",
      "powerpnt.exe",
      "outlook.exe",
    ];
    const shells = ["cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe"];
    if (
      officeApps.some((a) => parent.includes(a)) &&
      shells.some((s) => proc.includes(s))
    ) {
      severity = 5;
      attackTypes.push("office_macro_spawn");
    }
    // Process running from suspicious location
    if (
      rawData?.processPath &&
      /\\(downloads|temp|appdata\\local\\temp)\\/i.test(rawData.processPath)
    ) {
      severity = Math.max(severity, 4);
      attackTypes.push("execution_from_temp_path");
    }
  }

  // ── DNS malicious domain check — real-time cross-reference against ──
  // ── PhishTank + OpenPhish caches (same feeds your scanner already uses) ──
  if (logType === "dns_query" && rawData?.queriedDomain) {
    const result = isDomainMalicious(rawData.queriedDomain);
    if (result.found) {
      logType = "dns_malicious"; // reclassify — this becomes the alert type
      severity = 4;
      attackTypes.push("malicious_dns_query");
      rawData.threatSources = result.sources;
      description = `Malicious DNS query: ${rawData.queriedDomain} (confirmed by ${result.sources.join(", ")})`;
    } else {
      // Not malicious — don't even store it. This is the key cost control:
      // we only log DNS queries that actually match a known-bad domain,
      // not every DNS query the machine makes (which would be thousands/day).
      return null;
    }
  }

  // ── USB activity — flag unregistered devices ──
  if (logType === "usb_activity" && rawData?.isRegistered === false) {
    severity = 3;
    attackTypes.push("unregistered_usb_device");
  }

  const mitre = LOG_MITRE_MAP[logType] || null;

  const event = await LogEvent.create({
    logType,
    sourceHost,
    sourceIp,
    sourceUser,
    severity,
    eventId,
    description,
    rawData,
    attackTypes,
    mitre,
    correlationKey,
    collectedAt: data.collectedAt || new Date(),
    collectedBy: data.collectedBy || "system",
    integrityHash:
      data.integrityHash ||
      crypto
        .createHash("sha256")
        .update(JSON.stringify(rawData || {}))
        .digest("hex"),
  });

  return event;
}

// ── Get aggregate stats for dashboard (mirrors your stats endpoint pattern) ──
async function getLogStats() {
  const since24h = new Date(Date.now() - 24 * 60 * 60 * 1000);

  const [totalLogs, logs24h, byType, bySeverity, recentLogs, bruteForceCount] =
    await Promise.all([
      LogEvent.countDocuments({}),
      LogEvent.countDocuments({ createdAt: { $gte: since24h } }),
      LogEvent.aggregate([{ $group: { _id: "$logType", count: { $sum: 1 } } }]),
      LogEvent.aggregate([
        { $group: { _id: "$severity", count: { $sum: 1 } } },
      ]),
      LogEvent.find({}).sort({ createdAt: -1 }).limit(20).lean(),
      LogEvent.countDocuments({
        attackTypes: "brute_force",
        createdAt: { $gte: since24h },
      }),
    ]);

  const typeMap = {};
  byType.forEach((t) => {
    typeMap[t._id] = t.count;
  });
  const sevMap = { 1: 0, 2: 0, 3: 0, 4: 0, 5: 0 };
  bySeverity.forEach((s) => {
    sevMap[s._id] = s.count;
  });

  return {
    totalLogs,
    logs24h,
    bruteForceCount24h: bruteForceCount,
    byType: typeMap,
    bySeverity: sevMap,
    recentLogs,
  };
}

module.exports = { ingestLogEvent, getLogStats, LOG_MITRE_MAP };
