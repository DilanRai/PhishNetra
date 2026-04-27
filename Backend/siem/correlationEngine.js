// ================================================================
// FILE: backend/siem/correlationEngine.js
// SentinelCore Correlation Engine
// Links related events across time to detect attack chains
// This is what makes us more than just a log aggregator
// ================================================================

const Event = require("./models/Event");
const Alert = require("./models/Alert");

// ── Correlation window: 30 minutes by default ──
const CORRELATION_WINDOW_MS = 30 * 60 * 1000;

// ── Attack chain patterns to detect ──
const CHAIN_PATTERNS = [

  {
    id:   "CHAIN-001",
    name: "Phishing → Credential Harvest Chain",
    description: "Multiple phishing events targeting same domain, escalating in severity",
    detect: async (recentEvents) => {
      // Group by domain
      const byDomain = {};
      for (const e of recentEvents) {
        const d = e.target?.domain;
        if (!d) continue;
        if (!byDomain[d]) byDomain[d] = [];
        byDomain[d].push(e);
      }
      const chains = [];
      for (const [domain, events] of Object.entries(byDomain)) {
        if (events.length >= 3) {
          const hasOtp = events.some((e) =>
            e.rawData?.issues?.some((i) => /otp/i.test(i))
          );
          if (hasOtp) {
            chains.push({
              patternId:   "CHAIN-001",
              name:        "Phishing → Credential Harvest Chain",
              domain,
              eventCount:  events.length,
              eventIds:    events.map((e) => e.eventId),
              severity:    5,
              description: `Attack chain detected: ${events.length} phishing events targeting ${domain}, including OTP harvesting`,
            });
          }
        }
      }
      return chains;
    },
  },

  {
    id:   "CHAIN-002",
    name: "Brand Impersonation Campaign",
    description: "Multiple domains spoofing the same brand",
    detect: async (recentEvents) => {
      const spoofEvents = recentEvents.filter((e) =>
        e.rawData?.issues?.some((i) => /impersonat|spoofing/i.test(i))
      );
      if (spoofEvents.length < 3) return [];

      // Extract which brand is being spoofed
      const brandMap = {};
      for (const e of spoofEvents) {
        const issue = (e.rawData?.issues || []).find((i) => /impersonat|spoofing/i.test(i));
        const brandMatch = issue?.match(/"([^"]+)"/);
        const brand = brandMatch?.[1] || "unknown";
        if (!brandMap[brand]) brandMap[brand] = [];
        brandMap[brand].push(e);
      }

      const chains = [];
      for (const [brand, events] of Object.entries(brandMap)) {
        if (events.length >= 2) {
          chains.push({
            patternId:   "CHAIN-002",
            name:        `Brand Impersonation Campaign — ${brand}`,
            brand,
            eventCount:  events.length,
            eventIds:    events.map((e) => e.eventId),
            severity:    4,
            description: `${events.length} domains impersonating "${brand}" detected — coordinated campaign`,
          });
        }
      }
      return chains;
    },
  },

  {
    id:   "CHAIN-003",
    name: "Scanning Burst → Phishing",
    description: "High volume of scans followed by confirmed phishing",
    detect: async (recentEvents) => {
      const phishing = recentEvents.filter((e) => e.rawData?.status === "phishing" || e.riskScore >= 75);
      const total    = recentEvents.length;
      if (total >= 20 && phishing.length >= 5) {
        return [{
          patternId:   "CHAIN-003",
          name:        "Automated Phishing Campaign Burst",
          eventCount:  total,
          phishingCount: phishing.length,
          eventIds:    recentEvents.map((e) => e.eventId),
          severity:    4,
          description: `${phishing.length} phishing detections in burst of ${total} scans — possible automated campaign`,
        }];
      }
      return [];
    },
  },
];

// ── Run correlation on recent events ──
async function runCorrelation() {
  const since = new Date(Date.now() - CORRELATION_WINDOW_MS);
  const recentEvents = await Event.find({
    timestamp: { $gte: since },
    category:  "phishing",
  }).lean();

  if (recentEvents.length === 0) return { chains: 0, results: [] };

  const allChains = [];
  for (const pattern of CHAIN_PATTERNS) {
    try {
      const detected = await pattern.detect(recentEvents);
      allChains.push(...detected);
    } catch { /* pattern error — skip */ }
  }

  // Create correlation alerts for new chains
  for (const chain of allChains) {
    const correlationId = `CORR-${chain.patternId}-${Date.now()}`;

    // Mark events as correlated
    if (chain.eventIds?.length > 0) {
      await Event.updateMany(
        { eventId: { $in: chain.eventIds } },
        { $set: { correlationId } }
      );
    }

    // Create a high-severity alert for the chain
    try {
      await Alert.create({
        title:         chain.name,
        description:   chain.description,
        category:      "phishing",
        ruleId:        chain.patternId,
        ruleName:      chain.name,
        severity:      chain.severity,
        severityLabel: chain.severity >= 5 ? "CRITICAL" : "HIGH",
        eventIds:      chain.eventIds || [],
        eventCount:    chain.eventCount,
        target:        {},
        riskScore:     Math.min(chain.severity * 20, 100),
        correlationId,
        isCorrelated:  true,
        dedupKey:      `${chain.patternId}::${Math.floor(Date.now() / CORRELATION_WINDOW_MS)}`,
        tags:          ["correlation", "attack-chain"],
      });
    } catch { /* dedup collision — already exists */ }
  }

  return { chains: allChains.length, results: allChains };
}

module.exports = { runCorrelation };