// FILE: backend/services/attributionEngine.js
// GAP 10: Confidence-Based Attribution Scoring
// Multi-signal engine that scores 13 evidence signals and produces:
//   1. Overall attribution confidence (0-100%)
//   2. Actor type verdict
//   3. Per-signal breakdown with weight, score, detail
//   4. Legal investigation path
//   5. Investigation confidence tier (IDENTIFY / LOCATE / ATTRIBUTE)

"use strict";

// ── RFC1918 / loopback private IP check ──────────────────────
function isPrivateIP(ip) {
  if (!ip) return true;
  return (
    /^10\./.test(ip) ||
    /^172\.(1[6-9]|2\d|3[01])\./.test(ip) ||
    /^192\.168\./.test(ip) ||
    /^127\./.test(ip) ||
    /^::1$/.test(ip) ||
    /^fc00:/i.test(ip) ||
    /^fe80:/i.test(ip)
  );
}

// ════════════════════════════════════════════════════════════════
// ATTRIBUTION SIGNAL DEFINITIONS
// positive weight = helps attribution (we can identify the actor)
// negative weight = hurts attribution (actor is hiding)
// ════════════════════════════════════════════════════════════════
const ATTRIBUTION_SIGNALS = [
  // ── Identity concealment signals (REDUCE confidence) ────────

  {
    id: "tor_exit_node",
    label: "TOR Exit Node",
    weight: -85,
    check: (r) => !!(r.sourceGeo?.isTor || r.ipReputation?.isTorExitNode),
    detail: (r) =>
      `Source IP ${r.sourceIP} is a TOR exit node. Traffic is routed through multiple encrypted relays — the real sender IP cannot be determined from this header alone. Attribution is nearly impossible without TOR internal logs (requires legal process against TOR directory servers, which rarely cooperate).`,
    legalPath:
      "TOR exit node: File complaint with CERT-In (mandated under IT Act). Cross-reference TOR timing correlation with known PhishNetra scan timestamps. Consider upstream network traffic analysis if victim's ISP has full packet capture.",
    tier: "anonymized",
  },

  {
    id: "vpn_detected",
    label: "VPN Provider",
    weight: -55,
    check: (r) => !!(r.sourceGeo?.isVPN && !r.sourceGeo?.isTor),
    detail: (r) =>
      `Source IP ${r.sourceIP} belongs to VPN provider "${r.sourceGeo?.org || r.sourceGeo?.isp}". Real sender IP is masked. Attribution requires a legal preservation request to the VPN provider for connection logs (subscriber IP at timestamp).`,
    legalPath:
      "VPN subscriber records: Send preservation letter to VPN provider within 24-48 hours (logs may be auto-deleted). If provider is Indian: use Section 91 CrPC. If foreign: initiate MLAT (Mutual Legal Assistance Treaty) request via Ministry of Home Affairs.",
    tier: "anonymized",
  },

  {
    id: "datacenter_ip",
    label: "Datacenter / Cloud Hosting",
    weight: -30,
    check: (r) =>
      !!(
        r.sourceGeo?.isDatacenter &&
        !r.sourceGeo?.isVPN &&
        !r.sourceGeo?.isTor
      ),
    detail: (r) =>
      `Source IP ${r.sourceIP} is a cloud/hosting provider IP (${r.sourceGeo?.org || r.sourceGeo?.isp}, ASN: ${r.sourceGeo?.asnCode || r.sourceGeo?.asn}). Actor likely rented infrastructure. Attribution requires subpoena to hosting provider for account/billing records.`,
    legalPath:
      "Hosting provider subpoena: Send legal preservation request to provider (AWS/DO/Linode etc.) with IP + timestamp. Include 90-day hold request. For Indian providers: Section 91 CrPC. Billing records often link to real payment method or identity.",
    tier: "rented_infra",
  },

  {
    id: "relay_chain_anomalies",
    label: "Relay Chain Anomalies",
    weight: -25,
    check: (r) => (r.relayAnomalies?.length || 0) >= 2,
    detail: (r) =>
      `${r.relayAnomalies?.length} relay chain anomalies detected (${(r.relayAnomalies || []).map((a) => a.type).join(", ")}). Headers may have been forged to obscure the true origin. IP extracted from headers may not be the actual sender.`,
    legalPath:
      "Forged headers: Rely on MX server logs at the receiving mail server rather than the Received: headers (which attacker controls). Request victim organization's mail server logs via proper channel.",
    tier: "anonymized",
  },

  {
    id: "disposable_domain",
    label: "Disposable / Free Domain",
    weight: -20,
    check: (r) =>
      !!(r.domainIntel?.isFreeTLD || r.domainIntel?.isFreenomDomain),
    detail: (r) =>
      `Sender domain "${r.fromDomain}" uses a free/disposable TLD (${r.domainIntel?.tld}). Freenom and similar registrars provide domains at no cost with minimal registration requirements — no reliable identity information on file.`,
    legalPath:
      "Free domain registrar: Freenom domains rarely yield identity information. Focus attribution on IP infrastructure rather than domain registration.",
    tier: "spoofed_identity",
  },

  {
    id: "no_spf_live",
    label: "SPF Validation Failure",
    weight: -15,
    check: (r) =>
      r.mxValidation?.spfLiveResult === "fail" ||
      r.mxValidation?.spfLiveResult === "softfail",
    detail: (r) =>
      `Live SPF check: ${(r.mxValidation?.spfLiveResult || "unknown").toUpperCase()} — the sending IP (${r.sourceIP}) is not authorized by ${r.fromDomain}'s SPF record. This confirms the sender domain is spoofed.`,
    legalPath:
      "Domain spoofing confirmed: The real sending domain is NOT the displayed From: domain. Focus on the originating IP infrastructure, not the spoofed domain.",
    tier: "spoofed_identity",
  },

  // ── Identity confirmation signals (INCREASE confidence) ─────

  {
    id: "residential_ip",
    label: "Residential / Mobile IP",
    weight: +40,
    check: (r) =>
      !!(
        !r.sourceGeo?.isTor &&
        !r.sourceGeo?.isVPN &&
        !r.sourceGeo?.isDatacenter &&
        r.sourceIP &&
        !isPrivateIP(r.sourceIP)
      ),
    detail: (r) =>
      `Source IP ${r.sourceIP} is a residential/mobile ISP IP (${r.sourceGeo?.isp}). ISP subscriber records directly identify the account holder (name, address, phone) associated with this IP at the time of the email.`,
    legalPath:
      "ISP subscriber records: Send legal preservation request to ISP within 24-48 hours. Include exact IP, date, time, and timezone. For Indian ISPs: Section 91 CrPC order or court warrant required. ISP must retain records for 1 year under IT Rules 2011.",
    tier: "direct_actor",
  },

  {
    id: "geo_location_available",
    label: "Geolocation Available",
    weight: +20,
    check: (r) => !!(r.sourceGeo?.country && r.sourceGeo?.city),
    detail: (r) =>
      `IP ${r.sourceIP} geolocates to ${r.sourceGeo?.city}, ${r.sourceGeo?.region}, ${r.sourceGeo?.country}. This provides a probable operational location for the threat actor.`,
    legalPath:
      "Geographic context: Coordinate with law enforcement in the actor's probable jurisdiction. For India: contact state CID CyberCell or CERT-In. For foreign jurisdictions: request through INTERPOL or bilateral MLAT.",
    tier: "locate",
  },

  {
    id: "repeat_offender",
    label: "Repeat Offender IP",
    weight: +25,
    check: (r) => (r.ipReputation?.seenInScans || 0) > 3,
    detail: (r) =>
      `IP ${r.sourceIP} has appeared in ${r.ipReputation?.seenInScans} PhishNetra scans. Repeated use of the same IP across multiple attacks strongly suggests a persistent threat actor with a stable operational base.`,
    legalPath:
      "Pattern of conduct: Compile all scan records linking to this IP as evidence of systematic fraud. This supports charges under IPC 420 (cheating) and IT Act Section 66D. Attach PhishNetra scan reports with timestamps.",
    tier: "direct_actor",
  },

  {
    id: "dnsbl_confirmed",
    label: "Blacklisted IP (DNSBL)",
    weight: +15,
    check: (r) =>
      !!((r.ipReputation?.dnsblHits?.length || 0) > 0 && !r.sourceGeo?.isVPN),
    detail: (r) =>
      `IP ${r.sourceIP} is listed in ${r.ipReputation?.dnsblHits?.length} DNSBL(s): ${(
        r.ipReputation?.dnsblHits || []
      )
        .slice(0, 2)
        .map((h) => h.list)
        .join(
          ", ",
        )}. This confirms the IP has a history of malicious email activity.`,
    legalPath:
      "DNSBL listing supports case: Attach DNSBL verification output as technical evidence. Shows pattern of ongoing malicious use from this IP.",
    tier: "direct_actor",
  },

  {
    id: "spf_pass_confirmed",
    label: "SPF Pass — Authorized Sender",
    weight: +20,
    check: (r) => r.mxValidation?.spfLiveResult === "pass",
    detail: (r) =>
      `Live SPF check: PASS — IP ${r.sourceIP} is an authorized sender for ${r.fromDomain}. This confirms the email was sent from infrastructure under ${r.fromDomain}'s control, or a trusted third party.`,
    legalPath:
      "Authorized sender identity: Domain owner is accountable. Send legal notice to domain registrant (via WHOIS or RDAP). If domain registrar is Indian: use MeitY grievance portal.",
    tier: "direct_actor",
  },

  {
    id: "lookalike_brand_confirmed",
    label: "Brand Lookalike Domain",
    weight: +10,
    check: (r) => !!r.domainIntel?.lookalikeBrand,
    detail: (r) =>
      `Sender domain "${r.fromDomain}" is a deliberate lookalike of "${r.domainIntel?.lookalikeBrand}" using ${(r.domainIntel?.lookalikeTechnique || "").replace(/_/g, " ")}. This is intentional trademark infringement and phishing under IT Act Section 66C/66D.`,
    legalPath:
      "Brand impersonation: The targeted brand's cybercrime team (e.g., SBI CERT, PayPal Security) may have additional threat intelligence on this actor. File a parallel complaint with the targeted brand and with NCPCR if targeting individuals.",
    tier: "spoofed_identity",
  },

  {
    id: "botnet_infected",
    label: "Botnet Infected Host",
    weight: -40,
    check: (r) => !!r.ipReputation?.isBotnet,
    detail: (r) =>
      `IP ${r.sourceIP} is flagged as a botnet-infected host (${r.ipReputation?.dnsblHits?.[0]?.list || "DNSBL"}). The actual threat actor is remotely controlling this compromised machine — the IP owner may be an innocent victim.`,
    legalPath:
      "Compromised host: Contact the ISP to notify the account holder (they are likely a victim). The C2 server that controls the botnet is the actual target for attribution — requires deeper network forensics.",
    tier: "compromised_account",
  },
];

// ════════════════════════════════════════════════════════════════
// ACTOR TYPE CLASSIFICATION
// ════════════════════════════════════════════════════════════════
const ACTOR_TYPES = {
  direct_actor: {
    label: "Direct Threat Actor",
    color: "#f87171",
    desc: "Email appears to originate directly from the attacker's own infrastructure. IP subscriber records from ISP may directly identify the actor.",
    icon: "🎯",
  },
  rented_infra: {
    label: "Rented Infrastructure",
    color: "#fb923c",
    desc: "Attacker is using rented cloud/VPS infrastructure. Account records from the hosting provider (billing, identity verification) may identify the actor.",
    icon: "☁️",
  },
  anonymized: {
    label: "Anonymized / Obfuscated",
    color: "#fbbf24",
    desc: "Attacker is using anonymization tools (TOR, VPN, forged headers). Direct IP attribution is not possible — focus on behavioral patterns and campaign correlation.",
    icon: "🎭",
  },
  spoofed_identity: {
    label: "Spoofed Sender Identity",
    color: "#a78bfa",
    desc: "The displayed sender identity (From: domain, display name) is deliberately falsified. The real actor is hidden behind the spoofed identity.",
    icon: "🎪",
  },
  compromised_account: {
    label: "Compromised Account / Host",
    color: "#60a5fa",
    desc: "Email was sent from a legitimate account or machine that has been compromised. The IP owner is likely a victim, not the attacker.",
    icon: "🔓",
  },
  nation_state_proxy: {
    label: "Sophisticated Actor / APT Indicators",
    color: "#f43f5e",
    desc: "Multiple layers of obfuscation combined with precise targeting — possible nation-state or advanced persistent threat group.",
    icon: "🏴",
  },
};

// ── Determine actor type from active signals ──────────────────
function determineActorType(activeSignals, result) {
  const tiers = activeSignals.map((s) => s.tier);

  // Multiple anonymization layers = sophisticated actor
  const anonCount = tiers.filter((t) => t === "anonymized").length;
  if (anonCount >= 2 && (result.relayAnomalies?.length || 0) >= 2) {
    return "nation_state_proxy";
  }
  if (tiers.includes("anonymized")) return "anonymized";
  if (tiers.includes("compromised_account")) return "compromised_account";
  if (tiers.includes("direct_actor") && !tiers.includes("spoofed_identity"))
    return "direct_actor";
  if (tiers.includes("rented_infra")) return "rented_infra";
  if (tiers.includes("spoofed_identity")) return "spoofed_identity";
  return "direct_actor";
}

// ── Investigation capability tiers ───────────────────────────
function getInvestigationTier(confidence, actorType) {
  if (actorType === "anonymized" || actorType === "nation_state_proxy") {
    return {
      tier: "PATTERN",
      label: "Pattern Analysis Only",
      desc: "Direct attribution not possible. Focus on campaign correlation, timing analysis, and behavioral fingerprinting.",
      color: "#64748b",
    };
  }
  if (confidence >= 70) {
    return {
      tier: "IDENTIFY",
      label: "Can Likely Identify Actor",
      desc: "ISP/hosting provider subscriber records can likely identify the account holder. Legal process recommended immediately.",
      color: "#34d399",
    };
  }
  if (confidence >= 40) {
    return {
      tier: "LOCATE",
      label: "Can Locate Infrastructure",
      desc: "Can identify the infrastructure but not necessarily the person behind it. Hosting provider account records required.",
      color: "#fbbf24",
    };
  }
  return {
    tier: "CORRELATE",
    label: "Campaign Correlation Only",
    desc: "Insufficient signals for identity attribution. Build case through campaign pattern matching across multiple incidents.",
    color: "#fb923c",
  };
}

// ════════════════════════════════════════════════════════════════
// MAIN EXPORT — buildAttributionScore()
// Call with the full emailHeaderAnalyzer result object
// ════════════════════════════════════════════════════════════════
function buildAttributionScore(result) {
  if (!result) return null;

  // Evaluate all signals
  const activeSignals = [];
  let rawScore = 50; // start at neutral

  for (const signal of ATTRIBUTION_SIGNALS) {
    let triggered = false;
    try {
      triggered = !!signal.check(result);
    } catch (_) {
      /* skip */
    }

    if (triggered) {
      const detail = signal.detail(result);
      activeSignals.push({
        id: signal.id,
        label: signal.label,
        weight: signal.weight,
        detail,
        legalPath: signal.legalPath,
        tier: signal.tier,
        positive: signal.weight > 0,
      });
      rawScore += signal.weight;
    }
  }

  // Clamp 0-100
  const confidence = Math.max(0, Math.min(100, rawScore));

  // Actor type + info
  const actorType = determineActorType(activeSignals, result);
  const actorInfo = ACTOR_TYPES[actorType] || ACTOR_TYPES.direct_actor;

  // Investigation tier
  const investigationTier = getInvestigationTier(confidence, actorType);

  // Combined legal paths (deduplicated)
  const legalPaths = [
    ...new Set(
      activeSignals.filter((s) => s.legalPath).map((s) => s.legalPath),
    ),
  ];

  // Top 3 most actionable positive signals
  const priorityActions = activeSignals
    .filter((s) => s.positive && s.legalPath)
    .sort((a, b) => b.weight - a.weight)
    .slice(0, 3)
    .map((s) => ({ label: s.label, action: s.legalPath }));

  // Split signals
  const positiveSignals = activeSignals.filter((s) => s.positive);
  const negativeSignals = activeSignals.filter((s) => !s.positive);

  return {
    // Overall
    confidence,
    confidenceLabel:
      confidence >= 70
        ? "High"
        : confidence >= 40
          ? "Medium"
          : confidence >= 20
            ? "Low"
            : "Very Low",

    // Actor classification
    actorType,
    actorLabel: actorInfo.label,
    actorDesc: actorInfo.desc,
    actorIcon: actorInfo.icon,
    actorColor: actorInfo.color,

    // Investigation capability
    investigationTier: investigationTier.tier,
    investigationLabel: investigationTier.label,
    investigationDesc: investigationTier.desc,
    investigationColor: investigationTier.color,

    // Signal breakdown
    signals: {
      all: activeSignals,
      positive: positiveSignals,
      negative: negativeSignals,
      count: activeSignals.length,
    },

    // Legal paths
    priorityActions,
    legalPaths,

    // Key IOCs for investigation
    investigationIOCs: {
      sourceIP: result.sourceIP || null,
      sourceISP: result.sourceGeo?.isp || null,
      sourceCountry: result.sourceGeo?.country || null,
      sourceCity: result.sourceGeo?.city || null,
      fromDomain: result.fromDomain || null,
      replyToDomain: result.replyToDomain || null,
      mxProvider: result.mxValidation?.mxProvider || null,
    },
  };
}

module.exports = { buildAttributionScore };
