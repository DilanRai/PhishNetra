// FILE: src/pages/History.tsx
// Includes: auth headers on all write actions, error states, bulk PDF fix
import { useState, useEffect, useCallback } from "react";
import { motion, AnimatePresence } from "motion/react";
import {
  Clock,
  Search,
  Trash2,
  Tag,
  Share2,
  Download,
  Filter,
  ChevronDown,
  AlertTriangle,
  CheckCircle,
  FileText,
  RefreshCw,
  X,
  Copy,
  Eye,
  User,
  Microscope,
  CheckCheck,
  HelpCircle,
  ShieldAlert,
  PhoneCall,
  X as XIcon,
  Fingerprint,
} from "lucide-react";
import { useRole } from "../hooks/useRole";
import { API_BASE } from "../config";

const authHeader = () => ({
  "Content-Type": "application/json",
  Authorization: `Bearer ${localStorage.getItem("pg_token")}`,
});

interface ScanItem {
  _id: string;
  input: string;
  status: "phishing" | "suspicious" | "safe";
  riskScore: number;
  inputType: string;
  tags: string[] | null;
  notes: string | null;
  sandboxData?: {
    sandboxRiskLevel?: string;
    sandboxRiskScore?: number;
    liveStatus?: string;
    hasCredentialForm?: boolean;
    hasPhishingKit?: boolean;
    hasObfuscation?: boolean;
    crossDomainRedirect?: boolean;
    redirectHops?: number;
  };
  createdAt: string;
  // Full result fields (already in Scan model, returned by /history)
  issues?: string[];
  signals?: { label: string; value: string; color?: string }[];
  attackTypes?: string[];
  confidence?: string;
  mitre?: { tactic?: string; technique?: string; sub?: string };
  dna?: { fingerprint?: string; technique?: string; kitName?: string };
  evasion?: { detected: boolean; signals: number; techniques?: string[] };
  mlScore?: number;
  ruleScore?: number;
  // Email header fields
  sourceIP?: string;
  sourceGeo?: {
    country?: string;
    city?: string;
    isp?: string;
    isTor?: boolean;
    isVPN?: boolean;
    isDatacenter?: boolean;
    abuseRisk?: string;
  };
  originType?: string;
  attributionConfidence?: number;
  attribution?: {
    actorType?: string;
    actorLabel?: string;
    confidence?: number;
  };
  // IP reputation
  ipReputation?: {
    reputationScore?: number;
    verdict?: string;
    threatLabel?: string;
    dnsblHits?: any[];
  };
  // Domain intel
  domainIntel?: {
    lookalikeBrand?: string;
    tld?: string;
    tldRisk?: number;
    isHighRiskTLD?: boolean;
  };
  // MX/SPF
  mxValidation?: {
    spfLiveResult?: string;
    mxMismatch?: boolean;
    mxProvider?: string;
  };
  // AI detection
  aiDetection?: {
    aiProbability?: number;
    verdict?: string;
    fingerprintPhrases?: string[];
  };
  // From domain (email scans)
  fromDomain?: string;
  replyToDomain?: string;
}

const STATUS_COLORS = {
  phishing: {
    text: "#f87171",
    bg: "rgba(248,113,113,0.08)",
    border: "rgba(248,113,113,0.2)",
  },
  suspicious: {
    text: "#fbbf24",
    bg: "rgba(251,191,36,0.08)",
    border: "rgba(251,191,36,0.2)",
  },
  safe: {
    text: "#34d399",
    bg: "rgba(52,211,153,0.08)",
    border: "rgba(52,211,153,0.2)",
  },
};

const SandboxBadge = ({ scan }: { scan: ScanItem }) => {
  if (!scan.sandboxData?.sandboxRiskLevel) return null;

  const level = scan.sandboxData.sandboxRiskLevel;
  const color =
    level === "critical"
      ? "#f87171"
      : level === "high"
        ? "#f97316"
        : level === "medium"
          ? "#fbbf24"
          : null;

  if (!color) return null;

  return (
    <span
      className="text-xs px-1.5 py-0.5 rounded font-mono ml-1"
      title={`Sandbox: ${level} (score ${scan.sandboxData.sandboxRiskScore})`}
      style={{
        color,
        background: `${color}10`,
        border: `1px solid ${color}30`,
        fontFamily: "'JetBrains Mono', monospace",
      }}
    >
      🔬 {level.toUpperCase()}
    </span>
  );
};

// ── buildNormalViewFromItem ────────────────────────────────────
function buildNormalViewFromItem(item: ScanItem) {
  const status = item.status;
  const inputType = item.inputType || "url";
  const issues = item.issues || [];

  const WHAT_IS: Record<string, string> = {
    url: "a website link / URL",
    email: "an email message",
    sms: "a text message (SMS)",
    text: "written text or a message",
    email_header: "an email and its technical sending details",
  };
  const whatIs = WHAT_IS[inputType] || "a message or link";

  let whatHappened = "";
  let whatHappenedDetail = "";
  if (status === "safe") {
    whatHappened = "This looks safe.";
    whatHappenedDetail =
      "PhishNetra checked this and found no signs of fraud or danger. It appears genuine.";
  } else if (status === "suspicious") {
    whatHappened = "Something looks off — be careful.";
    whatHappenedDetail =
      "PhishNetra found warning signs matching patterns scammers use. Do not share personal information or make payments until you verify this is real.";
  } else {
    whatHappened = "⚠️ This is almost certainly a scam or fraud attempt.";
    whatHappenedDetail =
      "PhishNetra is highly confident this was designed to steal your money, passwords, or personal information.";
  }

  const ISSUE_TRANSLATIONS: [RegExp, string][] = [
    [
      /display name spoofing/i,
      "The sender's name is faked — it claims to be a known company but the actual address is different.",
    ],
    [
      /reply.to mismatch/i,
      "Replies go to a different person than the apparent sender — redirecting you to the scammer.",
    ],
    [
      /spf.*fail/i,
      "This was NOT sent from the organisation it claims — the email system flagged it as unauthorized.",
    ],
    [
      /tor exit node/i,
      "The sender is hiding their identity using TOR — legitimate organisations never do this.",
    ],
    [/vpn detect/i, "The sender masked their real location using a VPN."],
    [
      /brand.*spoof|impersonat/i,
      "This is pretending to be a well-known brand — your bank, delivery company, or government department.",
    ],
    [
      /urgency|immediate.*action/i,
      "This uses pressure tactics — trying to make you act quickly without thinking. Classic scam technique.",
    ],
    [
      /otp|one.time.password/i,
      "This is asking for a one-time password or verification code. Legitimate organisations NEVER ask for your OTP.",
    ],
    [
      /high.risk.*tld|\.tk|\.ml/i,
      "The website uses a cheap, anonymous domain extension — scammers use these for disposable phishing pages.",
    ],
    [
      /no mx records/i,
      "This email domain isn't set up for real email — it's a throwaway fake domain.",
    ],
    [
      /digital arrest/i,
      "This is the 'Digital Arrest' scam — fake police/government threats. 100% fraud. Hang up immediately.",
    ],
    [
      /upi.*fraud|upi.*scam/i,
      "Asking you to send money via UPI — scammers impersonate banks to steal money this way.",
    ],
    [
      /ai.generated/i,
      "This message was likely written by an AI chatbot to sound professional — a new scammer technique.",
    ],
    [
      /credential.*harvest/i,
      "This has a fake login form designed to steal your username and password.",
    ],
    [
      /redirect/i,
      "This link hides where it's actually sending you by going through multiple websites first.",
    ],
    [
      /phishing kit/i,
      "This uses a ready-made scam tool designed to steal login credentials at scale.",
    ],
  ];

  const simplifiedIssues: string[] = [];
  for (const issue of issues.slice(0, 8)) {
    for (const [pattern, translation] of ISSUE_TRANSLATIONS) {
      if (pattern.test(issue) && !simplifiedIssues.includes(translation)) {
        simplifiedIssues.push(translation);
        break;
      }
    }
  }

  const isGovImp = issues.some((i) =>
    /trai|cbi|income tax|customs|police|digital arrest/i.test(i),
  );
  const isBankImp = issues.some((i) =>
    /sbi|hdfc|icici|bank|paytm|gpay|phonepe/i.test(i),
  );
  const isCourier = issues.some((i) =>
    /fedex|dhl|bluedart|india post|parcel|courier/i.test(i),
  );
  const isTOR =
    item.sourceGeo?.isTor || issues.some((i) => /tor exit/i.test(i));
  const isVPN =
    item.sourceGeo?.isVPN || issues.some((i) => /vpn detect/i.test(i));

  let whoDid = "",
    whoDidDetail = "";
  if (status === "safe") {
    whoDid = "This appears to come from a genuine organisation.";
    whoDidDetail = "No signs of impersonation or fraud were detected.";
  } else if (isGovImp) {
    whoDid = "A scammer impersonating government authorities.";
    whoDidDetail =
      "Real police, CBI, TRAI, or Income Tax officials NEVER send threatening messages, demand payments, or ask you to stay on video calls. This is fraud.";
  } else if (isBankImp) {
    whoDid = "A scammer impersonating your bank or a payment app.";
    whoDidDetail =
      "Your real bank already has your details — they never need you to 'verify' your OTP, PIN, or card number over a message.";
  } else if (isCourier) {
    whoDid = "A scammer impersonating a delivery company.";
    whoDidDetail =
      "Delivery companies never ask for payments via SMS links. Go to the official website directly.";
  } else if (isTOR) {
    whoDid = "A sophisticated scammer hiding behind TOR anonymity tools.";
    whoDidDetail =
      "This person deliberately concealed their identity — indicating an intentional, organised fraud operation.";
  } else if (isVPN) {
    whoDid = "A scammer masking their real location.";
    whoDidDetail = item.sourceGeo?.country
      ? `The sender used a VPN but may originate from ${item.sourceGeo.country}.`
      : "The sender used privacy tools to hide their location.";
  } else if (status === "phishing") {
    whoDid = "A cybercriminal or organised fraud group.";
    whoDidDetail = item.sourceGeo?.country
      ? `This was sent from infrastructure in ${[item.sourceGeo.city, item.sourceGeo.country].filter(Boolean).join(", ")}. This information can assist law enforcement.`
      : "This appears to be a deliberate attempt to commit fraud.";
  } else {
    whoDid = "The source is unclear but shows suspicious patterns.";
    whoDidDetail =
      "PhishNetra couldn't confirm the identity behind this, but detected fraud-like patterns.";
  }

  const whatToDo: { icon: string; text: string; bold?: boolean }[] = [];
  if (status === "safe") {
    whatToDo.push(
      {
        icon: "✅",
        text: "You can proceed — this appears genuine.",
        bold: true,
      },
      {
        icon: "💡",
        text: "Always verify directly with the organisation if you're unsure.",
      },
    );
  } else if (status === "suspicious") {
    whatToDo.push(
      {
        icon: "🚫",
        text: "Do NOT click links or download attachments.",
        bold: true,
      },
      {
        icon: "🚫",
        text: "Do NOT share your OTP, password, or personal details.",
        bold: true,
      },
      {
        icon: "📞",
        text: "Contact the organisation using their official website number — NOT any number in this message.",
      },
      { icon: "🗑️", text: "Delete or block the sender." },
      {
        icon: "📢",
        text: "Report at cybercrime.gov.in or call 1930 (National Cyber Helpline).",
      },
    );
  } else {
    whatToDo.push(
      {
        icon: "🚫",
        text: "Stop — do not click anything or share any information.",
        bold: true,
      },
      {
        icon: "🚫",
        text: "Do NOT call any number from this message.",
        bold: true,
      },
      {
        icon: "🚫",
        text: "Do NOT make any payment or scan any QR code.",
        bold: true,
      },
      {
        icon: "🚫",
        text: "Do NOT share your OTP, PIN, bank details, or Aadhaar.",
        bold: true,
      },
      {
        icon: "📞",
        text: "If you already shared information — call your bank immediately on their official helpline.",
      },
      {
        icon: "📢",
        text: "Report this fraud at cybercrime.gov.in or call 1930 (free, 24×7).",
        bold: true,
      },
      { icon: "🗑️", text: "Delete and block the sender." },
    );
  }

  return {
    whatIs,
    whatHappened,
    whatHappenedDetail,
    simplifiedIssues,
    whoDid,
    whoDidDetail,
    whatToDo,
  };
}

// ── OverviewModal ──────────────────────────────────────────────
function OverviewModal({
  item,
  mode,
  onClose,
  onModeChange,
}: {
  item: ScanItem;
  mode: "normal" | "expert";
  onClose: () => void;
  onModeChange: (m: "normal" | "expert") => void;
}) {
  const sc = (
    {
      phishing: {
        color: "#f87171",
        bg: "rgba(248,113,113,0.07)",
        border: "rgba(248,113,113,0.2)",
        glow: "0 0 30px rgba(248,113,113,0.1)",
      },
      suspicious: {
        color: "#fbbf24",
        bg: "rgba(251,191,36,0.07)",
        border: "rgba(251,191,36,0.2)",
        glow: "none",
      },
      safe: {
        color: "#34d399",
        bg: "rgba(52,211,153,0.07)",
        border: "rgba(52,211,153,0.2)",
        glow: "0 0 20px rgba(52,211,153,0.08)",
      },
    } as const
  )[item.status] ?? {
    color: "#64748b",
    bg: "transparent",
    border: "var(--bg-border)",
    glow: "none",
  };

  const nv = buildNormalViewFromItem(item);
  const statusEmoji =
    item.status === "phishing"
      ? "🚨"
      : item.status === "suspicious"
        ? "⚠️"
        : "✅";
  const statusLabel =
    item.status === "phishing"
      ? "SCAM / FRAUD"
      : item.status === "suspicious"
        ? "SUSPICIOUS"
        : "LOOKS SAFE";

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center px-4 py-6 overflow-y-auto"
      style={{ background: "rgba(0,0,0,0.72)", backdropFilter: "blur(6px)" }}
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <motion.div
        initial={{ opacity: 0, scale: 0.96, y: 16 }}
        animate={{ opacity: 1, scale: 1, y: 0 }}
        exit={{ opacity: 0, scale: 0.96, y: 8 }}
        transition={{ duration: 0.22, ease: [0.23, 1, 0.32, 1] }}
        className="w-full max-w-3xl rounded-2xl overflow-hidden"
        style={{
          background: "var(--bg-elevated)",
          border: "1px solid var(--bg-border)",
          boxShadow: "0 24px 80px rgba(0,0,0,0.6)",
          marginTop: 16,
        }}
      >
        {/* Modal header */}
        <div
          className="flex items-center justify-between px-5 py-3.5 border-b"
          style={{
            borderColor: "var(--bg-border)",
            background: "var(--bg-card)",
          }}
        >
          <div className="flex items-center gap-3 min-w-0">
            <Eye
              className="size-4 flex-shrink-0"
              style={{ color: "#a78bfa" }}
            />
            <span
              className="text-sm font-semibold"
              style={{ color: "var(--text-primary)" }}
            >
              Scan Overview
            </span>
            <span
              className="text-xs truncate max-w-xs hidden sm:block"
              style={{
                color: "var(--text-muted)",
                fontFamily: "var(--font-mono)",
              }}
            >
              {item.input}
            </span>
          </div>
          <div className="flex items-center gap-2 flex-shrink-0">
            {/* Mode toggle */}
            <div
              className="flex items-center gap-1 p-1 rounded-lg"
              style={{
                background: "var(--bg-elevated)",
                border: "1px solid var(--bg-border)",
              }}
            >
              <button
                onClick={() => onModeChange("normal")}
                className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-md text-xs font-medium transition-all"
                style={{
                  background:
                    mode === "normal" ? "var(--bg-card)" : "transparent",
                  color:
                    mode === "normal"
                      ? "var(--text-primary)"
                      : "var(--text-muted)",
                  border:
                    mode === "normal"
                      ? "1px solid var(--bg-border)"
                      : "1px solid transparent",
                }}
              >
                <User className="size-3" /> Normal
              </button>
              <button
                onClick={() => onModeChange("expert")}
                className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-md text-xs font-medium transition-all"
                style={{
                  background:
                    mode === "expert" ? "var(--bg-card)" : "transparent",
                  color:
                    mode === "expert" ? "var(--accent)" : "var(--text-muted)",
                  border:
                    mode === "expert"
                      ? "1px solid var(--accent-border)"
                      : "1px solid transparent",
                }}
              >
                <Microscope className="size-3" /> Expert
              </button>
            </div>
            {/* Close */}
            <button
              onClick={onClose}
              className="p-1.5 rounded-lg transition-all"
              style={{
                color: "var(--text-muted)",
                background: "var(--bg-elevated)",
                border: "1px solid var(--bg-border)",
              }}
            >
              <XIcon className="size-4" />
            </button>
          </div>
        </div>

        {/* Scanned input bar */}
        <div
          className="px-5 py-2.5 border-b"
          style={{
            borderColor: "var(--bg-border)",
            background: "var(--bg-base)",
          }}
        >
          <div className="flex items-center gap-2">
            <span
              className="text-[9px] px-1.5 py-0.5 rounded font-bold flex-shrink-0"
              style={{
                color: "var(--accent)",
                background: "var(--accent-subtle)",
                border: "1px solid var(--accent-border)",
                fontFamily: "var(--font-mono)",
              }}
            >
              {item.inputType?.toUpperCase() || "URL"}
            </span>
            <code
              className="text-xs flex-1 truncate"
              style={{
                color: "var(--text-secondary)",
                fontFamily: "var(--font-mono)",
              }}
            >
              {item.input}
            </code>
            <span
              className="text-[10px] flex-shrink-0"
              style={{
                color: "var(--text-muted)",
                fontFamily: "var(--font-mono)",
              }}
            >
              {new Date(item.createdAt).toLocaleString()}
            </span>
          </div>
        </div>

        {/* Modal body */}
        <div className="p-5 space-y-4 max-h-[75vh] overflow-y-auto">
          {/* ── NORMAL VIEW ─────────────────────────────────── */}
          {mode === "normal" && (
            <div className="space-y-4">
              {/* Verdict banner */}
              <div
                className="rounded-xl px-5 py-4 flex items-center gap-4"
                style={{
                  background: sc.bg,
                  border: `2px solid ${sc.border}`,
                  boxShadow: sc.glow,
                }}
              >
                <span
                  className="text-4xl flex-shrink-0"
                  style={{ lineHeight: 1 }}
                >
                  {statusEmoji}
                </span>
                <div className="flex-1">
                  <div
                    className="text-xl font-black mb-0.5"
                    style={{
                      color: sc.color,
                      fontFamily: "var(--font-display)",
                      letterSpacing: "-0.03em",
                    }}
                  >
                    {statusLabel}
                  </div>
                  <p
                    className="text-sm"
                    style={{ color: "var(--text-secondary)" }}
                  >
                    {nv.whatHappened}
                  </p>
                </div>
                <div className="text-center flex-shrink-0 hidden sm:block">
                  <div
                    className="text-2xl font-black"
                    style={{ color: sc.color, fontFamily: "var(--font-mono)" }}
                  >
                    {item.riskScore}
                  </div>
                  <div
                    className="text-[9px]"
                    style={{ color: "var(--text-muted)" }}
                  >
                    RISK / 100
                  </div>
                </div>
              </div>

              {/* 4 cards grid */}
              <div className="grid sm:grid-cols-2 gap-3">
                {/* What is it */}
                <div
                  className="card p-4"
                  style={{ background: "var(--bg-card)" }}
                >
                  <div className="flex items-center gap-2 mb-2.5">
                    <div
                      className="w-7 h-7 rounded-lg flex items-center justify-center"
                      style={{
                        background: "rgba(96,165,250,0.1)",
                        border: "1px solid rgba(96,165,250,0.2)",
                      }}
                    >
                      <HelpCircle
                        className="size-3.5"
                        style={{ color: "#60a5fa" }}
                      />
                    </div>
                    <span
                      className="text-xs font-bold"
                      style={{ color: "#60a5fa" }}
                    >
                      What is this?
                    </span>
                  </div>
                  <p
                    className="text-sm leading-relaxed"
                    style={{ color: "var(--text-secondary)" }}
                  >
                    You scanned{" "}
                    <strong style={{ color: "var(--text-primary)" }}>
                      {nv.whatIs}
                    </strong>
                    . PhishNetra analysed it for scams, fraud, phishing, and
                    dangerous content.
                  </p>
                  {item.sourceGeo?.country && item.status !== "safe" && (
                    <div
                      className="mt-2.5 px-3 py-1.5 rounded-lg text-xs"
                      style={{
                        background: "var(--bg-elevated)",
                        border: "1px solid var(--bg-border)",
                        color: "var(--text-muted)",
                      }}
                    >
                      📍 Origin:{" "}
                      <strong style={{ color: "var(--text-secondary)" }}>
                        {[item.sourceGeo.city, item.sourceGeo.country]
                          .filter(Boolean)
                          .join(", ")}
                        {item.sourceGeo.isTor && " · 🔴 TOR"}
                        {item.sourceGeo.isVPN && " · 🟡 VPN"}
                      </strong>
                    </div>
                  )}
                </div>

                {/* What happened */}
                <div
                  className="card p-4"
                  style={{ background: "var(--bg-card)" }}
                >
                  <div className="flex items-center gap-2 mb-2.5">
                    <div
                      className="w-7 h-7 rounded-lg flex items-center justify-center"
                      style={{
                        background: `${sc.color}12`,
                        border: `1px solid ${sc.color}25`,
                      }}
                    >
                      <ShieldAlert
                        className="size-3.5"
                        style={{ color: sc.color }}
                      />
                    </div>
                    <span
                      className="text-xs font-bold"
                      style={{ color: sc.color }}
                    >
                      What happened?
                    </span>
                  </div>
                  <p
                    className="text-sm leading-relaxed mb-2.5"
                    style={{ color: "var(--text-secondary)" }}
                  >
                    {nv.whatHappenedDetail}
                  </p>
                  {nv.simplifiedIssues.length > 0 && (
                    <div className="space-y-1.5">
                      {nv.simplifiedIssues.slice(0, 4).map((issue, i) => (
                        <div
                          key={i}
                          className="flex items-start gap-2 text-xs"
                          style={{ color: "var(--text-secondary)" }}
                        >
                          <span
                            className="flex-shrink-0 mt-0.5"
                            style={{
                              color:
                                item.status === "safe" ? "#34d399" : sc.color,
                            }}
                          >
                            {item.status === "safe" ? "✓" : "•"}
                          </span>
                          {issue}
                        </div>
                      ))}
                    </div>
                  )}
                </div>

                {/* Who did this */}
                <div
                  className="card p-4"
                  style={{ background: "var(--bg-card)" }}
                >
                  <div className="flex items-center gap-2 mb-2.5">
                    <div
                      className="w-7 h-7 rounded-lg flex items-center justify-center"
                      style={{
                        background: "rgba(251,146,60,0.1)",
                        border: "1px solid rgba(251,146,60,0.2)",
                      }}
                    >
                      <Fingerprint
                        className="size-3.5"
                        style={{ color: "#fb923c" }}
                      />
                    </div>
                    <span
                      className="text-xs font-bold"
                      style={{ color: "#fb923c" }}
                    >
                      Who did this?
                    </span>
                  </div>
                  <p
                    className="text-sm font-semibold mb-1"
                    style={{ color: "var(--text-primary)" }}
                  >
                    {nv.whoDid}
                  </p>
                  <p
                    className="text-sm leading-relaxed"
                    style={{ color: "var(--text-secondary)" }}
                  >
                    {nv.whoDidDetail}
                  </p>
                </div>

                {/* What to do */}
                <div
                  className="card p-4"
                  style={{ background: "var(--bg-card)" }}
                >
                  <div className="flex items-center gap-2 mb-2.5">
                    <div
                      className="w-7 h-7 rounded-lg flex items-center justify-center"
                      style={{
                        background: "rgba(52,211,153,0.1)",
                        border: "1px solid rgba(52,211,153,0.2)",
                      }}
                    >
                      <CheckCheck
                        className="size-3.5"
                        style={{ color: "#34d399" }}
                      />
                    </div>
                    <span
                      className="text-xs font-bold"
                      style={{ color: "#34d399" }}
                    >
                      What should I do?
                    </span>
                  </div>
                  <div className="space-y-2">
                    {nv.whatToDo.map((action, i) => (
                      <div key={i} className="flex items-start gap-2">
                        <span
                          className="text-sm flex-shrink-0 mt-0.5"
                          style={{ lineHeight: 1 }}
                        >
                          {action.icon}
                        </span>
                        <span
                          className={`text-xs leading-relaxed${action.bold ? " font-semibold" : ""}`}
                          style={{
                            color: action.bold
                              ? "var(--text-primary)"
                              : "var(--text-secondary)",
                          }}
                        >
                          {action.text}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>

              {/* Helpline banner */}
              {item.status === "phishing" && (
                <div
                  className="rounded-xl px-4 py-3 flex items-center gap-3"
                  style={{
                    background: "rgba(248,113,113,0.06)",
                    border: "1.5px solid rgba(248,113,113,0.2)",
                  }}
                >
                  <PhoneCall
                    className="size-6 flex-shrink-0"
                    style={{ color: "#f87171" }}
                  />
                  <div className="flex-1 text-sm">
                    <strong style={{ color: "#f87171" }}>
                      Cyber Crime Helpline:{" "}
                    </strong>
                    <span style={{ color: "var(--text-secondary)" }}>
                      Call{" "}
                      <strong style={{ color: "var(--text-primary)" }}>
                        1930
                      </strong>{" "}
                      (free, 24×7) · Report at{" "}
                      <strong style={{ color: "var(--text-primary)" }}>
                        cybercrime.gov.in
                      </strong>
                    </span>
                  </div>
                  <a
                    href="https://cybercrime.gov.in"
                    target="_blank"
                    rel="noreferrer"
                    className="text-xs px-3 py-1.5 rounded-lg flex-shrink-0"
                    style={{
                      color: "#f87171",
                      background: "rgba(248,113,113,0.08)",
                      border: "1px solid rgba(248,113,113,0.25)",
                    }}
                  >
                    Report →
                  </a>
                </div>
              )}
            </div>
          )}

          {/* ── EXPERT VIEW ──────────────────────────────────── */}
          {mode === "expert" && (
            <div className="space-y-4">
              {/* Verdict + score */}
              <div
                className="rounded-xl px-5 py-4 flex items-center gap-5"
                style={{
                  background: sc.bg,
                  border: `2px solid ${sc.border}`,
                  boxShadow: sc.glow,
                }}
              >
                <div>
                  <div
                    className="text-2xl font-black"
                    style={{
                      color: sc.color,
                      fontFamily: "var(--font-display)",
                      letterSpacing: "-0.03em",
                    }}
                  >
                    {item.status.toUpperCase()}
                  </div>
                  <div
                    className="text-xs mt-1"
                    style={{
                      color: "var(--text-muted)",
                      fontFamily: "var(--font-mono)",
                    }}
                  >
                    Risk: {item.riskScore}/100 · Confidence:{" "}
                    {item.confidence || "—"} · Type: {item.inputType}
                    {item.mlScore != null && ` · ML: ${item.mlScore}`}
                    {item.ruleScore != null && ` · Rules: ${item.ruleScore}`}
                  </div>
                </div>
              </div>

              {/* Signals */}
              {item.signals && item.signals.length > 0 && (
                <div>
                  <div className="label-caps mb-2">Detection Signals</div>
                  <div className="flex flex-wrap gap-1.5">
                    {item.signals.map((s, i) => (
                      <span
                        key={i}
                        className="text-[10px] px-2.5 py-1 rounded font-bold"
                        style={{
                          color: s.color || "var(--accent)",
                          background: `${s.color || "var(--accent)"}15`,
                          border: `1px solid ${s.color || "var(--accent)"}30`,
                          fontFamily: "var(--font-mono)",
                        }}
                      >
                        {s.label}: {s.value}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* Attack types */}
              {item.attackTypes && item.attackTypes.length > 0 && (
                <div>
                  <div className="label-caps mb-2">Attack Types</div>
                  <div className="flex flex-wrap gap-1.5">
                    {item.attackTypes.map((a) => (
                      <span
                        key={a}
                        className="text-[10px] px-2 py-0.5 rounded"
                        style={{
                          color: "#f87171",
                          background: "rgba(248,113,113,0.08)",
                          border: "1px solid rgba(248,113,113,0.2)",
                          fontFamily: "var(--font-mono)",
                        }}
                      >
                        {a.replace(/_/g, " ")}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* IP / Geo */}
              {item.sourceIP && (
                <div>
                  <div className="label-caps mb-2">Origin Intelligence</div>
                  <div className="grid grid-cols-2 sm:grid-cols-3 gap-2">
                    {[
                      { label: "Source IP", value: item.sourceIP },
                      {
                        label: "Country",
                        value: item.sourceGeo?.country || "—",
                      },
                      { label: "City", value: item.sourceGeo?.city || "—" },
                      { label: "ISP", value: item.sourceGeo?.isp || "—" },
                      {
                        label: "Type",
                        value: item.originType?.replace(/_/g, " ") || "—",
                      },
                      {
                        label: "Attribution",
                        value:
                          item.attributionConfidence != null
                            ? `${item.attributionConfidence}%`
                            : "—",
                      },
                    ].map((f) => (
                      <div
                        key={f.label}
                        className="px-3 py-2 rounded-lg"
                        style={{
                          background: "var(--bg-elevated)",
                          border: "1px solid var(--bg-border)",
                        }}
                      >
                        <div className="text-[9px] mb-0.5 label-caps">
                          {f.label}
                        </div>
                        <div
                          className="text-xs font-medium"
                          style={{
                            color: "var(--text-primary)",
                            fontFamily: "var(--font-mono)",
                          }}
                        >
                          {f.value}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* MITRE */}
              {item.mitre?.technique && (
                <div>
                  <div className="label-caps mb-2">MITRE ATT&amp;CK</div>
                  <div className="flex gap-2 flex-wrap">
                    {item.mitre.tactic && (
                      <span
                        className="text-[10px] px-2.5 py-1 rounded"
                        style={{
                          color: "#a78bfa",
                          background: "rgba(167,139,250,0.08)",
                          border: "1px solid rgba(167,139,250,0.2)",
                          fontFamily: "var(--font-mono)",
                        }}
                      >
                        {item.mitre.tactic.split(" - ")[0]}
                      </span>
                    )}
                    <span
                      className="text-[10px] px-2.5 py-1 rounded"
                      style={{
                        color: "var(--text-secondary)",
                        background: "var(--bg-elevated)",
                        border: "1px solid var(--bg-border)",
                        fontFamily: "var(--font-mono)",
                      }}
                    >
                      {item.mitre.technique}
                    </span>
                  </div>
                </div>
              )}

              {/* AI Detection */}
              {item.aiDetection?.aiProbability != null &&
                item.aiDetection.aiProbability >= 35 && (
                  <div>
                    <div className="label-caps mb-2">
                      AI-Generated Content Detection
                    </div>
                    <div
                      className="px-4 py-3 rounded-xl"
                      style={{
                        background: "rgba(167,139,250,0.06)",
                        border: "1px solid rgba(167,139,250,0.2)",
                      }}
                    >
                      <span
                        className="text-sm font-bold"
                        style={{ color: "#a78bfa" }}
                      >
                        {item.aiDetection.aiProbability}% AI probability —{" "}
                        {item.aiDetection.verdict?.replace(/_/g, " ")}
                      </span>
                      {item.aiDetection.fingerprintPhrases &&
                        item.aiDetection.fingerprintPhrases.length > 0 && (
                          <div className="flex flex-wrap gap-1.5 mt-2">
                            {item.aiDetection.fingerprintPhrases
                              .slice(0, 4)
                              .map((p, i) => (
                                <span
                                  key={i}
                                  className="text-[9px] px-2 py-0.5 rounded"
                                  style={{
                                    color: "#a78bfa",
                                    background: "rgba(167,139,250,0.08)",
                                    border: "1px solid rgba(167,139,250,0.15)",
                                    fontFamily: "var(--font-mono)",
                                  }}
                                >
                                  "{p}"
                                </span>
                              ))}
                          </div>
                        )}
                    </div>
                  </div>
                )}

              {/* DNA fingerprint */}
              {item.dna?.fingerprint && (
                <div>
                  <div className="label-caps mb-2">PhishDNA™ Fingerprint</div>
                  <div
                    className="px-3 py-2 rounded-lg text-xs"
                    style={{
                      background: "var(--bg-elevated)",
                      border: "1px solid var(--bg-border)",
                      color: "#a78bfa",
                      fontFamily: "var(--font-mono)",
                    }}
                  >
                    🧬 #{item.dna.fingerprint}
                    {item.dna.kitName && ` · Kit: ${item.dna.kitName}`}
                    {item.dna.technique &&
                      ` · ${item.dna.technique.replace(/_/g, " ")}`}
                  </div>
                </div>
              )}

              {/* Full issues list */}
              {item.issues && item.issues.length > 0 && (
                <div>
                  <div className="label-caps mb-2">
                    Detection Issues ({item.issues.length})
                  </div>
                  <div className="space-y-1">
                    {item.issues.map((issue, i) => (
                      <div
                        key={i}
                        className="flex items-start gap-2 text-xs px-3 py-2 rounded-lg"
                        style={{
                          background: "var(--bg-elevated)",
                          border: "1px solid var(--bg-border)",
                        }}
                      >
                        <span
                          className="flex-shrink-0 font-bold mt-0.5"
                          style={{
                            color: sc.color,
                            fontFamily: "var(--font-mono)",
                          }}
                        >
                          {String(i + 1).padStart(2, "0")}
                        </span>
                        <span style={{ color: "var(--text-secondary)" }}>
                          {issue}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Evasion */}
              {item.evasion?.detected && (
                <div
                  className="px-4 py-3 rounded-xl text-xs"
                  style={{
                    background: "rgba(251,146,60,0.06)",
                    border: "1px solid rgba(251,146,60,0.2)",
                  }}
                >
                  <span className="font-bold" style={{ color: "#fb923c" }}>
                    Evasion detected: {item.evasion.signals} signal
                    {item.evasion.signals !== 1 ? "s" : ""}
                  </span>
                  {item.evasion.techniques &&
                    item.evasion.techniques.length > 0 && (
                      <span style={{ color: "var(--text-muted)" }}>
                        {" "}
                        — {item.evasion.techniques.join(", ")}
                      </span>
                    )}
                </div>
              )}
            </div>
          )}
        </div>
      </motion.div>
    </div>
  );
}

export default function History() {
  const { canWrite, canDelete } = useRole();
  const [history, setHistory] = useState<ScanItem[]>([]);
  const [filtered, setFiltered] = useState<ScanItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState("all");
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [editTagsId, setEditTagsId] = useState<string | null>(null);
  const [tagInput, setTagInput] = useState("");
  const [notesInput, setNotesInput] = useState("");
  const [shareLinks, setShareLinks] = useState<Record<string, string>>({});
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [selectMode, setSelectMode] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);
  const [allTags, setAllTags] = useState<string[]>([]);
  const [overviewId, setOverviewId] = useState<string | null>(null);
  const [overviewMode, setOverviewMode] = useState<"normal" | "expert">(
    "normal",
  );

  const overviewItem = overviewId
    ? filtered.find((i) => i._id === overviewId) || null
    : null;

  const fetchHistory = useCallback(async () => {
    setLoading(true);
    try {
      const token = localStorage.getItem("pg_token");
      const headers: Record<string, string> = token
        ? { Authorization: `Bearer ${token}` }
        : {};
      const res = await fetch(`${API_BASE}/api/scan/history`, { headers });
      if (res.ok) {
        const data = await res.json();
        setHistory(Array.isArray(data) ? data : []);
      }
    } catch {
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchHistory();
  }, [fetchHistory]);

  useEffect(() => {
    fetch(`${API_BASE}/api/scan/tags`)
      .then((r) => (r.ok ? r.json() : []))
      .then((tags) => setAllTags(tags))
      .catch(() => {});
  }, []);

  useEffect(() => {
    let result = [...history];
    if (statusFilter !== "all")
      result = result.filter((h) => h.status === statusFilter);
    if (search.trim()) {
      const q = search.toLowerCase();
      result = result.filter(
        (h) =>
          h.input.toLowerCase().includes(q) ||
          h.tags?.some((t) => t.toLowerCase().includes(q)) ||
          h.attackTypes?.some((a) => a.toLowerCase().includes(q)),
      );
    }
    setFiltered(result);
  }, [history, statusFilter, search]);

  const handleClearHistory = async () => {
    if (
      !canDelete ||
      !confirm("Delete all scan history? This cannot be undone.")
    )
      return;
    setActionError(null);
    try {
      const res = await fetch(`${API_BASE}/api/scan/history`, {
        method: "DELETE",
        headers: authHeader(),
      });
      if (!res.ok) {
        const d = await res.json().catch(() => ({}));
        throw new Error(d.error || `Failed to clear history (${res.status})`);
      }
      setHistory([]);
      setExpandedId(null);
    } catch (err: any) {
      setActionError(err.message);
    }
  };

  const handleDeleteItem = async (id: string) => {
    if (!canDelete) return;
    setActionError(null);
    try {
      const res = await fetch(`${API_BASE}/api/scan/history/${id}`, {
        method: "DELETE",
        headers: authHeader(),
      });
      if (!res.ok) {
        const d = await res.json().catch(() => ({}));
        throw new Error(d.error || `Failed to delete (${res.status})`);
      }
      setHistory((p) => p.filter((i) => i._id !== id));
    } catch (err: any) {
      setActionError(err.message);
    }
  };

  const saveTags = async (id: string, tags: string[], notes: string) => {
    setActionError(null);
    try {
      const res = await fetch(`${API_BASE}/api/scan/history/${id}/tags`, {
        method: "PATCH",
        headers: authHeader(),
        body: JSON.stringify({ tags, notes }),
      });
      if (!res.ok) {
        const d = await res.json().catch(() => ({}));
        throw new Error(d.error || `Failed to save tags (${res.status})`);
      }
      setHistory((p) =>
        p.map((h) => (h._id === id ? { ...h, tags, notes } : h)),
      );
      setEditTagsId(null);
    } catch (err: any) {
      setActionError(err.message);
    }
  };

  const handleShare = async (itemId: string) => {
    setActionError(null);
    try {
      const res = await fetch(`${API_BASE}/api/scan/history/${itemId}/share`, {
        method: "POST",
        headers: authHeader(),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok || !data.shareUrl)
        throw new Error(
          data.error || `Failed to create share link (${res.status})`,
        );
      setShareLinks((p) => ({ ...p, [itemId]: data.shareUrl }));
      navigator.clipboard.writeText(data.shareUrl);
      setCopiedId(itemId);
      setTimeout(() => setCopiedId(null), 2500);
    } catch (err: any) {
      setActionError(err.message);
    }
  };

  const handleBulkPDF = async () => {
    if (selected.size === 0) return;
    try {
      const res = await fetch(`${API_BASE}/api/scan/report/bulk`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ids: [...selected] }),
      });
      if (!res.ok) throw new Error(`PDF generation failed (${res.status})`);
      const blob = await res.blob();
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = `PhishNetra-bulk-${Date.now()}.pdf`;
      a.click();
      URL.revokeObjectURL(a.href);
      setSelected(new Set());
      setSelectMode(false);
    } catch (err: any) {
      setActionError(err.message);
    }
  };

  const toggleSelect = (id: string) => {
    setSelected((p) => {
      const next = new Set(p);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });
  };

  return (
    <div
      className="min-h-full py-10 px-6"
      style={{ background: "var(--bg-base)" }}
    >
      <div className="max-w-5xl mx-auto">
        {/* Header */}
        <motion.div
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          className="mb-8"
        >
          <div className="tag-blue inline-flex mb-3">
            <Clock className="size-3" /> HISTORY
          </div>
          <div className="flex items-start justify-between flex-wrap gap-4">
            <div>
              <h1
                className="font-display text-4xl mb-1.5"
                style={{ color: "var(--text-primary)" }}
              >
                Scan History
              </h1>
              <p style={{ color: "var(--text-muted)", fontSize: 14 }}>
                {history.length} total scans ·{" "}
                {history.filter((h) => h.status === "phishing").length} phishing
                detected
              </p>
            </div>
            <div className="flex items-center gap-2 flex-wrap">
              {selectMode && selected.size > 0 && (
                <button
                  onClick={handleBulkPDF}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs"
                  style={{
                    background: "var(--accent-subtle)",
                    color: "var(--accent)",
                    border: "1px solid var(--accent-border)",
                  }}
                >
                  <Download className="size-3.5" /> PDF ({selected.size})
                </button>
              )}
              <button
                onClick={() => {
                  setSelectMode((s) => !s);
                  setSelected(new Set());
                }}
                className="btn-ghost px-3.5 py-2 text-sm flex items-center gap-2"
              >
                {selectMode ? (
                  <>
                    <X className="size-4" /> Cancel
                  </>
                ) : (
                  <>
                    <FileText className="size-4" /> Select
                  </>
                )}
              </button>
              {canDelete && (
                <button
                  onClick={handleClearHistory}
                  className="btn-ghost px-3.5 py-2 text-sm flex items-center gap-2"
                  style={{ color: "var(--color-danger)" }}
                >
                  <Trash2 className="size-4" /> Clear All
                </button>
              )}
              <button
                onClick={fetchHistory}
                className="btn-ghost px-3.5 py-2 text-sm flex items-center gap-2"
              >
                <RefreshCw className="size-4" /> Refresh
              </button>
            </div>
          </div>
        </motion.div>

        {/* Error banner */}
        {actionError && (
          <div
            className="flex items-center gap-2 px-4 py-2.5 rounded-xl mb-4"
            style={{
              background: "rgba(248,113,113,0.08)",
              border: "1px solid rgba(248,113,113,0.2)",
            }}
          >
            <AlertTriangle
              className="size-4 flex-shrink-0"
              style={{ color: "var(--color-danger)" }}
            />
            <span
              className="text-xs flex-1"
              style={{ color: "var(--color-danger)" }}
            >
              {actionError}
            </span>
            <button
              onClick={() => setActionError(null)}
              style={{
                background: "none",
                border: "none",
                cursor: "pointer",
                color: "var(--text-muted)",
              }}
            >
              ✕
            </button>
          </div>
        )}

        {/* Filters */}
        <div className="flex gap-3 mb-6 flex-wrap">
          <div className="relative flex-1 min-w-48">
            <Search
              className="absolute left-3 top-1/2 -translate-y-1/2 size-4"
              style={{ color: "var(--text-muted)" }}
            />
            <input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search scans, tags, attack types..."
              className="w-full pl-9 pr-4 py-2 rounded-xl text-sm"
              style={{
                background: "var(--bg-elevated)",
                border: "1px solid var(--bg-border)",
                color: "var(--text-primary)",
                outline: "none",
              }}
            />
          </div>
          <div
            className="flex gap-1 p-1 rounded-xl"
            style={{ background: "var(--bg-elevated)" }}
          >
            {["all", "phishing", "suspicious", "safe"].map((s) => (
              <button
                key={s}
                onClick={() => setStatusFilter(s)}
                className="px-3 py-1 rounded-lg text-xs capitalize transition-all"
                style={{
                  background:
                    statusFilter === s ? "var(--accent-subtle)" : "transparent",
                  color:
                    statusFilter === s ? "var(--accent)" : "var(--text-muted)",
                }}
              >
                {s}
              </button>
            ))}
          </div>
        </div>

        {/* List */}
        {loading ? (
          <div className="flex items-center justify-center py-20">
            <RefreshCw
              className="size-6 animate-spin"
              style={{ color: "var(--text-muted)" }}
            />
          </div>
        ) : filtered.length === 0 ? (
          <div className="py-20 text-center">
            <div
              className="w-16 h-16 rounded-2xl mx-auto mb-5 flex items-center justify-center float"
              style={{
                background: "rgba(0,255,136,0.06)",
                border: "1px solid rgba(0,255,136,0.15)",
              }}
            >
              <Clock
                className="size-8"
                style={{ color: "rgba(0,255,136,0.4)" }}
              />
            </div>
            <p
              className="text-sm font-semibold mb-2"
              style={{
                color: "var(--text-secondary)",
                fontFamily: "'Syne', sans-serif",
              }}
            >
              No scan history yet
            </p>
            <p
              className="text-xs"
              style={{
                color: "var(--text-muted)",
                fontFamily: "'JetBrains Mono', monospace",
              }}
            >
              Run your first scan to see results here
            </p>
          </div>
        ) : (
          <div className="space-y-2">
            {filtered.map((item, i) => {
              const sc = STATUS_COLORS[item.status] || STATUS_COLORS.safe;
              const isExpanded = expandedId === item._id;
              const isEditingTags = editTagsId === item._id;
              const statusBadgeClass =
                item.status === "phishing"
                  ? "badge-phishing"
                  : item.status === "suspicious"
                    ? "badge-suspicious"
                    : "badge-safe";

              return (
                <motion.div
                  key={item._id}
                  layout
                  initial={{ opacity: 0, y: 6 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: i * 0.04 }}
                  className="card overflow-hidden"
                  style={{ background: "var(--bg-card)" }}
                >
                  <div
                    className="px-5 py-4 flex items-center gap-3 cursor-pointer"
                    onClick={() => setExpandedId(isExpanded ? null : item._id)}
                  >
                    {selectMode && (
                      <input
                        type="checkbox"
                        checked={selected.has(item._id)}
                        onChange={() => toggleSelect(item._id)}
                        onClick={(e) => e.stopPropagation()}
                        className="flex-shrink-0"
                      />
                    )}
                    <div
                      className="w-2 h-2 rounded-full flex-shrink-0"
                      style={{ background: sc.text }}
                    />
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-0.5">
                        <span
                          className={`text-xs font-bold px-2.5 py-1 rounded-lg flex-shrink-0 ${statusBadgeClass}`}
                          style={{
                            color: sc.text,
                            background: sc.bg,
                            border: `1px solid ${sc.border}`,
                            fontFamily: "var(--font-mono)",
                          }}
                        >
                          {item.status}
                        </span>
                        <SandboxBadge scan={item} />
                        <span
                          className="text-sm font-medium truncate"
                          style={{ color: "var(--text-primary)" }}
                        >
                          {item.input}
                        </span>
                      </div>
                      <div className="flex items-center gap-2 flex-wrap">
                        <span
                          className="text-xs"
                          style={{
                            color: "var(--text-muted)",
                            fontFamily: "var(--font-mono)",
                          }}
                        >
                          {item.inputType} · score {item.riskScore}/100
                        </span>
                        {(item.tags || []).map((tag) => (
                          <span
                            key={tag}
                            className="text-[9px] px-1.5 py-0.5 rounded"
                            style={{
                              background: "var(--bg-elevated)",
                              color: "var(--text-muted)",
                              fontFamily: "var(--font-mono)",
                            }}
                          >
                            #{tag}
                          </span>
                        ))}
                      </div>
                    </div>
                    <span
                      className="text-xs flex-shrink-0"
                      style={{
                        color: "var(--text-muted)",
                        fontFamily: "var(--font-mono)",
                      }}
                    >
                      {new Date(item.createdAt).toLocaleString()}
                    </span>
                    <ChevronDown
                      className={`size-4 flex-shrink-0 transition-transform ${isExpanded ? "rotate-180" : ""}`}
                      style={{ color: "var(--text-muted)" }}
                    />
                  </div>

                  <AnimatePresence>
                    {isExpanded && (
                      <motion.div
                        initial={{ height: 0 }}
                        animate={{ height: "auto" }}
                        exit={{ height: 0 }}
                        style={{ overflow: "hidden" }}
                      >
                        <div
                          className="px-5 pb-4 border-t"
                          style={{ borderColor: "var(--bg-border)" }}
                        >
                          <div className="flex gap-2 mt-3 flex-wrap">
                            {canWrite && (
                              <>
                                <button
                                  onClick={() => {
                                    setEditTagsId(item._id);
                                    setTagInput(
                                      (item.tags || []).join(", ") || "",
                                    );
                                    setNotesInput(item.notes || "");
                                  }}
                                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs"
                                  style={{
                                    background: "var(--bg-elevated)",
                                    color: "var(--text-secondary)",
                                    border: "1px solid var(--bg-border)",
                                  }}
                                >
                                  <Tag className="size-3.5" /> Edit Tags
                                </button>
                                <button
                                  onClick={() => {
                                    setOverviewId(item._id);
                                    setOverviewMode("normal");
                                  }}
                                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs"
                                  style={{
                                    background: "rgba(167,139,250,0.08)",
                                    color: "#a78bfa",
                                    border: "1px solid rgba(167,139,250,0.2)",
                                  }}
                                >
                                  <Eye className="size-3.5" /> Overview
                                </button>
                                <button
                                  onClick={() => handleShare(item._id)}
                                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs"
                                  style={{
                                    background: "var(--bg-elevated)",
                                    color: "var(--text-secondary)",
                                    border: "1px solid var(--bg-border)",
                                  }}
                                >
                                  {copiedId === item._id ? (
                                    <>
                                      <CheckCircle
                                        className="size-3.5"
                                        style={{ color: "var(--safe)" }}
                                      />{" "}
                                      Copied!
                                    </>
                                  ) : shareLinks[item._id] ? (
                                    <>
                                      <Copy className="size-3.5" /> Copy Link
                                    </>
                                  ) : (
                                    <>
                                      <Share2 className="size-3.5" /> Share
                                    </>
                                  )}
                                </button>
                              </>
                            )}
                            {canDelete && (
                              <button
                                onClick={() => handleDeleteItem(item._id)}
                                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs ml-auto"
                                style={{
                                  background: "rgba(248,113,113,0.07)",
                                  color: "#f87171",
                                  border: "1px solid rgba(248,113,113,0.2)",
                                }}
                              >
                                <Trash2 className="size-3.5" /> Delete
                              </button>
                            )}
                          </div>

                          {isEditingTags && (
                            <div className="mt-3 space-y-2">
                              <input
                                value={tagInput}
                                onChange={(e) => setTagInput(e.target.value)}
                                placeholder="Tags (comma-separated)"
                                className="w-full px-3 py-2 rounded-xl text-xs"
                                style={{
                                  background: "var(--bg-elevated)",
                                  border: "1px solid var(--bg-border)",
                                  color: "var(--text-primary)",
                                  outline: "none",
                                }}
                              />
                              <textarea
                                value={notesInput}
                                onChange={(e) => setNotesInput(e.target.value)}
                                placeholder="Notes..."
                                rows={2}
                                className="w-full px-3 py-2 rounded-xl text-xs resize-none"
                                style={{
                                  background: "var(--bg-elevated)",
                                  border: "1px solid var(--bg-border)",
                                  color: "var(--text-primary)",
                                  outline: "none",
                                }}
                              />
                              <div className="flex gap-2">
                                <button
                                  onClick={() =>
                                    saveTags(
                                      item._id,
                                      tagInput
                                        .split(",")
                                        .map((t) => t.trim())
                                        .filter(Boolean),
                                      notesInput,
                                    )
                                  }
                                  className="px-3 py-1.5 rounded-lg text-xs"
                                  style={{
                                    background: "var(--accent)",
                                    color: "#fff",
                                  }}
                                >
                                  Save
                                </button>
                                <button
                                  onClick={() => setEditTagsId(null)}
                                  className="px-3 py-1.5 rounded-lg text-xs"
                                  style={{
                                    background: "var(--bg-elevated)",
                                    color: "var(--text-muted)",
                                    border: "1px solid var(--bg-border)",
                                  }}
                                >
                                  Cancel
                                </button>
                              </div>
                            </div>
                          )}

                          <p
                            className="mt-2 text-xs"
                            style={{ color: "var(--text-muted)" }}
                          >
                            {item.notes || ""}
                          </p>

                          {item.sandboxData?.sandboxRiskLevel && (
                            <div
                              className="mt-3 pt-3 border-t"
                              style={{ borderColor: "rgba(30,39,54,0.6)" }}
                            >
                              <div
                                className="text-xs uppercase tracking-widest mb-2"
                                style={{
                                  color: "var(--text-muted)",
                                  fontFamily: "'JetBrains Mono', monospace",
                                }}
                              >
                                Sandbox Analysis
                              </div>
                              <div className="flex flex-wrap gap-2">
                                <span
                                  className="text-xs px-2 py-0.5 rounded"
                                  style={{
                                    color: "var(--text-muted)",
                                    background: "var(--bg-elevated)",
                                    fontFamily: "'JetBrains Mono', monospace",
                                  }}
                                >
                                  Risk: {item.sandboxData.sandboxRiskScore}/100
                                </span>
                                <span
                                  className="text-xs px-2 py-0.5 rounded"
                                  style={{
                                    color:
                                      item.sandboxData.liveStatus === "LIVE"
                                        ? "#ff4444"
                                        : item.sandboxData.liveStatus ===
                                            "TAKEN_DOWN"
                                          ? "#00ff88"
                                          : "var(--text-muted)",
                                    background: "var(--bg-elevated)",
                                    fontFamily: "'JetBrains Mono', monospace",
                                  }}
                                >
                                  {item.sandboxData.liveStatus || "Unknown"}
                                </span>
                                {item.sandboxData.hasCredentialForm && (
                                  <span
                                    className="text-xs px-2 py-0.5 rounded"
                                    style={{
                                      color: "#ff4444",
                                      background: "rgba(255,68,68,0.08)",
                                      fontFamily: "'JetBrains Mono', monospace",
                                    }}
                                  >
                                    Credential Form
                                  </span>
                                )}
                                {item.sandboxData.hasPhishingKit && (
                                  <span
                                    className="text-xs px-2 py-0.5 rounded"
                                    style={{
                                      color: "#ff4444",
                                      background: "rgba(255,68,68,0.08)",
                                      fontFamily: "'JetBrains Mono', monospace",
                                    }}
                                  >
                                    Phishing Kit
                                  </span>
                                )}
                                {item.sandboxData.hasObfuscation && (
                                  <span
                                    className="text-xs px-2 py-0.5 rounded"
                                    style={{
                                      color: "#f97316",
                                      background: "rgba(249,115,22,0.08)",
                                      fontFamily: "'JetBrains Mono', monospace",
                                    }}
                                  >
                                    Obfuscated JS
                                  </span>
                                )}
                                {item.sandboxData.crossDomainRedirect && (
                                  <span
                                    className="text-xs px-2 py-0.5 rounded"
                                    style={{
                                      color: "#fbbf24",
                                      background: "rgba(251,191,36,0.08)",
                                      fontFamily: "'JetBrains Mono', monospace",
                                    }}
                                  >
                                    Cross-Domain Redirect (
                                    {item.sandboxData.redirectHops} hops)
                                  </span>
                                )}
                              </div>
                            </div>
                          )}
                        </div>
                      </motion.div>
                    )}
                  </AnimatePresence>
                </motion.div>
              );
            })}
          </div>
        )}
      </div>

      <AnimatePresence>
        {overviewItem && (
          <OverviewModal
            item={overviewItem}
            mode={overviewMode}
            onClose={() => setOverviewId(null)}
            onModeChange={setOverviewMode}
          />
        )}
      </AnimatePresence>
    </div>
  );
}
