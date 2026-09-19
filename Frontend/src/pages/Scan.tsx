// FILE: src/pages/Scan.tsx

import { useState, useEffect, useRef } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { motion, AnimatePresence } from "motion/react";
import {
  TriangleAlert as AlertTriangle,
  CircleCheck as CheckCircle,
  XCircle,
  Search,
  RefreshCw,
  History as HistoryIcon,
  Mail,
  Link as LinkIcon,
  FileText,
  Terminal,
  ChevronRight,
  Activity,
  Cpu,
  Brain,
  Shield,
  Zap,
  Eye,
  Download,
  CheckSquare,
  ExternalLink,
  Hash,
  Globe,
  Lock,
  Calendar,
  Server,
  ShieldCheck,
  Fingerprint,
  User,
  Microscope,
  CheckCheck,
  HelpCircle,
  ShieldAlert,
  PhoneCall,
} from "lucide-react";
import { API_BASE } from "../config";
import type {
  AttachmentResult,
  DomainIntel,
  ScanResult,
  URLPreview,
  VTResult,
  OfficeIntel,
  PdfIntel,
} from "../types";

const SCAN_STEPS = [
  "Classifying input type...",
  "Running URL structure analysis...",
  "Checking domain reputation...",
  "Scanning for brand impersonation...",
  "Analyzing text patterns...",
  "Running social engineering checks...",
  "Calculating rule-based score...",
  "Running neural network...",
  "Blending hybrid score...",
  "Generating report...",
];

// ── Status config ──
const STATUS_CFG = {
  safe: {
    color: "#34d399",
    bg: "rgba(52,211,153,0.07)",
    border: "rgba(52,211,153,0.22)",
    glow: "0 4px 24px rgba(52,211,153,0.08)",
    label: "SAFE",
    icon: CheckCircle,
    msg: "No threats detected. This appears to be safe.",
    barGradient: "linear-gradient(90deg, #10b981, #34d399)",
    ringColor: "rgba(52,211,153,0.25)",
  },
  suspicious: {
    color: "#fbbf24",
    bg: "rgba(251,191,36,0.07)",
    border: "rgba(251,191,36,0.22)",
    glow: "0 4px 24px rgba(251,191,36,0.08)",
    label: "SUSPICIOUS",
    icon: AlertTriangle,
    msg: "Potential risks detected. Exercise caution before proceeding.",
    barGradient: "linear-gradient(90deg, #d97706, #fbbf24)",
    ringColor: "rgba(251,191,36,0.25)",
  },
  phishing: {
    color: "#f87171",
    bg: "rgba(248,113,113,0.07)",
    border: "rgba(248,113,113,0.22)",
    glow: "0 4px 24px rgba(248,113,113,0.1)",
    label: "PHISHING",
    icon: XCircle,
    msg: "High risk! This is likely a phishing attempt. Do not proceed.",
    barGradient: "linear-gradient(90deg, #dc2626, #f87171)",
    ringColor: "rgba(248,113,113,0.3)",
  },
};

const CONF_CFG = {
  high: { color: "#00ff88", label: "HIGH", bg: "rgba(0,255,136,0.08)" },
  medium: { color: "#f5a623", label: "MEDIUM", bg: "rgba(245,166,35,0.08)" },
  low: { color: "#8b95a8", label: "LOW", bg: "rgba(139,149,168,0.08)" },
};

const INPUT_CFG = {
  url: { icon: LinkIcon, label: "URL", color: "var(--accent-cyan)" },
  email: { icon: Mail, label: "Email Address", color: "#a78bfa" },
  text: { icon: FileText, label: "Text Message", color: "#f5a623" },
};

const getThreatContext = (url: string, result: ScanResult) => {
  if (!result || result.status === "safe" || result.inputType !== "url")
    return null;
  const signals: { label: string; risk: string; icon: string }[] = [];
  const lower = url.toLowerCase();
  const domain = (() => {
    try {
      return new URL(url.startsWith("http") ? url : `https://${url}`).hostname;
    } catch {
      return url;
    }
  })();
  if (/\.tk$|\.ml$|\.ga$|\.cf$|\.gq$/i.test(domain))
    signals.push({ label: "Free TLD (.tk/.ml/.ga)", risk: "high", icon: "🌑" });
  if (
    /login|verify|secure|account|update|confirm|banking|password/i.test(lower)
  )
    signals.push({
      label: "Credential keyword in path",
      risk: "high",
      icon: "🔑",
    });
  if (
    /paypal|google|amazon|apple|microsoft|netflix|bank|chase|irs/i.test(domain)
  )
    signals.push({
      label: "Brand name in suspicious domain",
      risk: "critical",
      icon: "🎭",
    });
  if ((domain.match(/-/g) || []).length >= 3)
    signals.push({
      label: "Excessive hyphens (phishing kit pattern)",
      risk: "medium",
      icon: "⚠️",
    });
  if (/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/i.test(domain))
    signals.push({
      label: "IP address hosting (no legitimate brand does this)",
      risk: "critical",
      icon: "🖥️",
    });
  if (/xn--/i.test(domain))
    signals.push({
      label: "Punycode domain (IDN homograph kit)",
      risk: "high",
      icon: "🔤",
    });
  if (domain.split(".").length - 2 > 2)
    signals.push({
      label: "Deep subdomain nesting",
      risk: "medium",
      icon: "📡",
    });
  return signals.length > 0 ? signals : null;
};

// ── Normal-mode plain-English builder ──────────────────────────────────────
function buildNormalView(result: any) {
  const status = result.status;
  const score = result.riskScore || 0;
  const inputType = result.inputType || "url";
  const issues = result.issues || [];

  // WHAT IS IT
  const WHAT_IS: Record<string, string> = {
    url: "a link / website address",
    email: "an email message",
    sms: "a text message (SMS)",
    text: "a text message or written content",
    email_header: "an email and its technical sending information",
  };
  const whatIs = WHAT_IS[inputType] || "a message or link";

  // WHAT HAPPENED
  let whatHappened = "";
  let whatHappenedDetail = "";
  if (status === "safe") {
    whatHappened = "This looks safe.";
    whatHappenedDetail =
      score <= 5
        ? "PhishNetra checked this thoroughly and found no signs of fraud or danger. This appears to be a genuine, legitimate source."
        : "PhishNetra found a few minor things to note but nothing that indicates this is dangerous. It appears to be legitimate.";
  } else if (status === "suspicious") {
    whatHappened = "Something about this looks off — be careful.";
    whatHappenedDetail =
      "PhishNetra found some warning signs. This might not be dangerous, but it's showing patterns that scammers often use. Do not click links, share personal information, or make payments until you've verified this is real by contacting the organisation directly.";
  } else {
    whatHappened = "⚠️ This is almost certainly a scam or fraud attempt.";
    whatHappenedDetail =
      "PhishNetra is highly confident this is designed to steal your money, passwords, or personal information. Do NOT interact with it further.";
  }

  // PLAIN-ENGLISH ISSUE TRANSLATIONS
  const ISSUE_TRANSLATIONS: [RegExp, string][] = [
    [
      /display name spoofing/i,
      "The sender's name is faked — it says it's from a company like SBI or PayPal, but the actual sending address is completely different.",
    ],
    [
      /reply.to mismatch/i,
      "If you reply to this, your message goes to a different person than who apparently sent it — a classic trick to redirect you to the scammer.",
    ],
    [
      /spf.*fail/i,
      "This message was NOT actually sent from the organisation it claims to be from. The email system itself flagged it as unauthorized.",
    ],
    [
      /dkim.*fail/i,
      "The email's digital signature is invalid — this message may have been tampered with or forged.",
    ],
    [
      /dmarc.*fail/i,
      "The sender's own domain policy rejects this email as unauthorized.",
    ],
    [
      /tor exit node/i,
      "The person who sent this is hiding their identity using special software (TOR) — legitimate organisations never do this.",
    ],
    [
      /vpn detected/i,
      "The sender is using a privacy tool to hide their real location.",
    ],
    [
      /brand.*spoof|impersonat/i,
      "This is pretending to be a well-known brand (like a bank, delivery company, or government) but it's fake.",
    ],
    [
      /urgency|immediate.*action/i,
      "This message is trying to pressure you to act quickly without thinking — a very common scam tactic.",
    ],
    [
      /otp|one.time.password/i,
      "This is asking for a one-time password or verification code. Legitimate organisations NEVER ask you to share your OTP.",
    ],
    [
      /suspicious.*tld|high.risk.*tld/i,
      "The website address uses an unusual ending (.tk, .ml, .xyz) — scammers use these because they're cheap and anonymous.",
    ],
    [
      /no mx records/i,
      "This email domain isn't actually set up to send real emails — it's a disposable fake domain.",
    ],
    [
      /digital arrest/i,
      "This is the 'Digital Arrest' scam — fake police or government officials threatening arrest. This is 100% fraud. Real authorities never contact you this way.",
    ],
    [
      /upi.*fraud|upi.*scam/i,
      "This is asking you to send money via UPI. Scammers often impersonate banks or officials to trick people into sending money.",
    ],
    [
      /ai.generated/i,
      "This message was likely written by an AI chatbot to sound more convincing and professional — a new technique used by scammers.",
    ],
    [
      /phishing kit/i,
      "This website is using a ready-made scam tool designed to steal login credentials.",
    ],
    [
      /credential.*harvest/i,
      "This page has a fake login form designed to steal your username and password.",
    ],
    [
      /redirect/i,
      "This link takes you through multiple websites before reaching the final destination — hiding where you're actually going.",
    ],
    [
      /domain.*1 day|domain.*new|recently registered/i,
      "The website was created very recently — scammers buy new websites constantly for each attack.",
    ],
    [
      /ip.*address.*hostname/i,
      "The link goes directly to an IP address instead of a real website name — legitimate websites don't do this.",
    ],
    [
      /bulk mailer/i,
      "This was sent using mass-email software — the kind used for spam campaigns.",
    ],
    [
      /free.*domain|freenom/i,
      "The sender used a completely free, disposable website address — scammers use these because they're anonymous.",
    ],
  ];

  const simplifiedIssues: string[] = [];
  for (const issue of issues.slice(0, 8)) {
    let found = false;
    for (const [pattern, translation] of ISSUE_TRANSLATIONS) {
      if (pattern.test(issue)) {
        if (!simplifiedIssues.includes(translation)) {
          simplifiedIssues.push(translation);
        }
        found = true;
        break;
      }
    }
    if (!found && simplifiedIssues.length < 4) {
      const cleaned = issue
        .replace(
          /^(Domain intel:|MX\/SPF:|Relay chain:|IP reputation:|AI:)\s*/i,
          "",
        )
        .replace(/\([^)]+\)/g, "")
        .trim();
      if (cleaned.length > 10 && cleaned.length < 200) {
        simplifiedIssues.push(cleaned);
      }
    }
  }

  // WHO DID THIS
  let whoDid = "";
  let whoDidDetail = "";
  const isTOR = issues.some((i: string) => /tor exit/i.test(i));
  const isVPN = issues.some((i: string) => /vpn detect/i.test(i));
  const isGovImp = issues.some((i: string) =>
    /trai|cbi|income tax|customs|police|digital arrest/i.test(i),
  );
  const isBankImp = issues.some((i: string) =>
    /sbi|hdfc|icici|bank|paytm|gpay|phonepe/i.test(i),
  );
  const isCourier = issues.some((i: string) =>
    /fedex|dhl|bluedart|india post|parcel|courier/i.test(i),
  );
  const attrType = result.attribution?.actorType;

  // India-specific attack type flags
  const isDigitalArrest = result.attackTypes?.includes("digital_arrest_scam");
  const isUPIScam = result.attackTypes?.includes("upi_scam");
  const isKYCFraud = result.attackTypes?.includes("kyc_fraud");
  const isCourierDrug = result.attackTypes?.includes("courier_drug_scam");
  const isFakeGovt = result.attackTypes?.includes("fake_govt_portal");

  if (status === "safe") {
    whoDid = "This appears to come from a genuine organisation.";
    whoDidDetail =
      "No signs of impersonation or fraudulent identity were found.";
  } else if (isDigitalArrest) {
    whoDid = "A cyber criminal running the 'Digital Arrest' scam.";
    whoDidDetail =
      "This is India's most reported cybercrime in 2024. Fake police/CBI/customs officials call or video-call victims, falsely threatening arrest. They then extort money. REAL POLICE NEVER DO THIS. Hang up immediately and call 1930.";
  } else if (isUPIScam) {
    whoDid = "A UPI fraud scammer.";
    whoDidDetail =
      "This scammer is trying to make you scan a QR code or click a UPI link believing you'll RECEIVE money — but you will actually SEND money to them. Reverse UPI requests always deduct from YOUR account.";
  } else if (isKYCFraud) {
    whoDid = "A scammer impersonating your bank's KYC team.";
    whoDidDetail =
      "Banks do NOT update KYC via SMS links. This fake 'KYC update' page will steal your Aadhaar number, PAN, account number, and OTP.";
  } else if (isCourierDrug) {
    whoDid = "A gang running the FedEx/Courier drug parcel scam.";
    whoDidDetail =
      "Fake FedEx/customs officials call saying drugs were found in a parcel with your name/address. This is completely fabricated. They then demand money to 'settle the case'. Hang up and call 1930.";
  } else if (isFakeGovt) {
    whoDid = "A scammer running a fake government website.";
    whoDidDetail =
      "This website is impersonating an official Indian government portal (UIDAI/IRCTC/Income Tax/DigiLocker). These fake sites steal your Aadhaar, PAN, banking credentials, or charge fake application fees.";
  } else if (isGovImp) {
    whoDid = "A scammer impersonating government authorities.";
    whoDidDetail =
      "Real government agencies (Police, CBI, TRAI, Income Tax) NEVER send threatening messages, demand immediate payment, or ask you to stay on a video call. This is fraud.";
  } else if (isBankImp) {
    whoDid = "A scammer impersonating your bank or a payment app.";
    whoDidDetail =
      "Your real bank will never ask for your OTP, PIN, or full card number. They already have your account details — they don't need you to 'verify' them.";
  } else if (isCourier) {
    whoDid = "A scammer impersonating a delivery company.";
    whoDidDetail =
      "Delivery companies never ask you to pay customs duty or 'release fees' via SMS links. Check the official website directly.";
  } else if (isTOR) {
    whoDid = "A scammer hiding their identity using advanced anonymity tools.";
    whoDidDetail =
      "This person deliberately concealed who they are — indicating a sophisticated and intentional fraud operation.";
  } else if (isVPN) {
    whoDid = "A scammer masking their real location.";
    whoDidDetail =
      "The sender used a tool to hide where they're actually located.";
  } else if (attrType === "direct_actor") {
    whoDid =
      "This appears to come directly from the person attempting the fraud.";
    whoDidDetail = result.sourceGeo?.country
      ? `The message originated from ${result.sourceGeo.city || ""} ${result.sourceGeo.country}. This information can help law enforcement trace the scammer.`
      : "The sender's infrastructure is identifiable — this information can help law enforcement.";
  } else if (status === "suspicious") {
    whoDid = "The source is unclear but shows suspicious behaviour.";
    whoDidDetail =
      "PhishNetra couldn't confirm who is behind this, but the patterns match known fraud techniques.";
  } else {
    whoDid = "A scammer or cybercriminal.";
    whoDidDetail =
      "This appears to be a deliberate attempt to commit fraud or steal information.";
  }

  // WHAT TO DO
  const whatToDo: { icon: string; text: string; bold?: boolean }[] = [];
  if (status === "safe") {
    whatToDo.push(
      {
        icon: "✅",
        text: "You can proceed normally — this appears to be genuine.",
        bold: true,
      },
      {
        icon: "💡",
        text: "Still use good judgement. If something feels off, contact the organisation directly using their official phone number or website.",
      },
    );
  } else if (status === "suspicious") {
    whatToDo.push(
      {
        icon: "🚫",
        text: "Do NOT click any links or download attachments.",
        bold: true,
      },
      {
        icon: "🚫",
        text: "Do NOT share your OTP, password, or personal details.",
        bold: true,
      },
      {
        icon: "📞",
        text: "Contact the organisation directly using the number on their official website — NOT any number in this message.",
      },
      { icon: "🗑️", text: "Delete or block the message." },
      {
        icon: "📢",
        text: "If you think it's fraud, report it on cybercrime.gov.in or call 1930 (India National Cyber Helpline).",
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
        text: "Do NOT call any number in this message.",
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
        text: "If you already shared any information — contact your bank immediately on their official helpline.",
      },
      {
        icon: "📢",
        text: "Report this fraud on cybercrime.gov.in or call 1930 (free, 24×7).",
        bold: true,
      },
      { icon: "🗑️", text: "Delete and block the sender." },
      {
        icon: "📤",
        text: "You can forward phishing SMS to 7726 (TRAI's spam reporting number).",
      },
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
// ────────────────────────────────────────────────────────────────────────────

export default function Scan() {
  const location = useLocation();
  const navigate = useNavigate();
  const [input, setInput] = useState((location.state as any)?.url || "");
  const [scanMode, setScanMode] = useState<
    "normal" | "email" | "sms" | "attachment" | "qr"
  >("normal");
  const [emailInput, setEmailInput] = useState("");
  const [attachResult, setAttachResult] = useState<AttachmentResult | null>(
    null,
  );
  const [attachLoading, setAttachLoading] = useState(false);
  const [attachError, setAttachError] = useState<string | null>(null);
  const [qrLoading, setQrLoading] = useState(false);
  const [qrError, setQrError] = useState<string | null>(null);
  const [qrDecoded, setQrDecoded] = useState<string | null>(null);
  const attachInputRef = useRef<HTMLInputElement>(null);
  const qrInputRef = useRef<HTMLInputElement>(null);
  const [downloading, setDownloading] = useState(false);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [scannedInput, setScannedInput] = useState("");
  const [scanStep, setScanStep] = useState(0);
  const [siemStatus, setSiemStatus] = useState<
    "idle" | "sending" | "sent" | "error"
  >("idle");
  const [domainIntel, setDomainIntel] = useState<DomainIntel | null>(null);
  const [intelLoading, setIntelLoading] = useState(false);
  const [urlPreview, setUrlPreview] = useState<URLPreview | null>(null);
  const [previewLoading, setPreviewLoading] = useState(false);
  const [detectedType, setDetectedType] = useState<string | null>(null);
  const hasAutoScanned = useRef(false);

  // ── Normal / Expert view mode ──
  const [viewMode, setViewMode] = useState<"normal" | "expert">(
    () =>
      (localStorage.getItem("pn-view-mode") as "normal" | "expert") || "normal",
  );
  const switchMode = (mode: "normal" | "expert") => {
    setViewMode(mode);
    localStorage.setItem("pn-view-mode", mode);
  };

  const getAuthHeaders = (): Record<string, string> => {
    const token = localStorage.getItem("pg_token");
    return token ? { Authorization: `Bearer ${token}` } : {};
  };

  const requireAuth = () => {
    const token = localStorage.getItem("pg_token");
    if (!token) {
      setError("Please log in before running a scan.");
      navigate("/login");
      return null;
    }
    return token;
  };

  const handleDownloadReport = async () => {
    if (!result) return;
    if (!requireAuth()) return;
    setDownloading(true);
    try {
      const res = await fetch(`${API_BASE}/api/scan/report`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...getAuthHeaders(),
        },
        body: JSON.stringify({ ...result, input: scannedInput }),
      });
      if (!res.ok) throw new Error("Report generation failed");
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `phishguard-report-${Date.now()}.pdf`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      console.error("Download error:", err);
    } finally {
      setDownloading(false);
    }
  };

  useEffect(() => {
    const state = location.state as any;
    if (state?.url && !hasAutoScanned.current) {
      hasAutoScanned.current = true;
      handleScan(state.url);
    }
  }, []);

  // Auto-feed result to SIEM (non-blocking)
  const feedToSIEM = async (scanResult: ScanResult, rawInput: string) => {
    if (scanResult.riskScore < 20 && scanResult.status === "safe") return;
    if (!requireAuth()) return;
    setSiemStatus("sending");
    try {
      await fetch(`${API_BASE}/api/siem/event`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...getAuthHeaders(),
        },
        body: JSON.stringify({
          type: "phishing_scan",
          sourceType: "scanner",
          agent: "PhishGuard Web UI",
          data: { ...scanResult, input: rawInput, url: rawInput },
        }),
      });
      setSiemStatus("sent");
    } catch {
      setSiemStatus("error");
    }
  };

  const handleScan = async (overrideInput?: string) => {
    const target = (overrideInput ?? input).trim();
    if (!target) return;
    if (!requireAuth()) return;

    setLoading(true);
    setResult(null);
    setError(null);
    setScannedInput(target);
    setScanStep(0);
    setSiemStatus("idle");

    const stepInterval = setInterval(() => {
      setScanStep((prev) => (prev >= SCAN_STEPS.length - 1 ? prev : prev + 1));
    }, 180);

    try {
      const res = await fetch(`${API_BASE}/api/scan`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...getAuthHeaders(),
        },
        body: JSON.stringify({ input: target }),
      });
      if (res.status === 401) {
        throw new Error("Your session expired. Please log in again.");
      }
      if (!res.ok) throw new Error(`Server error ${res.status}`);
      clearInterval(stepInterval);
      setScanStep(SCAN_STEPS.length);
      const data: ScanResult = await res.json();
      setResult(data);
      feedToSIEM(data, target);
      // Fetch domain intelligence for URL scans
      if (data.inputType === "url") {
        setDomainIntel(null);
        setIntelLoading(true);
        fetch(`${API_BASE}/api/scan/domain-intel`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            ...getAuthHeaders(),
          },
          body: JSON.stringify({ url: target }),
        })
          .then((r) => (r.ok ? r.json() : null))
          .then((intel) => {
            if (intel) setDomainIntel(intel);
          })
          .catch(() => {})
          .finally(() => setIntelLoading(false));
      }
      // Fetch URL preview for phishing/suspicious URLs
      if (data.inputType === "url" && data.status !== "safe") {
        setUrlPreview(null);
        setPreviewLoading(true);
        fetch(`${API_BASE}/api/scan/preview`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            ...getAuthHeaders(),
          },
          body: JSON.stringify({ url: target }),
        })
          .then((r) => (r.ok ? r.json() : null))
          .then((p) => {
            if (p) {
              setUrlPreview(p);
              // Persist sandbox data back to the scan record (non-blocking)
              if (data.status !== "safe") {
                fetch(`${API_BASE}/api/scan/preview/save`, {
                  method: "POST",
                  headers: {
                    "Content-Type": "application/json",
                    ...getAuthHeaders(),
                  },
                  body: JSON.stringify({
                    scanId: (data as any)._id || null,
                    preview: p,
                  }),
                }).catch(() => {}); // silent — non-critical
              }
              // If sandbox confirms credential harvesting + live + critical risk → amplify to phishing
              if (
                p.forms?.hasCredentialForm &&
                p.sandboxRisk?.riskLevel === "critical" &&
                data.status !== "phishing"
              ) {
                setResult((prev) =>
                  prev
                    ? {
                        ...prev,
                        status: "phishing" as const,
                        riskScore: Math.max(prev.riskScore, 85),
                      }
                    : prev,
                );
              }
            }
          })
          .catch(() => {})
          .finally(() => setPreviewLoading(false));
      }
    } catch (err: any) {
      setError(err.message || "Scan failed. Is the backend running?");
    } finally {
      clearInterval(stepInterval);
      setLoading(false);
    }
  };

  const handleReset = () => {
    setResult(null);
    setScannedInput("");
    setInput("");
    setEmailInput("");
    setScanMode("normal");
    setScanStep(0);
    setSiemStatus("idle");
    setError(null);
    setDomainIntel(null);
    setIntelLoading(false);
    setUrlPreview(null);
    setPreviewLoading(false);
    setDetectedType(null);
  };

  const handleAttachmentScan = async (file: File) => {
    setAttachLoading(true);
    setAttachResult(null);
    setAttachError(null);
    try {
      const formData = new FormData();
      formData.append("file", file);
      const res = await fetch(`${API_BASE}/api/scan/attachment`, {
        method: "POST",
        headers: getAuthHeaders(),
        body: formData,
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        setAttachError((err as any).error || `Upload failed (${res.status})`);
      } else {
        setAttachResult(await res.json());
      }
    } catch {
      setAttachError("Network error — is the backend running?");
    } finally {
      setAttachLoading(false);
    }
  };

  const handleQRUpload = async (file: File) => {
    if (!file.type.startsWith("image/")) {
      setQrError("Please upload an image file (PNG, JPG, WebP)");
      return;
    }
    setQrLoading(true);
    setQrError(null);
    setQrDecoded(null);
    try {
      const jsQR = (await import("jsqr")).default;
      const img = new Image();
      const url = URL.createObjectURL(file);
      img.src = url;
      await new Promise((res, rej) => {
        img.onload = res;
        img.onerror = rej;
      });
      const canvas = document.createElement("canvas");
      canvas.width = img.width;
      canvas.height = img.height;
      const ctx = canvas.getContext("2d")!;
      ctx.drawImage(img, 0, 0);
      const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
      URL.revokeObjectURL(url);
      const code = jsQR(imageData.data, imageData.width, imageData.height);
      if (!code) {
        setQrError("No QR code found — try a clearer image.");
        return;
      }
      setQrDecoded(code.data);
      setInput(code.data);
      setScanMode("normal");
      handleScan(code.data);
    } catch {
      setQrError(
        "Failed to decode — make sure jsqr is installed: npm install jsqr",
      );
    } finally {
      setQrLoading(false);
    }
  };

  return (
    <div
      className="min-h-full py-12 px-6"
      style={{ background: "var(--bg-base)" }}
    >
      <div className="max-w-3xl mx-auto">
        {/* ── HEADER ── */}
        <motion.div
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          className="mb-10"
        >
          <div className="tag-green inline-flex mb-4">
            <Terminal className="size-3" /> THREAT SCANNER
          </div>
          <h1
            className="text-4xl font-bold mb-2"
            style={{
              fontFamily: "'Syne', sans-serif",
              color: "var(--text-primary)",
            }}
          >
            Analyze & Detect
          </h1>
          <p className="text-sm" style={{ color: "var(--text-secondary)" }}>
            Paste a URL, email address, or any suspicious message below.
          </p>
        </motion.div>

        {/* ── INPUT BOX ── */}
        <AnimatePresence>
          {!result && !loading && (
            <motion.div
              initial={{ opacity: 0, y: 16 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -8 }}
              className="mb-8"
            >
              <div
                className="rounded-xl p-5"
                style={{
                  background: "var(--bg-card)",
                  border: "1px solid var(--bg-border)",
                }}
              >
                <div className="flex gap-2 mb-4">
                  {(
                    [
                      { key: "normal", label: "URL / Text / OTP" },
                      { key: "email", label: "Full Email" },
                      { key: "sms", label: "SMS / WhatsApp" },
                      { key: "attachment", label: "📎 Attachment" },
                      { key: "qr", label: "📷 QR Code" },
                    ] as const
                  ).map((m) => (
                    <button
                      key={m.key}
                      onClick={() => {
                        setScanMode(m.key);
                        setResult(null);
                        setError(null);
                      }}
                      className="px-3 py-1.5 rounded-lg text-xs font-bold transition-all"
                      style={{
                        fontFamily: "'JetBrains Mono', monospace",
                        background:
                          scanMode === m.key
                            ? "var(--accent-subtle)"
                            : "var(--bg-elevated)",
                        color:
                          scanMode === m.key
                            ? "var(--accent)"
                            : "var(--text-muted)",
                        border: `1px solid ${scanMode === m.key ? "var(--accent-border)" : "var(--bg-border)"}`,
                      }}
                    >
                      {m.label}
                    </button>
                  ))}
                </div>
                <div
                  className="text-xs mb-3"
                  style={{
                    color: "var(--text-muted)",
                    fontFamily: "'JetBrains Mono', monospace",
                  }}
                >
                  {scanMode === "email"
                    ? "FULL EMAIL INPUT"
                    : scanMode === "sms"
                      ? "SMS / WHATSAPP MESSAGE"
                      : scanMode === "attachment"
                        ? "FILE ATTACHMENT"
                        : scanMode === "qr"
                          ? "QR CODE IMAGE"
                          : "INPUT TARGET"}
                </div>
                {scanMode === "normal" ? (
                  <div className="flex gap-3 flex-col sm:flex-row">
                    <div className="relative flex-1">
                      <Search
                        className="absolute left-4 top-1/2 -translate-y-1/2 size-4"
                        style={{ color: "var(--text-muted)" }}
                      />
                      <input
                        type="text"
                        value={input}
                        onChange={(e) => {
                          const val = e.target.value;
                          setInput(val);
                          if (!val.trim()) {
                            setDetectedType(null);
                            return;
                          }
                          if (/^https?:\/\//i.test(val) || /^www\./i.test(val))
                            setDetectedType("url");
                          else if (
                            /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(val.trim())
                          )
                            setDetectedType("email");
                          else if (val.trim().length > 3)
                            setDetectedType("text");
                          else setDetectedType(null);
                        }}
                        onKeyDown={(e) => e.key === "Enter" && handleScan()}
                        placeholder="https://example.com or paste suspicious message..."
                        className="input-terminal w-full pl-11 pr-28 py-3.5 rounded-xl text-sm"
                        style={{
                          fontFamily: "'DM Sans', sans-serif",
                          background: "var(--bg-elevated)",
                          border: "1px solid var(--bg-border)",
                          color: "var(--text-primary)",
                          transition: "border-color 0.2s, box-shadow 0.2s",
                        }}
                        autoFocus
                      />
                      {detectedType && (
                        <motion.div
                          initial={{ opacity: 0, scale: 0.9 }}
                          animate={{ opacity: 1, scale: 1 }}
                          className="absolute right-3 top-1/2 -translate-y-1/2 flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs pointer-events-none"
                          style={{
                            fontFamily: "'JetBrains Mono', monospace",
                            color:
                              detectedType === "url"
                                ? "var(--accent-cyan)"
                                : detectedType === "email"
                                  ? "#a78bfa"
                                  : "#f5a623",
                            background:
                              detectedType === "url"
                                ? "rgba(0,212,255,0.08)"
                                : detectedType === "email"
                                  ? "rgba(163,120,251,0.08)"
                                  : "rgba(245,166,35,0.08)",
                            border: `1px solid ${
                              detectedType === "url"
                                ? "rgba(0,212,255,0.2)"
                                : detectedType === "email"
                                  ? "rgba(163,120,251,0.2)"
                                  : "rgba(245,166,35,0.2)"
                            }`,
                          }}
                        >
                          {detectedType === "url"
                            ? "🌐"
                            : detectedType === "email"
                              ? "📧"
                              : "💬"}{" "}
                          {detectedType.toUpperCase()}
                        </motion.div>
                      )}
                    </div>
                    <button
                      onClick={() => handleScan()}
                      disabled={loading || !input.trim()}
                      className="btn-primary flex items-center justify-center gap-2 px-6 py-3.5 text-sm"
                      style={{
                        fontFamily: "'Syne', sans-serif",
                        fontWeight: 700,
                        minWidth: 120,
                      }}
                    >
                      <Terminal className="size-4" /> Scan
                    </button>
                  </div>
                ) : null}

                {/* ── Full Email mode ── */}
                {scanMode === "email" && (
                  <div className="mt-3">
                    {/* Hint bar */}
                    <div className="flex items-center gap-2 mb-2 px-1">
                      <Mail
                        className="size-3.5"
                        style={{ color: "var(--accent-cyan)" }}
                      />
                      <span
                        className="text-xs"
                        style={{
                          color: "var(--text-muted)",
                          fontFamily: "'JetBrains Mono', monospace",
                        }}
                      >
                        Paste the full email — body, headers, links, anything.
                        Same engine runs on both modes.
                      </span>
                    </div>
                    <div className="relative">
                      <textarea
                        value={emailInput}
                        onChange={(e) => setEmailInput(e.target.value)}
                        placeholder={
                          'Paste your full email here — including:\n• Subject line\n• From / To headers\n• Email body text\n• Any links or attachments mentioned\n\nExample:\nFrom: "PayPal Support" <no-reply@paypa1.tk>\nSubject: Urgent: Verify your account now!\n\nDear Customer,\nYour account has been suspended...'
                        }
                        rows={10}
                        className="input-terminal w-full px-4 py-3 rounded-xl text-xs"
                        style={{
                          fontFamily: "'JetBrains Mono', monospace",
                          resize: "vertical",
                          overflowY: "auto",
                          maxHeight: "400px",
                        }}
                      />
                      {/* Scroll indicator */}
                      {emailInput.split("\n").length > 8 && (
                        <div
                          className="absolute bottom-3 right-3 flex items-center gap-1"
                          style={{
                            color: "var(--text-muted)",
                            fontFamily: "'JetBrains Mono', monospace",
                            fontSize: 9,
                          }}
                        >
                          <span>↕ scroll</span>
                        </div>
                      )}
                    </div>
                    {/* Character / line count */}
                    <div className="flex justify-between px-1 mt-1.5">
                      <span
                        className="text-xs"
                        style={{
                          color: "var(--text-muted)",
                          fontFamily: "'JetBrains Mono', monospace",
                        }}
                      >
                        {emailInput.length} chars ·{" "}
                        {emailInput.split("\n").filter(Boolean).length} lines
                      </span>
                      {emailInput && (
                        <button
                          onClick={() => setEmailInput("")}
                          className="text-xs"
                          style={{ color: "var(--text-muted)" }}
                        >
                          Clear
                        </button>
                      )}
                    </div>
                    <motion.button
                      onClick={() => {
                        if (!emailInput.trim()) return;
                        setInput(emailInput);
                        setScanMode("normal");
                        setTimeout(() => handleScan(emailInput), 50);
                      }}
                      disabled={loading || !emailInput.trim()}
                      className="btn-primary w-full flex items-center justify-center gap-2 py-3.5 text-sm mt-3"
                      style={{
                        fontFamily: "'Syne', sans-serif",
                        fontWeight: 700,
                      }}
                      whileHover={{ scale: emailInput.trim() ? 1.01 : 1 }}
                      whileTap={{ scale: 0.99 }}
                    >
                      <Mail className="size-4" />
                      Analyze Full Email
                    </motion.button>
                  </div>
                )}

                {/* ── SMS / WhatsApp mode ── */}
                {scanMode === "sms" && (
                  <div className="mt-3">
                    <div className="flex items-center gap-2 mb-2 px-1">
                      <span className="text-base">📱</span>
                      <span
                        className="text-xs"
                        style={{
                          color: "var(--text-muted)",
                          fontFamily: "'JetBrains Mono', monospace",
                        }}
                      >
                        Paste the suspicious SMS or WhatsApp message. Works with
                        delivery scams, bank alerts, OTP requests.
                      </span>
                    </div>
                    <textarea
                      value={emailInput}
                      onChange={(e) => setEmailInput(e.target.value)}
                      placeholder={
                        "Paste suspicious SMS/WhatsApp message here:\n\nExamples:\n• USPS: Your package is held. Pay $2.99 fee: bit.ly/xxxxx\n• Bank: Your account suspended. Verify: tinyurl.com/xxx\n• FreeMsg: You've won an iPhone! Claim at: rb.gy/xxxx\n• Your OTP is 847291. Do NOT share with anyone."
                      }
                      rows={6}
                      className="input-terminal w-full px-4 py-3 rounded-xl text-sm"
                      style={{
                        fontFamily: "'DM Sans', sans-serif",
                        resize: "vertical",
                      }}
                    />
                    <motion.button
                      onClick={() => {
                        if (!emailInput.trim()) return;
                        setInput(emailInput);
                        setScanMode("normal");
                        setTimeout(() => handleScan(emailInput), 50);
                      }}
                      disabled={loading || !emailInput.trim()}
                      className="btn-primary w-full flex items-center justify-center gap-2 py-3.5 text-sm mt-3"
                      style={{
                        fontFamily: "'Syne', sans-serif",
                        fontWeight: 700,
                      }}
                      whileHover={{ scale: emailInput.trim() ? 1.01 : 1 }}
                      whileTap={{ scale: 0.99 }}
                    >
                      <span>📱</span> Analyze SMS / WhatsApp
                    </motion.button>
                  </div>
                )}

                {/* ── Attachment mode ── */}
                {scanMode === "attachment" && (
                  <motion.div
                    initial={{ opacity: 0, y: 8 }}
                    animate={{ opacity: 1, y: 0 }}
                    className="rounded-2xl p-5"
                    style={{
                      background: "var(--bg-card)",
                      border: "1px solid var(--bg-border)",
                    }}
                  >
                    <p
                      className="text-xs mb-4"
                      style={{
                        color: "var(--text-muted)",
                        fontFamily: "'JetBrains Mono', monospace",
                      }}
                    >
                      Upload a file for static analysis — checks MIME mismatch,
                      macros, PDF JavaScript, embedded URLs, double extensions,
                      and magic bytes. No code is executed.
                    </p>
                    {/* Drop zone */}
                    <div
                      onClick={() => attachInputRef.current?.click()}
                      onDragOver={(e) => {
                        e.preventDefault();
                        (e.currentTarget as HTMLElement).style.borderColor =
                          "var(--accent)";
                      }}
                      onDragLeave={(e) => {
                        (e.currentTarget as HTMLElement).style.borderColor =
                          "var(--bg-border)";
                      }}
                      onDrop={(e) => {
                        e.preventDefault();
                        (e.currentTarget as HTMLElement).style.borderColor =
                          "var(--bg-border)";
                        const f = e.dataTransfer.files[0];
                        if (f) handleAttachmentScan(f);
                      }}
                      className="rounded-xl p-8 text-center cursor-pointer transition-all"
                      style={{
                        border: "2px dashed var(--bg-border)",
                        background: "var(--bg-elevated)",
                      }}
                    >
                      {attachLoading ? (
                        <div className="flex flex-col items-center gap-3">
                          <div
                            className="w-8 h-8 border-2 rounded-full animate-spin"
                            style={{
                              borderColor: "var(--accent)",
                              borderTopColor: "transparent",
                            }}
                          />
                          <p
                            className="text-sm"
                            style={{ color: "var(--text-muted)" }}
                          >
                            Analysing file...
                          </p>
                        </div>
                      ) : (
                        <div className="flex flex-col items-center gap-3">
                          <span className="text-3xl">📎</span>
                          <div>
                            <p
                              className="text-sm font-medium mb-1"
                              style={{ color: "var(--text-primary)" }}
                            >
                              Drop file here or click to browse
                            </p>
                            <p
                              className="text-xs"
                              style={{
                                color: "var(--text-muted)",
                                fontFamily: "'JetBrains Mono', monospace",
                              }}
                            >
                              PDF · DOCX · XLSX · ZIP · EXE · PS1 · up to 10MB
                            </p>
                          </div>
                        </div>
                      )}
                    </div>
                    <input
                      ref={attachInputRef}
                      type="file"
                      className="hidden"
                      onChange={(e) => {
                        const f = e.target.files?.[0];
                        if (f) handleAttachmentScan(f);
                      }}
                    />
                    {/* Error */}
                    {attachError && (
                      <div
                        className="mt-3 px-4 py-3 rounded-xl text-xs"
                        style={{
                          background: "rgba(248,113,113,0.07)",
                          border: "1px solid rgba(248,113,113,0.2)",
                          color: "var(--color-danger, #f87171)",
                          fontFamily: "'JetBrains Mono', monospace",
                        }}
                      >
                        ⚠ {attachError}
                      </div>
                    )}
                    {/* Result */}
                    {attachResult && (
                      <motion.div
                        initial={{ opacity: 0, y: 6 }}
                        animate={{ opacity: 1, y: 0 }}
                        className="mt-4 rounded-xl overflow-hidden"
                        style={{
                          border: `1px solid ${
                            attachResult.verdict === "malicious"
                              ? "rgba(248,113,113,0.3)"
                              : attachResult.verdict === "suspicious"
                                ? "rgba(251,191,36,0.3)"
                                : "rgba(52,211,153,0.3)"
                          }`,
                          background: "var(--bg-card)",
                        }}
                      >
                        {/* Header: verdict + score */}
                        <div
                          className="flex items-center justify-between px-4 py-3 border-b"
                          style={{ borderColor: "var(--bg-border)" }}
                        >
                          <div className="flex items-center gap-3">
                            <span className="text-2xl">
                              {attachResult.verdict === "malicious"
                                ? "🚨"
                                : attachResult.verdict === "suspicious"
                                  ? "⚠️"
                                  : "✅"}
                            </span>
                            <div>
                              <div
                                className="text-sm font-bold"
                                style={{
                                  fontFamily: "var(--font-mono)",
                                  color:
                                    attachResult.verdict === "malicious"
                                      ? "#f87171"
                                      : attachResult.verdict === "suspicious"
                                        ? "#fbbf24"
                                        : "var(--safe, #34d399)",
                                }}
                              >
                                {attachResult.verdict.toUpperCase()}
                              </div>
                              <div
                                className="text-xs mt-0.5"
                                style={{
                                  color: "var(--text-muted)",
                                  fontFamily: "var(--font-mono)",
                                }}
                              >
                                {attachResult.filename} · {attachResult.sizeKB}{" "}
                                KB
                              </div>
                            </div>
                          </div>
                          <div
                            className="text-2xl font-black"
                            style={{
                              fontFamily: "var(--font-mono)",
                              color:
                                attachResult.verdict === "malicious"
                                  ? "#f87171"
                                  : attachResult.verdict === "suspicious"
                                    ? "#fbbf24"
                                    : "var(--safe, #34d399)",
                            }}
                          >
                            {attachResult.score}
                            <span
                              className="text-xs font-normal"
                              style={{ color: "var(--text-muted)" }}
                            >
                              /100
                            </span>
                          </div>
                        </div>

                        {/* Identity row: extension, MIME, magic-byte, SHA-256 */}
                        <div
                          className="px-4 py-3 border-b grid grid-cols-2 md:grid-cols-4 gap-3"
                          style={{
                            borderColor: "var(--bg-border)",
                            background: "var(--bg-elevated)",
                          }}
                        >
                          {[
                            {
                              label: "Extension",
                              value: `.${attachResult.extension}`,
                            },
                            {
                              label: "Declared MIME",
                              value:
                                attachResult.mimetype
                                  ?.split("/")[1]
                                  ?.toUpperCase() ||
                                attachResult.mimetype ||
                                "—",
                            },
                            {
                              label: "Magic Bytes",
                              value:
                                attachResult.actualType?.toUpperCase() || "—",
                              color:
                                attachResult.actualType === "pe_executable"
                                  ? "#f87171"
                                  : attachResult.actualType &&
                                      attachResult.actualType !==
                                        attachResult.extension &&
                                      attachResult.actualType !== "unknown"
                                    ? "#fbbf24"
                                    : undefined,
                            },
                            {
                              label: "SHA-256",
                              value: attachResult.sha256
                                ? `${attachResult.sha256.substring(0, 12)}…`
                                : "—",
                              title: attachResult.sha256 || undefined,
                            },
                          ].map((item) => (
                            <div key={item.label}>
                              <div
                                className="text-[9px] uppercase tracking-widest mb-0.5"
                                style={{
                                  color: "var(--text-muted)",
                                  fontFamily: "var(--font-mono)",
                                }}
                              >
                                {item.label}
                              </div>
                              <div
                                className="text-xs truncate"
                                style={{
                                  color:
                                    (item as any).color ||
                                    "var(--text-secondary)",
                                  fontFamily: "var(--font-mono)",
                                }}
                                title={(item as any).title}
                              >
                                {item.value}
                              </div>
                            </div>
                          ))}
                        </div>

                        {/* Category chips */}
                        {attachResult.categories &&
                          attachResult.categories.length > 0 && (
                            <div
                              className="px-4 py-2 border-b flex flex-wrap gap-1.5"
                              style={{ borderColor: "var(--bg-border)" }}
                            >
                              {attachResult.categories.map((cat) => {
                                const catColors: Record<
                                  string,
                                  { color: string; bg: string; border: string }
                                > = {
                                  macro: {
                                    color: "#f87171",
                                    bg: "rgba(248,113,113,0.08)",
                                    border: "rgba(248,113,113,0.2)",
                                  },
                                  active_content: {
                                    color: "#f87171",
                                    bg: "rgba(248,113,113,0.08)",
                                    border: "rgba(248,113,113,0.2)",
                                  },
                                  identity: {
                                    color: "#f87171",
                                    bg: "rgba(248,113,113,0.08)",
                                    border: "rgba(248,113,113,0.2)",
                                  },
                                  credential_harvest: {
                                    color: "#f87171",
                                    bg: "rgba(248,113,113,0.08)",
                                    border: "rgba(248,113,113,0.2)",
                                  },
                                  extension: {
                                    color: "#fb923c",
                                    bg: "rgba(251,146,60,0.08)",
                                    border: "rgba(251,146,60,0.2)",
                                  },
                                  evasion: {
                                    color: "#fbbf24",
                                    bg: "rgba(251,191,36,0.08)",
                                    border: "rgba(251,191,36,0.2)",
                                  },
                                  obfuscation: {
                                    color: "#fbbf24",
                                    bg: "rgba(251,191,36,0.08)",
                                    border: "rgba(251,191,36,0.2)",
                                  },
                                  url: {
                                    color: "#60a5fa",
                                    bg: "rgba(96,165,250,0.08)",
                                    border: "rgba(96,165,250,0.2)",
                                  },
                                  embedded: {
                                    color: "#a78bfa",
                                    bg: "rgba(167,139,250,0.08)",
                                    border: "rgba(167,139,250,0.2)",
                                  },
                                };
                                const s = catColors[cat] || {
                                  color: "var(--text-muted)",
                                  bg: "var(--bg-elevated)",
                                  border: "var(--bg-border)",
                                };
                                return (
                                  <span
                                    key={cat}
                                    className="text-[10px] px-2 py-0.5 rounded font-bold uppercase tracking-wider"
                                    style={{
                                      color: s.color,
                                      background: s.bg,
                                      border: `1px solid ${s.border}`,
                                      fontFamily: "var(--font-mono)",
                                    }}
                                  >
                                    {cat.replace(/_/g, " ")}
                                  </span>
                                );
                              })}
                            </div>
                          )}

                        {/* Structured findings (v2) or flat signals fallback */}
                        {attachResult.findings &&
                        attachResult.findings.length > 0 ? (
                          <div
                            className="divide-y"
                            style={{ borderColor: "var(--bg-border)" }}
                          >
                            {attachResult.findings.map((finding, i) => {
                              const sevColor =
                                finding.severity === "critical"
                                  ? "#f87171"
                                  : finding.severity === "high"
                                    ? "#fb923c"
                                    : finding.severity === "medium"
                                      ? "#fbbf24"
                                      : "var(--text-muted)";
                              return (
                                <div
                                  key={i}
                                  className="px-4 py-2.5 flex items-start gap-3"
                                >
                                  <span
                                    className="text-[9px] font-black px-1.5 py-0.5 rounded mt-0.5 flex-shrink-0 uppercase"
                                    style={{
                                      color: sevColor,
                                      background: `${sevColor}14`,
                                      border: `1px solid ${sevColor}30`,
                                      fontFamily: "var(--font-mono)",
                                      minWidth: "52px",
                                      textAlign: "center",
                                    }}
                                  >
                                    {finding.severity}
                                  </span>
                                  <div className="flex-1 min-w-0">
                                    <div
                                      className="text-xs leading-snug"
                                      style={{
                                        color: "var(--text-secondary)",
                                        fontFamily: "var(--font-mono)",
                                      }}
                                    >
                                      {finding.detail}
                                    </div>
                                    {finding.extractedUrls &&
                                      finding.extractedUrls.length > 0 && (
                                        <div className="mt-1 flex flex-wrap gap-1">
                                          {finding.extractedUrls
                                            .slice(0, 3)
                                            .map((url, j) => (
                                              <span
                                                key={j}
                                                className="text-[9px] px-1.5 py-0.5 rounded truncate max-w-[200px]"
                                                style={{
                                                  color: "#60a5fa",
                                                  background:
                                                    "rgba(96,165,250,0.08)",
                                                  border:
                                                    "1px solid rgba(96,165,250,0.2)",
                                                  fontFamily:
                                                    "var(--font-mono)",
                                                }}
                                                title={url}
                                              >
                                                {url.substring(0, 50)}
                                                {url.length > 50 ? "…" : ""}
                                              </span>
                                            ))}
                                        </div>
                                      )}
                                  </div>
                                </div>
                              );
                            })}
                          </div>
                        ) : attachResult.signals &&
                          attachResult.signals.length > 0 ? (
                          <div className="p-4 space-y-2">
                            {attachResult.signals.map((sig, i) => (
                              <div
                                key={i}
                                className="flex items-start gap-3 px-4 py-3 rounded-xl"
                                style={{
                                  background: "var(--bg-elevated)",
                                  border: "1px solid var(--bg-border)",
                                }}
                              >
                                <span className="text-sm flex-shrink-0 mt-0.5">
                                  {sig.severity === "critical"
                                    ? "🔴"
                                    : sig.severity === "high"
                                      ? "🟠"
                                      : sig.severity === "medium"
                                        ? "🟡"
                                        : "⚪"}
                                </span>
                                <div>
                                  <p
                                    className="text-xs font-semibold mb-0.5"
                                    style={{
                                      color: "var(--text-primary)",
                                      fontFamily: "var(--font-mono)",
                                    }}
                                  >
                                    {sig.type}
                                  </p>
                                  <p
                                    className="text-xs"
                                    style={{ color: "var(--text-muted)" }}
                                  >
                                    {sig.detail}
                                  </p>
                                </div>
                              </div>
                            ))}
                          </div>
                        ) : (
                          <div
                            className="px-4 py-3 text-xs"
                            style={{
                              color: "var(--safe, #34d399)",
                              fontFamily: "var(--font-mono)",
                            }}
                          >
                            No threats detected — file appears clean.
                          </div>
                        )}

                        {/* SHA-256 copy row */}
                        {/* ── VirusTotal panel ── */}
                        {attachResult.virustotal !== undefined && (
                          <div
                            className="px-6 py-4 border-t"
                            style={{ borderColor: "rgba(255,255,255,0.06)" }}
                          >
                            <div
                              className="text-xs font-bold mb-3"
                              style={{
                                color: "var(--text-muted)",
                                fontFamily: "var(--font-mono)",
                                textTransform: "uppercase",
                                letterSpacing: "0.08em",
                              }}
                            >
                              🔬 VirusTotal Hash Lookup
                            </div>
                            {!attachResult.virustotal?.available &&
                            attachResult.virustotal?.reason ? (
                              <div
                                className="text-xs px-3 py-2 rounded-lg"
                                style={{
                                  background: "var(--bg-elevated)",
                                  color: "var(--text-muted)",
                                }}
                              >
                                {attachResult.virustotal.reason}
                              </div>
                            ) : attachResult.virustotal?.found === false ? (
                              <div
                                className="text-xs px-3 py-2 rounded-lg"
                                style={{
                                  background: "rgba(251,191,36,0.07)",
                                  border: "1px solid rgba(251,191,36,0.2)",
                                  color: "#fbbf24",
                                }}
                              >
                                ⚠ Hash not in VirusTotal database — file is
                                unknown. Novel/custom payload cannot be ruled
                                out.
                              </div>
                            ) : attachResult.virustotal?.found ? (
                              <div
                                className="flex items-center gap-4 px-4 py-3 rounded-xl"
                                style={{
                                  background:
                                    (attachResult.virustotal.detectionCount ??
                                      0) >= 5
                                      ? "rgba(248,113,113,0.08)"
                                      : (attachResult.virustotal
                                            .detectionCount ?? 0) >= 1
                                        ? "rgba(251,191,36,0.08)"
                                        : "rgba(52,211,153,0.07)",
                                  border: `1px solid ${(attachResult.virustotal.detectionCount ?? 0) >= 5 ? "rgba(248,113,113,0.25)" : (attachResult.virustotal.detectionCount ?? 0) >= 1 ? "rgba(251,191,36,0.25)" : "rgba(52,211,153,0.25)"}`,
                                }}
                              >
                                <div
                                  className="text-3xl font-black"
                                  style={{
                                    color:
                                      (attachResult.virustotal.detectionCount ??
                                        0) >= 5
                                        ? "#f87171"
                                        : (attachResult.virustotal
                                              .detectionCount ?? 0) >= 1
                                          ? "#fbbf24"
                                          : "var(--safe)",
                                  }}
                                >
                                  {attachResult.virustotal.detectionCount}/
                                  {attachResult.virustotal.totalEngines}
                                </div>
                                <div className="flex-1">
                                  <div
                                    className="font-semibold text-sm"
                                    style={{
                                      color:
                                        (attachResult.virustotal
                                          .detectionCount ?? 0) >= 5
                                          ? "#f87171"
                                          : (attachResult.virustotal
                                                .detectionCount ?? 0) >= 1
                                            ? "#fbbf24"
                                            : "var(--safe)",
                                    }}
                                  >
                                    {(attachResult.virustotal.detectionCount ??
                                      0) > 0
                                      ? `${attachResult.virustotal.detectionCount} AV engines detect this file as malicious`
                                      : "No AV engines detected threats"}
                                  </div>
                                  {attachResult.virustotal.malwareFamily && (
                                    <div
                                      className="text-xs mt-0.5"
                                      style={{ color: "var(--text-muted)" }}
                                    >
                                      Family:{" "}
                                      <strong style={{ color: "#f87171" }}>
                                        {attachResult.virustotal.malwareFamily}
                                      </strong>
                                    </div>
                                  )}
                                  {(attachResult.virustotal.threatNames
                                    ?.length ?? 0) > 0 && (
                                    <div
                                      className="text-xs mt-0.5"
                                      style={{ color: "var(--text-muted)" }}
                                    >
                                      {attachResult.virustotal
                                        .threatNames!.slice(0, 3)
                                        .join(" · ")}
                                    </div>
                                  )}
                                </div>
                                {attachResult.virustotal.vtLink && (
                                  <a
                                    href={attachResult.virustotal.vtLink}
                                    target="_blank"
                                    rel="noreferrer"
                                    className="flex items-center gap-1 text-xs px-2 py-1 rounded-lg flex-shrink-0"
                                    style={{
                                      color: "var(--accent)",
                                      background: "var(--accent-subtle)",
                                      border: "1px solid var(--accent-border)",
                                    }}
                                  >
                                    <ExternalLink className="size-3" /> VT
                                    Report
                                  </a>
                                )}
                              </div>
                            ) : null}
                          </div>
                        )}

                        {/* ── Office Intelligence panel ── */}
                        {attachResult.officeIntel && (
                          <div
                            className="px-6 py-4 border-t"
                            style={{ borderColor: "rgba(255,255,255,0.06)" }}
                          >
                            <div
                              className="text-xs font-bold mb-3"
                              style={{
                                color: "var(--text-muted)",
                                fontFamily: "var(--font-mono)",
                                textTransform: "uppercase",
                                letterSpacing: "0.08em",
                              }}
                            >
                              📄 Office Document Intelligence
                            </div>
                            <div className="grid grid-cols-2 md:grid-cols-4 gap-2 mb-3">
                              {(
                                [
                                  {
                                    label: "Macro Enabled",
                                    value:
                                      attachResult.officeIntel.macroEnabled,
                                  },
                                  {
                                    label: "VBA Detected",
                                    value: attachResult.officeIntel.vbaDetected,
                                  },
                                  {
                                    label: "Remote Template",
                                    value:
                                      !!attachResult.officeIntel.templateUrl,
                                  },
                                  {
                                    label: "Ext Queries",
                                    value:
                                      (attachResult.officeIntel.externalQueries
                                        ?.length ?? 0) > 0,
                                  },
                                ] as { label: string; value: boolean }[]
                              ).map((f) => (
                                <div
                                  key={f.label}
                                  className="flex items-center gap-2 px-3 py-2 rounded-lg"
                                  style={{
                                    background: "var(--bg-elevated)",
                                    border: "1px solid var(--bg-border)",
                                  }}
                                >
                                  <div
                                    className="w-2 h-2 rounded-full flex-shrink-0"
                                    style={{
                                      background: f.value
                                        ? "#f87171"
                                        : "var(--safe)",
                                    }}
                                  />
                                  <span
                                    className="text-[10px]"
                                    style={{
                                      color: f.value
                                        ? "#f87171"
                                        : "var(--text-muted)",
                                    }}
                                  >
                                    {f.label}
                                  </span>
                                </div>
                              ))}
                            </div>
                            {attachResult.officeIntel.templateUrl && (
                              <div
                                className="text-xs px-3 py-2 rounded-lg mb-2"
                                style={{
                                  background: "rgba(248,113,113,0.07)",
                                  border: "1px solid rgba(248,113,113,0.2)",
                                  color: "#f87171",
                                  fontFamily: "var(--font-mono)",
                                  wordBreak: "break-all",
                                }}
                              >
                                Remote Template:{" "}
                                {attachResult.officeIntel.templateUrl}
                              </div>
                            )}
                            {attachResult.officeIntel.metadata?.creator && (
                              <div
                                className="text-xs px-3 py-2 rounded-lg mb-2"
                                style={{
                                  background: "var(--bg-elevated)",
                                  border: "1px solid var(--bg-border)",
                                  color: "var(--text-muted)",
                                }}
                              >
                                Author:{" "}
                                {attachResult.officeIntel.metadata.creator}
                                {attachResult.officeIntel.metadata
                                  .lastModifiedBy &&
                                  ` · Modified by: ${attachResult.officeIntel.metadata.lastModifiedBy}`}
                              </div>
                            )}
                            {(attachResult.officeIntel.hyperlinks?.length ??
                              0) > 0 && (
                              <div className="mt-2">
                                <div
                                  className="text-[10px] font-bold mb-1"
                                  style={{
                                    color: "var(--text-muted)",
                                    fontFamily: "var(--font-mono)",
                                    textTransform: "uppercase",
                                  }}
                                >
                                  Embedded Hyperlinks (
                                  {attachResult.officeIntel.hyperlinks.length})
                                </div>
                                {attachResult.officeIntel.hyperlinks
                                  .slice(0, 5)
                                  .map((url, i) => (
                                    <div
                                      key={i}
                                      className="text-[10px] px-2 py-1 rounded mb-0.5 truncate"
                                      style={{
                                        background: "var(--bg-base)",
                                        color: "var(--accent)",
                                        fontFamily: "var(--font-mono)",
                                      }}
                                    >
                                      {url}
                                    </div>
                                  ))}
                              </div>
                            )}
                          </div>
                        )}

                        {/* ── PDF Intelligence panel ── */}
                        {attachResult.pdfIntel &&
                          (attachResult.pdfIntel.hasEmbeddedJS ||
                            attachResult.pdfIntel.hasLaunchAction ||
                            attachResult.pdfIntel.hasOpenAction ||
                            attachResult.pdfIntel.hasEmbeddedFiles ||
                            attachResult.pdfIntel.hasCredentialForm) && (
                            <div
                              className="px-6 py-4 border-t"
                              style={{ borderColor: "rgba(255,255,255,0.06)" }}
                            >
                              <div
                                className="text-xs font-bold mb-3"
                                style={{
                                  color: "var(--text-muted)",
                                  fontFamily: "var(--font-mono)",
                                  textTransform: "uppercase",
                                  letterSpacing: "0.08em",
                                }}
                              >
                                📕 PDF Threat Intelligence
                              </div>
                              <div className="grid grid-cols-2 md:grid-cols-5 gap-2">
                                {(
                                  [
                                    {
                                      label: "/JS Embedded",
                                      value:
                                        attachResult.pdfIntel.hasEmbeddedJS,
                                    },
                                    {
                                      label: "/Launch Action",
                                      value:
                                        attachResult.pdfIntel.hasLaunchAction,
                                    },
                                    {
                                      label: "/OpenAction",
                                      value:
                                        attachResult.pdfIntel.hasOpenAction,
                                    },
                                    {
                                      label: "Embedded Files",
                                      value:
                                        attachResult.pdfIntel.hasEmbeddedFiles,
                                    },
                                    {
                                      label: "Credential Form",
                                      value:
                                        attachResult.pdfIntel.hasCredentialForm,
                                    },
                                  ] as { label: string; value: boolean }[]
                                ).map((f) => (
                                  <div
                                    key={f.label}
                                    className="flex items-center gap-1.5 px-3 py-2 rounded-lg"
                                    style={{
                                      background: f.value
                                        ? "rgba(248,113,113,0.07)"
                                        : "var(--bg-elevated)",
                                      border: `1px solid ${f.value ? "rgba(248,113,113,0.2)" : "var(--bg-border)"}`,
                                    }}
                                  >
                                    <div
                                      className="w-1.5 h-1.5 rounded-full flex-shrink-0"
                                      style={{
                                        background: f.value
                                          ? "#f87171"
                                          : "var(--safe)",
                                      }}
                                    />
                                    <span
                                      className="text-[9px]"
                                      style={{
                                        color: f.value
                                          ? "#f87171"
                                          : "var(--text-muted)",
                                      }}
                                    >
                                      {f.label}
                                    </span>
                                  </div>
                                ))}
                              </div>
                            </div>
                          )}

                        {/* SHA-256 copy row */}
                        {attachResult.sha256 && (
                          <div
                            className="px-4 py-2.5 border-t flex items-center gap-2"
                            style={{
                              borderColor: "var(--bg-border)",
                              background: "var(--bg-elevated)",
                            }}
                          >
                            <span
                              className="text-[9px] uppercase tracking-widest flex-shrink-0"
                              style={{
                                color: "var(--text-muted)",
                                fontFamily: "var(--font-mono)",
                              }}
                            >
                              SHA-256
                            </span>
                            <span
                              className="text-[10px] truncate flex-1"
                              style={{
                                color: "var(--text-muted)",
                                fontFamily: "var(--font-mono)",
                              }}
                            >
                              {attachResult.sha256}
                            </span>
                            <button
                              onClick={() =>
                                navigator.clipboard.writeText(
                                  attachResult.sha256!,
                                )
                              }
                              className="text-[9px] px-2 py-0.5 rounded flex-shrink-0"
                              style={{
                                color: "var(--accent)",
                                background: "var(--accent-subtle)",
                                border: "1px solid var(--accent-border)",
                                fontFamily: "var(--font-mono)",
                              }}
                            >
                              Copy
                            </button>
                          </div>
                        )}
                      </motion.div>
                    )}
                  </motion.div>
                )}

                {/* ── QR Code mode ── */}
                {scanMode === "qr" && (
                  <motion.div
                    initial={{ opacity: 0, y: 8 }}
                    animate={{ opacity: 1, y: 0 }}
                    className="rounded-2xl p-5"
                    style={{
                      background: "var(--bg-card)",
                      border: "1px solid var(--bg-border)",
                    }}
                  >
                    <p
                      className="text-xs mb-4"
                      style={{
                        color: "var(--text-muted)",
                        fontFamily: "'JetBrains Mono', monospace",
                      }}
                    >
                      Upload an image with a QR code — we decode it and run the
                      extracted URL through the full phishing detection engine.
                    </p>
                    <div
                      onClick={() => qrInputRef.current?.click()}
                      onDragOver={(e) => {
                        e.preventDefault();
                        (e.currentTarget as HTMLElement).style.borderColor =
                          "var(--accent)";
                      }}
                      onDragLeave={(e) => {
                        (e.currentTarget as HTMLElement).style.borderColor =
                          "var(--bg-border)";
                      }}
                      onDrop={(e) => {
                        e.preventDefault();
                        (e.currentTarget as HTMLElement).style.borderColor =
                          "var(--bg-border)";
                        const f = e.dataTransfer.files[0];
                        if (f) handleQRUpload(f);
                      }}
                      className="rounded-xl p-8 text-center cursor-pointer transition-all"
                      style={{
                        border: "2px dashed var(--bg-border)",
                        background: "var(--bg-elevated)",
                      }}
                    >
                      {qrLoading ? (
                        <div className="flex flex-col items-center gap-3">
                          <div
                            className="w-8 h-8 border-2 rounded-full animate-spin"
                            style={{
                              borderColor: "var(--accent)",
                              borderTopColor: "transparent",
                            }}
                          />
                          <p
                            className="text-sm"
                            style={{ color: "var(--text-muted)" }}
                          >
                            Decoding QR code...
                          </p>
                        </div>
                      ) : (
                        <div className="flex flex-col items-center gap-3">
                          <span className="text-3xl">📷</span>
                          <div>
                            <p
                              className="text-sm font-medium mb-1"
                              style={{ color: "var(--text-primary)" }}
                            >
                              Drop QR image here or click to browse
                            </p>
                            <p
                              className="text-xs"
                              style={{
                                color: "var(--text-muted)",
                                fontFamily: "'JetBrains Mono', monospace",
                              }}
                            >
                              PNG · JPG · WebP · HEIC supported
                            </p>
                          </div>
                        </div>
                      )}
                    </div>
                    <input
                      ref={qrInputRef}
                      type="file"
                      accept="image/*"
                      className="hidden"
                      onChange={(e) => {
                        const f = e.target.files?.[0];
                        if (f) handleQRUpload(f);
                      }}
                    />
                    {qrError && (
                      <div
                        className="mt-3 px-4 py-3 rounded-xl text-xs"
                        style={{
                          background: "rgba(248,113,113,0.07)",
                          border: "1px solid rgba(248,113,113,0.2)",
                          color: "var(--color-danger, #f87171)",
                          fontFamily: "'JetBrains Mono', monospace",
                        }}
                      >
                        ⚠ {qrError}
                      </div>
                    )}
                    {qrDecoded && (
                      <div
                        className="mt-3 px-4 py-3 rounded-xl"
                        style={{
                          background: "rgba(52,211,153,0.06)",
                          border: "1px solid rgba(52,211,153,0.2)",
                        }}
                      >
                        <p
                          className="text-xs mb-1 font-semibold"
                          style={{
                            color: "var(--accent)",
                            fontFamily: "'JetBrains Mono', monospace",
                          }}
                        >
                          ✓ QR Decoded — scanning now:
                        </p>
                        <code
                          className="text-xs break-all"
                          style={{
                            color: "var(--text-secondary)",
                            fontFamily: "'JetBrains Mono', monospace",
                          }}
                        >
                          {qrDecoded}
                        </code>
                      </div>
                    )}
                  </motion.div>
                )}
              </div>
            </motion.div>
          )}
        </AnimatePresence>

        {/* ── SCANNING ANIMATION ── */}
        <AnimatePresence>
          {loading && (
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="rounded-2xl overflow-hidden relative scan-animate mb-6"
              style={{
                background: "var(--bg-card)",
                border: "1px solid rgba(0,255,136,0.2)",
                minHeight: 180,
              }}
            >
              <div className="flex flex-col items-center justify-center py-16 gap-5">
                {/* Animated radar rings */}
                <div className="relative w-16 h-16 flex items-center justify-center">
                  {[0, 1, 2].map((i) => (
                    <motion.div
                      key={i}
                      className="absolute inset-0 rounded-full border"
                      style={{ borderColor: "rgba(0,255,136,0.3)" }}
                      animate={{ scale: [1, 2.2], opacity: [0.6, 0] }}
                      transition={{
                        duration: 2,
                        repeat: Infinity,
                        delay: i * 0.6,
                        ease: "easeOut",
                      }}
                    />
                  ))}
                  <Shield
                    className="size-7 relative z-10"
                    style={{ color: "var(--accent-green)" }}
                  />
                </div>
                <div className="text-center">
                  <p
                    className="text-sm font-semibold mb-1"
                    style={{
                      color: "var(--text-primary)",
                      fontFamily: "'Syne', sans-serif",
                    }}
                  >
                    Analyzing Target
                  </p>
                  <p
                    className="text-xs cursor-blink"
                    style={{
                      color: "var(--accent-green)",
                      fontFamily: "'JetBrains Mono', monospace",
                    }}
                  >
                    Running 24-feature detection engine
                  </p>
                </div>
                {/* Animated progress steps */}
                <div className="flex items-center gap-3 mt-2">
                  {["Rules", "ML Model", "Threat Intel", "DNA"].map(
                    (step, i) => (
                      <motion.div
                        key={step}
                        initial={{ opacity: 0.2 }}
                        animate={{ opacity: [0.2, 1, 0.2] }}
                        transition={{
                          duration: 1.5,
                          repeat: Infinity,
                          delay: i * 0.35,
                        }}
                        className="text-xs px-2 py-1 rounded"
                        style={{
                          color: "var(--accent-green)",
                          background: "rgba(0,255,136,0.06)",
                          border: "1px solid rgba(0,255,136,0.15)",
                          fontFamily: "'JetBrains Mono', monospace",
                        }}
                      >
                        {step}
                      </motion.div>
                    ),
                  )}
                </div>
              </div>
            </motion.div>
          )}
        </AnimatePresence>

        {/* ── ERROR STATE ── */}
        {error && !loading && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            className="mb-6 rounded-xl p-5 flex items-start gap-3"
            style={{
              background: "rgba(255,68,68,0.06)",
              border: "1px solid rgba(255,68,68,0.2)",
            }}
          >
            <XCircle
              className="size-5 flex-shrink-0 mt-0.5"
              style={{ color: "#ff4444" }}
            />
            <div>
              <p
                className="text-sm font-semibold mb-1"
                style={{ color: "#ff4444" }}
              >
                Scan Failed
              </p>
              <p
                className="text-xs"
                style={{
                  color: "var(--text-muted)",
                  fontFamily: "'JetBrains Mono', monospace",
                }}
              >
                {error}
              </p>
            </div>
            <button
              onClick={handleReset}
              className="ml-auto text-xs px-3 py-1.5 rounded-lg"
              style={{
                color: "var(--text-muted)",
                border: "1px solid var(--bg-border)",
                background: "var(--bg-card)",
              }}
            >
              Try Again
            </button>
          </motion.div>
        )}

        {/* ── RESULT ── */}
        <AnimatePresence>
          {result &&
            !loading &&
            (() => {
              const c = STATUS_CFG[result.status] || STATUS_CFG.safe;
              const Icon = c.icon;
              const inputCfg = INPUT_CFG[result.inputType] || INPUT_CFG.text;
              const InputIcon = inputCfg.icon;
              const confCfg =
                CONF_CFG[result.confidence as keyof typeof CONF_CFG] ||
                CONF_CFG.low;

              return (
                <motion.div
                  initial={{ opacity: 0, y: 16 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0 }}
                  className="space-y-4"
                >
                  {/* Community + Threat Intel Confirmed Banner */}
                  {(result.communityMatch || result.threatIntel?.found) && (
                    <motion.div
                      initial={{ opacity: 0, scale: 0.97 }}
                      animate={{ opacity: 1, scale: 1 }}
                      transition={{ delay: 0.3 }}
                      className="rounded-xl overflow-hidden"
                      style={{
                        border: "2px solid rgba(255,68,68,0.4)",
                        boxShadow: "0 0 30px rgba(255,68,68,0.1)",
                      }}
                    >
                      <div
                        className="px-5 py-3 flex items-center gap-3 flex-wrap"
                        style={{ background: "rgba(255,68,68,0.08)" }}
                      >
                        <span className="text-lg">🌐</span>
                        <div>
                          <p
                            className="text-sm font-bold"
                            style={{
                              color: "#ff4444",
                              fontFamily: "'Syne', sans-serif",
                            }}
                          >
                            {result.communityMatch
                              ? `Community Confirmed Phishing — ${result.communityMatch.reportCount} organization${result.communityMatch.reportCount !== 1 ? "s" : ""} flagged`
                              : `Confirmed by Threat Intelligence`}
                          </p>
                          <p
                            className="text-xs mt-0.5"
                            style={{
                              color: "var(--text-muted)",
                              fontFamily: "'JetBrains Mono', monospace",
                            }}
                          >
                            {result.communityMatch
                              ? `Confidence: ${result.communityMatch.confidence}% · STIX ID: ${result.communityMatch.stixId?.slice(0, 24)}...`
                              : `Sources: ${result.threatIntel?.sources?.join(" · ")}`}
                          </p>
                        </div>
                        <span
                          className="ml-auto text-xs px-2 py-0.5 rounded font-bold"
                          style={{
                            color: "#ff4444",
                            background: "rgba(255,68,68,0.12)",
                            border: "1px solid rgba(255,68,68,0.3)",
                            fontFamily: "'JetBrains Mono', monospace",
                          }}
                        >
                          {result.communityMatch
                            ? "COMMUNITY CONFIRMED"
                            : "THREAT INTEL HIT"}
                        </span>
                      </div>
                    </motion.div>
                  )}

                  {/* Evasion Attempt Detection */}
                  {result.evasion?.detected && (
                    <motion.div
                      initial={{ opacity: 0, y: 8 }}
                      animate={{ opacity: 1, y: 0 }}
                      transition={{ delay: 0.51 }}
                      className="rounded-xl overflow-hidden"
                      style={{
                        border: `2px solid ${
                          result.evasion.level === "SOPHISTICATED"
                            ? "rgba(255,68,68,0.4)"
                            : result.evasion.level === "MODERATE"
                              ? "rgba(249,115,22,0.35)"
                              : "rgba(245,166,35,0.3)"
                        }`,
                      }}
                    >
                      {/* Header */}
                      <div
                        className="px-5 py-3 flex items-center gap-2 flex-wrap"
                        style={{
                          background:
                            result.evasion.level === "SOPHISTICATED"
                              ? "rgba(255,68,68,0.09)"
                              : result.evasion.level === "MODERATE"
                                ? "rgba(249,115,22,0.08)"
                                : "rgba(245,166,35,0.07)",
                          borderBottom: "1px solid rgba(30,39,54,0.8)",
                        }}
                      >
                        <span className="text-lg">🛡️</span>
                        <span
                          className="text-xs font-bold uppercase tracking-wider"
                          style={{
                            color:
                              result.evasion.level === "SOPHISTICATED"
                                ? "#ff4444"
                                : result.evasion.level === "MODERATE"
                                  ? "#f97316"
                                  : "#f5a623",
                            fontFamily: "'JetBrains Mono', monospace",
                          }}
                        >
                          Evasion Attempt Detected
                        </span>
                        <span
                          className="ml-auto text-xs px-2 py-0.5 rounded font-bold uppercase"
                          style={{
                            color:
                              result.evasion.level === "SOPHISTICATED"
                                ? "#ff4444"
                                : result.evasion.level === "MODERATE"
                                  ? "#f97316"
                                  : "#f5a623",
                            background: "rgba(0,0,0,0.3)",
                            fontFamily: "'JetBrains Mono', monospace",
                          }}
                        >
                          {result.evasion.level}
                        </span>
                      </div>

                      {/* Content */}
                      <div
                        className="px-5 py-4"
                        style={{ background: "var(--bg-card)" }}
                      >
                        <div
                          className="text-sm font-semibold mb-0.5"
                          style={{
                            color: "var(--text-primary)",
                            fontFamily: "'Syne', sans-serif",
                          }}
                        >
                          {result.evasion.level === "SOPHISTICATED"
                            ? "Attacker is using multiple advanced evasion techniques"
                            : result.evasion.level === "MODERATE"
                              ? "Multiple evasion signals detected — skilled attacker"
                              : "Single evasion technique detected — possible evasion attempt"}
                        </div>
                        <div
                          className="text-xs mb-3"
                          style={{
                            color: "var(--text-muted)",
                            fontFamily: "'JetBrains Mono', monospace",
                          }}
                        >
                          {result.evasion.signals} evasion signal
                          {result.evasion.signals !== 1 ? "s" : ""} fired ·
                          MITRE T1027 — Obfuscated Files or Information
                        </div>

                        <div className="flex flex-wrap gap-2">
                          {result.evasion.techniques.map((tech: string) => (
                            <span
                              key={tech}
                              className="text-xs px-2 py-0.5 rounded capitalize"
                              style={{
                                color: "var(--text-secondary)",
                                background: "var(--bg-elevated)",
                                border: "1px solid var(--bg-border)",
                                fontFamily: "'JetBrains Mono', monospace",
                              }}
                            >
                              {tech.replace(/_/g, " ")}
                            </span>
                          ))}
                        </div>
                        <p
                          className="text-xs mt-3"
                          style={{
                            color: "var(--text-muted)",
                            fontFamily: "'JetBrains Mono', monospace",
                          }}
                        >
                          ↑ Second-pass evasion detection engine — catches
                          sophisticated attackers who engineer URLs to score
                          just below detection thresholds
                        </p>
                      </div>
                    </motion.div>
                  )}

                  {/* Target label */}
                  <div
                    className="flex items-center gap-2 text-xs px-1"
                    style={{
                      color: "var(--text-muted)",
                      fontFamily: "'JetBrains Mono', monospace",
                    }}
                  >
                    <InputIcon
                      className="size-3.5"
                      style={{ color: inputCfg.color }}
                    />
                    <span style={{ color: inputCfg.color }}>
                      {inputCfg.label}:
                    </span>
                    <span className="truncate max-w-sm">{scannedInput}</span>
                    {siemStatus === "sent" && (
                      <span
                        className="ml-auto flex items-center gap-1"
                        style={{
                          color: "var(--accent-green)",
                          fontFamily: "'JetBrains Mono', monospace",
                        }}
                      >
                        <Shield className="size-3" /> SIEM logged
                      </span>
                    )}
                  </div>

                  {/* ── View Mode Toggle ── */}
                  <div
                    className="flex items-center gap-2 p-1 rounded-xl w-fit"
                    style={{
                      background: "var(--bg-elevated)",
                      border: "1px solid var(--bg-border)",
                    }}
                  >
                    <button
                      onClick={() => switchMode("normal")}
                      className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-all"
                      style={{
                        background:
                          viewMode === "normal"
                            ? "var(--bg-card)"
                            : "transparent",
                        color:
                          viewMode === "normal"
                            ? "var(--text-primary)"
                            : "var(--text-muted)",
                        border:
                          viewMode === "normal"
                            ? "1px solid var(--bg-border)"
                            : "1px solid transparent",
                        boxShadow:
                          viewMode === "normal" ? "var(--shadow-sm)" : "none",
                      }}
                    >
                      <User className="size-3.5" />
                      Normal
                    </button>
                    <button
                      onClick={() => switchMode("expert")}
                      className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-all"
                      style={{
                        background:
                          viewMode === "expert"
                            ? "var(--bg-card)"
                            : "transparent",
                        color:
                          viewMode === "expert"
                            ? "var(--accent)"
                            : "var(--text-muted)",
                        border:
                          viewMode === "expert"
                            ? "1px solid var(--accent-border)"
                            : "1px solid transparent",
                        boxShadow:
                          viewMode === "expert" ? "var(--shadow-sm)" : "none",
                      }}
                    >
                      <Microscope className="size-3.5" />
                      Expert
                    </button>
                  </div>

                  {viewMode === "expert" ? (
                    /* ── EXPERT VIEW — existing card unchanged ── */
                    <div
                      className={`rounded-2xl overflow-hidden ${result.status === "phishing" ? "card-glow-red" : result.status === "safe" ? "card-glow-green" : ""}`}
                      style={{
                        background: "var(--bg-card)",
                        border: `2px solid ${c.border}`,
                        boxShadow: c.glow,
                      }}
                    >
                      {/* ── COLOR VERDICT HEADER ── */}
                      <motion.div
                        initial={{ scale: 0.96, opacity: 0 }}
                        animate={{ scale: 1, opacity: 1 }}
                        transition={{
                          type: "spring",
                          bounce: 0.3,
                          duration: 0.6,
                        }}
                        className="px-6 py-6 flex items-center gap-5"
                        style={{
                          background: c.bg,
                          borderBottom: `1px solid ${c.border}`,
                          boxShadow:
                            result.status === "phishing"
                              ? "inset 0 -1px 0 rgba(248,113,113,0.15)"
                              : result.status === "suspicious"
                                ? "inset 0 -1px 0 rgba(251,191,36,0.12)"
                                : "inset 0 -1px 0 rgba(52,211,153,0.10)",
                        }}
                      >
                        <div className="relative flex-shrink-0">
                          <div
                            className="w-16 h-16 rounded-2xl flex items-center justify-center"
                            style={{
                              background: c.bg,
                              border: `2px solid ${c.border}`,
                              boxShadow: `inset 0 1px 0 rgba(255,255,255,0.08)`,
                            }}
                          >
                            <Icon
                              className="size-9"
                              style={{ color: c.color }}
                              strokeWidth={2}
                            />
                          </div>
                          {result.status === "phishing" && (
                            <div
                              className="absolute inset-0 rounded-2xl animate-ping opacity-30"
                              style={{ border: `2px solid ${c.color}` }}
                            />
                          )}
                        </div>

                        <div className="flex-1 min-w-0">
                          <div
                            className="text-3xl font-black mb-1 tracking-tight"
                            style={{
                              color: c.color,
                              fontFamily: "'Syne', sans-serif",
                            }}
                          >
                            {c.label}
                          </div>
                          <p
                            className="text-sm"
                            style={{ color: "var(--text-secondary)" }}
                          >
                            {c.msg}
                          </p>

                          {/* ── Detection badges ── */}
                          <div className="flex flex-wrap items-center gap-2 mt-3">
                            <div
                              className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-medium"
                              style={{
                                background: "rgba(0,0,0,0.3)",
                                border: "1px solid var(--bg-border)",
                                color: inputCfg.color,
                                fontFamily: "'JetBrains Mono', monospace",
                              }}
                            >
                              <InputIcon className="size-3" />
                              Detected as:{" "}
                              <span className="font-bold">
                                {inputCfg.label}
                              </span>
                            </div>
                            <div
                              className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-medium"
                              style={{
                                background: confCfg.bg,
                                border: `1px solid ${confCfg.color}40`,
                                color: confCfg.color,
                                fontFamily: "'JetBrains Mono', monospace",
                              }}
                            >
                              <Eye className="size-3" />
                              Confidence:{" "}
                              <span className="font-bold">{confCfg.label}</span>
                            </div>
                            <div
                              className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-bold"
                              style={{
                                background: `${c.color}15`,
                                border: `1px solid ${c.border}`,
                                color: c.color,
                                fontFamily: "'JetBrains Mono', monospace",
                              }}
                            >
                              <Zap className="size-3" />
                              Score: {result.riskScore}/100
                            </div>
                          </div>

                          {/* ── Sandbox mini-badges ── */}
                          {urlPreview?.sandboxRisk && (
                            <div className="flex items-center gap-2 mt-2 flex-wrap">
                              {urlPreview.forms?.hasCredentialForm && (
                                <span
                                  className="text-xs px-2 py-0.5 rounded font-mono"
                                  style={{
                                    color: "#ff4444",
                                    background: "rgba(255,68,68,0.08)",
                                    border: "1px solid rgba(255,68,68,0.2)",
                                  }}
                                >
                                  ⚠ CRED HARVESTER
                                </span>
                              )}
                              {urlPreview.technologies?.hasPhishingKit && (
                                <span
                                  className="text-xs px-2 py-0.5 rounded font-mono"
                                  style={{
                                    color: "#ff4444",
                                    background: "rgba(255,68,68,0.08)",
                                    border: "1px solid rgba(255,68,68,0.2)",
                                  }}
                                >
                                  ⚠ PHISHING KIT
                                </span>
                              )}
                              {urlPreview.technologies?.hasObfuscation && (
                                <span
                                  className="text-xs px-2 py-0.5 rounded font-mono"
                                  style={{
                                    color: "#f97316",
                                    background: "rgba(249,115,22,0.08)",
                                    border: "1px solid rgba(249,115,22,0.2)",
                                  }}
                                >
                                  ⚠ OBFUSCATED JS
                                </span>
                              )}
                              {urlPreview.redirectChain?.crossDomain && (
                                <span
                                  className="text-xs px-2 py-0.5 rounded font-mono"
                                  style={{
                                    color: "#f5a623",
                                    background: "rgba(245,166,35,0.08)",
                                    border: "1px solid rgba(245,166,35,0.2)",
                                  }}
                                >
                                  ↪ REDIRECT CHAIN
                                </span>
                              )}
                              {urlPreview.liveStatus === "LIVE" && (
                                <span
                                  className="text-xs px-2 py-0.5 rounded font-mono"
                                  style={{
                                    color: "#ff4444",
                                    background: "rgba(255,68,68,0.06)",
                                    border: "1px solid rgba(255,68,68,0.18)",
                                  }}
                                >
                                  ● LIVE PAGE
                                </span>
                              )}
                              {urlPreview.liveStatus === "TAKEN_DOWN" && (
                                <span
                                  className="text-xs px-2 py-0.5 rounded font-mono"
                                  style={{
                                    color: "#00ff88",
                                    background: "rgba(0,255,136,0.06)",
                                    border: "1px solid rgba(0,255,136,0.18)",
                                  }}
                                >
                                  ✓ TAKEN DOWN
                                </span>
                              )}
                            </div>
                          )}
                        </div>
                      </motion.div>

                      {/* ── COLOR-CODED RISK BAR ── */}
                      <div
                        className="px-6 py-5 border-b"
                        style={{ borderColor: "var(--bg-border)" }}
                      >
                        <div
                          className="flex justify-between text-xs mb-2"
                          style={{
                            color: "var(--text-muted)",
                            fontFamily: "'JetBrains Mono', monospace",
                          }}
                        >
                          <span className="flex items-center gap-2">
                            <span
                              className="w-2 h-2 rounded-full inline-block"
                              style={{ background: "#00ff88" }}
                            />
                            Safe
                            <span
                              className="w-2 h-2 rounded-full inline-block ml-1"
                              style={{ background: "#f5a623" }}
                            />
                            Suspicious
                            <span
                              className="w-2 h-2 rounded-full inline-block ml-1"
                              style={{ background: "#ff4444" }}
                            />
                            Phishing
                          </span>
                          <span
                            className="font-bold"
                            style={{ color: c.color, fontSize: 13 }}
                          >
                            {result.riskScore} / 100
                          </span>
                        </div>
                        <div
                          className="relative h-4 rounded-full overflow-hidden"
                          style={{ background: "var(--bg-border)" }}
                        >
                          <div
                            className="absolute top-0 left-0 h-full opacity-20 rounded-l-full"
                            style={{ width: "25%", background: "#00ff88" }}
                          />
                          <div
                            className="absolute top-0 h-full opacity-20"
                            style={{
                              left: "25%",
                              width: "40%",
                              background: "#f5a623",
                            }}
                          />
                          <div
                            className="absolute top-0 h-full opacity-20 rounded-r-full"
                            style={{
                              left: "65%",
                              width: "35%",
                              background: "#ff4444",
                            }}
                          />
                          <motion.div
                            className="absolute top-0 left-0 h-full rounded-full"
                            initial={{ width: 0 }}
                            animate={{ width: `${result.riskScore}%` }}
                            transition={{
                              duration: 1.2,
                              ease: "easeOut",
                              delay: 0.3,
                            }}
                            style={{
                              background: c.barGradient,
                            }}
                          />
                          <motion.div
                            className="absolute top-0 h-full w-1 rounded-full"
                            initial={{ left: "0%" }}
                            animate={{
                              left: `calc(${result.riskScore}% - 2px)`,
                            }}
                            transition={{
                              duration: 1.2,
                              ease: "easeOut",
                              delay: 0.3,
                            }}
                            style={{
                              background: "#fff",
                              boxShadow: `0 0 6px ${c.color}`,
                            }}
                          />
                        </div>
                        <div
                          className="flex justify-between mt-1.5 text-xs"
                          style={{
                            color: "var(--text-muted)",
                            fontFamily: "'JetBrains Mono', monospace",
                          }}
                        >
                          <span style={{ color: "#00ff88" }}>0 — Safe</span>
                          <span>25</span>
                          <span>65</span>
                          <span style={{ color: "#ff4444" }}>
                            100 — Phishing
                          </span>
                        </div>
                      </div>

                      {/* ── ML HYBRID PANEL ── */}
                      {result.mlEnabled && result.mlScore !== null && (
                        <div
                          className="px-6 py-5 border-b"
                          style={{ borderColor: "var(--bg-border)" }}
                        >
                          <div className="flex items-center gap-2 mb-4">
                            <Brain
                              className="size-3.5"
                              style={{ color: "var(--accent-cyan)" }}
                            />
                            <span
                              className="text-xs font-bold uppercase tracking-wider"
                              style={{
                                color: "var(--accent-cyan)",
                                fontFamily: "'JetBrains Mono', monospace",
                              }}
                            >
                              ML Hybrid Analysis
                            </span>
                            <span
                              className="ml-auto text-xs px-2 py-0.5 rounded"
                              style={{
                                background: "rgba(0,212,255,0.08)",
                                color: "var(--accent-cyan)",
                                border: "1px solid rgba(0,212,255,0.2)",
                                fontFamily: "'JetBrains Mono', monospace",
                              }}
                            >
                              v{result.detectionVersion}
                            </span>
                          </div>
                          <div className="grid grid-cols-2 gap-4">
                            {[
                              {
                                label: "NEURAL NET",
                                val: result.mlScore!,
                                color: "var(--accent-cyan)",
                                delay: 0.4,
                              },
                              {
                                label: "RULE ENGINE",
                                val: result.ruleScore,
                                color: "var(--accent-green)",
                                delay: 0.5,
                              },
                            ].map(({ label, val, color, delay }) => (
                              <div key={label}>
                                <div
                                  className="flex justify-between text-xs mb-1.5"
                                  style={{
                                    color: "var(--text-muted)",
                                    fontFamily: "'JetBrains Mono', monospace",
                                  }}
                                >
                                  <span>{label}</span>
                                  <span style={{ color }}>{val}</span>
                                </div>
                                <div
                                  className="h-2 rounded-full overflow-hidden"
                                  style={{ background: "var(--bg-border)" }}
                                >
                                  <motion.div
                                    className="h-full rounded-full"
                                    initial={{ width: 0 }}
                                    animate={{ width: `${val}%` }}
                                    transition={{
                                      duration: 1,
                                      ease: "easeOut",
                                      delay,
                                    }}
                                    style={{
                                      background: color,
                                      boxShadow: `0 0 6px ${color}80`,
                                    }}
                                  />
                                </div>
                              </div>
                            ))}
                          </div>
                          <p
                            className="text-xs mt-3"
                            style={{
                              color: "var(--text-muted)",
                              fontFamily: "'JetBrains Mono', monospace",
                            }}
                          >
                            Final = Neural Net (45%) + Rule Engine (55%) blended
                          </p>
                        </div>
                      )}

                      {/* ── DETECTED ISSUES ── */}
                      {result.issues.length > 0 && (
                        <div
                          className="px-6 py-5 border-b"
                          style={{ borderColor: "var(--bg-border)" }}
                        >
                          <div className="flex items-center gap-2 mb-4">
                            <AlertTriangle
                              className="size-4"
                              style={{ color: "#f5a623" }}
                            />
                            <span
                              className="text-xs font-bold uppercase tracking-wider"
                              style={{
                                color: "var(--text-secondary)",
                                fontFamily: "'JetBrains Mono', monospace",
                              }}
                            >
                              Detected Issues ({result.issues.length})
                            </span>
                          </div>
                          <div className="space-y-2">
                            {result.issues.map((issue, i) => {
                              const isCritical =
                                /otp|impersonat|spoof|credential|corporate_phishing|conversation_hijacking|homograph/i.test(
                                  issue,
                                );
                              const isHigh =
                                /brand|typosquatting|redirect|punycode|low_and_slow|defanged/i.test(
                                  issue,
                                );
                              const dotColor = isCritical
                                ? "#ff4444"
                                : isHigh
                                  ? "#f97316"
                                  : "#f5a623";
                              return (
                                <motion.div
                                  key={i}
                                  initial={{ opacity: 0, x: -8 }}
                                  animate={{ opacity: 1, x: 0 }}
                                  transition={{ delay: 0.4 + i * 0.06 }}
                                  className="flex items-start gap-3 rounded-xl px-4 py-3 text-sm"
                                  style={{
                                    background: "var(--bg-elevated)",
                                    border: `1px solid ${dotColor}20`,
                                  }}
                                >
                                  <div
                                    className="w-2 h-2 rounded-full flex-shrink-0 mt-1.5"
                                    style={{
                                      background: dotColor,
                                      boxShadow: `0 0 6px ${dotColor}80`,
                                    }}
                                  />
                                  <span
                                    style={{ color: "var(--text-secondary)" }}
                                  >
                                    {issue}
                                  </span>
                                </motion.div>
                              );
                            })}
                          </div>
                        </div>
                      )}

                      {/* ── Email Origin Intelligence (geo panel) ── */}
                      {(result as any)?.sourceGeo &&
                        (result as any).sourceGeo.country && (
                          <div
                            className="px-6 py-4 border-t"
                            style={{ borderColor: "rgba(255,255,255,0.06)" }}
                          >
                            <div
                              className="text-xs font-bold mb-3"
                              style={{
                                color: "var(--text-muted)",
                                fontFamily: "var(--font-mono)",
                                textTransform: "uppercase",
                                letterSpacing: "0.08em",
                              }}
                            >
                              📍 Email Origin Intelligence
                            </div>
                            <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
                              {/* Location */}
                              <div
                                className="px-3 py-2.5 rounded-xl"
                                style={{
                                  background: "var(--bg-elevated)",
                                  border: "1px solid var(--bg-border)",
                                }}
                              >
                                <div
                                  className="text-[10px] mb-1"
                                  style={{
                                    color: "var(--text-muted)",
                                    fontFamily: "var(--font-mono)",
                                    textTransform: "uppercase",
                                  }}
                                >
                                  Origin Location
                                </div>
                                <div
                                  className="text-sm font-semibold"
                                  style={{ color: "var(--text-primary)" }}
                                >
                                  {[
                                    (result as any).sourceGeo.city,
                                    (result as any).sourceGeo.region,
                                    (result as any).sourceGeo.country,
                                  ]
                                    .filter(Boolean)
                                    .join(", ")}
                                </div>
                              </div>

                              {/* ISP/Org */}
                              <div
                                className="px-3 py-2.5 rounded-xl"
                                style={{
                                  background: "var(--bg-elevated)",
                                  border: "1px solid var(--bg-border)",
                                }}
                              >
                                <div
                                  className="text-[10px] mb-1"
                                  style={{
                                    color: "var(--text-muted)",
                                    fontFamily: "var(--font-mono)",
                                    textTransform: "uppercase",
                                  }}
                                >
                                  ISP / Network
                                </div>
                                <div
                                  className="text-sm font-semibold truncate"
                                  style={{ color: "var(--text-primary)" }}
                                >
                                  {(result as any).sourceGeo.isp ||
                                    (result as any).sourceGeo.org ||
                                    "Unknown"}
                                </div>
                                <div
                                  className="text-[10px] mt-0.5"
                                  style={{
                                    color: "var(--text-muted)",
                                    fontFamily: "var(--font-mono)",
                                  }}
                                >
                                  {(result as any).sourceGeo.asn}
                                </div>
                              </div>

                              {/* IP Type */}
                              <div
                                className="px-3 py-2.5 rounded-xl"
                                style={{
                                  background: (result as any).sourceGeo.isTor
                                    ? "rgba(248,113,113,0.08)"
                                    : (result as any).sourceGeo.isVPN
                                      ? "rgba(251,191,36,0.08)"
                                      : (result as any).sourceGeo.isDatacenter
                                        ? "rgba(251,146,60,0.08)"
                                        : "var(--bg-elevated)",
                                  border: `1px solid ${
                                    (result as any).sourceGeo.isTor
                                      ? "rgba(248,113,113,0.25)"
                                      : (result as any).sourceGeo.isVPN
                                        ? "rgba(251,191,36,0.25)"
                                        : (result as any).sourceGeo.isDatacenter
                                          ? "rgba(251,146,60,0.25)"
                                          : "var(--bg-border)"
                                  }`,
                                }}
                              >
                                <div
                                  className="text-[10px] mb-1"
                                  style={{
                                    color: "var(--text-muted)",
                                    fontFamily: "var(--font-mono)",
                                    textTransform: "uppercase",
                                  }}
                                >
                                  Connection Type
                                </div>
                                <div
                                  className="text-sm font-bold"
                                  style={{
                                    color: (result as any).sourceGeo.isTor
                                      ? "#f87171"
                                      : (result as any).sourceGeo.isVPN
                                        ? "#fbbf24"
                                        : (result as any).sourceGeo.isDatacenter
                                          ? "#fb923c"
                                          : "var(--safe)",
                                  }}
                                >
                                  {(result as any).sourceGeo.isTor
                                    ? "🔴 TOR Exit Node"
                                    : (result as any).sourceGeo.isVPN
                                      ? "🟡 VPN Detected"
                                      : (result as any).sourceGeo.isDatacenter
                                        ? "🟠 Datacenter / Hosting"
                                        : (result as any).sourceGeo.isMobile
                                          ? "📱 Mobile Network"
                                          : "🟢 Residential"}
                                </div>
                              </div>

                              {/* Source IP */}
                              <div
                                className="px-3 py-2.5 rounded-xl"
                                style={{
                                  background: "var(--bg-elevated)",
                                  border: "1px solid var(--bg-border)",
                                }}
                              >
                                <div
                                  className="text-[10px] mb-1"
                                  style={{
                                    color: "var(--text-muted)",
                                    fontFamily: "var(--font-mono)",
                                    textTransform: "uppercase",
                                  }}
                                >
                                  Source IP
                                </div>
                                <div
                                  className="text-sm font-semibold"
                                  style={{
                                    color: "var(--accent)",
                                    fontFamily: "var(--font-mono)",
                                  }}
                                >
                                  {(result as any).sourceIP || "Not found"}
                                </div>
                              </div>

                              {/* Attribution Confidence */}
                              <div
                                className="px-3 py-2.5 rounded-xl"
                                style={{
                                  background: "var(--bg-elevated)",
                                  border: "1px solid var(--bg-border)",
                                }}
                              >
                                <div
                                  className="text-[10px] mb-1"
                                  style={{
                                    color: "var(--text-muted)",
                                    fontFamily: "var(--font-mono)",
                                    textTransform: "uppercase",
                                  }}
                                >
                                  Attribution Confidence
                                </div>
                                <div
                                  className="text-sm font-bold"
                                  style={{
                                    color:
                                      ((result as any).attributionConfidence ||
                                        0) >= 60
                                        ? "var(--safe)"
                                        : ((result as any)
                                              .attributionConfidence || 0) >= 30
                                          ? "#fbbf24"
                                          : "#f87171",
                                  }}
                                >
                                  {(result as any).attributionConfidence ?? 0}%
                                </div>
                                <div
                                  className="text-[10px] mt-0.5"
                                  style={{ color: "var(--text-muted)" }}
                                >
                                  {(result as any).sourceGeo.isTor
                                    ? "TOR — nearly untraceable"
                                    : (result as any).sourceGeo.isVPN
                                      ? "VPN — difficult to attribute"
                                      : (result as any).sourceGeo.isDatacenter
                                        ? "Datacenter — subpoena hosting provider"
                                        : "Geolocation reliable"}
                                </div>
                              </div>

                              {/* Abuse Risk */}
                              <div
                                className="px-3 py-2.5 rounded-xl"
                                style={{
                                  background: "var(--bg-elevated)",
                                  border: "1px solid var(--bg-border)",
                                }}
                              >
                                <div
                                  className="text-[10px] mb-1"
                                  style={{
                                    color: "var(--text-muted)",
                                    fontFamily: "var(--font-mono)",
                                    textTransform: "uppercase",
                                  }}
                                >
                                  Abuse Risk
                                </div>
                                <div
                                  className="text-sm font-bold capitalize"
                                  style={{
                                    color:
                                      (result as any).sourceGeo.abuseRisk ===
                                      "critical"
                                        ? "#f87171"
                                        : (result as any).sourceGeo
                                              .abuseRisk === "high"
                                          ? "#fb923c"
                                          : (result as any).sourceGeo
                                                .abuseRisk === "medium"
                                            ? "#fbbf24"
                                            : "var(--safe)",
                                  }}
                                >
                                  {(result as any).sourceGeo.abuseRisk || "Low"}
                                </div>
                              </div>
                            </div>
                          </div>
                        )}

                      {/* ── IP Reputation Panel (DNSBL / TOR / Botnet / VPN) ── */}
                      {(result as any)?.ipReputation &&
                        (result as any).ipReputation.verdict !== "clean" && (
                          <div
                            className="px-6 py-4 border-t"
                            style={{ borderColor: "rgba(255,255,255,0.06)" }}
                          >
                            <div
                              className="text-xs font-bold mb-3"
                              style={{
                                color: "var(--text-muted)",
                                fontFamily: "var(--font-mono)",
                                textTransform: "uppercase",
                                letterSpacing: "0.08em",
                              }}
                            >
                              🛡️ IP Reputation —{" "}
                              {(result as any).ipReputation.ip}
                            </div>

                            {/* Verdict banner */}
                            <div
                              className="flex items-center gap-3 px-4 py-3 rounded-xl mb-3"
                              style={{
                                background:
                                  (result as any).ipReputation.verdict ===
                                  "malicious"
                                    ? "rgba(248,113,113,0.08)"
                                    : "rgba(251,191,36,0.08)",
                                border: `1px solid ${
                                  (result as any).ipReputation.verdict ===
                                  "malicious"
                                    ? "rgba(248,113,113,0.25)"
                                    : "rgba(251,191,36,0.25)"
                                }`,
                              }}
                            >
                              <div
                                className="text-2xl font-black"
                                style={{
                                  color:
                                    (result as any).ipReputation.verdict ===
                                    "malicious"
                                      ? "#f87171"
                                      : "#fbbf24",
                                  fontFamily: "var(--font-mono)",
                                }}
                              >
                                {(result as any).ipReputation.reputationScore}
                                /100
                              </div>
                              <div>
                                <div
                                  className="font-bold text-sm"
                                  style={{
                                    color:
                                      (result as any).ipReputation.verdict ===
                                      "malicious"
                                        ? "#f87171"
                                        : "#fbbf24",
                                  }}
                                >
                                  {(result as any).ipReputation.threatLabel ||
                                    (
                                      result as any
                                    ).ipReputation.verdict.toUpperCase()}
                                </div>
                                {(result as any).ipReputation.seenInScans >
                                  1 && (
                                  <div
                                    className="text-xs mt-0.5"
                                    style={{ color: "var(--text-muted)" }}
                                  >
                                    Seen{" "}
                                    {(result as any).ipReputation.seenInScans}×
                                    in PhishNetra scans
                                    {(result as any).ipReputation.firstSeenAt &&
                                      ` · First: ${new Date((result as any).ipReputation.firstSeenAt).toLocaleDateString()}`}
                                  </div>
                                )}
                              </div>
                            </div>

                            {/* DNSBL hits */}
                            {(result as any).ipReputation.dnsblHits?.length >
                              0 && (
                              <div className="space-y-1.5">
                                <div
                                  className="text-[10px] font-bold mb-1"
                                  style={{
                                    color: "var(--text-muted)",
                                    fontFamily: "var(--font-mono)",
                                    textTransform: "uppercase",
                                  }}
                                >
                                  Blacklist Hits (
                                  {
                                    (result as any).ipReputation.dnsblHits
                                      .length
                                  }
                                  )
                                </div>
                                {(result as any).ipReputation.dnsblHits.map(
                                  (hit: any, i: number) => (
                                    <div
                                      key={i}
                                      className="flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs"
                                      style={{
                                        background: "var(--bg-elevated)",
                                        border: "1px solid var(--bg-border)",
                                      }}
                                    >
                                      <span
                                        className="font-semibold flex-shrink-0"
                                        style={{
                                          color:
                                            hit.score >= 70
                                              ? "#f87171"
                                              : "#fbbf24",
                                          fontFamily: "var(--font-mono)",
                                        }}
                                      >
                                        {hit.list}
                                      </span>
                                      <span
                                        style={{ color: "var(--text-muted)" }}
                                      >
                                        {hit.meaning}
                                      </span>
                                      <span
                                        className="ml-auto text-[9px] px-1.5 py-0.5 rounded flex-shrink-0"
                                        style={{
                                          color:
                                            hit.score >= 70
                                              ? "#f87171"
                                              : "#fbbf24",
                                          background:
                                            hit.score >= 70
                                              ? "rgba(248,113,113,0.1)"
                                              : "rgba(251,191,36,0.1)",
                                          fontFamily: "var(--font-mono)",
                                        }}
                                      >
                                        score {hit.score}
                                      </span>
                                    </div>
                                  ),
                                )}
                              </div>
                            )}
                          </div>
                        )}

                      {(result as any)?.relayChain?.length > 0 && (
                        <div
                          className="px-6 py-4 border-t"
                          style={{ borderColor: "rgba(255,255,255,0.06)" }}
                        >
                          <div
                            className="text-xs font-bold mb-3"
                            style={{
                              color: "var(--text-muted)",
                              fontFamily: "var(--font-mono)",
                              textTransform: "uppercase",
                              letterSpacing: "0.08em",
                            }}
                          >
                            📡 SMTP Relay Chain —{" "}
                            {(result as any).relayChain.length} hop
                            {(result as any).relayChain.length !== 1 ? "s" : ""}
                            {(result as any).relayAnomalies?.length > 0 && (
                              <span
                                className="ml-2 text-[10px] px-2 py-0.5 rounded"
                                style={{
                                  color: "#f87171",
                                  background: "rgba(248,113,113,0.1)",
                                  border: "1px solid rgba(248,113,113,0.2)",
                                }}
                              >
                                {(result as any).relayAnomalies.length} anomal
                                {(result as any).relayAnomalies.length !== 1
                                  ? "ies"
                                  : "y"}{" "}
                                detected
                              </span>
                            )}
                          </div>

                          {/* Relay timeline — horizontal chain */}
                          <div className="flex items-center gap-0 overflow-x-auto pb-2 mb-4">
                            {(result as any).relayChain.map(
                              (hop: any, i: number) => {
                                const hasAnomaly = hop.anomalies?.length > 0;
                                const isFirst = i === 0;
                                const isLast =
                                  i === (result as any).relayChain.length - 1;
                                return (
                                  <div
                                    key={i}
                                    className="flex items-center flex-shrink-0"
                                  >
                                    {/* Hop node */}
                                    <div
                                      className="flex flex-col items-center"
                                      style={{ minWidth: 120 }}
                                    >
                                      {/* Node circle */}
                                      <div
                                        className="w-8 h-8 rounded-full flex items-center justify-center text-xs font-bold mb-1.5"
                                        style={{
                                          background: hasAnomaly
                                            ? "rgba(248,113,113,0.15)"
                                            : isFirst
                                              ? "rgba(96,165,250,0.15)"
                                              : isLast
                                                ? "rgba(52,211,153,0.15)"
                                                : "var(--bg-elevated)",
                                          border: `2px solid ${
                                            hasAnomaly
                                              ? "#f87171"
                                              : isFirst
                                                ? "#60a5fa"
                                                : isLast
                                                  ? "#34d399"
                                                  : "var(--bg-border)"
                                          }`,
                                          color: hasAnomaly
                                            ? "#f87171"
                                            : isFirst
                                              ? "#60a5fa"
                                              : isLast
                                                ? "#34d399"
                                                : "var(--text-muted)",
                                        }}
                                      >
                                        {i + 1}
                                      </div>

                                      {/* Hop label */}
                                      <div
                                        className="text-center"
                                        style={{ maxWidth: 110 }}
                                      >
                                        <div
                                          className="text-[10px] font-semibold truncate"
                                          style={{
                                            color: hasAnomaly
                                              ? "#f87171"
                                              : "var(--text-secondary)",
                                            fontFamily: "var(--font-mono)",
                                          }}
                                        >
                                          {hop.fromHost?.length > 16
                                            ? hop.fromHost.substring(0, 14) +
                                              "…"
                                            : hop.fromHost ||
                                              hop.fromIP ||
                                              "unknown"}
                                        </div>
                                        {hop.fromIP &&
                                          hop.fromIP !== hop.fromHost && (
                                            <div
                                              className="text-[9px]"
                                              style={{
                                                color: "var(--text-muted)",
                                                fontFamily: "var(--font-mono)",
                                              }}
                                            >
                                              {hop.fromIP}
                                            </div>
                                          )}
                                        {hop.protocol && (
                                          <div
                                            className="text-[9px] mt-0.5 px-1.5 rounded"
                                            style={{
                                              color: "var(--accent)",
                                              background:
                                                "var(--accent-subtle)",
                                              display: "inline-block",
                                              fontFamily: "var(--font-mono)",
                                            }}
                                          >
                                            {hop.protocol}
                                          </div>
                                        )}
                                        {hop.delayFormatted && i > 0 && (
                                          <div
                                            className="text-[9px] mt-0.5"
                                            style={{
                                              color:
                                                hop.delayMs < 0
                                                  ? "#f87171"
                                                  : hop.delayMs > 7200000
                                                    ? "#fbbf24"
                                                    : "var(--text-muted)",
                                            }}
                                          >
                                            +{hop.delayFormatted}
                                          </div>
                                        )}
                                        {hasAnomaly && (
                                          <div
                                            className="text-[9px] mt-0.5"
                                            style={{ color: "#f87171" }}
                                          >
                                            ⚠ {hop.anomalies[0].label}
                                          </div>
                                        )}
                                      </div>
                                    </div>

                                    {/* Arrow connector */}
                                    {i <
                                      (result as any).relayChain.length - 1 && (
                                      <div
                                        className="flex-shrink-0 mx-1 text-xs"
                                        style={{ color: "var(--text-muted)" }}
                                      >
                                        →
                                      </div>
                                    )}
                                  </div>
                                );
                              },
                            )}
                          </div>

                          {/* Relay anomaly details */}
                          {(result as any).relayAnomalies?.length > 0 && (
                            <div className="space-y-1.5">
                              {(result as any).relayAnomalies.map(
                                (anomaly: any, i: number) => (
                                  <div
                                    key={i}
                                    className="flex items-start gap-2 px-3 py-2 rounded-xl text-xs"
                                    style={{
                                      background: "rgba(248,113,113,0.06)",
                                      border:
                                        "1px solid rgba(248,113,113,0.15)",
                                    }}
                                  >
                                    <span
                                      style={{
                                        color: "#f87171",
                                        flex: "0 0 auto",
                                      }}
                                    >
                                      ⚠
                                    </span>
                                    <div>
                                      <span
                                        className="font-semibold"
                                        style={{ color: "#f87171" }}
                                      >
                                        {anomaly.label}:{" "}
                                      </span>
                                      <span
                                        style={{ color: "var(--text-muted)" }}
                                      >
                                        {anomaly.detail}
                                      </span>
                                    </div>
                                    <span
                                      className="ml-auto flex-shrink-0 text-[9px] px-1.5 py-0.5 rounded"
                                      style={{
                                        color: "#f87171",
                                        background: "rgba(248,113,113,0.1)",
                                        fontFamily: "var(--font-mono)",
                                      }}
                                    >
                                      +{anomaly.risk} risk
                                    </span>
                                  </div>
                                ),
                              )}
                            </div>
                          )}
                        </div>
                      )}

                      {result?.domainIntel && (
                        <div
                          className="px-6 py-4 border-t"
                          style={{ borderColor: "rgba(255,255,255,0.06)" }}
                        >
                          <div
                            className="text-xs font-bold mb-3"
                            style={{
                              color: "var(--text-muted)",
                              fontFamily: "var(--font-mono)",
                              textTransform: "uppercase",
                              letterSpacing: "0.08em",
                            }}
                          >
                            🌐 Sender Domain Intelligence —{" "}
                            {result.domainIntel.domain}
                            {result.domainIntel.domainAnomalies?.length > 0 && (
                              <span
                                className="ml-2 text-[10px] px-2 py-0.5 rounded"
                                style={{
                                  color: "#f87171",
                                  background: "rgba(248,113,113,0.1)",
                                  border: "1px solid rgba(248,113,113,0.2)",
                                }}
                              >
                                {result.domainIntel.domainAnomalies.length}{" "}
                                anomal
                                {result.domainIntel.domainAnomalies.length !== 1
                                  ? "ies"
                                  : "y"}
                              </span>
                            )}
                          </div>

                          {/* Domain stats grid */}
                          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-4">
                            {/* MX Records */}
                            <div
                              className="px-3 py-2.5 rounded-xl"
                              style={{
                                background: result.domainIntel.hasMX
                                  ? "var(--bg-elevated)"
                                  : "rgba(248,113,113,0.07)",
                                border: `1px solid ${result.domainIntel.hasMX ? "var(--bg-border)" : "rgba(248,113,113,0.25)"}`,
                              }}
                            >
                              <div
                                className="text-[10px] mb-1"
                                style={{
                                  color: "var(--text-muted)",
                                  fontFamily: "var(--font-mono)",
                                  textTransform: "uppercase",
                                }}
                              >
                                MX Records
                              </div>
                              <div
                                className="text-sm font-bold"
                                style={{
                                  color: result.domainIntel.hasMX
                                    ? "var(--safe)"
                                    : "#f87171",
                                }}
                              >
                                {result.domainIntel.hasMX
                                  ? `✓ ${result.domainIntel.mxRecords.length} record${result.domainIntel.mxRecords.length > 1 ? "s" : ""}`
                                  : "✗ None"}
                              </div>
                              {result.domainIntel.mxProvider && (
                                <div
                                  className="text-[10px] mt-0.5"
                                  style={{ color: "var(--text-muted)" }}
                                >
                                  via {result.domainIntel.mxProvider}
                                </div>
                              )}
                            </div>

                            {/* NS / Registrar */}
                            <div
                              className="px-3 py-2.5 rounded-xl"
                              style={{
                                background: result.domainIntel.isFreenomDomain
                                  ? "rgba(248,113,113,0.07)"
                                  : "var(--bg-elevated)",
                                border: `1px solid ${result.domainIntel.isFreenomDomain ? "rgba(248,113,113,0.25)" : "var(--bg-border)"}`,
                              }}
                            >
                              <div
                                className="text-[10px] mb-1"
                                style={{
                                  color: "var(--text-muted)",
                                  fontFamily: "var(--font-mono)",
                                  textTransform: "uppercase",
                                }}
                              >
                                Registrar
                              </div>
                              <div
                                className="text-sm font-bold"
                                style={{
                                  color: result.domainIntel.isFreenomDomain
                                    ? "#f87171"
                                    : "var(--text-primary)",
                                }}
                              >
                                {result.domainIntel.registrarHint ||
                                  (result.domainIntel.hasNS
                                    ? "Unknown registrar"
                                    : "✗ Not configured")}
                              </div>
                              <div
                                className="text-[10px] mt-0.5"
                                style={{ color: "var(--text-muted)" }}
                              >
                                {result.domainIntel.nsRecords?.[0] ||
                                  "No NS found"}
                              </div>
                            </div>

                            {/* TLD Risk */}
                            <div
                              className="px-3 py-2.5 rounded-xl"
                              style={{
                                background: result.domainIntel.isHighRiskTLD
                                  ? "rgba(251,146,60,0.07)"
                                  : "var(--bg-elevated)",
                                border: `1px solid ${result.domainIntel.isHighRiskTLD ? "rgba(251,146,60,0.25)" : "var(--bg-border)"}`,
                              }}
                            >
                              <div
                                className="text-[10px] mb-1"
                                style={{
                                  color: "var(--text-muted)",
                                  fontFamily: "var(--font-mono)",
                                  textTransform: "uppercase",
                                }}
                              >
                                TLD Risk
                              </div>
                              <div
                                className="text-sm font-bold"
                                style={{
                                  color: result.domainIntel.isHighRiskTLD
                                    ? "#fb923c"
                                    : "var(--safe)",
                                }}
                              >
                                {result.domainIntel.tld}
                                {result.domainIntel.isHighRiskTLD &&
                                  ` — ${result.domainIntel.tldRisk}/100`}
                              </div>
                              <div
                                className="text-[10px] mt-0.5"
                                style={{
                                  color: result.domainIntel.isFreeTLD
                                    ? "#f87171"
                                    : "var(--text-muted)",
                                }}
                              >
                                {result.domainIntel.isFreeTLD
                                  ? "Free TLD — disposable"
                                  : result.domainIntel.isHighRiskTLD
                                    ? "High-abuse TLD"
                                    : "Standard TLD"}
                              </div>
                            </div>

                            {/* Lookalike */}
                            <div
                              className="px-3 py-2.5 rounded-xl"
                              style={{
                                background: result.domainIntel.lookalikeBrand
                                  ? "rgba(248,113,113,0.07)"
                                  : "var(--bg-elevated)",
                                border: `1px solid ${result.domainIntel.lookalikeBrand ? "rgba(248,113,113,0.25)" : "var(--bg-border)"}`,
                              }}
                            >
                              <div
                                className="text-[10px] mb-1"
                                style={{
                                  color: "var(--text-muted)",
                                  fontFamily: "var(--font-mono)",
                                  textTransform: "uppercase",
                                }}
                              >
                                Brand Lookalike
                              </div>
                              <div
                                className="text-sm font-bold"
                                style={{
                                  color: result.domainIntel.lookalikeBrand
                                    ? "#f87171"
                                    : "var(--safe)",
                                }}
                              >
                                {result.domainIntel.lookalikeBrand
                                  ? `⚠ ${result.domainIntel.lookalikeBrand}`
                                  : "✓ No match"}
                              </div>
                              {result.domainIntel.lookalikeTechnique && (
                                <div
                                  className="text-[10px] mt-0.5"
                                  style={{ color: "#f87171" }}
                                >
                                  {result.domainIntel.lookalikeTechnique.replace(
                                    /_/g,
                                    " ",
                                  )}
                                </div>
                              )}
                            </div>
                          </div>

                          {/* Domain anomaly details */}
                          {result.domainIntel.domainAnomalies?.length > 0 && (
                            <div className="space-y-1.5">
                              {result.domainIntel.domainAnomalies.map(
                                (anomaly: any, i: number) => (
                                  <div
                                    key={i}
                                    className="flex items-start gap-2 px-3 py-2 rounded-xl text-xs"
                                    style={{
                                      background: "rgba(251,146,60,0.05)",
                                      border: "1px solid rgba(251,146,60,0.15)",
                                    }}
                                  >
                                    <span
                                      style={{
                                        color: "#fb923c",
                                        flex: "0 0 auto",
                                      }}
                                    >
                                      ●
                                    </span>
                                    <div>
                                      <span
                                        className="font-semibold"
                                        style={{ color: "#fb923c" }}
                                      >
                                        {anomaly.label}:{" "}
                                      </span>
                                      <span
                                        style={{ color: "var(--text-muted)" }}
                                      >
                                        {anomaly.detail}
                                      </span>
                                    </div>
                                    <span
                                      className="ml-auto flex-shrink-0 text-[9px] px-1.5 py-0.5 rounded"
                                      style={{
                                        color: "#fb923c",
                                        background: "rgba(251,146,60,0.1)",
                                        fontFamily: "var(--font-mono)",
                                      }}
                                    >
                                      +{anomaly.risk} risk
                                    </span>
                                  </div>
                                ),
                              )}
                            </div>
                          )}
                        </div>
                      )}

                      {/* ── GAP 5: Mail Infrastructure Validation Panel ── */}
                      {result?.mxValidation && (
                        <div
                          className="px-6 py-4 border-t"
                          style={{ borderColor: "rgba(255,255,255,0.06)" }}
                        >
                          <div
                            className="text-xs font-bold mb-3"
                            style={{
                              color: "var(--text-muted)",
                              fontFamily: "var(--font-mono)",
                              textTransform: "uppercase",
                              letterSpacing: "0.08em",
                            }}
                          >
                            📬 Mail Infrastructure Validation —{" "}
                            {result.mxValidation.domain}
                            {result.mxValidation.infrastructureAnomaly && (
                              <span
                                className="ml-2 text-[10px] px-2 py-0.5 rounded"
                                style={{
                                  color: "#f87171",
                                  background: "rgba(248,113,113,0.1)",
                                  border: "1px solid rgba(248,113,113,0.2)",
                                }}
                              >
                                {result.mxValidation.anomalies.length} anomal
                                {result.mxValidation.anomalies.length !== 1
                                  ? "ies"
                                  : "y"}
                              </span>
                            )}
                          </div>

                          {/* MX / SPF status row */}
                          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-4">
                            {/* MX Records */}
                            <div
                              className="px-3 py-2.5 rounded-xl"
                              style={{
                                background: result.mxValidation.hasMX
                                  ? "var(--bg-elevated)"
                                  : "rgba(248,113,113,0.07)",
                                border: `1px solid ${
                                  result.mxValidation.hasMX
                                    ? "var(--bg-border)"
                                    : "rgba(248,113,113,0.25)"
                                }`,
                              }}
                            >
                              <div
                                className="text-[10px] mb-1"
                                style={{
                                  color: "var(--text-muted)",
                                  fontFamily: "var(--font-mono)",
                                  textTransform: "uppercase",
                                }}
                              >
                                MX Records
                              </div>
                              <div
                                className="text-sm font-bold"
                                style={{
                                  color: result.mxValidation.hasMX
                                    ? "var(--safe)"
                                    : "#f87171",
                                }}
                              >
                                {result.mxValidation.hasMX
                                  ? `✓ ${result.mxValidation.mxRecords.length} found`
                                  : "✗ None"}
                              </div>
                              <div
                                className="text-[10px] mt-0.5 truncate"
                                style={{ color: "var(--text-muted)" }}
                              >
                                {result.mxValidation.mxRecords[0] || "—"}
                              </div>
                            </div>

                            {/* Mail Provider */}
                            <div
                              className="px-3 py-2.5 rounded-xl"
                              style={{
                                background:
                                  result.mxValidation.mxProviderTier ===
                                  "consumer"
                                    ? "rgba(251,191,36,0.07)"
                                    : "var(--bg-elevated)",
                                border: `1px solid ${
                                  result.mxValidation.mxProviderTier ===
                                  "consumer"
                                    ? "rgba(251,191,36,0.25)"
                                    : "var(--bg-border)"
                                }`,
                              }}
                            >
                              <div
                                className="text-[10px] mb-1"
                                style={{
                                  color: "var(--text-muted)",
                                  fontFamily: "var(--font-mono)",
                                  textTransform: "uppercase",
                                }}
                              >
                                Mail Platform
                              </div>
                              <div
                                className="text-sm font-bold"
                                style={{
                                  color:
                                    result.mxValidation.mxProviderTier ===
                                    "consumer"
                                      ? "#fbbf24"
                                      : "var(--text-primary)",
                                }}
                              >
                                {result.mxValidation.mxProvider}
                              </div>
                              <div
                                className="text-[10px] mt-0.5 capitalize"
                                style={{
                                  color:
                                    result.mxValidation.mxProviderTier ===
                                    "consumer"
                                      ? "#fbbf24"
                                      : "var(--text-muted)",
                                }}
                              >
                                {result.mxValidation.mxProviderTier}
                                {result.mxValidation.mxProviderTier ===
                                  "consumer" && " ⚠"}
                              </div>
                            </div>

                            {/* Live SPF Result */}
                            <div
                              className="px-3 py-2.5 rounded-xl"
                              style={{
                                background:
                                  result.mxValidation.spfLiveResult === "fail"
                                    ? "rgba(248,113,113,0.07)"
                                    : result.mxValidation.spfLiveResult ===
                                        "pass"
                                      ? "rgba(52,211,153,0.07)"
                                      : "rgba(251,191,36,0.07)",
                                border: `1px solid ${
                                  result.mxValidation.spfLiveResult === "fail"
                                    ? "rgba(248,113,113,0.25)"
                                    : result.mxValidation.spfLiveResult ===
                                        "pass"
                                      ? "rgba(52,211,153,0.25)"
                                      : "rgba(251,191,36,0.25)"
                                }`,
                              }}
                            >
                              <div
                                className="text-[10px] mb-1"
                                style={{
                                  color: "var(--text-muted)",
                                  fontFamily: "var(--font-mono)",
                                  textTransform: "uppercase",
                                }}
                              >
                                Live SPF Check
                              </div>
                              <div
                                className="text-sm font-bold uppercase"
                                style={{
                                  color:
                                    result.mxValidation.spfLiveResult === "fail"
                                      ? "#f87171"
                                      : result.mxValidation.spfLiveResult ===
                                          "pass"
                                        ? "var(--safe)"
                                        : result.mxValidation.spfLiveResult ===
                                            "softfail"
                                          ? "#fbbf24"
                                          : "var(--text-muted)",
                                }}
                              >
                                {result.mxValidation.spfLiveResult || "unknown"}
                              </div>
                              <div
                                className="text-[10px] mt-0.5"
                                style={{ color: "var(--text-muted)" }}
                              >
                                Real-time DNS validation
                              </div>
                            </div>

                            {/* MX Route Match */}
                            <div
                              className="px-3 py-2.5 rounded-xl"
                              style={{
                                background: result.mxValidation.mxMismatch
                                  ? "rgba(248,113,113,0.07)"
                                  : "rgba(52,211,153,0.07)",
                                border: `1px solid ${
                                  result.mxValidation.mxMismatch
                                    ? "rgba(248,113,113,0.25)"
                                    : "rgba(52,211,153,0.25)"
                                }`,
                              }}
                            >
                              <div
                                className="text-[10px] mb-1"
                                style={{
                                  color: "var(--text-muted)",
                                  fontFamily: "var(--font-mono)",
                                  textTransform: "uppercase",
                                }}
                              >
                                MX Route Match
                              </div>
                              <div
                                className="text-sm font-bold"
                                style={{
                                  color: result.mxValidation.mxMismatch
                                    ? "#f87171"
                                    : "var(--safe)",
                                }}
                              >
                                {result.mxValidation.mxMismatch
                                  ? "✗ Mismatch"
                                  : "✓ Matches"}
                              </div>
                              <div
                                className="text-[10px] mt-0.5"
                                style={{ color: "var(--text-muted)" }}
                              >
                                {result.mxValidation.mxMismatch
                                  ? "Route bypasses declared MX"
                                  : "Route via declared MX"}
                              </div>
                            </div>
                          </div>

                          {/* SPF record display */}
                          {result.mxValidation.spfRecord && (
                            <div
                              className="px-3 py-2 rounded-xl mb-3 text-[10px] overflow-x-auto"
                              style={{
                                background: "var(--bg-base)",
                                border: "1px solid var(--bg-border)",
                                color: "var(--accent)",
                                fontFamily: "var(--font-mono)",
                                whiteSpace: "nowrap",
                              }}
                            >
                              {result.mxValidation.spfRecord}
                            </div>
                          )}

                          {/* Anomaly details */}
                          {result.mxValidation.anomalies?.length > 0 && (
                            <div className="space-y-1.5">
                              {result.mxValidation.anomalies.map(
                                (anomaly: any, i: number) => (
                                  <div
                                    key={i}
                                    className="flex items-start gap-2 px-3 py-2 rounded-xl text-xs"
                                    style={{
                                      background: "rgba(248,113,113,0.05)",
                                      border:
                                        "1px solid rgba(248,113,113,0.15)",
                                    }}
                                  >
                                    <span
                                      style={{
                                        color: "#f87171",
                                        flex: "0 0 auto",
                                      }}
                                    >
                                      ▸
                                    </span>
                                    <div>
                                      <span
                                        className="font-semibold"
                                        style={{ color: "#f87171" }}
                                      >
                                        {anomaly.label}:{" "}
                                      </span>
                                      <span
                                        style={{ color: "var(--text-muted)" }}
                                      >
                                        {anomaly.detail}
                                      </span>
                                    </div>
                                    <span
                                      className="ml-auto flex-shrink-0 text-[9px] px-1.5 py-0.5 rounded"
                                      style={{
                                        color: "#f87171",
                                        background: "rgba(248,113,113,0.1)",
                                        fontFamily: "var(--font-mono)",
                                      }}
                                    >
                                      +{anomaly.risk} risk
                                    </span>
                                  </div>
                                ),
                              )}
                            </div>
                          )}
                        </div>
                      )}

                      {/* Safe ── */}
                      {result.status === "safe" &&
                        result.issues.length === 0 && (
                          <div
                            className="px-6 py-5 border-b flex items-center gap-3"
                            style={{
                              borderColor: "var(--bg-border)",
                              background: "rgba(0,255,136,0.04)",
                            }}
                          >
                            <CheckCircle
                              className="size-5 flex-shrink-0"
                              style={{ color: "var(--accent-green)" }}
                            />
                            <span
                              className="text-sm"
                              style={{ color: "var(--accent-green)" }}
                            >
                              No threats detected. This URL appears safe to
                              visit.
                            </span>
                          </div>
                        )}

                      {/* SIEM status row */}
                      {siemStatus !== "idle" && (
                        <div
                          className="px-6 py-3 border-b flex items-center gap-2"
                          style={{
                            borderColor: "var(--bg-border)",
                            background:
                              siemStatus === "sent"
                                ? "rgba(0,255,136,0.03)"
                                : siemStatus === "error"
                                  ? "rgba(255,68,68,0.03)"
                                  : "rgba(124,58,237,0.03)",
                          }}
                        >
                          <Shield
                            className="size-3.5 flex-shrink-0"
                            style={{
                              color:
                                siemStatus === "sent"
                                  ? "var(--accent-green)"
                                  : siemStatus === "error"
                                    ? "#ff4444"
                                    : "#a78bfa",
                            }}
                          />
                          <span
                            className="text-xs"
                            style={{
                              color: "var(--text-muted)",
                              fontFamily: "'JetBrains Mono', monospace",
                            }}
                          >
                            {siemStatus === "sending" &&
                              "Sending to SentinelCore SIEM..."}
                            {siemStatus === "sent" &&
                              "✓ Event logged in SentinelCore SIEM"}
                            {siemStatus === "error" &&
                              "SIEM offline — event not logged"}
                          </span>
                          {siemStatus === "sent" && (
                            <button
                              onClick={() => navigate("/siem")}
                              className="ml-auto text-xs px-2 py-0.5 rounded"
                              style={{
                                color: "var(--accent-green)",
                                background: "rgba(0,255,136,0.08)",
                                border: "1px solid rgba(0,255,136,0.2)",
                                fontFamily: "'JetBrains Mono', monospace",
                              }}
                            >
                              View in SIEM →
                            </button>
                          )}
                        </div>
                      )}

                      {/* Actions */}
                      <div className="px-6 py-4 flex flex-col sm:flex-row gap-3">
                        <button
                          onClick={handleReset}
                          className="btn-primary flex-1 flex items-center justify-center gap-2 px-5 py-3 text-sm"
                          style={{
                            fontFamily: "'Syne', sans-serif",
                            fontWeight: 700,
                          }}
                        >
                          <RefreshCw className="size-4" /> Scan Another
                        </button>
                        <button
                          onClick={() => navigate("/history")}
                          className="btn-ghost flex-1 flex items-center justify-center gap-2 px-5 py-3 text-sm"
                          style={{ fontFamily: "'DM Sans', sans-serif" }}
                        >
                          <HistoryIcon className="size-4" /> View History
                        </button>
                        <button
                          onClick={handleDownloadReport}
                          disabled={downloading}
                          className="btn-ghost flex-1 flex items-center justify-center gap-2 px-5 py-3 text-sm"
                          style={{
                            fontFamily: "'DM Sans', sans-serif",
                            borderColor: "rgba(0,212,255,0.3)",
                            color: downloading
                              ? "var(--text-muted)"
                              : "var(--accent-cyan)",
                          }}
                        >
                          {downloading ? (
                            <Activity className="size-4 animate-spin" />
                          ) : (
                            <Download className="size-4" />
                          )}
                          {downloading ? "Generating..." : "PDF Report"}
                        </button>
                      </div>
                    </div>
                  ) : (
                    /* ── NORMAL VIEW — plain English for non-tech users ── */
                    (() => {
                      const nv = buildNormalView(result);
                      const statusEmoji =
                        result.status === "phishing"
                          ? "🚨"
                          : result.status === "suspicious"
                            ? "⚠️"
                            : "✅";
                      const statusLabel =
                        result.status === "phishing"
                          ? "SCAM / FRAUD"
                          : result.status === "suspicious"
                            ? "SUSPICIOUS"
                            : "LOOKS SAFE";
                      return (
                        <div className="space-y-4">
                          {/* Verdict banner */}
                          <div
                            className="rounded-2xl px-6 py-5 flex items-center gap-5"
                            style={{
                              background: c.bg,
                              border: `2px solid ${c.border}`,
                              boxShadow: c.glow,
                            }}
                          >
                            <span
                              className="text-5xl flex-shrink-0"
                              style={{ lineHeight: 1 }}
                            >
                              {statusEmoji}
                            </span>
                            <div className="flex-1">
                              <div
                                className="text-2xl font-black mb-1"
                                style={{
                                  color: c.color,
                                  fontFamily: "var(--font-display)",
                                  letterSpacing: "-0.03em",
                                }}
                              >
                                {statusLabel}
                              </div>
                              <p
                                className="text-sm"
                                style={{
                                  color: "var(--text-secondary)",
                                  lineHeight: 1.6,
                                }}
                              >
                                {nv.whatHappened}
                              </p>
                            </div>
                            {/* Risk meter */}
                            <div className="flex-shrink-0 text-center hidden sm:block">
                              <div
                                className="text-3xl font-black"
                                style={{
                                  color: c.color,
                                  fontFamily: "var(--font-mono)",
                                }}
                              >
                                {result.riskScore}
                              </div>
                              <div
                                className="text-[10px] mt-0.5"
                                style={{
                                  color: "var(--text-muted)",
                                  fontFamily: "var(--font-mono)",
                                }}
                              >
                                RISK SCORE
                              </div>
                              <div
                                className="text-[9px]"
                                style={{ color: "var(--text-muted)" }}
                              >
                                out of 100
                              </div>
                            </div>
                          </div>

                          {/* 4 explanation cards */}
                          <div className="grid md:grid-cols-2 gap-3">
                            {/* WHAT IS IT */}
                            <div
                              className="card p-5"
                              style={{ background: "var(--bg-card)" }}
                            >
                              <div className="flex items-center gap-2 mb-3">
                                <div
                                  className="w-8 h-8 rounded-xl flex items-center justify-center flex-shrink-0"
                                  style={{
                                    background: "rgba(96,165,250,0.1)",
                                    border: "1px solid rgba(96,165,250,0.2)",
                                  }}
                                >
                                  <HelpCircle
                                    className="size-4"
                                    style={{ color: "#60a5fa" }}
                                  />
                                </div>
                                <span
                                  className="text-sm font-bold"
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
                                <strong
                                  style={{ color: "var(--text-primary)" }}
                                >
                                  {nv.whatIs}
                                </strong>
                                . PhishNetra analysed it for signs of scams,
                                fraud, phishing, and dangerous content.
                              </p>
                              {result.sourceGeo?.country &&
                                result.status !== "safe" && (
                                  <div
                                    className="mt-3 px-3 py-2 rounded-lg text-xs"
                                    style={{
                                      background: "var(--bg-elevated)",
                                      border: "1px solid var(--bg-border)",
                                      color: "var(--text-muted)",
                                    }}
                                  >
                                    📍 This appears to originate from{" "}
                                    <strong
                                      style={{ color: "var(--text-secondary)" }}
                                    >
                                      {[
                                        result.sourceGeo.city,
                                        result.sourceGeo.country,
                                      ]
                                        .filter(Boolean)
                                        .join(", ")}
                                    </strong>
                                  </div>
                                )}
                            </div>

                            {/* WHAT HAPPENED */}
                            <div
                              className="card p-5"
                              style={{ background: "var(--bg-card)" }}
                            >
                              <div className="flex items-center gap-2 mb-3">
                                <div
                                  className="w-8 h-8 rounded-xl flex items-center justify-center flex-shrink-0"
                                  style={{
                                    background: `${c.color}15`,
                                    border: `1px solid ${c.color}30`,
                                  }}
                                >
                                  <ShieldAlert
                                    className="size-4"
                                    style={{ color: c.color }}
                                  />
                                </div>
                                <span
                                  className="text-sm font-bold"
                                  style={{ color: c.color }}
                                >
                                  What happened?
                                </span>
                              </div>
                              <p
                                className="text-sm leading-relaxed mb-3"
                                style={{ color: "var(--text-secondary)" }}
                              >
                                {nv.whatHappenedDetail}
                              </p>
                              {nv.simplifiedIssues.length > 0 && (
                                <div className="space-y-2">
                                  {nv.simplifiedIssues
                                    .slice(0, 4)
                                    .map((issue, i) => (
                                      <div
                                        key={i}
                                        className="flex items-start gap-2 text-xs"
                                        style={{
                                          color: "var(--text-secondary)",
                                        }}
                                      >
                                        <span
                                          className="flex-shrink-0 mt-0.5"
                                          style={{
                                            color:
                                              result.status === "safe"
                                                ? "#34d399"
                                                : c.color,
                                          }}
                                        >
                                          {result.status === "safe" ? "✓" : "•"}
                                        </span>
                                        {issue}
                                      </div>
                                    ))}
                                </div>
                              )}
                            </div>

                            {/* WHO DID THIS */}
                            <div
                              className="card p-5"
                              style={{ background: "var(--bg-card)" }}
                            >
                              <div className="flex items-center gap-2 mb-3">
                                <div
                                  className="w-8 h-8 rounded-xl flex items-center justify-center flex-shrink-0"
                                  style={{
                                    background: "rgba(251,146,60,0.1)",
                                    border: "1px solid rgba(251,146,60,0.2)",
                                  }}
                                >
                                  <Fingerprint
                                    className="size-4"
                                    style={{ color: "#fb923c" }}
                                  />
                                </div>
                                <span
                                  className="text-sm font-bold"
                                  style={{ color: "#fb923c" }}
                                >
                                  Who did this?
                                </span>
                              </div>
                              <p
                                className="text-sm font-semibold mb-1.5"
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

                            {/* WHAT TO DO */}
                            <div
                              className="card p-5"
                              style={{ background: "var(--bg-card)" }}
                            >
                              <div className="flex items-center gap-2 mb-3">
                                <div
                                  className="w-8 h-8 rounded-xl flex items-center justify-center flex-shrink-0"
                                  style={{
                                    background: "rgba(52,211,153,0.1)",
                                    border: "1px solid rgba(52,211,153,0.2)",
                                  }}
                                >
                                  <CheckCheck
                                    className="size-4"
                                    style={{ color: "#34d399" }}
                                  />
                                </div>
                                <span
                                  className="text-sm font-bold"
                                  style={{ color: "#34d399" }}
                                >
                                  What should I do?
                                </span>
                              </div>
                              <div className="space-y-2.5">
                                {nv.whatToDo.map((action, i) => (
                                  <div
                                    key={i}
                                    className="flex items-start gap-2.5"
                                  >
                                    <span
                                      className="text-base flex-shrink-0 mt-0.5"
                                      style={{ lineHeight: 1 }}
                                    >
                                      {action.icon}
                                    </span>
                                    <span
                                      className={`text-sm leading-relaxed ${action.bold ? "font-semibold" : ""}`}
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

                          {/* Emergency helpline — only for phishing */}
                          {result.status === "phishing" && (
                            <div
                              className="rounded-2xl px-5 py-4 flex items-center gap-4"
                              style={{
                                background: "rgba(248,113,113,0.06)",
                                border: "2px solid rgba(248,113,113,0.2)",
                              }}
                            >
                              <PhoneCall
                                className="size-8 flex-shrink-0"
                                style={{ color: "#f87171" }}
                              />
                              <div className="flex-1">
                                <div
                                  className="text-sm font-bold mb-0.5"
                                  style={{ color: "#f87171" }}
                                >
                                  Cyber Crime Helpline — Report This Now
                                </div>
                                <div
                                  className="text-sm"
                                  style={{ color: "var(--text-secondary)" }}
                                >
                                  Call{" "}
                                  <strong
                                    style={{ color: "var(--text-primary)" }}
                                  >
                                    1930
                                  </strong>{" "}
                                  (free, 24×7) · Report online at{" "}
                                  <strong
                                    style={{ color: "var(--text-primary)" }}
                                  >
                                    cybercrime.gov.in
                                  </strong>{" "}
                                  · WhatsApp evidence to the helpline
                                </div>
                              </div>
                              <a
                                href="https://cybercrime.gov.in"
                                target="_blank"
                                rel="noreferrer"
                                className="btn-ghost text-xs px-3 py-2 flex-shrink-0"
                                style={{
                                  color: "#f87171",
                                  borderColor: "rgba(248,113,113,0.3)",
                                }}
                              >
                                Report →
                              </a>
                            </div>
                          )}

                          {/* Switch to Expert hint */}
                          <div className="text-center">
                            <button
                              onClick={() => switchMode("expert")}
                              className="text-xs"
                              style={{
                                color: "var(--text-muted)",
                                background: "none",
                                border: "none",
                                cursor: "pointer",
                                fontFamily: "var(--font-mono)",
                              }}
                            >
                              Want the technical details?{" "}
                              <span style={{ color: "var(--accent)" }}>
                                Switch to Expert mode →
                              </span>
                            </button>
                          </div>
                        </div>
                      );
                    })()
                  )}

                  {/* ── Evasion Attempt Detection ── */}
                  {result.evasion?.detected && (
                    <motion.div
                      initial={{ opacity: 0, y: 8 }}
                      animate={{ opacity: 1, y: 0 }}
                      transition={{ delay: 0.51 }}
                      className="rounded-xl overflow-hidden"
                      style={{
                        border: `2px solid ${
                          result.evasion.level === "SOPHISTICATED"
                            ? "rgba(255,68,68,0.4)"
                            : result.evasion.level === "MODERATE"
                              ? "rgba(249,115,22,0.35)"
                              : "rgba(245,166,35,0.3)"
                        }`,
                      }}
                    >
                      {/* Header */}
                      <div
                        className="px-5 py-3 flex items-center gap-2 flex-wrap"
                        style={{
                          background:
                            result.evasion.level === "SOPHISTICATED"
                              ? "rgba(255,68,68,0.09)"
                              : result.evasion.level === "MODERATE"
                                ? "rgba(249,115,22,0.08)"
                                : "rgba(245,166,35,0.07)",
                          borderBottom: "1px solid rgba(30,39,54,0.8)",
                        }}
                      >
                        <span className="text-base">🛡️</span>
                        <span
                          className="text-xs font-bold uppercase tracking-wider"
                          style={{
                            color:
                              result.evasion.level === "SOPHISTICATED"
                                ? "#ff4444"
                                : result.evasion.level === "MODERATE"
                                  ? "#f97316"
                                  : "#f5a623",
                            fontFamily: "'JetBrains Mono', monospace",
                          }}
                        >
                          Evasion Attempt Detected
                        </span>
                        <span
                          className="ml-auto text-xs px-2 py-0.5 rounded font-bold uppercase"
                          style={{
                            color:
                              result.evasion.level === "SOPHISTICATED"
                                ? "#ff4444"
                                : result.evasion.level === "MODERATE"
                                  ? "#f97316"
                                  : "#f5a623",
                            background: "rgba(0,0,0,0.3)",
                            fontFamily: "'JetBrains Mono', monospace",
                          }}
                        >
                          {result.evasion.level}
                        </span>
                      </div>
                      {/* Content */}
                      <div
                        className="px-5 py-4"
                        style={{ background: "var(--bg-card)" }}
                      >
                        <div className="flex items-center gap-4 mb-3">
                          <div>
                            <div
                              className="text-sm font-semibold mb-0.5"
                              style={{
                                color: "var(--text-primary)",
                                fontFamily: "'Syne', sans-serif",
                              }}
                            >
                              {result.evasion.level === "SOPHISTICATED"
                                ? "Attacker is using multiple advanced evasion techniques"
                                : result.evasion.level === "MODERATE"
                                  ? "Multiple evasion signals detected — skilled attacker"
                                  : "Single evasion technique detected — possible evasion attempt"}
                            </div>
                            <div
                              className="text-xs"
                              style={{
                                color: "var(--text-muted)",
                                fontFamily: "'JetBrains Mono', monospace",
                              }}
                            >
                              {result.evasion.signals} evasion signal
                              {result.evasion.signals !== 1 ? "s" : ""} fired ·
                              MITRE T1027 — Obfuscated Files or Information
                            </div>
                          </div>
                        </div>
                        <div className="flex flex-wrap gap-1.5">
                          {result.evasion.techniques.map((tech) => (
                            <span
                              key={tech}
                              className="text-xs px-2 py-0.5 rounded capitalize"
                              style={{
                                color: "var(--text-secondary)",
                                background: "var(--bg-elevated)",
                                border: "1px solid var(--bg-border)",
                                fontFamily: "'JetBrains Mono', monospace",
                              }}
                            >
                              {tech.replace(/_/g, " ")}
                            </span>
                          ))}
                        </div>
                        <p
                          className="text-xs mt-3"
                          style={{
                            color: "var(--text-muted)",
                            fontFamily: "'JetBrains Mono', monospace",
                          }}
                        >
                          ↑ Second-pass evasion detection engine — catches
                          sophisticated attackers who engineer URLs to score
                          just below detection thresholds
                        </p>
                      </div>
                    </motion.div>
                  )}

                  {/* ── Phishing Kit DNA Panel ── */}
                  {result.kitMatch && (
                    <motion.div
                      initial={{ opacity: 0, y: 8 }}
                      animate={{ opacity: 1, y: 0 }}
                      transition={{ delay: 0.54 }}
                      className="rounded-xl overflow-hidden"
                      style={{
                        border: `1px solid ${
                          result.kitMatch.sophistication === "expert"
                            ? "rgba(255,68,68,0.3)"
                            : result.kitMatch.sophistication === "high"
                              ? "rgba(249,115,22,0.3)"
                              : result.kitMatch.sophistication === "medium"
                                ? "rgba(245,166,35,0.25)"
                                : "rgba(0,255,136,0.2)"
                        }`,
                      }}
                    >
                      {/* Kit panel header */}
                      <div
                        className="px-5 py-3 flex items-center gap-2 flex-wrap"
                        style={{
                          background:
                            result.kitMatch.sophistication === "expert"
                              ? "rgba(255,68,68,0.07)"
                              : result.kitMatch.sophistication === "high"
                                ? "rgba(249,115,22,0.07)"
                                : result.kitMatch.sophistication === "medium"
                                  ? "rgba(245,166,35,0.06)"
                                  : "rgba(0,255,136,0.05)",
                          borderBottom: "1px solid rgba(30,39,54,0.8)",
                        }}
                      >
                        <Fingerprint
                          className="size-4"
                          style={{
                            color:
                              result.kitMatch.sophistication === "expert"
                                ? "#ff4444"
                                : result.kitMatch.sophistication === "high"
                                  ? "#f97316"
                                  : result.kitMatch.sophistication === "medium"
                                    ? "#f5a623"
                                    : "#00ff88",
                          }}
                        />
                        <span
                          className="text-xs font-bold uppercase tracking-wider"
                          style={{
                            color:
                              result.kitMatch.sophistication === "expert"
                                ? "#ff4444"
                                : result.kitMatch.sophistication === "high"
                                  ? "#f97316"
                                  : result.kitMatch.sophistication === "medium"
                                    ? "#f5a623"
                                    : "#00ff88",
                            fontFamily: "'JetBrains Mono', monospace",
                          }}
                        >
                          Phishing Kit Identified
                        </span>
                        <span
                          className="ml-auto text-xs px-2 py-0.5 rounded font-bold uppercase"
                          style={{
                            color:
                              result.kitMatch.sophistication === "expert"
                                ? "#ff4444"
                                : result.kitMatch.sophistication === "high"
                                  ? "#f97316"
                                  : result.kitMatch.sophistication === "medium"
                                    ? "#f5a623"
                                    : "#00ff88",
                            background: "rgba(0,0,0,0.3)",
                            fontFamily: "'JetBrains Mono', monospace",
                          }}
                        >
                          {result.kitMatch.sophistication} sophistication
                        </span>
                      </div>

                      {/* Kit panel body */}
                      <div
                        className="px-5 py-4"
                        style={{ background: "var(--bg-card)" }}
                      >
                        {/* Kit name + ID + confidence */}
                        <div className="flex items-start gap-4 mb-3">
                          <div className="flex-1 min-w-0">
                            <div
                              className="text-base font-bold mb-1"
                              style={{
                                color: "var(--text-primary)",
                                fontFamily: "'Syne', sans-serif",
                              }}
                            >
                              {result.kitMatch.kitName}
                            </div>
                            <div className="flex items-center gap-2 flex-wrap">
                              <span
                                className="text-xs px-2 py-0.5 rounded"
                                style={{
                                  color: "var(--accent-cyan)",
                                  background: "rgba(0,212,255,0.06)",
                                  border: "1px solid rgba(0,212,255,0.15)",
                                  fontFamily: "'JetBrains Mono', monospace",
                                }}
                              >
                                {result.kitMatch.kitId}
                              </span>
                              <span
                                className="text-xs"
                                style={{
                                  color: "var(--text-muted)",
                                  fontFamily: "'JetBrains Mono', monospace",
                                }}
                              >
                                Match confidence: {result.kitMatch.confidence}%
                              </span>
                            </div>
                          </div>
                          {/* Confidence number */}
                          <div className="text-center flex-shrink-0">
                            <div
                              className="text-2xl font-black"
                              style={{
                                color:
                                  result.kitMatch.sophistication === "expert"
                                    ? "#ff4444"
                                    : result.kitMatch.sophistication === "high"
                                      ? "#f97316"
                                      : result.kitMatch.sophistication ===
                                          "medium"
                                        ? "#f5a623"
                                        : "#00ff88",
                                fontFamily: "'Syne', sans-serif",
                              }}
                            >
                              {result.kitMatch.confidence}%
                            </div>
                            <div
                              className="text-xs"
                              style={{
                                color: "var(--text-muted)",
                                fontFamily: "'JetBrains Mono', monospace",
                              }}
                            >
                              match
                            </div>
                          </div>
                        </div>

                        {/* Target brands */}
                        {result.kitMatch.targetBrands &&
                          result.kitMatch.targetBrands.length > 0 && (
                            <div className="flex items-center gap-2 flex-wrap mb-3">
                              <span
                                className="text-xs"
                                style={{
                                  color: "var(--text-muted)",
                                  fontFamily: "'JetBrains Mono', monospace",
                                }}
                              >
                                Known targets:
                              </span>
                              {result.kitMatch.targetBrands.map((brand) => (
                                <span
                                  key={brand}
                                  className="text-xs px-2 py-0.5 rounded capitalize"
                                  style={{
                                    color: "#f97316",
                                    background: "rgba(249,115,22,0.08)",
                                    border: "1px solid rgba(249,115,22,0.2)",
                                    fontFamily: "'JetBrains Mono', monospace",
                                  }}
                                >
                                  {brand}
                                </span>
                              ))}
                            </div>
                          )}

                        {/* MITRE tag */}
                        <div
                          className="text-xs px-3 py-2 rounded-lg"
                          style={{
                            background: "rgba(124,58,237,0.07)",
                            border: "1px solid rgba(124,58,237,0.15)",
                            color: "#a78bfa",
                            fontFamily: "'JetBrains Mono', monospace",
                          }}
                        >
                          {result.kitMatch.sophistication === "expert"
                            ? "MITRE: T1557 — Adversary-in-the-Middle"
                            : result.kitMatch.sophistication === "high"
                              ? "MITRE: T1566.002 — Spearphishing Link"
                              : "MITRE: T1566 — Phishing"}
                        </div>
                      </div>
                    </motion.div>
                  )}

                  {/* ── Domain Intelligence Panel ── */}
                  {result.inputType === "url" &&
                    (intelLoading || domainIntel) && (
                      <motion.div
                        initial={{ opacity: 0, y: 8 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={{ delay: 0.55 }}
                        className="rounded-xl overflow-hidden"
                        style={{ border: "1px solid rgba(0,212,255,0.2)" }}
                      >
                        {/* Header */}
                        <div
                          className="px-5 py-3 flex items-center gap-2"
                          style={{
                            background: "rgba(0,212,255,0.06)",
                            borderBottom: "1px solid rgba(0,212,255,0.15)",
                          }}
                        >
                          <Globe
                            className="size-4"
                            style={{ color: "var(--accent-cyan)" }}
                          />
                          <span
                            className="text-xs font-bold uppercase tracking-wider"
                            style={{
                              color: "var(--accent-cyan)",
                              fontFamily: "'JetBrains Mono', monospace",
                            }}
                          >
                            🔍 Domain Intelligence
                          </span>
                          {domainIntel && (
                            <span
                              className="ml-auto text-xs px-2 py-0.5 rounded font-bold"
                              style={{
                                fontFamily: "'JetBrains Mono', monospace",
                                color:
                                  domainIntel.risk.riskLevel === "critical"
                                    ? "#ff4444"
                                    : domainIntel.risk.riskLevel === "high"
                                      ? "#f97316"
                                      : domainIntel.risk.riskLevel === "medium"
                                        ? "#f5a623"
                                        : "#00ff88",
                                background:
                                  domainIntel.risk.riskLevel === "critical"
                                    ? "rgba(255,68,68,0.1)"
                                    : domainIntel.risk.riskLevel === "high"
                                      ? "rgba(249,115,22,0.1)"
                                      : domainIntel.risk.riskLevel === "medium"
                                        ? "rgba(245,166,35,0.1)"
                                        : "rgba(0,255,136,0.08)",
                                border: `1px solid ${
                                  domainIntel.risk.riskLevel === "critical"
                                    ? "rgba(255,68,68,0.3)"
                                    : domainIntel.risk.riskLevel === "high"
                                      ? "rgba(249,115,22,0.3)"
                                      : domainIntel.risk.riskLevel === "medium"
                                        ? "rgba(245,166,35,0.3)"
                                        : "rgba(0,255,136,0.2)"
                                }`,
                              }}
                            >
                              {domainIntel.risk.riskLevel.toUpperCase()}
                            </span>
                          )}
                        </div>

                        {/* Loading state */}
                        {intelLoading && !domainIntel && (
                          <div
                            className="px-5 py-6 flex items-center gap-3"
                            style={{ background: "var(--bg-card)" }}
                          >
                            <div
                              className="w-4 h-4 border-2 rounded-full animate-spin flex-shrink-0"
                              style={{
                                borderColor: "var(--accent-cyan)",
                                borderTopColor: "transparent",
                              }}
                            />
                            <span
                              className="text-xs"
                              style={{
                                color: "var(--text-muted)",
                                fontFamily: "'JetBrains Mono', monospace",
                              }}
                            >
                              Analyzing domain intelligence...
                            </span>
                          </div>
                        )}

                        {/* Data grid */}
                        {domainIntel && (
                          <div style={{ background: "var(--bg-card)" }}>
                            {/* 4-column info grid */}
                            <div
                              className="grid grid-cols-2 md:grid-cols-4"
                              style={{
                                borderBottom: "1px solid rgba(26,36,64,0.6)",
                              }}
                            >
                              {/* Domain Age */}
                              <div
                                className="px-4 py-4 border-r"
                                style={{ borderColor: "rgba(26,36,64,0.6)" }}
                              >
                                <div className="flex items-center gap-1.5 mb-2">
                                  <Calendar
                                    className="size-3.5"
                                    style={{ color: "var(--accent-cyan)" }}
                                  />
                                  <span
                                    className="text-xs uppercase tracking-widest"
                                    style={{
                                      color: "var(--text-muted)",
                                      fontFamily: "'JetBrains Mono', monospace",
                                    }}
                                  >
                                    Domain Age
                                  </span>
                                </div>
                                <div
                                  className="text-sm font-semibold"
                                  style={{
                                    color: domainIntel.age.isSuspicious
                                      ? "#ff4444"
                                      : domainIntel.age.isNew
                                        ? "#f5a623"
                                        : "var(--text-primary)",
                                  }}
                                >
                                  {domainIntel.age.ageLabel || "Unknown"}
                                </div>
                                {domainIntel.age.registeredAt && (
                                  <div
                                    className="text-xs mt-1"
                                    style={{
                                      color: "var(--text-muted)",
                                      fontFamily: "'JetBrains Mono', monospace",
                                    }}
                                  >
                                    Reg: {domainIntel.age.registeredAt}
                                  </div>
                                )}
                                {domainIntel.age.registrar && (
                                  <div
                                    className="text-xs mt-0.5 truncate"
                                    style={{
                                      color: "var(--text-muted)",
                                      fontFamily: "'JetBrains Mono', monospace",
                                    }}
                                  >
                                    {domainIntel.age.registrar.substring(0, 22)}
                                  </div>
                                )}
                              </div>

                              {/* SSL */}
                              <div
                                className="px-4 py-4 border-r"
                                style={{ borderColor: "rgba(26,36,64,0.6)" }}
                              >
                                <div className="flex items-center gap-1.5 mb-2">
                                  <Lock
                                    className="size-3.5"
                                    style={{ color: "var(--accent-cyan)" }}
                                  />
                                  <span
                                    className="text-xs uppercase tracking-widest"
                                    style={{
                                      color: "var(--text-muted)",
                                      fontFamily: "'JetBrains Mono', monospace",
                                    }}
                                  >
                                    SSL / TLS
                                  </span>
                                </div>
                                <div
                                  className="text-sm font-semibold"
                                  style={{
                                    color: domainIntel.ssl.valid
                                      ? "#00ff88"
                                      : "#ff4444",
                                  }}
                                >
                                  {domainIntel.ssl.valid
                                    ? "✓ Valid"
                                    : "✗ Invalid"}
                                </div>
                                {domainIntel.ssl.valid &&
                                  domainIntel.ssl.daysLeft !== null && (
                                    <div
                                      className="text-xs mt-1"
                                      style={{
                                        color:
                                          domainIntel.ssl.daysLeft < 30
                                            ? "#f5a623"
                                            : "var(--text-muted)",
                                        fontFamily:
                                          "'JetBrains Mono', monospace",
                                      }}
                                    >
                                      {domainIntel.ssl.daysLeft}d until expiry
                                    </div>
                                  )}
                                {domainIntel.ssl.issuer && (
                                  <div
                                    className="text-xs mt-0.5 truncate"
                                    style={{
                                      color: "var(--text-muted)",
                                      fontFamily: "'JetBrains Mono', monospace",
                                    }}
                                  >
                                    {domainIntel.ssl.selfSigned
                                      ? "⚠ Self-signed"
                                      : domainIntel.ssl.issuer.substring(0, 20)}
                                  </div>
                                )}
                                {!domainIntel.ssl.valid &&
                                  domainIntel.ssl.error && (
                                    <div
                                      className="text-xs mt-1 truncate"
                                      style={{
                                        color: "#ff4444",
                                        fontFamily:
                                          "'JetBrains Mono', monospace",
                                      }}
                                    >
                                      {domainIntel.ssl.error}
                                    </div>
                                  )}
                              </div>

                              {/* Server / Geo */}
                              <div
                                className="px-4 py-4 border-r"
                                style={{ borderColor: "rgba(26,36,64,0.6)" }}
                              >
                                <div className="flex items-center gap-1.5 mb-2">
                                  <Server
                                    className="size-3.5"
                                    style={{ color: "var(--accent-cyan)" }}
                                  />
                                  <span
                                    className="text-xs uppercase tracking-widest"
                                    style={{
                                      color: "var(--text-muted)",
                                      fontFamily: "'JetBrains Mono', monospace",
                                    }}
                                  >
                                    Server
                                  </span>
                                </div>
                                <div
                                  className="text-sm font-semibold"
                                  style={{ color: "var(--text-primary)" }}
                                >
                                  {domainIntel.dns.flag}{" "}
                                  {domainIntel.dns.country || "Unknown"}
                                </div>
                                {domainIntel.dns.ip && (
                                  <div
                                    className="text-xs mt-1"
                                    style={{
                                      color: "var(--text-muted)",
                                      fontFamily: "'JetBrains Mono', monospace",
                                    }}
                                  >
                                    {domainIntel.dns.ip}
                                  </div>
                                )}
                                {domainIntel.dns.city && (
                                  <div
                                    className="text-xs mt-0.5"
                                    style={{
                                      color: "var(--text-muted)",
                                      fontFamily: "'JetBrains Mono', monospace",
                                    }}
                                  >
                                    {domainIntel.dns.city}
                                  </div>
                                )}
                              </div>

                              {/* Blacklist */}
                              <div className="px-4 py-4">
                                <div className="flex items-center gap-1.5 mb-2">
                                  <ShieldCheck
                                    className="size-3.5"
                                    style={{ color: "var(--accent-cyan)" }}
                                  />
                                  <span
                                    className="text-xs uppercase tracking-widest"
                                    style={{
                                      color: "var(--text-muted)",
                                      fontFamily: "'JetBrains Mono', monospace",
                                    }}
                                  >
                                    Blacklists
                                  </span>
                                </div>
                                <div
                                  className="text-sm font-semibold"
                                  style={{
                                    color: domainIntel.blacklist.found
                                      ? "#ff4444"
                                      : "#00ff88",
                                  }}
                                >
                                  {domainIntel.blacklist.found
                                    ? `✗ Listed (${domainIntel.blacklist.count})`
                                    : "✓ Clean"}
                                </div>
                                <div className="flex flex-wrap gap-1 mt-1.5">
                                  {Object.entries(
                                    domainIntel.blacklist.results,
                                  ).map(([feed, hit]) => (
                                    <span
                                      key={feed}
                                      className="rounded"
                                      style={{
                                        fontSize: 9,
                                        padding: "2px 6px",
                                        fontFamily:
                                          "'JetBrains Mono', monospace",
                                        color: hit ? "#ff4444" : "#00ff88",
                                        background: hit
                                          ? "rgba(255,68,68,0.08)"
                                          : "rgba(0,255,136,0.06)",
                                        border: `1px solid ${hit ? "rgba(255,68,68,0.2)" : "rgba(0,255,136,0.15)"}`,
                                      }}
                                    >
                                      {feed}
                                    </span>
                                  ))}
                                </div>
                              </div>
                            </div>

                            {/* Risk signals bar */}
                            {domainIntel.risk.riskSignals.length > 0 && (
                              <div
                                className="px-5 py-3 flex items-start gap-2 flex-wrap"
                                style={{
                                  borderTop: "1px solid rgba(26,36,64,0.6)",
                                }}
                              >
                                <span
                                  className="text-xs flex-shrink-0 mt-0.5"
                                  style={{ color: "#f5a623" }}
                                >
                                  ⚠
                                </span>
                                <div className="flex flex-wrap gap-2">
                                  {domainIntel.risk.riskSignals.map(
                                    (sig, i) => (
                                      <span
                                        key={i}
                                        className="text-xs px-2 py-0.5 rounded"
                                        style={{
                                          color: "#f5a623",
                                          background: "rgba(245,166,35,0.06)",
                                          border:
                                            "1px solid rgba(245,166,35,0.2)",
                                          fontFamily:
                                            "'JetBrains Mono', monospace",
                                        }}
                                      >
                                        {sig}
                                      </span>
                                    ),
                                  )}
                                </div>
                              </div>
                            )}
                          </div>
                        )}
                      </motion.div>
                    )}

                  {/* ── Sandbox Analysis Panel ── */}
                  {result.inputType === "url" &&
                    result.status !== "safe" &&
                    (previewLoading || urlPreview) && (
                      <motion.div
                        initial={{ opacity: 0, y: 8 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={{ delay: 0.5 }}
                        className="rounded-xl overflow-hidden"
                        style={{
                          border: `1px solid ${
                            urlPreview?.sandboxRisk?.riskLevel === "critical"
                              ? "rgba(255,68,68,0.35)"
                              : urlPreview?.sandboxRisk?.riskLevel === "high"
                                ? "rgba(249,115,22,0.3)"
                                : "rgba(249,115,22,0.25)"
                          }`,
                        }}
                      >
                        {/* Header */}
                        <div
                          className="px-5 py-3 flex items-center gap-2 flex-wrap"
                          style={{
                            background: "rgba(249,115,22,0.06)",
                            borderBottom: "1px solid rgba(249,115,22,0.15)",
                          }}
                        >
                          <Eye
                            className="size-4"
                            style={{ color: "#f97316" }}
                          />
                          <span
                            className="text-xs font-bold uppercase tracking-wider"
                            style={{
                              color: "#f97316",
                              fontFamily: "'JetBrains Mono', monospace",
                            }}
                          >
                            Sandbox Analysis
                          </span>
                          {/* Live status badge */}
                          {urlPreview && (
                            <span
                              className="text-xs px-2 py-0.5 rounded font-bold"
                              style={{
                                fontFamily: "'JetBrains Mono', monospace",
                                color:
                                  urlPreview.liveStatus === "LIVE"
                                    ? "#ff4444"
                                    : urlPreview.liveStatus === "TAKEN_DOWN"
                                      ? "#00ff88"
                                      : urlPreview.liveStatus === "UNREACHABLE"
                                        ? "#8b95a8"
                                        : "#f5a623",
                                background:
                                  urlPreview.liveStatus === "LIVE"
                                    ? "rgba(255,68,68,0.1)"
                                    : urlPreview.liveStatus === "TAKEN_DOWN"
                                      ? "rgba(0,255,136,0.08)"
                                      : "rgba(139,149,168,0.08)",
                                border: `1px solid ${
                                  urlPreview.liveStatus === "LIVE"
                                    ? "rgba(255,68,68,0.3)"
                                    : urlPreview.liveStatus === "TAKEN_DOWN"
                                      ? "rgba(0,255,136,0.2)"
                                      : "rgba(139,149,168,0.2)"
                                }`,
                              }}
                            >
                              {urlPreview.liveStatus === "LIVE"
                                ? "LIVE"
                                : urlPreview.liveStatus === "TAKEN_DOWN"
                                  ? "TAKEN DOWN"
                                  : urlPreview.liveStatus === "UNREACHABLE"
                                    ? "UNREACHABLE"
                                    : `HTTP ${urlPreview.statusCode}`}
                            </span>
                          )}
                          {/* Sandbox risk score — right */}
                          {urlPreview?.sandboxRisk && (
                            <span
                              className="ml-auto text-xs px-2 py-0.5 rounded font-bold uppercase"
                              style={{
                                fontFamily: "'JetBrains Mono', monospace",
                                background: "rgba(0,0,0,0.3)",
                                color:
                                  urlPreview.sandboxRisk.riskLevel ===
                                  "critical"
                                    ? "#ff4444"
                                    : urlPreview.sandboxRisk.riskLevel ===
                                        "high"
                                      ? "#f97316"
                                      : urlPreview.sandboxRisk.riskLevel ===
                                          "medium"
                                        ? "#f5a623"
                                        : "#00ff88",
                              }}
                            >
                              Sandbox:{" "}
                              {urlPreview.sandboxRisk.riskLevel.toUpperCase()} (
                              {urlPreview.sandboxRisk.riskScore}/100)
                            </span>
                          )}
                        </div>

                        {/* Loading state */}
                        {previewLoading && !urlPreview && (
                          <div
                            className="px-5 py-5 flex items-center gap-3"
                            style={{ background: "var(--bg-card)" }}
                          >
                            <div
                              className="w-4 h-4 border-2 rounded-full animate-spin flex-shrink-0"
                              style={{
                                borderColor: "#f97316",
                                borderTopColor: "transparent",
                              }}
                            />
                            <span
                              className="text-xs"
                              style={{
                                color: "var(--text-muted)",
                                fontFamily: "'JetBrains Mono', monospace",
                              }}
                            >
                              Running sandbox analysis — form detection, tech
                              fingerprinting, redirect chain...
                            </span>
                          </div>
                        )}

                        {/* Full sandbox results */}
                        {urlPreview && (
                          <div style={{ background: "var(--bg-card)" }}>
                            {/* Brand impersonation alert */}
                            {urlPreview.brandMismatch?.found && (
                              <div
                                className="px-5 py-3 flex items-start gap-3"
                                style={{
                                  background: "rgba(255,68,68,0.06)",
                                  borderBottom:
                                    "1px solid rgba(255,68,68,0.15)",
                                }}
                              >
                                <span className="text-base flex-shrink-0">
                                  🚨
                                </span>
                                <div>
                                  <p
                                    className="text-sm font-bold"
                                    style={{
                                      color: "#ff4444",
                                      fontFamily: "'Syne', sans-serif",
                                    }}
                                  >
                                    Brand Impersonation Confirmed
                                  </p>
                                  <p
                                    className="text-xs mt-0.5"
                                    style={{ color: "var(--text-secondary)" }}
                                  >
                                    {urlPreview.brandMismatch.message}
                                  </p>
                                </div>
                              </div>
                            )}
                            {/* Page metadata row */}
                            <div
                              className="px-5 py-4 flex items-start gap-4 border-b"
                              style={{ borderColor: "var(--bg-border)" }}
                            >
                              <div
                                className="w-10 h-10 rounded-lg flex items-center justify-center flex-shrink-0 overflow-hidden"
                                style={{
                                  background: "var(--bg-elevated)",
                                  border: "1px solid var(--bg-border)",
                                }}
                              >
                                {urlPreview.favicon ? (
                                  <img
                                    src={urlPreview.favicon}
                                    alt=""
                                    className="w-6 h-6 object-contain"
                                    onError={(e) => {
                                      (
                                        e.target as HTMLImageElement
                                      ).style.display = "none";
                                    }}
                                  />
                                ) : (
                                  <ExternalLink
                                    className="size-4"
                                    style={{ color: "var(--text-muted)" }}
                                  />
                                )}
                              </div>
                              <div className="flex-1 min-w-0">
                                {urlPreview.title ? (
                                  <p
                                    className="text-sm font-semibold mb-1 leading-snug"
                                    style={{
                                      color: urlPreview.brandMismatch?.found
                                        ? "#f97316"
                                        : "var(--text-primary)",
                                      fontFamily: "'Syne', sans-serif",
                                    }}
                                  >
                                    {urlPreview.title}
                                  </p>
                                ) : (
                                  <p
                                    className="text-sm italic mb-1"
                                    style={{ color: "var(--text-muted)" }}
                                  >
                                    No page title
                                  </p>
                                )}
                                {urlPreview.description && (
                                  <p
                                    className="text-xs leading-relaxed mb-2"
                                    style={{ color: "var(--text-muted)" }}
                                  >
                                    {urlPreview.description.substring(0, 120)}
                                    {urlPreview.description.length > 120
                                      ? "…"
                                      : ""}
                                  </p>
                                )}
                                <div className="flex items-center gap-2 flex-wrap">
                                  <span
                                    className="text-xs"
                                    style={{
                                      color: "var(--accent-cyan)",
                                      fontFamily: "'JetBrains Mono', monospace",
                                    }}
                                  >
                                    {urlPreview.domain}
                                  </span>
                                  {urlPreview.generator && (
                                    <span
                                      className="text-xs px-1.5 py-0.5 rounded"
                                      style={{
                                        color: "var(--text-muted)",
                                        background: "var(--bg-elevated)",
                                        fontFamily:
                                          "'JetBrains Mono', monospace",
                                      }}
                                    >
                                      {urlPreview.generator.substring(0, 30)}
                                    </span>
                                  )}
                                </div>
                              </div>
                            </div>

                            {/* 4-column analysis grid */}
                            <div
                              className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 divide-y lg:divide-x lg:divide-y-0"
                              style={{ borderColor: "rgba(30,39,54,0.6)" }}
                            >
                              {/* Forms */}
                              <div className="px-4 py-4">
                                <div
                                  className="text-xs uppercase tracking-widest mb-2"
                                  style={{
                                    color: "var(--text-muted)",
                                    fontFamily: "'JetBrains Mono', monospace",
                                  }}
                                >
                                  Forms
                                </div>
                                {urlPreview.forms.count === 0 ? (
                                  <div
                                    className="text-xs"
                                    style={{ color: "#00ff88" }}
                                  >
                                    No forms
                                  </div>
                                ) : (
                                  <div className="space-y-1">
                                    <div
                                      className="text-sm font-bold"
                                      style={{
                                        color: urlPreview.forms
                                          .hasCredentialForm
                                          ? "#ff4444"
                                          : "#f5a623",
                                        fontFamily: "'Syne', sans-serif",
                                      }}
                                    >
                                      {urlPreview.forms.count} form
                                      {urlPreview.forms.count !== 1 ? "s" : ""}
                                    </div>
                                    {urlPreview.forms.hasPasswordField && (
                                      <div
                                        className="text-xs"
                                        style={{
                                          color: "#ff4444",
                                          fontFamily:
                                            "'JetBrains Mono', monospace",
                                        }}
                                      >
                                        Password field
                                      </div>
                                    )}
                                    {urlPreview.forms.hasCredentialForm && (
                                      <div
                                        className="text-xs"
                                        style={{
                                          color: "#ff4444",
                                          fontFamily:
                                            "'JetBrains Mono', monospace",
                                        }}
                                      >
                                        Credential harvester
                                      </div>
                                    )}
                                    {urlPreview.forms.hasExternalAction && (
                                      <div
                                        className="text-xs"
                                        style={{
                                          color: "#f97316",
                                          fontFamily:
                                            "'JetBrains Mono', monospace",
                                        }}
                                      >
                                        External action
                                      </div>
                                    )}
                                  </div>
                                )}
                              </div>
                              {/* Tech Stack */}
                              <div className="px-4 py-4">
                                <div
                                  className="text-xs uppercase tracking-widest mb-2"
                                  style={{
                                    color: "var(--text-muted)",
                                    fontFamily: "'JetBrains Mono', monospace",
                                  }}
                                >
                                  Tech Stack
                                </div>
                                {urlPreview.technologies.detected.length ===
                                0 ? (
                                  <div
                                    className="text-xs"
                                    style={{ color: "var(--text-muted)" }}
                                  >
                                    Unknown
                                  </div>
                                ) : (
                                  <div className="space-y-1">
                                    {urlPreview.technologies.hasPhishingKit && (
                                      <div
                                        className="text-xs font-bold"
                                        style={{ color: "#ff4444" }}
                                      >
                                        Phishing Kit
                                      </div>
                                    )}
                                    {urlPreview.technologies.hasObfuscation && (
                                      <div
                                        className="text-xs font-bold"
                                        style={{ color: "#f97316" }}
                                      >
                                        Obfuscated JS
                                      </div>
                                    )}
                                    {urlPreview.technologies.detected
                                      .filter(
                                        (t) =>
                                          t.category !== "phishing_kit" &&
                                          t.category !== "obfuscation",
                                      )
                                      .slice(0, 3)
                                      .map((t) => (
                                        <div
                                          key={t.name}
                                          className="text-xs"
                                          style={{
                                            color:
                                              t.risk === "high"
                                                ? "#f5a623"
                                                : "var(--text-muted)",
                                            fontFamily:
                                              "'JetBrains Mono', monospace",
                                          }}
                                        >
                                          {t.name}
                                        </div>
                                      ))}
                                  </div>
                                )}
                              </div>
                              {/* Redirects */}
                              <div className="px-4 py-4">
                                <div
                                  className="text-xs uppercase tracking-widest mb-2"
                                  style={{
                                    color: "var(--text-muted)",
                                    fontFamily: "'JetBrains Mono', monospace",
                                  }}
                                >
                                  Redirects
                                </div>
                                <div
                                  className="text-sm font-bold mb-1"
                                  style={{
                                    color:
                                      urlPreview.redirectChain.hops > 2
                                        ? "#ff4444"
                                        : urlPreview.redirectChain.hasRedirects
                                          ? "#f5a623"
                                          : "#00ff88",
                                    fontFamily: "'Syne', sans-serif",
                                  }}
                                >
                                  {urlPreview.redirectChain.hops} hop
                                  {urlPreview.redirectChain.hops !== 1
                                    ? "s"
                                    : ""}
                                </div>
                                {urlPreview.redirectChain.crossDomain && (
                                  <div
                                    className="text-xs"
                                    style={{
                                      color: "#ff4444",
                                      fontFamily: "'JetBrains Mono', monospace",
                                    }}
                                  >
                                    Cross-domain
                                  </div>
                                )}
                                {!urlPreview.redirectChain.hasRedirects && (
                                  <div
                                    className="text-xs"
                                    style={{ color: "#00ff88" }}
                                  >
                                    Direct
                                  </div>
                                )}
                                {urlPreview.redirectChain.finalUrl !==
                                  urlPreview.url && (
                                  <div
                                    className="text-xs truncate mt-1"
                                    style={{
                                      color: "#f97316",
                                      fontFamily: "'JetBrains Mono', monospace",
                                    }}
                                  >
                                    {urlPreview.redirectChain.finalUrl.substring(
                                      0,
                                      28,
                                    )}
                                    ...
                                  </div>
                                )}
                              </div>
                              {/* Sandbox Risk Score */}
                              <div className="px-4 py-4">
                                <div
                                  className="text-xs uppercase tracking-widest mb-2"
                                  style={{
                                    color: "var(--text-muted)",
                                    fontFamily: "'JetBrains Mono', monospace",
                                  }}
                                >
                                  Sandbox Risk
                                </div>
                                <div
                                  className="text-2xl font-black mb-0.5"
                                  style={{
                                    color:
                                      urlPreview.sandboxRisk.riskLevel ===
                                      "critical"
                                        ? "#ff4444"
                                        : urlPreview.sandboxRisk.riskLevel ===
                                            "high"
                                          ? "#f97316"
                                          : urlPreview.sandboxRisk.riskLevel ===
                                              "medium"
                                            ? "#f5a623"
                                            : "#00ff88",
                                    fontFamily: "'Syne', sans-serif",
                                  }}
                                >
                                  {urlPreview.sandboxRisk.riskScore}
                                </div>
                                <div
                                  className="text-xs uppercase font-bold"
                                  style={{
                                    color:
                                      urlPreview.sandboxRisk.riskLevel ===
                                      "critical"
                                        ? "#ff4444"
                                        : urlPreview.sandboxRisk.riskLevel ===
                                            "high"
                                          ? "#f97316"
                                          : urlPreview.sandboxRisk.riskLevel ===
                                              "medium"
                                            ? "#f5a623"
                                            : "#00ff88",
                                    fontFamily: "'JetBrains Mono', monospace",
                                  }}
                                >
                                  {urlPreview.sandboxRisk.riskLevel}
                                </div>
                              </div>
                            </div>
                            {/* Sandbox signal chips */}
                            {urlPreview.sandboxRisk.signals.length > 0 && (
                              <div
                                className="px-5 py-3 border-t flex flex-wrap gap-2"
                                style={{ borderColor: "var(--bg-border)" }}
                              >
                                {urlPreview.sandboxRisk.signals.map(
                                  (sig, i) => (
                                    <span
                                      key={i}
                                      className="text-xs px-2 py-0.5 rounded"
                                      style={{
                                        color: "#f5a623",
                                        background: "rgba(245,166,35,0.06)",
                                        border:
                                          "1px solid rgba(245,166,35,0.2)",
                                        fontFamily:
                                          "'JetBrains Mono', monospace",
                                      }}
                                    >
                                      {sig}
                                    </span>
                                  ),
                                )}
                              </div>
                            )}
                            {/* Redirect chain detail */}
                            {urlPreview.redirectChain.hasRedirects && (
                              <div
                                className="px-5 py-3 border-t"
                                style={{ borderColor: "var(--bg-border)" }}
                              >
                                <div
                                  className="text-xs mb-2 uppercase tracking-widest"
                                  style={{
                                    color: "var(--text-muted)",
                                    fontFamily: "'JetBrains Mono', monospace",
                                  }}
                                >
                                  Redirect Chain
                                </div>
                                <div className="space-y-1">
                                  {urlPreview.redirectChain.chain.map(
                                    (hop, i) => (
                                      <div
                                        key={i}
                                        className="flex items-center gap-2 text-xs"
                                        style={{
                                          fontFamily:
                                            "'JetBrains Mono', monospace",
                                        }}
                                      >
                                        <span
                                          className="w-4 text-center"
                                          style={{ color: "var(--text-muted)" }}
                                        >
                                          {hop.hop}
                                        </span>
                                        <span
                                          className="text-xs px-1.5 py-0.5 rounded flex-shrink-0"
                                          style={{
                                            background: "var(--bg-elevated)",
                                            color:
                                              hop.statusCode === 200
                                                ? "#00ff88"
                                                : hop.statusCode &&
                                                    hop.statusCode >= 300 &&
                                                    hop.statusCode < 400
                                                  ? "#f5a623"
                                                  : "#8b95a8",
                                          }}
                                        >
                                          {hop.statusCode ?? "?"}
                                        </span>
                                        <span
                                          className="truncate flex-1"
                                          style={{
                                            color:
                                              i ===
                                              urlPreview.redirectChain.chain
                                                .length -
                                                1
                                                ? "var(--text-primary)"
                                                : "var(--text-muted)",
                                          }}
                                        >
                                          {hop.url}
                                        </span>
                                      </div>
                                    ),
                                  )}
                                </div>
                              </div>
                            )}
                            {/* OG image preview */}
                            {urlPreview.ogImage && urlPreview.isLive && (
                              <div
                                className="px-5 pb-4 border-t"
                                style={{ borderColor: "var(--bg-border)" }}
                              >
                                <div
                                  className="text-xs mb-2 mt-3 uppercase tracking-widest"
                                  style={{
                                    color: "var(--text-muted)",
                                    fontFamily: "'JetBrains Mono', monospace",
                                  }}
                                >
                                  Page Preview Image
                                </div>
                                <img
                                  src={urlPreview.ogImage}
                                  alt="Page preview"
                                  className="w-full max-h-32 object-cover rounded-xl"
                                  style={{
                                    border: "1px solid var(--bg-border)",
                                  }}
                                  onError={(e) => {
                                    (
                                      e.target as HTMLImageElement
                                    ).style.display = "none";
                                  }}
                                />
                              </div>
                            )}
                            {/* Taken down notice */}
                            {urlPreview.isTakenDown && (
                              <div
                                className="px-5 py-3 border-t flex items-center gap-2"
                                style={{
                                  borderColor: "var(--bg-border)",
                                  background: "rgba(0,255,136,0.04)",
                                }}
                              >
                                <CheckCircle
                                  className="size-4 flex-shrink-0"
                                  style={{ color: "#00ff88" }}
                                />
                                <p
                                  className="text-xs"
                                  style={{
                                    color: "#00ff88",
                                    fontFamily: "'JetBrains Mono', monospace",
                                  }}
                                >
                                  This phishing page has been taken down (HTTP{" "}
                                  {urlPreview.statusCode})
                                </p>
                              </div>
                            )}
                            {/* Error note */}
                            {urlPreview.error && (
                              <div
                                className="px-5 py-2 text-xs border-t"
                                style={{
                                  borderColor: "var(--bg-border)",
                                  color: "var(--text-muted)",
                                  fontFamily: "'JetBrains Mono', monospace",
                                }}
                              >
                                Note: {urlPreview.error}
                              </div>
                            )}
                          </div>
                        )}
                      </motion.div>
                    )}

                  {/* Dark Web Threat Context */}
                  {result.inputType === "url" &&
                    result.status !== "safe" &&
                    (() => {
                      const ctx = getThreatContext(scannedInput, result);
                      if (!ctx || ctx.length === 0) return null;
                      return (
                        <motion.div
                          initial={{ opacity: 0, y: 8 }}
                          animate={{ opacity: 1, y: 0 }}
                          transition={{ delay: 0.52 }}
                          className="rounded-xl overflow-hidden"
                          style={{ border: "1px solid rgba(124,58,237,0.25)" }}
                        >
                          <div
                            className="px-5 py-3 flex items-center gap-2"
                            style={{
                              background: "rgba(124,58,237,0.07)",
                              borderBottom: "1px solid rgba(124,58,237,0.15)",
                            }}
                          >
                            <span className="text-base">🕷️</span>
                            <span
                              className="text-xs font-bold uppercase tracking-wider"
                              style={{
                                color: "#a78bfa",
                                fontFamily: "'JetBrains Mono', monospace",
                              }}
                            >
                              Threat Context Intelligence
                            </span>
                            <span
                              className="ml-auto text-xs px-2 py-0.5 rounded"
                              style={{
                                color: "var(--text-muted)",
                                background: "rgba(0,0,0,0.3)",
                                fontFamily: "'JetBrains Mono', monospace",
                              }}
                            >
                              Pattern analysis
                            </span>
                          </div>

                          <div
                            className="px-5 py-4 space-y-2"
                            style={{ background: "var(--bg-card)" }}
                          >
                            {ctx.map((sig, i) => {
                              const riskColor =
                                sig.risk === "critical"
                                  ? "#ff4444"
                                  : sig.risk === "high"
                                    ? "#f97316"
                                    : "#f5a623";
                              return (
                                <div
                                  key={i}
                                  className="flex items-center gap-3 px-3 py-2.5 rounded-lg"
                                  style={{
                                    background: `${riskColor}06`,
                                    border: `1px solid ${riskColor}20`,
                                  }}
                                >
                                  <span className="text-base">{sig.icon}</span>
                                  <span
                                    className="text-xs flex-1"
                                    style={{ color: "var(--text-secondary)" }}
                                  >
                                    {sig.label}
                                  </span>
                                  <span
                                    className="text-xs font-bold uppercase px-1.5 py-0.5 rounded flex-shrink-0"
                                    style={{
                                      color: riskColor,
                                      background: `${riskColor}12`,
                                      fontFamily: "'JetBrains Mono', monospace",
                                    }}
                                  >
                                    {sig.risk}
                                  </span>
                                </div>
                              );
                            })}
                            <p
                              className="text-xs pt-1"
                              style={{
                                color: "var(--text-muted)",
                                fontFamily: "'JetBrains Mono', monospace",
                              }}
                            >
                              ↑ Matches known phishing kit naming conventions
                            </p>
                          </div>
                        </motion.div>
                      );
                    })()}

                  {/* PhishDNA Fingerprint */}
                  {result.dna && (
                    <motion.div
                      initial={{ opacity: 0, y: 8 }}
                      animate={{ opacity: 1, y: 0 }}
                      transition={{ delay: 0.6 }}
                      className="rounded-xl p-4 border"
                      style={{
                        background: "rgba(163,120,251,0.05)",
                        borderColor: "rgba(163,120,251,0.2)",
                      }}
                    >
                      <div className="flex items-center gap-2 mb-3">
                        <span
                          className="text-xs font-bold uppercase tracking-wider"
                          style={{
                            color: "#a78bfa",
                            fontFamily: "'JetBrains Mono', monospace",
                          }}
                        >
                          🧬 PhishDNA™ Fingerprint
                        </span>
                        <span
                          className="ml-auto text-xs px-2 py-0.5 rounded font-mono font-bold"
                          style={{
                            background: "rgba(163,120,251,0.12)",
                            color: "#a78bfa",
                            border: "1px solid rgba(163,120,251,0.3)",
                          }}
                        >
                          #{result.dna.fingerprint}
                        </span>
                      </div>
                      <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-1.5">
                        {[
                          {
                            label: "Brand Targeted",
                            value:
                              result.dna.brand === "unknown"
                                ? "None"
                                : result.dna.brand,
                          },
                          {
                            label: "Attack Technique",
                            value: result.dna.technique.replace(/_/g, " "),
                          },
                          { label: "TLD Used", value: result.dna.tld },
                          {
                            label: "Severity Bucket",
                            value: result.dna.severity,
                          },
                        ].map(({ label, value }) => (
                          <div key={label}>
                            <span
                              className="text-xs"
                              style={{
                                color: "var(--text-muted)",
                                fontFamily: "'JetBrains Mono', monospace",
                              }}
                            >
                              {label}:
                            </span>{" "}
                            <span
                              className="text-xs font-semibold capitalize"
                              style={{ color: "var(--text-secondary)" }}
                            >
                              {value}
                            </span>
                          </div>
                        ))}
                      </div>
                      <p
                        className="text-xs mt-3"
                        style={{
                          color: "var(--text-muted)",
                          fontFamily: "'JetBrains Mono', monospace",
                        }}
                      >
                        Scans sharing fingerprint #{result.dna.fingerprint}{" "}
                        belong to the same attack campaign
                      </p>
                    </motion.div>
                  )}

                  {/* Remediation Engine */}
                  {result.remediation && result.status !== "safe" && (
                    <motion.div
                      initial={{ opacity: 0, y: 8 }}
                      animate={{ opacity: 1, y: 0 }}
                      transition={{ delay: 0.7 }}
                      className="rounded-xl overflow-hidden"
                      style={{ border: "1px solid var(--bg-border)" }}
                    >
                      <div
                        className="px-5 py-3 flex items-center gap-2"
                        style={{
                          background: "var(--bg-elevated)",
                          borderBottom: "1px solid var(--bg-border)",
                        }}
                      >
                        <CheckSquare
                          className="size-4"
                          style={{ color: "var(--accent-green)" }}
                        />
                        <span
                          className="text-xs font-bold uppercase tracking-wider"
                          style={{
                            color: "var(--accent-green)",
                            fontFamily: "'JetBrains Mono', monospace",
                          }}
                        >
                          Remediation Plan
                        </span>
                        <span
                          className="ml-2 text-xs"
                          style={{ color: "var(--text-muted)" }}
                        >
                          {result.remediation.summary}
                        </span>
                      </div>

                      <div
                        className="p-4 space-y-2"
                        style={{ background: "var(--bg-card)" }}
                      >
                        {result.remediation.steps.map((step, i) => {
                          const cfg =
                            result.remediation!.priorityConfig[step.priority] ||
                            {};
                          return (
                            <div
                              key={i}
                              className="flex items-start gap-3 rounded-lg px-3 py-2.5"
                              style={{
                                background: cfg.bg,
                                border: `1px solid ${cfg.border}`,
                              }}
                            >
                              <span
                                className="text-xs font-bold flex-shrink-0 w-16 mt-0.5"
                                style={{
                                  color: cfg.color,
                                  fontFamily: "'JetBrains Mono', monospace",
                                }}
                              >
                                {step.priority}
                              </span>
                              <span
                                className="text-xs leading-relaxed"
                                style={{ color: "var(--text-secondary)" }}
                              >
                                {step.action}
                              </span>
                            </div>
                          );
                        })}
                      </div>

                      {result.remediation.compliance && (
                        <div
                          className="px-5 py-3 border-t"
                          style={{
                            borderColor: "var(--bg-border)",
                            background: "rgba(163,120,251,0.04)",
                          }}
                        >
                          <p
                            className="text-xs"
                            style={{
                              color: "#a78bfa",
                              fontFamily: "'JetBrains Mono', monospace",
                            }}
                          >
                            ⚖️ {result.remediation.compliance}
                          </p>
                        </div>
                      )}

                      <div
                        className="px-5 py-3 border-t flex flex-wrap gap-2"
                        style={{
                          borderColor: "var(--bg-border)",
                          background: "var(--bg-elevated)",
                        }}
                      >
                        <span
                          className="text-xs mr-1 self-center"
                          style={{
                            color: "var(--text-muted)",
                            fontFamily: "'JetBrains Mono', monospace",
                          }}
                        >
                          Report to:
                        </span>
                        {result.remediation.reportLinks.map((link) => (
                          <a
                            key={link.url}
                            href={link.url}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="flex items-center gap-1 text-xs px-2.5 py-1 rounded-lg transition-all"
                            style={{
                              color: "var(--accent-cyan)",
                              background: "rgba(0,212,255,0.06)",
                              border: "1px solid rgba(0,212,255,0.2)",
                              fontFamily: "'JetBrains Mono', monospace",
                              textDecoration: "none",
                            }}
                          >
                            <ExternalLink className="size-2.5" />
                            {link.label}
                          </a>
                        ))}
                      </div>
                    </motion.div>
                  )}

                  {/* MITRE ATT&CK + CVE */}
                  {(() => {
                    // Prefer the new array field; fall back to legacy single-object for old DB records
                    const mitreEntries: {
                      tactic: string;
                      technique: string;
                    }[] =
                      Array.isArray(result.mitreAttack) &&
                      result.mitreAttack.length > 0
                        ? result.mitreAttack
                        : result.mitre
                          ? [result.mitre]
                          : [];

                    if (mitreEntries.length === 0 && !result.cve) return null;

                    return (
                      <motion.div
                        initial={{ opacity: 0, y: 8 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={{ delay: 0.65 }}
                        className="rounded-xl p-4"
                        style={{
                          background: "rgba(124,58,237,0.05)",
                          border: "1px solid rgba(124,58,237,0.2)",
                        }}
                      >
                        {/* Header */}
                        <div className="flex items-center gap-2 mb-3">
                          <span
                            className="text-xs font-bold uppercase tracking-wider"
                            style={{
                              color: "#a78bfa",
                              fontFamily: "'JetBrains Mono', monospace",
                            }}
                          >
                            🎯 MITRE ATT&CK
                          </span>
                          {mitreEntries.length > 1 && (
                            <span
                              className="text-[10px] px-1.5 py-0.5 rounded-full"
                              style={{
                                color: "#a78bfa",
                                background: "rgba(124,58,237,0.15)",
                                border: "1px solid rgba(124,58,237,0.3)",
                                fontFamily: "'JetBrains Mono', monospace",
                              }}
                            >
                              {mitreEntries.length} tactics
                            </span>
                          )}
                        </div>

                        {/* One row per matched tactic/technique */}
                        <div className="flex flex-col gap-2">
                          {mitreEntries.map((entry, idx) => (
                            <div
                              key={idx}
                              className="rounded-lg px-3 py-2.5 flex flex-col gap-1.5"
                              style={{
                                background: "rgba(124,58,237,0.04)",
                                border: "1px solid rgba(124,58,237,0.12)",
                              }}
                            >
                              <div className="flex items-center gap-2 flex-wrap">
                                <span
                                  className="text-[10px] flex-shrink-0"
                                  style={{
                                    color: "var(--text-muted)",
                                    fontFamily: "'JetBrains Mono', monospace",
                                    minWidth: 56,
                                  }}
                                >
                                  Tactic:
                                </span>
                                <span
                                  className="text-xs px-2 py-0.5 rounded"
                                  style={{
                                    color: "#a78bfa",
                                    background: "rgba(124,58,237,0.1)",
                                    border: "1px solid rgba(124,58,237,0.25)",
                                    fontFamily: "'JetBrains Mono', monospace",
                                  }}
                                >
                                  {entry.tactic}
                                </span>
                              </div>
                              <div className="flex items-center gap-2 flex-wrap">
                                <span
                                  className="text-[10px] flex-shrink-0"
                                  style={{
                                    color: "var(--text-muted)",
                                    fontFamily: "'JetBrains Mono', monospace",
                                    minWidth: 56,
                                  }}
                                >
                                  Technique:
                                </span>
                                <span
                                  className="text-xs px-2 py-0.5 rounded"
                                  style={{
                                    color: "var(--text-secondary)",
                                    background: "rgba(124,58,237,0.05)",
                                    border: "1px solid rgba(124,58,237,0.15)",
                                    fontFamily: "'JetBrains Mono', monospace",
                                  }}
                                >
                                  {entry.technique}
                                </span>
                              </div>
                            </div>
                          ))}

                          {/* CVE/CWE row */}
                          {result.cve && (
                            <div className="flex items-center gap-2 flex-wrap mt-0.5">
                              <span
                                className="text-[10px] flex-shrink-0"
                                style={{
                                  color: "var(--text-muted)",
                                  fontFamily: "'JetBrains Mono', monospace",
                                  minWidth: 56,
                                }}
                              >
                                CVE/CWE:
                              </span>
                              <span
                                className="text-xs px-2 py-0.5 rounded"
                                style={{
                                  color: "#f97316",
                                  background: "rgba(249,115,22,0.08)",
                                  border: "1px solid rgba(249,115,22,0.2)",
                                  fontFamily: "'JetBrains Mono', monospace",
                                }}
                              >
                                {result.cve}
                              </span>
                            </div>
                          )}
                        </div>
                      </motion.div>
                    );
                  })()}

                  {/* ── Dark Web Threat Context ── */}
                  {result.inputType === "url" &&
                    result.status !== "safe" &&
                    (() => {
                      const ctx = getThreatContext(scannedInput, result);
                      if (!ctx || ctx.length === 0) return null;
                      return (
                        <motion.div
                          initial={{ opacity: 0, y: 8 }}
                          animate={{ opacity: 1, y: 0 }}
                          transition={{ delay: 0.52 }}
                          className="rounded-xl overflow-hidden"
                          style={{ border: "1px solid rgba(124,58,237,0.25)" }}
                        >
                          <div
                            className="px-5 py-3 flex items-center gap-2"
                            style={{
                              background: "rgba(124,58,237,0.07)",
                              borderBottom: "1px solid rgba(124,58,237,0.15)",
                            }}
                          >
                            <span className="text-base">🕷️</span>
                            <span
                              className="text-xs font-bold uppercase tracking-wider"
                              style={{
                                color: "#a78bfa",
                                fontFamily: "'JetBrains Mono', monospace",
                              }}
                            >
                              Threat Context Intelligence
                            </span>
                            <span
                              className="ml-auto text-xs px-2 py-0.5 rounded"
                              style={{
                                color: "var(--text-muted)",
                                background: "rgba(0,0,0,0.3)",
                                fontFamily: "'JetBrains Mono', monospace",
                              }}
                            >
                              Pattern analysis
                            </span>
                          </div>
                          <div
                            className="px-5 py-4 space-y-2"
                            style={{ background: "var(--bg-card)" }}
                          >
                            {ctx.map((sig, i) => {
                              const riskColor =
                                sig.risk === "critical"
                                  ? "#ff4444"
                                  : sig.risk === "high"
                                    ? "#f97316"
                                    : "#f5a623";
                              return (
                                <div
                                  key={i}
                                  className="flex items-center gap-3 px-3 py-2.5 rounded-lg"
                                  style={{
                                    background: `${riskColor}06`,
                                    border: `1px solid ${riskColor}20`,
                                  }}
                                >
                                  <span className="text-sm flex-shrink-0">
                                    {sig.icon}
                                  </span>
                                  <span
                                    className="text-xs flex-1"
                                    style={{ color: "var(--text-secondary)" }}
                                  >
                                    {sig.label}
                                  </span>
                                  <span
                                    className="text-xs font-bold uppercase px-1.5 py-0.5 rounded flex-shrink-0"
                                    style={{
                                      color: riskColor,
                                      background: `${riskColor}12`,
                                      fontFamily: "'JetBrains Mono', monospace",
                                    }}
                                  >
                                    {sig.risk}
                                  </span>
                                </div>
                              );
                            })}
                            <p
                              className="text-xs pt-1"
                              style={{
                                color: "var(--text-muted)",
                                fontFamily: "'JetBrains Mono', monospace",
                              }}
                            >
                              ↑ Matches known phishing kit naming conventions
                            </p>
                          </div>
                        </motion.div>
                      );
                    })()}

                  {/* ── GAP 12: AI-Generated Content Analysis Panel ── */}
                  {(result as any)?.aiDetection &&
                    (result as any).aiDetection.aiProbability >= 35 && (
                      <motion.div
                        initial={{ opacity: 0, y: 8 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={{ delay: 0.75 }}
                        className="rounded-xl overflow-hidden"
                        style={{ border: "1px solid rgba(167,139,250,0.25)" }}
                      >
                        {/* Section header */}
                        <div
                          className="px-5 py-3 flex items-center gap-2"
                          style={{
                            background: "rgba(167,139,250,0.07)",
                            borderBottom: "1px solid rgba(167,139,250,0.15)",
                          }}
                        >
                          <Brain
                            className="size-4"
                            style={{ color: "#a78bfa" }}
                          />
                          <span
                            className="text-xs font-bold uppercase tracking-wider"
                            style={{
                              color: "#a78bfa",
                              fontFamily: "'JetBrains Mono', monospace",
                            }}
                          >
                            🤖 AI-Generated Content Analysis
                          </span>
                          <span
                            className="ml-auto text-xs px-2 py-0.5 rounded"
                            style={{
                              color: "var(--text-muted)",
                              background: "rgba(0,0,0,0.3)",
                              fontFamily: "'JetBrains Mono', monospace",
                            }}
                          >
                            GAP 12
                          </span>
                        </div>

                        <div
                          className="px-6 py-4"
                          style={{ background: "var(--bg-card)" }}
                        >
                          {/* AI probability verdict banner */}
                          <div
                            className="flex items-center gap-4 px-5 py-4 rounded-xl mb-4"
                            style={{
                              background:
                                (result as any).aiDetection.verdict ===
                                "likely_ai"
                                  ? "rgba(167,139,250,0.08)"
                                  : "rgba(251,191,36,0.07)",
                              border: `1px solid ${
                                (result as any).aiDetection.verdict ===
                                "likely_ai"
                                  ? "rgba(167,139,250,0.25)"
                                  : "rgba(251,191,36,0.25)"
                              }`,
                            }}
                          >
                            <div
                              className="text-3xl font-black"
                              style={{
                                color:
                                  (result as any).aiDetection.verdict ===
                                  "likely_ai"
                                    ? "#a78bfa"
                                    : "#fbbf24",
                                fontFamily: "'JetBrains Mono', monospace",
                              }}
                            >
                              {(result as any).aiDetection.aiProbability}%
                            </div>
                            <div className="flex-1">
                              <div
                                className="font-bold text-sm"
                                style={{
                                  color:
                                    (result as any).aiDetection.verdict ===
                                    "likely_ai"
                                      ? "#a78bfa"
                                      : "#fbbf24",
                                }}
                              >
                                {(result as any).aiDetection.verdictLabel}
                              </div>
                              <div
                                className="text-xs mt-0.5"
                                style={{ color: "var(--text-muted)" }}
                              >
                                {(result as any).aiDetection.verdict ===
                                "likely_ai"
                                  ? "LLM-generated phishing bypasses keyword-based detection — no typos, perfect grammar, professional tone."
                                  : "Linguistic patterns partially consistent with AI generation."}
                              </div>
                            </div>
                            {(result as any).aiDetection.riskBoost > 0 && (
                              <div
                                className="flex-shrink-0 text-xs px-2.5 py-1 rounded-lg font-bold"
                                style={{
                                  color: "#f87171",
                                  background: "rgba(248,113,113,0.1)",
                                  border: "1px solid rgba(248,113,113,0.25)",
                                  fontFamily: "'JetBrains Mono', monospace",
                                }}
                              >
                                +{(result as any).aiDetection.riskBoost} risk
                              </div>
                            )}
                          </div>

                          {/* AI fingerprint phrases */}
                          {(result as any).aiDetection.fingerprintPhrases
                            ?.length > 0 && (
                            <div className="mb-4">
                              <div
                                className="text-[10px] uppercase tracking-wider mb-2 font-bold"
                                style={{
                                  color: "var(--text-muted)",
                                  fontFamily: "'JetBrains Mono', monospace",
                                }}
                              >
                                AI Fingerprint Phrases Detected
                              </div>
                              <div className="flex flex-wrap gap-1.5">
                                {(
                                  result as any
                                ).aiDetection.fingerprintPhrases.map(
                                  (phrase: string, i: number) => (
                                    <span
                                      key={i}
                                      className="text-[10px] px-2.5 py-1 rounded-lg"
                                      style={{
                                        color: "#a78bfa",
                                        background: "rgba(167,139,250,0.1)",
                                        border:
                                          "1px solid rgba(167,139,250,0.25)",
                                        fontFamily:
                                          "'JetBrains Mono', monospace",
                                      }}
                                    >
                                      "{phrase}"
                                    </span>
                                  ),
                                )}
                              </div>
                            </div>
                          )}

                          {/* Linguistic profile grid */}
                          {(result as any).aiDetection.linguisticProfile && (
                            <div className="mb-4">
                              <div
                                className="text-[10px] uppercase tracking-wider mb-2 font-bold"
                                style={{
                                  color: "var(--text-muted)",
                                  fontFamily: "'JetBrains Mono', monospace",
                                }}
                              >
                                Linguistic Profile
                              </div>
                              <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
                                {(
                                  [
                                    {
                                      label: "Word Count",
                                      value: (result as any).aiDetection
                                        .linguisticProfile.wordCount,
                                    },
                                    {
                                      label: "Char Entropy",
                                      value:
                                        (result as any).aiDetection
                                          .linguisticProfile.charEntropy +
                                        " bits",
                                    },
                                    {
                                      label: "Avg Sentence Len",
                                      value:
                                        (result as any).aiDetection
                                          .linguisticProfile.avgSentenceLength +
                                        " words",
                                    },
                                    {
                                      label: "Sentence Std Dev",
                                      value:
                                        (result as any).aiDetection
                                          .linguisticProfile
                                          .sentenceLengthStdDev + " words",
                                      flag:
                                        (result as any).aiDetection
                                          .linguisticProfile
                                          .sentenceLengthStdDev < 4,
                                    },
                                    {
                                      label: "Vocab Richness",
                                      value: (result as any).aiDetection
                                        .linguisticProfile.vocabularyRichness,
                                    },
                                    {
                                      label: "Punct Density",
                                      value:
                                        (result as any).aiDetection
                                          .linguisticProfile
                                          .punctuationDensity + "/word",
                                    },
                                    {
                                      label: "Human Markers",
                                      value: (result as any).aiDetection
                                        .linguisticProfile.humanMarkers,
                                      good:
                                        (result as any).aiDetection
                                          .linguisticProfile.humanMarkers > 0,
                                    },
                                    {
                                      label: "Template Markers",
                                      value: (result as any).aiDetection
                                        .linguisticProfile.templateMarkers,
                                    },
                                  ] as any[]
                                ).map((s) => (
                                  <div
                                    key={s.label}
                                    className="px-3 py-2 rounded-lg"
                                    style={{
                                      background: "var(--bg-elevated)",
                                      border: "1px solid var(--bg-border)",
                                    }}
                                  >
                                    <div
                                      className="text-[9px] uppercase tracking-wider mb-0.5"
                                      style={{
                                        color: "var(--text-muted)",
                                        fontFamily:
                                          "'JetBrains Mono', monospace",
                                      }}
                                    >
                                      {s.label}
                                    </div>
                                    <div
                                      className="text-xs font-bold"
                                      style={{
                                        color: s.flag
                                          ? "#f87171"
                                          : s.good
                                            ? "#34d399"
                                            : "var(--text-primary)",
                                        fontFamily:
                                          "'JetBrains Mono', monospace",
                                      }}
                                    >
                                      {s.value}
                                    </div>
                                  </div>
                                ))}
                              </div>
                            </div>
                          )}

                          {/* Detection signals */}
                          {(result as any).aiDetection.signals?.filter(
                            (s: any) => s.weight > 0,
                          ).length > 0 && (
                            <div>
                              <div
                                className="text-[10px] uppercase tracking-wider mb-2 font-bold"
                                style={{
                                  color: "var(--text-muted)",
                                  fontFamily: "'JetBrains Mono', monospace",
                                }}
                              >
                                Detection Signals
                              </div>
                              <div className="space-y-1.5">
                                {(result as any).aiDetection.signals
                                  .filter((s: any) => s.weight > 0)
                                  .map((sig: any, i: number) => (
                                    <div
                                      key={i}
                                      className="flex items-start gap-2 px-3 py-2 rounded-xl text-xs"
                                      style={{
                                        background: "rgba(167,139,250,0.05)",
                                        border:
                                          "1px solid rgba(167,139,250,0.15)",
                                      }}
                                    >
                                      <span
                                        style={{
                                          color: "#a78bfa",
                                          flex: "0 0 auto",
                                        }}
                                      >
                                        ◆
                                      </span>
                                      <div className="flex-1">
                                        <span
                                          className="font-semibold"
                                          style={{ color: "#a78bfa" }}
                                        >
                                          {sig.label}:{" "}
                                        </span>
                                        <span
                                          style={{
                                            color: "var(--text-muted)",
                                          }}
                                        >
                                          {sig.detail}
                                        </span>
                                        {sig.finding && (
                                          <div
                                            className="mt-0.5 text-[10px] italic"
                                            style={{
                                              color: "var(--text-muted)",
                                            }}
                                          >
                                            {sig.finding}
                                          </div>
                                        )}
                                      </div>
                                      <span
                                        className="ml-auto text-[9px] px-1.5 py-0.5 rounded flex-shrink-0"
                                        style={{
                                          color: "#a78bfa",
                                          background: "rgba(167,139,250,0.1)",
                                          fontFamily:
                                            "'JetBrains Mono', monospace",
                                        }}
                                      >
                                        +{sig.weight}%
                                      </span>
                                    </div>
                                  ))}
                              </div>
                            </div>
                          )}
                        </div>
                      </motion.div>
                    )}

                  {/* Engine tag */}
                  <div className="flex justify-end">
                    <div
                      className="flex items-center gap-2 text-xs px-3 py-1.5 rounded-lg"
                      style={{
                        color: "var(--text-muted)",
                        background: "var(--bg-card)",
                        border: "1px solid var(--bg-border)",
                        fontFamily: "'JetBrains Mono', monospace",
                      }}
                    >
                      <Cpu className="size-3" />
                      engine v{result.detectionVersion} ·{" "}
                      {result.mlEnabled ? "hybrid ML+rules" : "rules only"} ·{" "}
                      {result.inputType} mode
                    </div>
                  </div>
                </motion.div>
              );
            })()}
        </AnimatePresence>
      </div>
    </div>
  );
}
