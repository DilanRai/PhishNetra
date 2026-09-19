// FILE: Frontend/src/pages/Home.tsx — PhishNetra v6.0
// Email-threat focused redesign
// Design system: Geist font, --bg-base #080c14, --accent #3b82f6

import { useState, useEffect, useRef, useCallback } from "react";
import { motion, AnimatePresence } from "motion/react";
import { useNavigate } from "react-router";
import {
  Mail,
  Shield,
  Search,
  AlertTriangle,
  CheckCircle,
  ChevronRight,
  ArrowRight,
  Brain,
  Fingerprint,
  Activity,
  Database,
  Globe,
  Lock,
  Terminal,
  Zap,
  Eye,
  Network,
  Phone,
  FileSearch,
  Clock,
  TrendingUp,
  Users,
  Link as LinkIcon,
  ShieldCheck,
  XCircle,
  Info,
  ExternalLink,
} from "lucide-react";
import { API_BASE } from "../config";

// ── Types ──────────────────────────────────────────────────────
interface LiveStats {
  total?: number;
  phishing?: number;
  suspicious?: number;
  safe?: number;
  threatRate?: number;
}

// ── Animated counter ──────────────────────────────────────────
function useCounter(target: number, duration = 1600) {
  const [count, setCount] = useState(0);
  useEffect(() => {
    if (!target) return;
    let frame = 0;
    const total = Math.ceil(duration / 16);
    const timer = setInterval(() => {
      frame++;
      const progress = frame / total;
      const eased = 1 - Math.pow(1 - progress, 3); // ease-out cubic
      setCount(Math.floor(eased * target));
      if (frame >= total) {
        setCount(target);
        clearInterval(timer);
      }
    }, 16);
    return () => clearInterval(timer);
  }, [target, duration]);
  return count;
}

// ── Typing animation ──────────────────────────────────────────
function useTyping(texts: string[], speed = 55) {
  const [displayed, setDisplayed] = useState("");
  const [idx, setIdx] = useState(0);
  const [char, setChar] = useState(0);
  const [del, setDel] = useState(false);

  useEffect(() => {
    const cur = texts[idx];
    const delay = del ? 22 : char === cur.length ? 2200 : speed;
    const t = setTimeout(() => {
      if (!del) {
        if (char < cur.length) {
          setDisplayed(cur.slice(0, char + 1));
          setChar((c) => c + 1);
        } else setDel(true);
      } else {
        if (char > 0) {
          setDisplayed(cur.slice(0, char - 1));
          setChar((c) => c - 1);
        } else {
          setDel(false);
          setIdx((i) => (i + 1) % texts.length);
        }
      }
    }, delay);
    return () => clearTimeout(t);
  }, [char, del, idx, texts, speed]);
  return displayed;
}

// ── Live scan examples (rotating) ─────────────────────────────
const EXAMPLE_SCANS = [
  {
    input: "paypal-secure-login.tk/verify",
    status: "phishing",
    score: 94,
    technique: "Fake TLD + Brand Spoof",
  },
  {
    input: "SBI Alert: OTP share karo abhi",
    status: "phishing",
    score: 88,
    technique: "Hindi Urgency + OTP Harvest",
  },
  {
    input: "Digital arrest hua hai — CBI officer",
    status: "phishing",
    score: 91,
    technique: "India Digital Arrest Scam",
  },
  {
    input: "https://amazon.in/orders",
    status: "safe",
    score: 2,
    technique: "Verified Domain",
  },
  {
    input: "Your IRCTC account is blocked. Click:",
    status: "suspicious",
    score: 61,
    technique: "Brand Impersonation",
  },
  {
    input: "FedEx: Parcel held. Pay ₹499 now:",
    status: "phishing",
    score: 85,
    technique: "Courier Scam Pattern",
  },
];

const statusCfg = (s: string) =>
  ({
    phishing: {
      color: "#f87171",
      bg: "rgba(248,113,113,0.08)",
      border: "rgba(248,113,113,0.2)",
      label: "PHISHING",
    },
    suspicious: {
      color: "#fbbf24",
      bg: "rgba(251,191,36,0.08)",
      border: "rgba(251,191,36,0.2)",
      label: "SUSPICIOUS",
    },
    safe: {
      color: "#34d399",
      bg: "rgba(52,211,153,0.08)",
      border: "rgba(52,211,153,0.18)",
      label: "SAFE",
    },
  })[s] || {
    color: "#64748b",
    bg: "transparent",
    border: "transparent",
    label: "UNKNOWN",
  };

// ── Detection features ─────────────────────────────────────────
const FEATURES = [
  {
    icon: Mail,
    color: "#60a5fa",
    tag: "EMAIL",
    title: "Email Header Forensics",
    desc: "Full SMTP relay chain reconstruction. Live SPF, DKIM, DMARC validation via real DNS — not header trust. Catches spoofed authentication headers.",
  },
  {
    icon: Globe,
    color: "#a78bfa",
    tag: "DOMAIN",
    title: "Domain & IP Reputation",
    desc: "6 DNSBL checks (Spamhaus ZEN, Barracuda, SORBS, SpamCop, UCEPROTECT, SpamRats), TOR exit node detection, VPN/datacenter flag, repeat-offender tracking.",
  },
  {
    icon: Brain,
    color: "#34d399",
    tag: "AI",
    title: "AI-Generated Text Detection",
    desc: "36 LLM fingerprint phrases, sentence uniformity scoring, zero-casual language flag. Detects ChatGPT-written phishing emails that fool traditional filters.",
  },
  {
    icon: Phone,
    color: "#fbbf24",
    tag: "INDIA",
    title: "India Fraud Pattern Engine",
    desc: "Digital Arrest, TRAI SIM block, UPI harvest, FedEx drug parcel, electricity scam — Hindi & Hinglish detection with IOC keyword extraction and 1930 helpline.",
  },
  {
    icon: FileSearch,
    color: "#fb923c",
    tag: "ATTACH",
    title: "Deep Attachment Analysis",
    desc: "VirusTotal SHA-256 hash lookup, Office VBA/XLM macro detection, remote template injection URLs, PDF embedded JS/Launch/OpenAction actions.",
  },
  {
    icon: Fingerprint,
    color: "#f87171",
    tag: "INTEL",
    title: "Attribution Intelligence",
    desc: "13-signal attribution scoring — TOR, VPN, residential, DNSBL, repeat-offender. 6 actor types. Legal investigation paths: Section 91 CrPC, MLAT, CERT-In.",
  },
  {
    icon: Network,
    color: "#a78bfa",
    tag: "CAMPAIGN",
    title: "Campaign Case Management",
    desc: "Graph-based email sender correlation, auto-clusters by IP/domain/MX/replyTo. Named cases with analyst notes, forensic ID chain of custody, and timeline.",
  },
  {
    icon: Shield,
    color: "#3b82f6",
    tag: "SIEM",
    title: "SentinelCore SIEM",
    desc: "94 MITRE-mapped detection rules, Sigma + Splunk ESCU enrichment, SLA timers, custom rules, shift handover notes, correlated alert chains.",
  },
  {
    icon: Eye,
    color: "#34d399",
    tag: "EVASION",
    title: "Evasion-Resistance Engine",
    desc: "Second-pass scoring catches threshold engineering. Minimum evidence requirements prevent false negatives on carefully crafted low-signal phishing.",
  },
];

// ── How it works steps ─────────────────────────────────────────
const PIPELINE = [
  {
    step: "01",
    icon: Search,
    color: "#3b82f6",
    title: "Input",
    desc: "Paste URL, full email headers, email body, SMS, or domain. Auto-detects input type.",
    tags: ["URL", "Headers", "SMS", "Domain"],
  },
  {
    step: "02",
    icon: Mail,
    color: "#60a5fa",
    title: "Header Forensics",
    desc: "Live DNS for SPF/MX, SMTP relay reconstruction, DNSBL × 6, IP geolocation, TOR check.",
    tags: ["SPF Live", "DNSBL", "Relay Chain", "TOR"],
  },
  {
    step: "03",
    icon: Brain,
    color: "#a78bfa",
    title: "ML + 64 Rules",
    desc: "Neural network (15→32→16→1, 85.4% acc) blended with 64 rule checks for final risk score.",
    tags: ["ML v4", "64 Checks", "Hybrid Score"],
  },
  {
    step: "04",
    icon: Fingerprint,
    color: "#34d399",
    title: "Attribution & SIEM",
    desc: "13-signal attribution, PhishDNA fingerprint, MITRE mapping, forensic chain of custody, SIEM alert.",
    tags: ["MITRE", "Attribution", "SIEM", "PDF Report"],
  },
];

// ── Radar SVG ─────────────────────────────────────────────────
function ThreatRadar() {
  return (
    <div className="relative w-72 h-72 mx-auto">
      {[1, 2, 3, 4].map((r) => (
        <div
          key={r}
          className="absolute inset-0 rounded-full border"
          style={{
            margin: `${(r - 1) * 18}px`,
            borderColor: `rgba(52,211,153,${0.06 + r * 0.03})`,
          }}
        />
      ))}
      <motion.div className="absolute inset-0 rounded-full overflow-hidden">
        <motion.div
          animate={{ rotate: 360 }}
          transition={{ duration: 4, repeat: Infinity, ease: "linear" }}
          className="absolute inset-0"
          style={{ transformOrigin: "center" }}
        >
          <div
            className="absolute top-0 left-1/2 -translate-x-1/2 w-0.5 h-1/2"
            style={{
              background:
                "linear-gradient(to bottom, #3b82f6 0%, transparent 100%)",
              transformOrigin: "bottom center",
              opacity: 0.7,
            }}
          />
          <div
            className="absolute inset-0"
            style={{
              background:
                "conic-gradient(from 0deg at 50% 50%, rgba(52,211,153,0.1) 0deg, transparent 60deg)",
              transformOrigin: "center",
            }}
          />
        </motion.div>
      </motion.div>
      <div className="absolute inset-0 flex items-center justify-center">
        <div
          className="w-full h-px"
          style={{ background: "rgba(52,211,153,0.08)" }}
        />
      </div>
      <div className="absolute inset-0 flex items-center justify-center">
        <div
          className="w-px h-full"
          style={{ background: "rgba(52,211,153,0.08)" }}
        />
      </div>
      {[
        { cx: "55%", cy: "32%", size: 6, color: "#f87171", delay: 0.5 },
        { cx: "72%", cy: "60%", size: 5, color: "#fbbf24", delay: 1.2 },
        { cx: "38%", cy: "68%", size: 7, color: "#f87171", delay: 2.0 },
        { cx: "25%", cy: "42%", size: 4, color: "#fb923c", delay: 0.8 },
        { cx: "60%", cy: "75%", size: 5, color: "#fbbf24", delay: 1.6 },
      ].map((dot, i) => (
        <motion.div
          key={i}
          initial={{ opacity: 0, scale: 0 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{
            delay: dot.delay,
            duration: 0.4,
            ease: [0.34, 1.56, 0.64, 1],
          }}
          className="absolute rounded-full"
          style={{
            left: dot.cx,
            top: dot.cy,
            width: dot.size,
            height: dot.size,
            background: dot.color,
            transform: "translate(-50%,-50%)",
            boxShadow: `0 0 8px ${dot.color}`,
          }}
        >
          <motion.div
            className="absolute inset-0 rounded-full"
            animate={{ scale: [1, 2.5], opacity: [0.6, 0] }}
            transition={{ duration: 2, repeat: Infinity, delay: dot.delay }}
            style={{ background: dot.color }}
          />
        </motion.div>
      ))}
      <div className="absolute inset-0 flex items-center justify-center">
        <div
          className="w-12 h-12 rounded-full flex items-center justify-center"
          style={{
            background: "var(--bg-elevated)",
            border: "1px solid var(--bg-border)",
          }}
        >
          <Shield className="size-6" style={{ color: "#3b82f6" }} />
        </div>
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════
// MAIN HOME COMPONENT
// ═══════════════════════════════════════════════════════════════
export default function Home() {
  const navigate = useNavigate();
  const statsRef = useRef<HTMLDivElement>(null);

  const [input, setInput] = useState("");
  const [liveStats, setLiveStats] = useState<LiveStats>({});
  const [threatIdx, setThreatIdx] = useState(0);
  const [statsVisible, setStatsVisible] = useState(false);
  const [activeTab, setActiveTab] = useState<"url" | "email" | "sms">("email");
  const [showPanel, setShowPanel] = useState(true);

  const TYPING_EXAMPLES = {
    url: [
      "paypal-secure-login.tk/verify",
      "micr0soft-auth.example/reset",
      "http://secure-update.ml/login",
    ],
    email: [
      "Paste email headers here...",
      "Received: from mail.attacker.ru...",
      "X-Originating-IP: 185.234.x.x",
    ],
    sms: [
      "FedEx: Parcel seized. Pay ₹499 to release: bit.ly/xxx",
      "TRAI: Your number will be blocked. Call 9876543210",
      "Digital arrest hua — CBI officer line pe hai",
    ],
  };

  const typingText = useTyping(TYPING_EXAMPLES[activeTab]);

  // Fetch live stats
  useEffect(() => {
    fetch(`${API_BASE}/api/scan/stats`)
      .then((r) => (r.ok ? r.json() : null))
      .then((d) => {
        if (d) setLiveStats(d);
      })
      .catch(() => {});
  }, []);

  // Cycle scans
  useEffect(() => {
    const t = setInterval(() => {
      setShowPanel(false);
      setTimeout(() => {
        setThreatIdx((i) => (i + 1) % EXAMPLE_SCANS.length);
        setShowPanel(true);
      }, 380);
    }, 3200);
    return () => clearInterval(t);
  }, []);

  // Intersection observer for stats
  useEffect(() => {
    const obs = new IntersectionObserver(
      ([e]) => {
        if (e.isIntersecting) setStatsVisible(true);
      },
      { threshold: 0.3 },
    );
    if (statsRef.current) obs.observe(statsRef.current);
    return () => obs.disconnect();
  }, []);

  const totalScans = useCounter(
    statsVisible ? liveStats.total || 18420 : 0,
    1600,
  );
  const phishCount = useCounter(
    statsVisible ? liveStats.phishing || 4103 : 0,
    1400,
  );
  const accuracy = useCounter(statsVisible ? 85 : 0, 1000);
  const patterns = useCounter(statsVisible ? 64 : 0, 900);

  const handleScan = useCallback(() => {
    if (!input.trim()) return;
    navigate("/scan", { state: { url: input.trim() } });
  }, [input, navigate]);

  const TAB_CONFIGS = [
    {
      key: "email" as const,
      label: "Email Headers",
      icon: Mail,
      color: "#60a5fa",
    },
    {
      key: "url" as const,
      label: "URL / Domain",
      icon: Globe,
      color: "#3b82f6",
    },
    {
      key: "sms" as const,
      label: "SMS / Smishing",
      icon: Phone,
      color: "#fbbf24",
    },
  ];

  return (
    <div className="min-h-full" style={{ background: "var(--bg-base)" }}>
      {/* ═══ HERO ══════════════════════════════════════════════ */}
      <section
        className="relative min-h-screen flex items-center"
        style={{ paddingTop: 72, paddingBottom: 64 }}
      >
        {/* Background glows */}
        <div className="absolute inset-0 pointer-events-none overflow-hidden">
          <div
            className="absolute"
            style={{
              top: "-10%",
              left: "55%",
              transform: "translateX(-50%)",
              width: 900,
              height: 600,
              background:
                "radial-gradient(ellipse, rgba(59,130,246,0.05) 0%, transparent 65%)",
            }}
          />
          <div
            className="absolute"
            style={{
              top: "40%",
              left: "10%",
              width: 500,
              height: 500,
              background:
                "radial-gradient(ellipse, rgba(96,165,250,0.04) 0%, transparent 70%)",
            }}
          />
        </div>

        <div className="relative z-10 max-w-7xl mx-auto px-6 w-full">
          <div className="grid lg:grid-cols-2 gap-14 items-center">
            {/* ── LEFT COLUMN ── */}
            <div>
              {/* Live status badge */}
              <motion.div
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.45, ease: [0.23, 1, 0.32, 1] }}
                className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full mb-8"
                style={{
                  background: "rgba(59,130,246,0.06)",
                  border: "1px solid rgba(59,130,246,0.15)",
                }}
              >
                <div
                  className="w-1.5 h-1.5 rounded-full"
                  style={{
                    background: "#3b82f6",
                    boxShadow: "0 0 6px #3b82f6",
                  }}
                />
                <span
                  className="text-xs font-medium"
                  style={{ color: "#60a5fa", fontFamily: "var(--font-mono)" }}
                >
                  Email Threat Detection Engine · v6.0 · Active
                </span>
              </motion.div>

              <motion.h1
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{
                  duration: 0.55,
                  delay: 0.05,
                  ease: [0.23, 1, 0.32, 1],
                }}
                style={{
                  fontSize: "clamp(2.6rem,4.8vw,4rem)",
                  fontWeight: 800,
                  color: "var(--text-primary)",
                  lineHeight: 1.06,
                  letterSpacing: "-0.04em",
                  marginBottom: "1.25rem",
                }}
              >
                Detect phishing emails
                <br />
                <span style={{ color: "#3b82f6" }}>before the click.</span>
              </motion.h1>

              <motion.p
                initial={{ opacity: 0, y: 12 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{
                  duration: 0.55,
                  delay: 0.1,
                  ease: [0.23, 1, 0.32, 1],
                }}
                className="text-base mb-8 max-w-lg leading-relaxed"
                style={{ color: "var(--text-secondary)" }}
              >
                Paste email headers, URLs, or SMS text. PhishNetra reconstructs
                the SMTP relay chain, validates SPF/DKIM/DMARC live via DNS,
                runs 6 DNSBL checks, and scores with an ML model trained on real
                phishing datasets — including India-specific fraud patterns.
              </motion.p>

              {/* ── Input area with tabs ── */}
              <motion.div
                initial={{ opacity: 0, y: 12 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{
                  duration: 0.55,
                  delay: 0.15,
                  ease: [0.23, 1, 0.32, 1],
                }}
                className="mb-6"
              >
                {/* Tab selector */}
                <div className="flex gap-1 mb-3">
                  {TAB_CONFIGS.map((tab) => {
                    const Icon = tab.icon;
                    const active = activeTab === tab.key;
                    return (
                      <button
                        key={tab.key}
                        onClick={() => {
                          setActiveTab(tab.key);
                          setInput("");
                        }}
                        className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-all"
                        style={{
                          background: active ? `${tab.color}10` : "transparent",
                          border: active
                            ? `1px solid ${tab.color}28`
                            : "1px solid transparent",
                          color: active ? tab.color : "var(--text-muted)",
                          fontFamily: "var(--font-mono)",
                        }}
                      >
                        <Icon className="size-3" />
                        {tab.label}
                      </button>
                    );
                  })}
                </div>

                {/* Input field */}
                <div className="relative mb-3">
                  {activeTab === "email" ? (
                    <textarea
                      value={input}
                      onChange={(e) => setInput(e.target.value)}
                      onKeyDown={(e) =>
                        e.key === "Enter" && e.ctrlKey && handleScan()
                      }
                      placeholder={
                        typingText ||
                        "Paste raw email headers (Received:, X-Originating-IP:, DKIM-Signature:...)"
                      }
                      rows={4}
                      className="w-full px-4 py-3 text-sm rounded-xl resize-none"
                      style={{
                        background: "var(--bg-card)",
                        border: "1px solid var(--bg-border)",
                        color: "var(--text-primary)",
                        fontFamily: "var(--font-mono)",
                        fontSize: "11px",
                        lineHeight: 1.7,
                        outline: "none",
                      }}
                    />
                  ) : (
                    <input
                      type="text"
                      value={input}
                      onChange={(e) => setInput(e.target.value)}
                      onKeyDown={(e) => e.key === "Enter" && handleScan()}
                      placeholder={
                        typingText ||
                        (activeTab === "url"
                          ? "Paste URL or domain..."
                          : "Paste SMS message...")
                      }
                      className="w-full px-4 py-3.5 text-sm rounded-xl"
                      style={{
                        background: "var(--bg-card)",
                        border: "1px solid var(--bg-border)",
                        color: "var(--text-primary)",
                        fontFamily:
                          activeTab === "url" ? "var(--font-mono)" : "inherit",
                        fontSize: "13px",
                        outline: "none",
                      }}
                    />
                  )}
                </div>

                {/* Action buttons */}
                <div className="flex gap-2">
                  <button
                    onClick={handleScan}
                    className="flex-1 flex items-center justify-center gap-2 py-3 rounded-xl text-sm font-semibold transition-all"
                    style={{
                      background: "#3b82f6",
                      color: "#fff",
                      boxShadow: "0 0 0 0 rgba(59,130,246,0)",
                    }}
                    onMouseEnter={(e) =>
                      (e.currentTarget.style.background = "#2563eb")
                    }
                    onMouseLeave={(e) =>
                      (e.currentTarget.style.background = "#3b82f6")
                    }
                  >
                    <Search className="size-4" />
                    {activeTab === "email"
                      ? "Analyze Headers"
                      : activeTab === "url"
                        ? "Scan URL"
                        : "Analyze SMS"}
                  </button>
                  <button
                    onClick={() => navigate("/email-forensics")}
                    className="flex items-center gap-2 px-4 py-3 rounded-xl text-sm font-medium transition-all"
                    style={{
                      background: "var(--bg-card)",
                      border: "1px solid var(--bg-border)",
                      color: "var(--text-secondary)",
                    }}
                    onMouseEnter={(e) =>
                      (e.currentTarget.style.borderColor = "#60a5fa40")
                    }
                    onMouseLeave={(e) =>
                      (e.currentTarget.style.borderColor = "var(--bg-border)")
                    }
                  >
                    <Mail className="size-4" style={{ color: "#60a5fa" }} />
                    <span style={{ color: "#60a5fa" }}>Full Forensics</span>
                  </button>
                </div>

                <p
                  className="text-xs mt-2.5"
                  style={{
                    color: "var(--text-muted)",
                    fontFamily: "var(--font-mono)",
                  }}
                >
                  {activeTab === "email"
                    ? "Paste full raw headers including Received:, Authentication-Results:, DKIM-Signature:"
                    : activeTab === "url"
                      ? "URL · Domain · IP address · Ctrl+Enter to scan"
                      : "SMS, WhatsApp message, or phone call script in English or Hindi/Hinglish"}
                </p>
              </motion.div>

              {/* Quick links */}
              <motion.div
                initial={{ opacity: 0, y: 8 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.45, delay: 0.22 }}
                className="flex items-center gap-2 flex-wrap"
              >
                {[
                  {
                    label: "SIEM Dashboard",
                    icon: Activity,
                    path: "/siem",
                    color: "#3b82f6",
                  },
                  {
                    label: "Campaign Tracker",
                    icon: Network,
                    path: "/campaigns",
                    color: "#a78bfa",
                  },
                  {
                    label: "Evidence Vault",
                    icon: Database,
                    path: "/evidence",
                    color: "#34d399",
                  },
                ].map((l) => {
                  const Icon = l.icon;
                  return (
                    <button
                      key={l.label}
                      onClick={() => navigate(l.path)}
                      className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs transition-all"
                      style={{
                        background: "var(--bg-card)",
                        border: "1px solid var(--bg-border)",
                        color: "var(--text-muted)",
                      }}
                      onMouseEnter={(e) => {
                        e.currentTarget.style.borderColor = `${l.color}30`;
                        e.currentTarget.style.color = l.color;
                      }}
                      onMouseLeave={(e) => {
                        e.currentTarget.style.borderColor = "var(--bg-border)";
                        e.currentTarget.style.color = "var(--text-muted)";
                      }}
                    >
                      <Icon className="size-3" />
                      {l.label}
                      <ChevronRight className="size-2.5" />
                    </button>
                  );
                })}
              </motion.div>
            </div>

            {/* RIGHT — Radar + live scan ticker */}
            <motion.div
              initial={{ opacity: 0, scale: 0.94 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={{
                duration: 0.8,
                delay: 0.15,
                ease: [0.23, 1, 0.32, 1],
              }}
              className="hidden lg:block relative"
            >
              {/* Floating threat labels */}
              {[
                {
                  label: "Digital Arrest Scam",
                  color: "#f87171",
                  x: "0%",
                  y: "12%",
                  delay: 0,
                },
                {
                  label: "AiTM Proxy",
                  color: "#f87171",
                  x: "74%",
                  y: "12%",
                  delay: 0.4,
                },
                {
                  label: "UPI Fraud",
                  color: "#fbbf24",
                  x: "72%",
                  y: "65%",
                  delay: 0.8,
                },
                {
                  label: "BEC Attack",
                  color: "#fb923c",
                  x: "2%",
                  y: "62%",
                  delay: 1.2,
                },
                {
                  label: "Phishing Kit",
                  color: "#fbbf24",
                  x: "36%",
                  y: "-18%",
                  delay: 0.6,
                },
              ].map((t, i) => (
                <motion.div
                  key={i}
                  initial={{ opacity: 0, scale: 0.8, y: 10 }}
                  animate={{ opacity: 1, scale: 1, y: 0 }}
                  transition={{
                    delay: t.delay + 0.6,
                    duration: 0.5,
                    ease: [0.34, 1.56, 0.64, 1],
                  }}
                  style={{
                    position: "absolute",
                    left: t.x,
                    top: t.y,
                    zIndex: 10,
                  }}
                >
                  <div
                    className="flex items-center gap-2 px-3 py-1.5 rounded-lg"
                    style={{
                      background: `${t.color}12`,
                      border: `1px solid ${t.color}30`,
                      backdropFilter: "blur(12px)",
                    }}
                  >
                    <div
                      className="w-1.5 h-1.5 rounded-full"
                      style={{ background: t.color }}
                    />
                    <span
                      className="text-xs font-semibold whitespace-nowrap"
                      style={{ color: t.color, fontFamily: "var(--font-mono)" }}
                    >
                      {t.label}
                    </span>
                  </div>
                </motion.div>
              ))}

              <ThreatRadar />

              {/* Live scan ticker */}
              <div className="mt-14 mx-auto max-w-xs relative z-20">
                <div
                  className="rounded-xl overflow-hidden"
                  style={{
                    background: "var(--bg-elevated)",
                    border: "1px solid var(--bg-border)",
                  }}
                >
                  <div
                    className="px-4 py-2 border-b flex items-center"
                    style={{ borderColor: "var(--bg-border)" }}
                  >
                    <div
                      className="w-2.5 h-2.5 rounded-full mr-1.5"
                      style={{ background: "#ff5f57" }}
                    />
                    <div
                      className="w-2.5 h-2.5 rounded-full mr-1.5"
                      style={{ background: "#febc2e" }}
                    />
                    <div
                      className="w-2.5 h-2.5 rounded-full mr-1.5"
                      style={{ background: "#28c840" }}
                    />
                    <span
                      className="ml-2 text-[10px]"
                      style={{
                        color: "var(--text-muted)",
                        fontFamily: "var(--font-mono)",
                      }}
                    >
                      live · detection engine
                    </span>
                    <div
                      className="ml-auto text-[9px] font-bold"
                      style={{
                        color: "#34d399",
                        fontFamily: "var(--font-mono)",
                      }}
                    >
                      ACTIVE
                    </div>
                  </div>
                  <AnimatePresence mode="wait">
                    <motion.div
                      key={threatIdx}
                      initial={{ opacity: 0, y: 6 }}
                      animate={{ opacity: 1, y: 0 }}
                      exit={{ opacity: 0, y: -6 }}
                      transition={{ duration: 0.3 }}
                      className="px-4 py-3 flex items-center gap-3"
                    >
                      {(() => {
                        const scan = EXAMPLE_SCANS[threatIdx];
                        const cfg = statusCfg(scan.status);
                        return (
                          <>
                            <div
                              className="w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0 text-xs font-bold"
                              style={{
                                background: cfg.bg,
                                border: `1px solid ${cfg.border}`,
                                color: cfg.color,
                                fontFamily: "var(--font-mono)",
                              }}
                            >
                              {scan.score}
                            </div>
                            <div className="flex-1 min-w-0">
                              <code
                                className="text-[10px] truncate block"
                                style={{
                                  color: "var(--text-secondary)",
                                  fontFamily: "var(--font-mono)",
                                }}
                              >
                                {scan.input}
                              </code>
                              <div
                                className="text-[9px] mt-0.5"
                                style={{
                                  color: "var(--text-muted)",
                                  fontFamily: "var(--font-mono)",
                                }}
                              >
                                {scan.technique}
                              </div>
                            </div>
                            <span
                              className="text-[9px] font-bold px-2 py-0.5 rounded flex-shrink-0"
                              style={{
                                color: cfg.color,
                                background: cfg.bg,
                                border: `1px solid ${cfg.border}`,
                                fontFamily: "var(--font-mono)",
                              }}
                            >
                              {cfg.label}
                            </span>
                          </>
                        );
                      })()}
                    </motion.div>
                  </AnimatePresence>
                </div>
              </div>
            </motion.div>
          </div>
        </div>
      </section>

      {/* ═══ STATS STRIP ═══════════════════════════════════════ */}
      <div ref={statsRef}>
        <section
          className="border-y"
          style={{
            borderColor: "var(--bg-border)",
            background: "var(--bg-surface)",
          }}
        >
          <div className="max-w-5xl mx-auto px-6 py-12">
            <div className="grid grid-cols-2 md:grid-cols-4 gap-6">
              {[
                {
                  value: totalScans,
                  suffix: "",
                  label: "Total Scans",
                  sub: "all time",
                  color: "#3b82f6",
                  icon: Database,
                },
                {
                  value: phishCount,
                  suffix: "",
                  label: "Threats Caught",
                  sub: "phishing + susp",
                  color: "#f87171",
                  icon: AlertTriangle,
                },
                {
                  value: accuracy,
                  suffix: "%",
                  label: "ML Accuracy",
                  sub: "v4 model",
                  color: "#a78bfa",
                  icon: Brain,
                },
                {
                  value: patterns,
                  suffix: "",
                  label: "Detection Patterns",
                  sub: "rules + ML signals",
                  color: "#34d399",
                  icon: ShieldCheck,
                },
              ].map((s, i) => {
                const Icon = s.icon;
                return (
                  <motion.div
                    key={s.label}
                    initial={{ opacity: 0, y: 16 }}
                    whileInView={{ opacity: 1, y: 0 }}
                    viewport={{ once: true }}
                    transition={{ delay: i * 0.07, duration: 0.45 }}
                    className="flex items-center gap-4"
                  >
                    <div
                      className="w-10 h-10 rounded-xl flex items-center justify-center flex-shrink-0"
                      style={{
                        background: `${s.color}10`,
                        border: `1px solid ${s.color}20`,
                      }}
                    >
                      <Icon className="size-5" style={{ color: s.color }} />
                    </div>
                    <div>
                      <div
                        className="text-2xl font-black leading-none mb-0.5"
                        style={{
                          color: s.color,
                          fontFamily: "var(--font-mono)",
                          letterSpacing: "-0.03em",
                        }}
                      >
                        {s.value.toLocaleString()}
                        {s.suffix}
                      </div>
                      <div
                        className="text-xs font-semibold"
                        style={{ color: "var(--text-secondary)" }}
                      >
                        {s.label}
                      </div>
                      <div
                        className="text-[9px]"
                        style={{
                          color: "var(--text-muted)",
                          fontFamily: "var(--font-mono)",
                        }}
                      >
                        {s.sub}
                      </div>
                    </div>
                  </motion.div>
                );
              })}
            </div>
          </div>
        </section>
      </div>

      {/* ═══ PIPELINE ══════════════════════════════════════════ */}
      <section className="py-20 px-6">
        <div className="max-w-5xl mx-auto">
          <motion.div
            initial={{ opacity: 0, y: 14 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.45 }}
            className="text-center mb-14"
          >
            <div
              className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs mb-5"
              style={{
                background: "rgba(59,130,246,0.06)",
                border: "1px solid rgba(59,130,246,0.14)",
                color: "#60a5fa",
                fontFamily: "var(--font-mono)",
              }}
            >
              How it works
            </div>
            <h2
              className="text-3xl font-bold mb-3"
              style={{ color: "var(--text-primary)", letterSpacing: "-0.03em" }}
            >
              Four-layer detection pipeline
            </h2>
            <p
              className="text-sm max-w-md mx-auto"
              style={{ color: "var(--text-secondary)" }}
            >
              Every submission runs through header forensics, ML scoring, rule
              matching, and attribution — in under 2 seconds.
            </p>
          </motion.div>

          <div className="relative">
            {/* Connector line */}
            <div
              className="hidden md:block absolute top-10 left-0 right-0 h-px"
              style={{
                background:
                  "linear-gradient(90deg, transparent, var(--bg-border), var(--bg-border), transparent)",
                zIndex: 0,
              }}
            />

            <div className="grid md:grid-cols-4 gap-4 relative z-10">
              {PIPELINE.map((step, i) => {
                const Icon = step.icon;
                return (
                  <motion.div
                    key={step.step}
                    initial={{ opacity: 0, y: 16 }}
                    whileInView={{ opacity: 1, y: 0 }}
                    viewport={{ once: true }}
                    transition={{
                      delay: i * 0.1,
                      duration: 0.45,
                      ease: [0.23, 1, 0.32, 1],
                    }}
                    className="rounded-xl p-5"
                    style={{
                      background: "var(--bg-card)",
                      border: "1px solid var(--bg-border)",
                    }}
                  >
                    {/* Step icon with number */}
                    <div className="flex items-center gap-3 mb-4">
                      <div
                        className="w-10 h-10 rounded-xl flex items-center justify-center"
                        style={{
                          background: `${step.color}10`,
                          border: `1px solid ${step.color}22`,
                        }}
                      >
                        <Icon
                          className="size-5"
                          style={{ color: step.color }}
                        />
                      </div>
                      <span
                        className="text-xs font-bold"
                        style={{
                          color: "var(--text-muted)",
                          fontFamily: "var(--font-mono)",
                        }}
                      >
                        {step.step}
                      </span>
                    </div>
                    <h3
                      className="text-sm font-semibold mb-2"
                      style={{
                        color: "var(--text-primary)",
                        letterSpacing: "-0.01em",
                      }}
                    >
                      {step.title}
                    </h3>
                    <p
                      className="text-xs leading-relaxed mb-3"
                      style={{ color: "var(--text-muted)" }}
                    >
                      {step.desc}
                    </p>
                    <div className="flex flex-wrap gap-1">
                      {step.tags.map((t) => (
                        <span
                          key={t}
                          className="text-[9px] px-1.5 py-0.5 rounded"
                          style={{
                            color: step.color,
                            background: `${step.color}0d`,
                            border: `1px solid ${step.color}20`,
                            fontFamily: "var(--font-mono)",
                          }}
                        >
                          {t}
                        </span>
                      ))}
                    </div>
                  </motion.div>
                );
              })}
            </div>
          </div>
        </div>
      </section>

      {/* ═══ EMAIL THREAT ANATOMY (unique section) ══════════════ */}
      <section
        className="py-20 px-6 border-t"
        style={{
          borderColor: "var(--bg-border)",
          background: "var(--bg-surface)",
        }}
      >
        <div className="max-w-5xl mx-auto">
          <motion.div
            initial={{ opacity: 0, y: 14 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            className="mb-12"
          >
            <div
              className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs mb-5"
              style={{
                background: "rgba(96,165,250,0.06)",
                border: "1px solid rgba(96,165,250,0.14)",
                color: "#60a5fa",
                fontFamily: "var(--font-mono)",
              }}
            >
              <Mail className="size-3" /> Email Threat Anatomy
            </div>
            <h2
              className="text-3xl font-bold mb-3"
              style={{ color: "var(--text-primary)", letterSpacing: "-0.03em" }}
            >
              What PhishNetra reads in an email
            </h2>
            <p
              className="text-sm max-w-xl"
              style={{ color: "var(--text-secondary)" }}
            >
              Most tools only check the visible content. PhishNetra reads the
              infrastructure — every hop the email passed through, the
              authentication it failed, and the IP it came from.
            </p>
          </motion.div>

          <div className="grid md:grid-cols-3 gap-4">
            {[
              {
                label: "SMTP Relay Chain",
                icon: Network,
                color: "#60a5fa",
                items: [
                  "Full hop-by-hop reconstruction",
                  "Time travel detection (future timestamps)",
                  "Localhost injection flag",
                  "Bulletproof host identification",
                  "Geographic path anomalies",
                ],
              },
              {
                label: "Authentication",
                icon: ShieldCheck,
                color: "#34d399",
                items: [
                  "SPF validation via live DNS lookup",
                  "DKIM signature verification",
                  "DMARC policy enforcement check",
                  "Display name vs envelope mismatch",
                  "Reply-To hijacking detection",
                ],
              },
              {
                label: "Infrastructure Intel",
                icon: Globe,
                color: "#a78bfa",
                items: [
                  "6 DNSBL checks (Spamhaus, SORBS…)",
                  "TOR exit node detection",
                  "VPN / datacenter flag",
                  "IP geolocation + ISP",
                  "MongoDB repeat-offender tracking",
                ],
              },
            ].map((panel, i) => {
              const Icon = panel.icon;
              return (
                <motion.div
                  key={panel.label}
                  initial={{ opacity: 0, y: 14 }}
                  whileInView={{ opacity: 1, y: 0 }}
                  viewport={{ once: true }}
                  transition={{ delay: i * 0.1, duration: 0.45 }}
                  className="rounded-xl overflow-hidden"
                  style={{
                    background: "var(--bg-card)",
                    border: "1px solid var(--bg-border)",
                  }}
                >
                  <div
                    className="px-5 py-3.5 border-b flex items-center gap-2.5"
                    style={{
                      borderColor: "var(--bg-border)",
                      background: "var(--bg-elevated)",
                    }}
                  >
                    <div
                      className="w-7 h-7 rounded-lg flex items-center justify-center"
                      style={{
                        background: `${panel.color}10`,
                        border: `1px solid ${panel.color}20`,
                      }}
                    >
                      <Icon className="size-4" style={{ color: panel.color }} />
                    </div>
                    <span
                      className="text-xs font-bold tracking-wider"
                      style={{
                        color: panel.color,
                        fontFamily: "var(--font-mono)",
                      }}
                    >
                      {panel.label}
                    </span>
                  </div>
                  <div className="p-5 space-y-2.5">
                    {panel.items.map((item, j) => (
                      <motion.div
                        key={item}
                        initial={{ opacity: 0, x: -6 }}
                        whileInView={{ opacity: 1, x: 0 }}
                        viewport={{ once: true }}
                        transition={{ delay: i * 0.1 + j * 0.06 }}
                        className="flex items-start gap-2.5"
                      >
                        <ChevronRight
                          className="size-3.5 flex-shrink-0 mt-0.5"
                          style={{ color: panel.color }}
                        />
                        <span
                          className="text-xs leading-snug"
                          style={{ color: "var(--text-secondary)" }}
                        >
                          {item}
                        </span>
                      </motion.div>
                    ))}
                  </div>
                </motion.div>
              );
            })}
          </div>
        </div>
      </section>

      {/* ═══ FEATURES GRID ═════════════════════════════════════ */}
      <section className="py-20 px-6">
        <div className="max-w-5xl mx-auto">
          <motion.div
            initial={{ opacity: 0, y: 14 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            className="mb-12 flex items-end justify-between flex-wrap gap-4"
          >
            <div>
              <div
                className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs mb-5"
                style={{
                  background: "rgba(59,130,246,0.06)",
                  border: "1px solid rgba(59,130,246,0.14)",
                  color: "#60a5fa",
                  fontFamily: "var(--font-mono)",
                }}
              >
                All Features
              </div>
              <h2
                className="text-3xl font-bold"
                style={{
                  color: "var(--text-primary)",
                  letterSpacing: "-0.03em",
                }}
              >
                Built for real SOC work.
              </h2>
            </div>
            <p
              className="text-sm max-w-xs"
              style={{ color: "var(--text-secondary)" }}
            >
              Every feature solves a documented blue team gap — not demo-ware.
            </p>
          </motion.div>

          <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-3">
            {FEATURES.map((f, i) => {
              const Icon = f.icon;
              return (
                <motion.div
                  key={f.title}
                  initial={{ opacity: 0, y: 10 }}
                  whileInView={{ opacity: 1, y: 0 }}
                  viewport={{ once: true }}
                  transition={{ delay: i * 0.04, duration: 0.4 }}
                  className="rounded-xl p-5 group cursor-default transition-all"
                  style={{
                    background: "var(--bg-card)",
                    border: "1px solid var(--bg-border)",
                  }}
                  onMouseEnter={(e) =>
                    (e.currentTarget.style.borderColor = `${f.color}25`)
                  }
                  onMouseLeave={(e) =>
                    (e.currentTarget.style.borderColor = "var(--bg-border)")
                  }
                >
                  <div className="flex items-start justify-between mb-3">
                    <div
                      className="w-8 h-8 rounded-lg flex items-center justify-center"
                      style={{
                        background: `${f.color}10`,
                        border: `1px solid ${f.color}20`,
                      }}
                    >
                      <Icon className="size-4" style={{ color: f.color }} />
                    </div>
                    <span
                      className="text-[9px] px-2 py-0.5 rounded font-bold"
                      style={{
                        color:
                          f.tag === "INDIA"
                            ? "#fbbf24"
                            : f.tag === "AI"
                              ? "#34d399"
                              : "#3b82f6",
                        background:
                          f.tag === "INDIA"
                            ? "rgba(251,191,36,0.06)"
                            : f.tag === "AI"
                              ? "rgba(52,211,153,0.06)"
                              : "rgba(59,130,246,0.06)",
                        border:
                          f.tag === "INDIA"
                            ? "1px solid rgba(251,191,36,0.18)"
                            : f.tag === "AI"
                              ? "1px solid rgba(52,211,153,0.18)"
                              : "1px solid rgba(59,130,246,0.18)",
                        fontFamily: "var(--font-mono)",
                      }}
                    >
                      {f.tag}
                    </span>
                  </div>
                  <h3
                    className="text-sm font-semibold mb-1.5"
                    style={{
                      color: "var(--text-primary)",
                      letterSpacing: "-0.01em",
                    }}
                  >
                    {f.title}
                  </h3>
                  <p
                    className="text-xs leading-relaxed"
                    style={{ color: "var(--text-muted)" }}
                  >
                    {f.desc}
                  </p>
                </motion.div>
              );
            })}
          </div>
        </div>
      </section>

      {/* ═══ CTA ════════════════════════════════════════════════ */}
      <section
        className="py-20 px-6 border-t"
        style={{ borderColor: "var(--bg-border)" }}
      >
        <div className="max-w-5xl mx-auto">
          <motion.div
            initial={{ opacity: 0, y: 14 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.55, ease: [0.23, 1, 0.32, 1] }}
          >
            <div
              className="rounded-2xl p-12 text-center relative overflow-hidden"
              style={{
                background:
                  "linear-gradient(135deg, rgba(59,130,246,0.05) 0%, rgba(96,165,250,0.04) 50%, rgba(167,139,250,0.04) 100%)",
                border: "1px solid rgba(59,130,246,0.12)",
              }}
            >
              <div
                className="absolute inset-0 pointer-events-none"
                style={{
                  backgroundImage:
                    "radial-gradient(circle, rgba(148,163,184,0.03) 1px, transparent 1px)",
                  backgroundSize: "28px 28px",
                }}
              />
              <div className="relative z-10">
                <div
                  className="w-14 h-14 rounded-2xl flex items-center justify-center mx-auto mb-6"
                  style={{
                    background: "rgba(59,130,246,0.08)",
                    border: "2px solid rgba(59,130,246,0.2)",
                  }}
                >
                  <Mail className="size-7" style={{ color: "#3b82f6" }} />
                </div>
                <h2
                  className="text-4xl font-black mb-4"
                  style={{
                    color: "var(--text-primary)",
                    letterSpacing: "-0.04em",
                  }}
                >
                  Analyze a suspicious email
                </h2>
                <p
                  className="text-base mb-8 max-w-md mx-auto leading-relaxed"
                  style={{ color: "var(--text-secondary)" }}
                >
                  Paste raw email headers or body text. Get SPF/DKIM/DMARC
                  verdict, SMTP relay chain, DNSBL results, MITRE technique
                  mapping, attribution confidence, and a forensic PDF report.
                </p>
                <div className="flex gap-3 justify-center flex-wrap">
                  <button
                    onClick={() => navigate("/email-forensics")}
                    className="flex items-center gap-2 px-6 py-3.5 rounded-xl text-sm font-semibold transition-all"
                    style={{ background: "#3b82f6", color: "#fff" }}
                    onMouseEnter={(e) =>
                      (e.currentTarget.style.background = "#2563eb")
                    }
                    onMouseLeave={(e) =>
                      (e.currentTarget.style.background = "#3b82f6")
                    }
                  >
                    <Mail className="size-4" /> Email Forensics Lab
                  </button>
                  <button
                    onClick={() => navigate("/scan")}
                    className="flex items-center gap-2 px-6 py-3.5 rounded-xl text-sm font-medium transition-all"
                    style={{
                      background: "var(--bg-card)",
                      border: "1px solid var(--bg-border)",
                      color: "var(--text-secondary)",
                    }}
                    onMouseEnter={(e) =>
                      (e.currentTarget.style.borderColor = "#3b82f640")
                    }
                    onMouseLeave={(e) =>
                      (e.currentTarget.style.borderColor = "var(--bg-border)")
                    }
                  >
                    <Terminal className="size-4" /> Full Scanner
                  </button>
                  <button
                    onClick={() => navigate("/siem")}
                    className="flex items-center gap-2 px-6 py-3.5 rounded-xl text-sm font-medium transition-all"
                    style={{
                      background: "var(--bg-card)",
                      border: "1px solid var(--bg-border)",
                      color: "var(--text-secondary)",
                    }}
                    onMouseEnter={(e) =>
                      (e.currentTarget.style.borderColor = "#a78bfa40")
                    }
                    onMouseLeave={(e) =>
                      (e.currentTarget.style.borderColor = "var(--bg-border)")
                    }
                  >
                    <Activity className="size-4" /> SIEM Dashboard
                  </button>
                </div>
              </div>
            </div>
          </motion.div>
        </div>
      </section>
    </div>
  );
}
