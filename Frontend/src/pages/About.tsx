// FILE: src/pages/About.tsx — PhishNetra v6.0 Updated
// Reflects: GAP 1-12, Email Forensics, Attribution Engine,
// AI text detection, Case Management, Forensic IDs,
// India fraud patterns, DNSBL, ML v4 model

import { motion } from "motion/react";
import { useNavigate } from "react-router";
import {
  Shield,
  Brain,
  Zap,
  Globe,
  Terminal,
  Code,
  Lock,
  Activity,
  Database,
  Fingerprint,
  Network,
  Eye,
  ShieldCheck,
  GitBranch,
  Layers,
  Cpu,
  Mail,
  MapPin,
  FileSearch,
  Phone,
  FileText,
  Search,
  Link as LinkIcon,
  Key,
  AlertTriangle,
} from "lucide-react";

// ── Version timeline ─────────────────────────────────────────
const TIMELINE = [
  {
    version: "v1.0",
    label: "Foundation",
    desc: "Rule-based URL scanner, basic phishing heuristics, single-page React UI. Core HTTPS/TLD/keyword checks.",
    color: "var(--text-muted)",
    current: false,
  },
  {
    version: "v2.0",
    label: "ML Hybrid",
    desc: "Synaptic.js neural network, 18-feature hybrid AI + rules engine, confidence scoring, SAFE_DOMAINS whitelist.",
    color: "var(--color-info)",
    current: false,
  },
  {
    version: "v3.0",
    label: "SIEM Platform",
    desc: "SentinelCore SIEM with 37 rules, WebSockets, PhishDNA™ fingerprinting, remediation engine, honeypot traps.",
    color: "var(--accent)",
    current: false,
  },
  {
    version: "v4.0",
    label: "SOC Grade",
    desc: "Domain intel engine, IDS middleware, adversary profiling, campaign tracker, kit fingerprinting (65 kits), STIX 2.1 threat sharing.",
    color: "#a78bfa",
    current: false,
  },
  {
    version: "v5.0",
    label: "Enterprise Expansion",
    desc: "India fraud detection (Hindi/Hinglish), CSV/JSON dataset training, Sigma + Splunk ESCU rule enrichment, evasion-resistance engine, auto-training pipeline.",
    color: "#fb923c",
    current: false,
  },
  {
    version: "v6.0",
    label: "Full SIEM Platform",
    desc: "IOC extraction engine, custom SIEM rules, shift handover notes, evidence vault, ransomware early warning, government portal detection, network anomaly baseline.",
    color: "#60a5fa",
    current: false,
  },
  {
    version: "v6.0",
    label: "Forensic Intelligence",
    desc: "Email forensics (SMTP relay chain, live SPF/MX, DNSBL × 6, IP geolocation, TOR detection), AI-generated text detection, multi-signal attribution with legal investigation paths, campaign case management, forensic ID chain of custody, light/dark theme, ML v4 model (85.4% accuracy, dead-network bug fixed).",
    color: "#34d399",
    current: true,
  },
];

// ── Detection coverage ────────────────────────────────────────
const DETECTIONS = [
  {
    icon: "🎣",
    label: "Brand Impersonation",
    desc: "200+ safe domains, 50 major brands, country TLD variants — amazon.in, google.co.in",
  },
  {
    icon: "🔤",
    label: "Typosquatting",
    desc: "Character substitution, keyboard-adjacency, Levenshtein distance analysis",
  },
  {
    icon: "🌐",
    label: "Homoglyph / Unicode",
    desc: "Internationalized domain homograph — paypaI, micr0soft, аmazon (Cyrillic)",
  },
  {
    icon: "🔗",
    label: "Open Redirects",
    desc: "6 redirect parameter patterns, URL chain analysis, path-based redirect tricks",
  },
  {
    icon: "🆔",
    label: "Punycode / IDN",
    desc: "Internationalized domain detection, xn-- prefix analysis, visual spoofing",
  },
  {
    icon: "🔐",
    label: "OTP / Credential Harvest",
    desc: "11 regex patterns for OTP requests, credential harvesting, form-based phishing",
  },
  {
    icon: "🎭",
    label: "Social Engineering",
    desc: "Authority impersonation, fear/urgency tactics, executive impersonation (BEC)",
  },
  {
    icon: "💬",
    label: "Smishing (SMS)",
    desc: "13 carrier-specific SMS phishing patterns, SMS header spoofing indicators",
  },
  {
    icon: "📧",
    label: "Email Spoofing",
    desc: "Live SPF/MX via DNS (not header trust), SMTP relay chain, display name spoofing",
  },
  {
    icon: "🏗️",
    label: "Phishing Kit DNA",
    desc: "65 kit signatures — 16Shop, EvilProxy, W3LL Panel, Zphisher, GoPhish variants",
  },
  {
    icon: "🛡️",
    label: "AiTM / Reverse Proxy",
    desc: "Adversary-in-the-middle signals, EvilProxy patterns, reverse proxy header detection",
  },
  {
    icon: "💰",
    label: "BEC / CEO Fraud",
    desc: "Wire transfer, gift card, invoice fraud patterns — with AI-generated BEC detection",
  },
  {
    icon: "📎",
    label: "Malicious Attachments",
    desc: "VBA/XLM macros, remote template injection, PDF embedded JS/Launch, VirusTotal hash",
  },
  {
    icon: "🤖",
    label: "AI-Generated Phishing",
    desc: "36 LLM fingerprint phrases, sentence uniformity, zero-casual language detection",
  },
  {
    icon: "🇮🇳",
    label: "India Fraud Patterns",
    desc: "Digital arrest, TRAI SIM block, UPI scam, FedEx drug parcel, OTP Hinglish patterns",
  },
  {
    icon: "📍",
    label: "IP Geolocation",
    desc: "Source IP country/city/ISP, VPN/TOR/datacenter flag, 30-min cached via ip-api.com",
  },
  {
    icon: "🔴",
    label: "DNSBL Reputation",
    desc: "6 DNSBLs: Spamhaus ZEN, Barracuda, SORBS, SpamCop, UCEPROTECT, SpamRats + TOR DNSBL",
  },
  {
    icon: "📡",
    label: "SMTP Relay Analysis",
    desc: "Full relay chain reconstruction, time travel detection, localhost injection flag",
  },
  {
    icon: "🔧",
    label: "Evasion Resistance",
    desc: "Second-pass engine catches threshold engineering, score minimum evidence threshold",
  },
  {
    icon: "🏛️",
    label: "Government Portal Spoof",
    desc: "20+ India-specific fake gov URL patterns — UIDAI, IRCTC, income tax, DigiLocker",
  },
];

// ── Platform capabilities ─────────────────────────────────────
const CAPABILITIES = [
  {
    icon: Brain,
    label: "ML v4 Engine",
    color: "#a78bfa",
    desc: "64-feature neural network (15→32→16→1). Xavier init, balanced 1:1 dataset 6,788 samples. Acc 85.4%, F1 84.7%. Hybrid: ML 45% + rules 55%.",
  },
  {
    icon: ShieldCheck,
    label: "SentinelCore SIEM",
    color: "var(--accent)",
    desc: "94 detection rules, MITRE ATT&CK mapping, Sigma + Splunk ESCU enrichment, SLA timers, shift handover notes, forensic IDs.",
  },
  {
    icon: Mail,
    label: "Email Forensics Platform",
    color: "#60a5fa",
    desc: "6-tab investigation dashboard: relay chain, domain intel, IP reputation, live SPF/MX, attribution confidence, correlation.",
  },
  {
    icon: Fingerprint,
    label: "Attribution Engine",
    color: "var(--color-danger)",
    desc: "13-signal scoring: TOR/VPN/residential/DNSBL/repeat-offender. 6 actor types. Legal paths: Section 91 CrPC, MLAT, CERT-In.",
  },
  {
    icon: Network,
    label: "Campaign Correlation",
    color: "#a78bfa",
    desc: "Graph-based email sender clustering by IP/domain/MX/replyTo. Auto-promotes clusters to named cases with analyst notes.",
  },
  {
    icon: FileSearch,
    label: "Deep Attachment Analysis",
    color: "#fb923c",
    desc: "VirusTotal SHA-256 hash lookup, Office VBA/XLM macro detection, remote template injection, PDF /JS /Launch /OpenAction.",
  },
  {
    icon: Key,
    label: "Forensic ID System",
    color: "#34d399",
    desc: "ALT/EVT/LOG/SHN prefixes. Format: PREFIX-YYYYMMDD-HHMM-4HEX. Chain of custody, SHA-256 integrity hash on logs.",
  },
  {
    icon: Phone,
    label: "India Fraud Detection",
    color: "#fbbf24",
    desc: "10 India-specific scam patterns: digital arrest, TRAI notice, courier fraud, UPI harvest, OTP Hinglish — with IOC keyword extraction.",
  },
  {
    icon: Layers,
    label: "URL Sandbox",
    color: "var(--color-info)",
    desc: "Form detection, tech fingerprinting, redirect chain tracking, HTML smuggling, MOTW bypass (ISO/IMG), polyglot files.",
  },
];

// ── Tech stack ────────────────────────────────────────────────
const STACK = [
  {
    layer: "Frontend",
    icon: Globe,
    color: "var(--color-info)",
    items: [
      "React 18 + TypeScript",
      "Tailwind CSS v3",
      "Motion/React",
      "Vite 5",
      "Light/Dark Theme",
    ],
  },
  {
    layer: "Backend",
    icon: Database,
    color: "var(--accent)",
    items: [
      "Node.js + Express",
      "MongoDB + Mongoose",
      "Socket.io (WebSocket)",
      "PDFKit + Nodemailer",
      "JWT + bcryptjs",
    ],
  },
  {
    layer: "AI / ML",
    icon: Brain,
    color: "#a78bfa",
    items: [
      "ML v4 (15→32→16→1)",
      "64-feature hybrid",
      "Synaptic.js fallback",
      "JSON/CSV training",
      "autoTrainingEngine",
    ],
  },
  {
    layer: "Security",
    icon: Shield,
    color: "#fbbf24",
    items: [
      "SentinelCore SIEM",
      "37 MITRE rules",
      "Sigma + Splunk ESCU",
      "Forensic ID chain",
      "DNSBL × 6 + TOR",
    ],
  },
  {
    layer: "Extension",
    icon: Eye,
    color: "#fb923c",
    items: [
      "Chrome MV3",
      "Inbox-level scan",
      "Gmail + Outlook",
      "shouldSkipUrl()",
      "X-Source header",
    ],
  },
];

export default function About() {
  const navigate = useNavigate();

  return (
    <div className="min-h-full" style={{ background: "var(--bg-base)" }}>
      {/* ── HERO ─────────────────────────────────────────────── */}
      <section
        className="relative overflow-hidden py-24 px-6 border-b"
        style={{ borderColor: "var(--bg-border)" }}
      >
        <div className="absolute inset-0 pointer-events-none">
          <div
            className="absolute top-0 right-0 w-96 h-96 rounded-full"
            style={{
              background:
                "radial-gradient(circle, rgba(167,139,250,0.06), transparent 70%)",
              filter: "blur(60px)",
            }}
          />
          <div
            className="absolute bottom-0 left-0 w-80 h-80 rounded-full"
            style={{
              background:
                "radial-gradient(circle, rgba(52,211,153,0.05), transparent 70%)",
              filter: "blur(60px)",
            }}
          />
          <div className="absolute inset-0 pattern-dots opacity-40" />
        </div>

        <div className="max-w-4xl mx-auto text-center relative">
          <motion.div
            initial={{ opacity: 0, y: 16 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, ease: [0.23, 1, 0.32, 1] }}
          >
            <div className="tag-green inline-flex mb-6">
              <Shield className="size-3" /> PhishNetra v6.0 — Forensic
              Intelligence Platform
            </div>
            <h1
              className="font-display mb-5"
              style={{
                fontSize: "clamp(2.8rem,5vw,4rem)",
                color: "var(--text-primary)",
                lineHeight: 1.05,
              }}
            >
              Built for the Threat Detection
              <br />
            </h1>
            <p
              className="text-lg max-w-2xl mx-auto leading-relaxed mb-8"
              style={{ color: "var(--text-secondary)" }}
            >
              Full-stack phishing detection platform — ML v4 neural network,
              email forensics with SMTP relay reconstruction, live SPF/MX
              validation, 6-DNSBL reputation, attribution confidence engine with
              legal investigation paths, and India-specific fraud detection in
              Hindi and Hinglish.
            </p>

            {/* Version badges */}
            <div className="flex flex-wrap gap-2 justify-center mb-8">
              {[
                {
                  label: "v6.0 · Forensic Intelligence",
                  color: "var(--accent)",
                },
                { label: "ML v4 · 85.4% Accuracy", color: "#a78bfa" },
                { label: "64 Detection Patterns", color: "#60a5fa" },
                { label: "6 DNSBL · TOR Detection", color: "#fbbf24" },
                { label: "India Fraud · Hindi/Hinglish", color: "#34d399" },
              ].map((b) => (
                <span
                  key={b.label}
                  className="text-[10px] font-bold px-2.5 py-1 rounded-full"
                  style={{
                    color: b.color,
                    background: `${b.color}10`,
                    border: `1px solid ${b.color}25`,
                    fontFamily: "var(--font-mono)",
                  }}
                >
                  {b.label}
                </span>
              ))}
            </div>
          </motion.div>
        </div>
      </section>

      <div className="max-w-6xl mx-auto px-6 py-16 space-y-24">
        {/* ── CAPABILITIES ─────────────────────────────────── */}
        <motion.section
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
        >
          <div className="tag-green inline-flex mb-6">
            <Zap className="size-3" /> CAPABILITIES
          </div>
          <div className="flex items-end justify-between mb-10 flex-wrap gap-4">
            <h2
              className="font-display text-3xl"
              style={{ color: "var(--text-primary)" }}
            >
              Platform capabilities
            </h2>
            <p
              className="text-sm max-w-xs"
              style={{ color: "var(--text-secondary)" }}
            >
              Every component works standalone or as an integrated forensic
              security stack.
            </p>
          </div>
          <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-4">
            {CAPABILITIES.map((c, i) => {
              const Icon = c.icon;
              return (
                <motion.div
                  key={c.label}
                  initial={{ opacity: 0, y: 12 }}
                  whileInView={{ opacity: 1, y: 0 }}
                  viewport={{ once: true }}
                  transition={{ delay: i * 0.06 }}
                  className="card p-5 stat-card"
                >
                  <div
                    className="w-10 h-10 rounded-xl flex items-center justify-center mb-4"
                    style={{
                      background: `${c.color}10`,
                      border: `1px solid ${c.color}22`,
                    }}
                  >
                    <Icon className="size-5" style={{ color: c.color }} />
                  </div>
                  <h3
                    className="text-sm font-semibold mb-1.5"
                    style={{
                      color: "var(--text-primary)",
                      letterSpacing: "-0.01em",
                    }}
                  >
                    {c.label}
                  </h3>
                  <p
                    className="text-xs leading-relaxed"
                    style={{ color: "var(--text-muted)" }}
                  >
                    {c.desc}
                  </p>
                </motion.div>
              );
            })}
          </div>
        </motion.section>

        {/* ── VERSION TIMELINE ─────────────────────────────── */}
        <motion.section
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
        >
          <div className="tag-green inline-flex mb-6">
            <GitBranch className="size-3" /> VERSION HISTORY
          </div>
          <h2
            className="font-display text-3xl mb-10"
            style={{ color: "var(--text-primary)" }}
          >
            Evolution of PhishNetra
          </h2>
          <div className="relative">
            <div
              className="absolute left-6 top-0 bottom-0 w-px"
              style={{
                background:
                  "linear-gradient(180deg, rgba(52,211,153,0.6) 0%, rgba(52,211,153,0.05) 100%)",
              }}
            />
            <div className="space-y-4 pl-16">
              {TIMELINE.map((t, i) => (
                <motion.div
                  key={t.version}
                  initial={{ opacity: 0, x: -16 }}
                  whileInView={{ opacity: 1, x: 0 }}
                  viewport={{ once: true }}
                  transition={{ delay: i * 0.08, duration: 0.4 }}
                  className="relative card p-5"
                  style={{
                    background: t.current
                      ? "var(--bg-hover)"
                      : "var(--bg-card)",
                    borderColor: t.current
                      ? `${t.color}35`
                      : "var(--bg-border)",
                  }}
                >
                  {/* Timeline dot */}
                  <div
                    className="absolute -left-[52px] top-5 w-4 h-4 rounded-full border-2 flex items-center justify-center"
                    style={{
                      background: t.current ? t.color : "var(--bg-base)",
                      borderColor: t.color,
                      boxShadow: t.current ? `0 0 12px ${t.color}60` : "none",
                    }}
                  >
                    {t.current && (
                      <div
                        className="w-1.5 h-1.5 rounded-full"
                        style={{ background: "var(--bg-base)" }}
                      />
                    )}
                  </div>
                  <div className="flex items-center gap-3 mb-1.5 flex-wrap">
                    <span
                      className="text-xs font-bold px-2 py-0.5 rounded"
                      style={{
                        color: t.color,
                        background: `${t.color}12`,
                        border: `1px solid ${t.color}28`,
                        fontFamily: "var(--font-mono)",
                      }}
                    >
                      {t.version}
                    </span>
                    <span
                      className="text-sm font-semibold"
                      style={{ color: t.color }}
                    >
                      {t.label}
                    </span>
                    {t.current && (
                      <span
                        className="text-[9px] px-2 py-0.5 rounded safe-pulse"
                        style={{
                          color: "var(--accent)",
                          background: "rgba(52,211,153,0.08)",
                          border: "1px solid rgba(52,211,153,0.2)",
                          fontFamily: "var(--font-mono)",
                        }}
                      >
                        CURRENT
                      </span>
                    )}
                  </div>
                  <p
                    className="text-sm"
                    style={{ color: "var(--text-secondary)" }}
                  >
                    {t.desc}
                  </p>
                </motion.div>
              ))}
            </div>
          </div>
        </motion.section>

        {/* ── DETECTION COVERAGE ───────────────────────────── */}
        <motion.section
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
        >
          <div className="tag-green inline-flex mb-6">
            <Brain className="size-3" /> DETECTION COVERAGE
          </div>
          <div className="flex items-end justify-between mb-10 flex-wrap gap-4">
            <h2
              className="font-display text-3xl"
              style={{ color: "var(--text-primary)" }}
            >
              {DETECTIONS.length} attack types detected
            </h2>
            <div className="flex items-center gap-2">
              <div
                className="w-1.5 h-1.5 rounded-full safe-pulse"
                style={{ background: "var(--accent)" }}
              />
              <span
                className="text-xs"
                style={{
                  color: "var(--text-muted)",
                  fontFamily: "var(--font-mono)",
                }}
              >
                v6.0 · detection engine active
              </span>
            </div>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
            {DETECTIONS.map((d, i) => (
              <motion.div
                key={d.label}
                initial={{ opacity: 0, scale: 0.97 }}
                whileInView={{ opacity: 1, scale: 1 }}
                viewport={{ once: true }}
                transition={{ delay: i * 0.03, duration: 0.35 }}
                className="card p-4 flex items-start gap-3 stat-card"
              >
                <span className="text-xl flex-shrink-0 mt-0.5">{d.icon}</span>
                <div>
                  <p
                    className="text-sm font-semibold mb-0.5"
                    style={{
                      color: "var(--text-primary)",
                      letterSpacing: "-0.01em",
                    }}
                  >
                    {d.label}
                  </p>
                  <p className="text-xs" style={{ color: "var(--text-muted)" }}>
                    {d.desc}
                  </p>
                </div>
              </motion.div>
            ))}
          </div>
        </motion.section>

        {/* ── TECH STACK ───────────────────────────────────── */}
        <motion.section
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
        >
          <div className="tag-green inline-flex mb-6">
            <Code className="size-3" /> TECH STACK
          </div>
          <h2
            className="font-display text-3xl mb-10"
            style={{ color: "var(--text-primary)" }}
          >
            Built with modern tools
          </h2>
          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-4">
            {STACK.map((s, i) => {
              const Icon = s.icon;
              return (
                <motion.div
                  key={s.layer}
                  initial={{ opacity: 0, y: 16 }}
                  whileInView={{ opacity: 1, y: 0 }}
                  viewport={{ once: true }}
                  transition={{ delay: i * 0.07, duration: 0.4 }}
                  className="card p-5"
                  style={{ background: "var(--bg-card)" }}
                >
                  <div className="flex items-center gap-2 mb-4">
                    <div
                      className="w-7 h-7 rounded-lg flex items-center justify-center flex-shrink-0"
                      style={{
                        background: `${s.color}10`,
                        border: `1px solid ${s.color}20`,
                      }}
                    >
                      <Icon className="size-3.5" style={{ color: s.color }} />
                    </div>
                    <span
                      className="text-[10px] font-bold uppercase tracking-widest"
                      style={{ color: s.color, fontFamily: "var(--font-mono)" }}
                    >
                      {s.layer}
                    </span>
                  </div>
                  <div className="space-y-2">
                    {s.items.map((item) => (
                      <div key={item} className="flex items-center gap-2">
                        <div
                          className="w-1 h-1 rounded-full flex-shrink-0"
                          style={{ background: s.color, opacity: 0.7 }}
                        />
                        <span
                          className="text-xs"
                          style={{ color: "var(--text-secondary)" }}
                        >
                          {item}
                        </span>
                      </div>
                    ))}
                  </div>
                </motion.div>
              );
            })}
          </div>
        </motion.section>

        {/* ── ML v4 HIGHLIGHT ──────────────────────────────── */}
        <motion.section
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
        >
          <div className="tag-green inline-flex mb-6">
            <Cpu className="size-3" /> ML ENGINE v4
          </div>
          <h2
            className="font-display text-3xl mb-6"
            style={{ color: "var(--text-primary)" }}
          >
            Dead-network bug fixed in v4
          </h2>
          <div className="card p-6" style={{ background: "var(--bg-card)" }}>
            <div className="grid md:grid-cols-2 gap-8">
              <div>
                <div
                  className="text-xs font-bold mb-3 uppercase tracking-wider"
                  style={{
                    color: "var(--color-danger)",
                    fontFamily: "var(--font-mono)",
                  }}
                >
                  v3 Problem — Constant 77% output
                </div>
                <p
                  className="text-sm leading-relaxed mb-4"
                  style={{ color: "var(--text-secondary)" }}
                >
                  Every URL — phishing or legitimate — returned exactly 77.0%.
                  The network's hidden weights collapsed near zero during
                  training, so the output neuron returned sigmoid(bias_only) =
                  constant 0.77 regardless of input.
                </p>
                <div className="space-y-2">
                  {[
                    "Class imbalance (2:1 phishing:safe ratio)",
                    "Vanishing gradient from too-small initial weights",
                    "Overparameterized architecture (5,136 connections, 6k samples)",
                  ].map((issue, i) => (
                    <div
                      key={i}
                      className="flex items-start gap-2 text-xs"
                      style={{ color: "var(--text-muted)" }}
                    >
                      <span
                        className="flex-shrink-0 mt-0.5"
                        style={{ color: "var(--color-danger)" }}
                      >
                        ✗
                      </span>
                      {issue}
                    </div>
                  ))}
                </div>
              </div>
              <div>
                <div
                  className="text-xs font-bold mb-3 uppercase tracking-wider"
                  style={{
                    color: "var(--safe)",
                    fontFamily: "var(--font-mono)",
                  }}
                >
                  v4 Fix — 85.4% Accuracy
                </div>
                <p
                  className="text-sm leading-relaxed mb-4"
                  style={{ color: "var(--text-secondary)" }}
                >
                  Rebuilt from scratch: Xavier weight initialization, balanced
                  1:1 dataset (6,788 samples), reduced architecture
                  (15→32→16→1), trusted domain feature that cleanly separates
                  amazon.com from amazon-secure.tk.
                </p>
                <div className="grid grid-cols-2 gap-3">
                  {[
                    {
                      label: "Accuracy",
                      value: "85.4%",
                      color: "var(--accent)",
                    },
                    { label: "F1 Score", value: "84.7%", color: "#a78bfa" },
                    { label: "Precision", value: "88.5%", color: "#60a5fa" },
                    { label: "MSE", value: "0.100", color: "#34d399" },
                  ].map((s) => (
                    <div
                      key={s.label}
                      className="px-3 py-2.5 rounded-xl"
                      style={{
                        background: "var(--bg-elevated)",
                        border: "1px solid var(--bg-border)",
                      }}
                    >
                      <div
                        className="text-[10px] mb-0.5"
                        style={{
                          color: "var(--text-muted)",
                          fontFamily: "var(--font-mono)",
                        }}
                      >
                        {s.label}
                      </div>
                      <div
                        className="text-lg font-black"
                        style={{
                          color: s.color,
                          fontFamily: "var(--font-mono)",
                        }}
                      >
                        {s.value}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        </motion.section>
      </div>
    </div>
  );
}
