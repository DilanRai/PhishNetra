// FILE: src/pages/Scan.tsx

import { useState, useEffect, useRef } from "react";
import { useLocation, useNavigate } from "react-router";
import { motion, AnimatePresence } from "motion/react";
import {
  TriangleAlert as AlertTriangle,
  CircleCheck as CheckCircle,
  XCircle, Search, RefreshCw,
  History as HistoryIcon, Mail,
  Link as LinkIcon, FileText,
  Terminal, ChevronRight, Activity,
  Cpu, Brain, Shield, Zap, Eye,
} from "lucide-react";
import type { ScanResult } from "../types";

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

// ── status config ──
const STATUS_CFG = {
  safe: {
    color: "#00ff88", bg: "rgba(0,255,136,0.07)", border: "rgba(0,255,136,0.25)",
    glow: "0 0 40px rgba(0,255,136,0.12)",
    label: "SAFE", icon: CheckCircle,
    msg: "No threats detected. This appears to be safe.",
    barGradient: "linear-gradient(90deg, #00c960, #00ff88)",
    ringColor: "rgba(0,255,136,0.3)",
  },
  suspicious: {
    color: "#f5a623", bg: "rgba(245,166,35,0.07)", border: "rgba(245,166,35,0.25)",
    glow: "0 0 40px rgba(245,166,35,0.12)",
    label: "SUSPICIOUS", icon: AlertTriangle,
    msg: "Potential risks detected. Exercise caution before proceeding.",
    barGradient: "linear-gradient(90deg, #e08b00, #f5a623)",
    ringColor: "rgba(245,166,35,0.3)",
  },
  phishing: {
    color: "#ff4444", bg: "rgba(255,68,68,0.07)", border: "rgba(255,68,68,0.25)",
    glow: "0 0 40px rgba(255,68,68,0.14)",
    label: "PHISHING", icon: XCircle,
    msg: "High risk! This is likely a phishing attempt. Do not proceed.",
    barGradient: "linear-gradient(90deg, #cc0000, #ff4444)",
    ringColor: "rgba(255,68,68,0.4)",
  },
};

// ── confidence config ──
const CONF_CFG = {
  high:   { color: "#00ff88", label: "HIGH",   bg: "rgba(0,255,136,0.08)"  },
  medium: { color: "#f5a623", label: "MEDIUM", bg: "rgba(245,166,35,0.08)" },
  low:    { color: "#8b95a8", label: "LOW",    bg: "rgba(139,149,168,0.08)"},
};

// ── input type config ──
const INPUT_CFG = {
  url:   { icon: LinkIcon,  label: "URL",          color: "var(--accent-cyan)"  },
  email: { icon: Mail,      label: "Email Address", color: "#a78bfa"             },
  text:  { icon: FileText,  label: "Text Message", color: "#f5a623"             },
};

export default function Scan() {
  const location = useLocation();
  const navigate = useNavigate();
  const [input,        setInput]        = useState(location.state?.url || "");
  const [loading,      setLoading]      = useState(false);
  const [result,       setResult]       = useState<ScanResult | null>(null);
  const [scannedInput, setScannedInput] = useState("");
  const [scanStep,     setScanStep]     = useState(0);
  const [siemStatus,   setSiemStatus]   = useState<"idle"|"sending"|"sent"|"error">("idle");
  const hasAutoScanned = useRef(false);

  useEffect(() => {
    if (location.state?.url && !hasAutoScanned.current) {
      hasAutoScanned.current = true;
      handleScan(location.state.url);
    }
  }, []);

  // ── Auto-feed result to SIEM ──
  const feedToSIEM = async (scanResult: ScanResult, rawInput: string) => {
    if (scanResult.riskScore < 20 && scanResult.status === "safe") return;
    setSiemStatus("sending");
    try {
      await fetch("http://localhost:5000/api/siem/event", {
        method:  "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          type:       "phishing_scan",
          sourceType: "scanner",
          agent:      "PhishGuard Web UI",
          data: {
            ...scanResult,
            input:     rawInput,
            url:       rawInput,
          },
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

    setLoading(true);
    setResult(null);
    setScannedInput(target);
    setScanStep(0);
    setSiemStatus("idle");

    const stepInterval = setInterval(() => {
      setScanStep((prev) => (prev >= SCAN_STEPS.length - 1 ? prev : prev + 1));
    }, 180);

    try {
      const res = await fetch("http://localhost:5000/api/scan", {
        method:  "POST",
        headers: { "Content-Type": "application/json" },
        body:    JSON.stringify({ input: target }),
      });
      if (!res.ok) throw new Error(`Server error ${res.status}`);
      clearInterval(stepInterval);
      setScanStep(SCAN_STEPS.length);
      const data: ScanResult = await res.json();
      setResult(data);
      // Feed to SIEM (non-blocking)
      feedToSIEM(data, target);
    } catch (err) {
      console.error("Scan failed:", err);
    } finally {
      clearInterval(stepInterval);
      setLoading(false);
    }
  };

  const handleReset = () => {
    setResult(null); setScannedInput(""); setInput("");
    setScanStep(0); setSiemStatus("idle");
  };

  return (
    <div className="min-h-full py-12 px-6" style={{ background: "var(--bg-base)" }}>
      <div className="max-w-3xl mx-auto">

        {/* ── HEADER ── */}
        <motion.div initial={{ opacity:0, y:16 }} animate={{ opacity:1, y:0 }} className="mb-10">
          <div className="tag-green inline-flex mb-4">
            <Terminal className="size-3" /> THREAT SCANNER
          </div>
          <h1 className="text-4xl font-bold mb-2"
              style={{ fontFamily:"'Syne', sans-serif", color:"var(--text-primary)" }}>
            Analyze & Detect
          </h1>
          <p className="text-sm" style={{ color:"var(--text-secondary)" }}>
            Paste a URL, email address, or any suspicious message below.
          </p>
        </motion.div>

        {/* ── INPUT BOX ── */}
        <AnimatePresence>
          {!result && (
            <motion.div initial={{ opacity:0, y:16 }} animate={{ opacity:1, y:0 }}
                        exit={{ opacity:0, y:-8 }} className="mb-8">
              <div className="rounded-xl p-5"
                   style={{ background:"var(--bg-card)", border:"1px solid var(--bg-border)" }}>
                <div className="text-xs mb-3"
                     style={{ color:"var(--text-muted)", fontFamily:"'JetBrains Mono', monospace" }}>
                  INPUT TARGET
                </div>
                <div className="flex gap-3 flex-col sm:flex-row">
                  <div className="relative flex-1">
                    <Search className="absolute left-4 top-1/2 -translate-y-1/2 size-4"
                            style={{ color:"var(--text-muted)" }} />
                    <input type="text" value={input}
                           onChange={(e) => setInput(e.target.value)}
                           onKeyDown={(e) => e.key === "Enter" && handleScan()}
                           placeholder="https://example.com or paste suspicious message..."
                           className="input-terminal w-full pl-11 pr-4 py-3.5 rounded-xl text-sm"
                           autoFocus />
                  </div>
                  <button onClick={() => handleScan()} disabled={loading || !input.trim()}
                          className="btn-primary flex items-center justify-center gap-2 px-6 py-3.5 text-sm"
                          style={{ fontFamily:"'Syne', sans-serif", fontWeight:700, minWidth:120 }}>
                    {loading
                      ? <Activity className="size-4 animate-spin" />
                      : <><Terminal className="size-4" /> Scan</>}
                  </button>
                </div>
              </div>
            </motion.div>
          )}
        </AnimatePresence>

        {/* ── SCANNING ANIMATION ── */}
        <AnimatePresence>
          {loading && (
            <motion.div initial={{ opacity:0, scale:0.97 }} animate={{ opacity:1, scale:1 }}
                        exit={{ opacity:0 }} className="rounded-xl overflow-hidden"
                        style={{ background:"var(--bg-card)", border:"1px solid var(--bg-border)" }}>
              <div className="flex items-center gap-2 px-4 py-3 border-b"
                   style={{ borderColor:"var(--bg-border)", background:"rgba(0,0,0,0.4)" }}>
                <div className="flex gap-1.5">
                  <div className="w-2.5 h-2.5 rounded-full" style={{ background:"#ff5f57" }} />
                  <div className="w-2.5 h-2.5 rounded-full" style={{ background:"#febc2e" }} />
                  <div className="w-2.5 h-2.5 rounded-full" style={{ background:"#28c840" }} />
                </div>
                <span className="text-xs ml-1"
                      style={{ color:"var(--text-muted)", fontFamily:"'JetBrains Mono', monospace" }}>
                  phishguard_v3.sh — running
                </span>
                <div className="ml-auto flex items-center gap-1.5">
                  <div className="w-1.5 h-1.5 rounded-full safe-pulse" style={{ background:"var(--accent-green)" }} />
                </div>
              </div>
              <div className="p-5 space-y-1.5">
                <div className="text-xs mb-4 truncate"
                     style={{ color:"var(--text-muted)", fontFamily:"'JetBrains Mono', monospace" }}>
                  $ analyzing: <span style={{ color:"var(--accent-cyan)" }}>{scannedInput}</span>
                </div>
                {SCAN_STEPS.map((step, i) => (
                  <motion.div key={i} initial={{ opacity:0 }}
                              animate={{ opacity: i <= scanStep ? 1 : 0.2 }}
                              className="flex items-center gap-3 text-xs"
                              style={{ fontFamily:"'JetBrains Mono', monospace" }}>
                    {i < scanStep   ? <span style={{ color:"var(--accent-green)" }}>✓</span>
                    : i === scanStep ? <span style={{ color:"var(--accent-cyan)" }}>›</span>
                    : <span style={{ color:"var(--text-muted)" }}>·</span>}
                    {(i === 7 || i === 8) && <Brain className="size-3" style={{ color:"var(--accent-cyan)" }} />}
                    <span style={{ color: i < scanStep ? "var(--text-secondary)" : i === scanStep ? "var(--text-primary)" : "var(--text-muted)" }}>
                      {step}
                    </span>
                  </motion.div>
                ))}
              </div>
              <div className="px-5 pb-5">
                <div className="h-1 rounded-full overflow-hidden" style={{ background:"var(--bg-border)" }}>
                  <motion.div className="h-full rounded-full"
                    initial={{ width:"0%" }}
                    animate={{ width:`${((scanStep + 1) / SCAN_STEPS.length) * 100}%` }}
                    style={{ background:"var(--accent-green)", boxShadow:"0 0 8px rgba(0,255,136,0.5)" }} />
                </div>
              </div>
            </motion.div>
          )}
        </AnimatePresence>

        {/* ── RESULT ── */}
        <AnimatePresence>
          {result && !loading && (() => {
            const c    = STATUS_CFG[result.status] || STATUS_CFG.safe;
            const Icon = c.icon;
            const inputCfg = INPUT_CFG[result.inputType] || INPUT_CFG.text;
            const InputIcon = inputCfg.icon;
            const confCfg = CONF_CFG[result.confidence as keyof typeof CONF_CFG] || CONF_CFG.low;

            return (
              <motion.div initial={{ opacity:0, y:16 }} animate={{ opacity:1, y:0 }}
                          exit={{ opacity:0 }} className="space-y-4">

                {/* Scanned target label */}
                <div className="flex items-center gap-2 text-xs px-1"
                     style={{ color:"var(--text-muted)", fontFamily:"'JetBrains Mono', monospace" }}>
                  <InputIcon className="size-3.5" style={{ color: inputCfg.color }} />
                  <span style={{ color: inputCfg.color }}>{inputCfg.label}:</span>
                  <span className="truncate max-w-sm">{scannedInput}</span>
                  {/* SIEM status */}
                  {siemStatus === "sent" && (
                    <span className="ml-auto text-xs flex items-center gap-1"
                          style={{ color:"var(--accent-green)", fontFamily:"'JetBrains Mono', monospace" }}>
                      <Shield className="size-3" /> SIEM logged
                    </span>
                  )}
                </div>

                {/* ══════ MAIN RESULT CARD ══════ */}
                <div className="rounded-2xl overflow-hidden"
                     style={{ background:"var(--bg-card)", border:`2px solid ${c.border}`, boxShadow: c.glow }}>

                  {/* ── COLOR VERDICT HEADER ── */}
                  <div className="px-6 py-6 flex items-center gap-5"
                       style={{ background: c.bg, borderBottom:`1px solid ${c.border}` }}>

                    {/* Big icon with ring */}
                    <div className="relative flex-shrink-0">
                      <div className="w-16 h-16 rounded-2xl flex items-center justify-center"
                           style={{ background: c.bg, border:`2px solid ${c.border}`,
                                    boxShadow:`0 0 20px ${c.ringColor}` }}>
                        <Icon className="size-9" style={{ color: c.color }} strokeWidth={2} />
                      </div>
                      {/* Pulsing ring for phishing */}
                      {result.status === "phishing" && (
                        <div className="absolute inset-0 rounded-2xl animate-ping opacity-30"
                             style={{ border:`2px solid ${c.color}` }} />
                      )}
                    </div>

                    <div className="flex-1 min-w-0">
                      {/* Verdict label */}
                      <div className="text-3xl font-black mb-1 tracking-tight"
                           style={{ color: c.color, fontFamily:"'Syne', sans-serif",
                                    textShadow:`0 0 20px ${c.ringColor}` }}>
                        {c.label}
                      </div>
                      <p className="text-sm" style={{ color:"var(--text-secondary)" }}>{c.msg}</p>

                      {/* ── PRIORITY 3: Detection Type + Confidence badges ── */}
                      <div className="flex flex-wrap items-center gap-2 mt-3">

                        {/* Detected As */}
                        <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-medium"
                             style={{ background:"rgba(0,0,0,0.3)", border:"1px solid var(--bg-border)",
                                      color: inputCfg.color, fontFamily:"'JetBrains Mono', monospace" }}>
                          <InputIcon className="size-3" />
                          Detected as: <span className="font-bold">{inputCfg.label}</span>
                        </div>

                        {/* Confidence */}
                        <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-medium"
                             style={{ background: confCfg.bg, border:`1px solid ${confCfg.color}40`,
                                      color: confCfg.color, fontFamily:"'JetBrains Mono', monospace" }}>
                          <Eye className="size-3" />
                          Confidence: <span className="font-bold">{confCfg.label}</span>
                        </div>

                        {/* Risk score badge */}
                        <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-bold"
                             style={{ background:`${c.color}15`, border:`1px solid ${c.border}`,
                                      color: c.color, fontFamily:"'JetBrains Mono', monospace" }}>
                          <Zap className="size-3" />
                          Score: {result.riskScore}/100
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* ── PRIORITY 1: Color-coded risk score bar ── */}
                  <div className="px-6 py-5 border-b" style={{ borderColor:"var(--bg-border)" }}>
                    <div className="flex justify-between text-xs mb-2"
                         style={{ color:"var(--text-muted)", fontFamily:"'JetBrains Mono', monospace" }}>
                      <span className="flex items-center gap-1.5">
                        <span className="w-2 h-2 rounded-full inline-block" style={{ background:"#00ff88" }} />
                        Safe
                        <span className="mx-2" style={{ color:"var(--bg-border)" }}>|</span>
                        <span className="w-2 h-2 rounded-full inline-block" style={{ background:"#f5a623" }} />
                        Suspicious
                        <span className="mx-2" style={{ color:"var(--bg-border)" }}>|</span>
                        <span className="w-2 h-2 rounded-full inline-block" style={{ background:"#ff4444" }} />
                        Phishing
                      </span>
                      <span className="font-bold" style={{ color: c.color, fontSize:13 }}>
                        {result.riskScore} / 100
                      </span>
                    </div>

                    {/* Segmented color bar */}
                    <div className="relative h-4 rounded-full overflow-hidden"
                         style={{ background:"var(--bg-border)" }}>
                      {/* Safe zone */}
                      <div className="absolute top-0 left-0 h-full opacity-20 rounded-l-full"
                           style={{ width:"25%", background:"#00ff88" }} />
                      {/* Suspicious zone */}
                      <div className="absolute top-0 h-full opacity-20"
                           style={{ left:"25%", width:"40%", background:"#f5a623" }} />
                      {/* Phishing zone */}
                      <div className="absolute top-0 h-full opacity-20 rounded-r-full"
                           style={{ left:"65%", width:"35%", background:"#ff4444" }} />

                      {/* Score fill */}
                      <motion.div className="absolute top-0 left-0 h-full rounded-full"
                        initial={{ width:0 }}
                        animate={{ width:`${result.riskScore}%` }}
                        transition={{ duration:1.2, ease:"easeOut", delay:0.2 }}
                        style={{ background: c.barGradient,
                                 boxShadow:`0 0 12px ${c.color}80` }} />

                      {/* Score pointer */}
                      <motion.div className="absolute top-0 h-full w-1 rounded-full"
                        initial={{ left:"0%" }}
                        animate={{ left:`calc(${result.riskScore}% - 2px)` }}
                        transition={{ duration:1.2, ease:"easeOut", delay:0.2 }}
                        style={{ background:"#fff", boxShadow:`0 0 6px ${c.color}` }} />
                    </div>

                    <div className="flex justify-between mt-1.5 text-xs"
                         style={{ color:"var(--text-muted)", fontFamily:"'JetBrains Mono', monospace" }}>
                      <span style={{ color:"#00ff88" }}>0 — Safe</span>
                      <span>25</span>
                      <span>65</span>
                      <span style={{ color:"#ff4444" }}>100 — Phishing</span>
                    </div>
                  </div>

                  {/* ── ML HYBRID PANEL ── */}
                  {result.mlEnabled && result.mlScore !== null && (
                    <div className="px-6 py-5 border-b" style={{ borderColor:"var(--bg-border)" }}>
                      <div className="flex items-center gap-2 mb-4">
                        <Brain className="size-3.5" style={{ color:"var(--accent-cyan)" }} />
                        <span className="text-xs font-bold uppercase tracking-wider"
                              style={{ color:"var(--accent-cyan)", fontFamily:"'JetBrains Mono', monospace" }}>
                          ML Hybrid Analysis
                        </span>
                        <span className="ml-auto text-xs px-2 py-0.5 rounded"
                              style={{ background:"rgba(0,212,255,0.08)", color:"var(--accent-cyan)",
                                       border:"1px solid rgba(0,212,255,0.2)", fontFamily:"'JetBrains Mono', monospace" }}>
                          v{result.detectionVersion}
                        </span>
                      </div>
                      <div className="grid grid-cols-2 gap-4">
                        <div>
                          <div className="flex justify-between text-xs mb-1.5"
                               style={{ color:"var(--text-muted)", fontFamily:"'JetBrains Mono', monospace" }}>
                            <span>NEURAL NET</span>
                            <span style={{ color:"var(--accent-cyan)" }}>{result.mlScore}</span>
                          </div>
                          <div className="h-2 rounded-full overflow-hidden" style={{ background:"var(--bg-border)" }}>
                            <motion.div className="h-full rounded-full"
                              initial={{ width:0 }} animate={{ width:`${result.mlScore}%` }}
                              transition={{ duration:1, ease:"easeOut", delay:0.4 }}
                              style={{ background:"var(--accent-cyan)", boxShadow:"0 0 6px rgba(0,212,255,0.5)" }} />
                          </div>
                        </div>
                        <div>
                          <div className="flex justify-between text-xs mb-1.5"
                               style={{ color:"var(--text-muted)", fontFamily:"'JetBrains Mono', monospace" }}>
                            <span>RULE ENGINE</span>
                            <span style={{ color:"var(--accent-green)" }}>{result.ruleScore}</span>
                          </div>
                          <div className="h-2 rounded-full overflow-hidden" style={{ background:"var(--bg-border)" }}>
                            <motion.div className="h-full rounded-full"
                              initial={{ width:0 }} animate={{ width:`${result.ruleScore}%` }}
                              transition={{ duration:1, ease:"easeOut", delay:0.5 }}
                              style={{ background:"var(--accent-green)", boxShadow:"0 0 6px rgba(0,255,136,0.5)" }} />
                          </div>
                        </div>
                      </div>
                      <p className="text-xs mt-3"
                         style={{ color:"var(--text-muted)", fontFamily:"'JetBrains Mono', monospace" }}>
                        Final = Neural Net (45%) + Rule Engine (55%) blended
                      </p>
                    </div>
                  )}

                  {/* ── PRIORITY 1: Issues list ── */}
                  {result.issues.length > 0 && (
                    <div className="px-6 py-5 border-b" style={{ borderColor:"var(--bg-border)" }}>
                      <div className="flex items-center gap-2 mb-4">
                        <AlertTriangle className="size-4" style={{ color:"#f5a623" }} />
                        <span className="text-xs font-bold uppercase tracking-wider"
                              style={{ color:"var(--text-secondary)", fontFamily:"'JetBrains Mono', monospace" }}>
                          Detected Issues ({result.issues.length})
                        </span>
                      </div>
                      <div className="space-y-2">
                        {result.issues.map((issue, i) => {
                          // Categorize issue severity by keywords for color coding
                          const isCritical = /otp|impersonat|spoof|display name|credential/i.test(issue);
                          const isHigh     = /brand|typosquatting|redirect|punycode/i.test(issue);
                          const dotColor   = isCritical ? "#ff4444" : isHigh ? "#f97316" : "#f5a623";
                          return (
                            <motion.div key={i}
                              initial={{ opacity:0, x:-12 }} animate={{ opacity:1, x:0 }}
                              transition={{ delay:0.3 + i * 0.06 }}
                              className="flex items-start gap-3 rounded-xl px-4 py-3 text-sm"
                              style={{ background:"var(--bg-elevated)", border:`1px solid ${dotColor}20` }}>
                              <div className="w-2 h-2 rounded-full flex-shrink-0 mt-1.5"
                                   style={{ background: dotColor, boxShadow:`0 0 6px ${dotColor}80` }} />
                              <span style={{ color:"var(--text-secondary)" }}>{issue}</span>
                            </motion.div>
                          );
                        })}
                      </div>
                    </div>
                  )}

                  {/* Safe message */}
                  {result.status === "safe" && result.issues.length === 0 && (
                    <div className="px-6 py-5 border-b flex items-center gap-3"
                         style={{ borderColor:"var(--bg-border)", background:"rgba(0,255,136,0.04)" }}>
                      <CheckCircle className="size-5 flex-shrink-0" style={{ color:"var(--accent-green)" }} />
                      <span className="text-sm" style={{ color:"var(--accent-green)" }}>
                        No threats detected. This URL appears safe to visit.
                      </span>
                    </div>
                  )}

                  {/* ── PRIORITY 2: SIEM status row ── */}
                  {siemStatus !== "idle" && (
                    <div className="px-6 py-3 border-b flex items-center gap-2"
                         style={{ borderColor:"var(--bg-border)",
                                  background: siemStatus === "sent"    ? "rgba(0,255,136,0.03)"
                                            : siemStatus === "error"   ? "rgba(255,68,68,0.03)"
                                            : "rgba(124,58,237,0.03)" }}>
                      <Shield className="size-3.5 flex-shrink-0"
                              style={{ color: siemStatus === "sent"    ? "var(--accent-green)"
                                            : siemStatus === "error"   ? "#ff4444"
                                            : "#a78bfa",
                                       animation: siemStatus === "sending" ? "pulse 1s infinite" : "none" }} />
                      <span className="text-xs" style={{ color:"var(--text-muted)", fontFamily:"'JetBrains Mono', monospace" }}>
                        {siemStatus === "sending" && "Sending to SentinelCore SIEM..."}
                        {siemStatus === "sent"    && "✓ Event logged in SentinelCore SIEM"}
                        {siemStatus === "error"   && "SIEM offline — event not logged"}
                      </span>
                      {siemStatus === "sent" && (
                        <button onClick={() => navigate("/siem")}
                                className="ml-auto text-xs px-2 py-0.5 rounded transition-all"
                                style={{ color:"var(--accent-green)", background:"rgba(0,255,136,0.08)",
                                         border:"1px solid rgba(0,255,136,0.2)", fontFamily:"'JetBrains Mono', monospace" }}>
                          View in SIEM →
                        </button>
                      )}
                    </div>
                  )}

                  {/* Actions */}
                  <div className="px-6 py-4 flex flex-col sm:flex-row gap-3">
                    <button onClick={handleReset}
                            className="btn-primary flex-1 flex items-center justify-center gap-2 px-5 py-3 text-sm"
                            style={{ fontFamily:"'Syne', sans-serif", fontWeight:700 }}>
                      <RefreshCw className="size-4" /> Scan Another
                    </button>
                    <button onClick={() => navigate("/history")}
                            className="btn-ghost flex-1 flex items-center justify-center gap-2 px-5 py-3 text-sm"
                            style={{ fontFamily:"'DM Sans', sans-serif" }}>
                      <HistoryIcon className="size-4" /> View History
                    </button>
                  </div>
                </div>

                {/* Engine tag */}
                <div className="flex justify-end">
                  <div className="flex items-center gap-2 text-xs px-3 py-1.5 rounded-lg"
                       style={{ color:"var(--text-muted)", background:"var(--bg-card)",
                                border:"1px solid var(--bg-border)", fontFamily:"'JetBrains Mono', monospace" }}>
                    <Cpu className="size-3" />
                    engine v{result.detectionVersion} · {result.mlEnabled ? "hybrid ML+rules" : "rules only"} · {result.inputType} mode
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