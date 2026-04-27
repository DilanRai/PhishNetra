import { useState } from "react";
import { useNavigate } from "react-router";
import { motion } from "motion/react";
import {
  Shield, Search, Globe, Link as LinkIcon,
  TriangleAlert as AlertTriangle, FileSearch,
  Cpu, Lock, Eye, Zap, ChevronRight, Terminal,
  CheckCircle, Activity
} from "lucide-react";

const EXAMPLE_SCANS = [
  { input: "http://paypal-secure-login.tk/verify", status: "phishing", score: 92 },
  { input: "https://google.com", status: "safe", score: 0 },
  { input: "Urgent! Your account has been suspended. Verify now!", status: "suspicious", score: 58 },
];

export default function Home() {
  const navigate = useNavigate();
  const [url, setUrl] = useState("");

  const handleScan = () => {
    if (url.trim()) navigate("/scan", { state: { url } });
  };

  const features = [
    { icon: Search, title: "URL Analysis", description: "Deep inspection of URL structure, length, character encoding, and path keywords that indicate credential harvesting.", tag: "ACTIVE" },
    { icon: Globe, title: "Domain Spoofing", description: "Levenshtein distance matching catches typosquatting like 'gooogle.com' even if not in a known fakes list.", tag: "ACTIVE" },
    { icon: Shield, title: "Brand Impersonation", description: "Detects 13 major brands including PayPal, Google, Apple, Chase, IRS using pattern matching and fuzzy logic.", tag: "ACTIVE" },
    { icon: LinkIcon, title: "Redirect Detection", description: "Identifies open redirect parameters, URL shorteners, and data URI schemes that mask true destinations.", tag: "ACTIVE" },
    { icon: AlertTriangle, title: "Social Engineering", description: "Detects authority impersonation (IRS/FBI), fear tactics, OTP requests, and urgency manipulation patterns.", tag: "ACTIVE" },
    { icon: FileSearch, title: "Email Content Analysis", description: "Full NLP-style analysis of email body, subject lines, attachment indicators, and header anomalies.", tag: "ACTIVE" },
    { icon: Cpu, title: "Homoglyph Detection", description: "Catches Unicode lookalike characters — 'rn' for 'm', '0' for 'o' — used to create visually identical fake domains.", tag: "NEW" },
    { icon: Lock, title: "OTP Credential Harvesting", description: "11 regex patterns detect when messages ask for OTP, PIN, CVV, or passwords — a major phishing signal.", tag: "NEW" },
    { icon: Eye, title: "Punycode / IDN Domains", description: "Detects xn-- prefixed internationalized domain names used to create visually identical impersonation URLs.", tag: "NEW" },
  ];

  const stats = [
    { value: "16", label: "Detection Modules", icon: Cpu },
    { value: "3", label: "Analysis Engines", icon: Activity },
    { value: "< 1s", label: "Response Time", icon: Zap },
    { value: "99%", label: "URL Coverage", icon: Shield },
  ];

  const statusColor = (s: string) => {
    if (s === "phishing") return { color: "#ff4444", bg: "rgba(255,68,68,0.08)", border: "rgba(255,68,68,0.2)", label: "PHISHING" };
    if (s === "suspicious") return { color: "#f5a623", bg: "rgba(245,166,35,0.08)", border: "rgba(245,166,35,0.2)", label: "SUSPICIOUS" };
    return { color: "#00ff88", bg: "rgba(0,255,136,0.08)", border: "rgba(0,255,136,0.2)", label: "SAFE" };
  };

  return (
    <div className="min-h-full">

      {/* ════════════════════════════════════════
          HERO
      ════════════════════════════════════════ */}
      <section className="relative overflow-hidden hex-pattern" style={{ minHeight: "88vh", display: "flex", alignItems: "center" }}>

        {/* Background glows */}
        <div className="absolute inset-0 pointer-events-none">
          <div className="absolute top-1/4 left-1/4 w-[600px] h-[600px] rounded-full opacity-10"
            style={{ background: "radial-gradient(circle, #00ff88, transparent 70%)", filter: "blur(80px)" }} />
          <div className="absolute bottom-1/4 right-1/4 w-[400px] h-[400px] rounded-full opacity-8"
            style={{ background: "radial-gradient(circle, #7c3aed, transparent 70%)", filter: "blur(100px)" }} />
        </div>

        <div className="relative max-w-6xl mx-auto px-6 py-24 w-full">
          <div className="max-w-3xl">

            {/* Eyebrow tag */}
            <motion.div initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.5 }}>
              <div className="tag-green inline-flex mb-8">
                <div className="w-1.5 h-1.5 rounded-full safe-pulse" style={{ background: "var(--accent-green)" }} />
                AI-POWERED · REAL-TIME · v2.0
              </div>
            </motion.div>

            {/* Headline */}
            <motion.h1
              initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1, duration: 0.6 }}
              className="mb-6 leading-none tracking-tight"
              style={{ fontFamily: "'Syne', sans-serif", fontWeight: 800, fontSize: "clamp(2.8rem, 5vw, 4.5rem)", color: "var(--text-primary)" }}>
              Detect Phishing<br />
              <span style={{ color: "var(--accent-green)" }} className="text-glow-green">
                Before It Strikes.
              </span>
            </motion.h1>

            {/* Subheading */}
            <motion.p
              initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.2, duration: 0.6 }}
              className="mb-10 text-lg leading-relaxed max-w-xl"
              style={{ color: "var(--text-secondary)", fontFamily: "'DM Sans', sans-serif" }}>
              Analyze URLs, emails, and suspicious messages with 16 real-world detection
              techniques. Typosquatting, brand impersonation, OTP harvesting — caught instantly.
            </motion.p>

            {/* Input */}
            <motion.div
              initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.3, duration: 0.6 }}
              className="mb-4">
              <div className="flex gap-3 flex-col sm:flex-row">
                <div className="relative flex-1">
                  <Search className="absolute left-4 top-1/2 -translate-y-1/2 size-4"
                    style={{ color: "var(--text-muted)" }} />
                  <input
                    type="text" value={url}
                    onChange={(e) => setUrl(e.target.value)}
                    onKeyDown={(e) => e.key === "Enter" && handleScan()}
                    placeholder="Paste URL, email, or suspicious message..."
                    className="input-terminal w-full pl-11 pr-4 py-4 rounded-xl text-sm"
                    style={{ fontFamily: "'DM Sans', sans-serif" }}
                  />
                </div>
                <button onClick={handleScan} disabled={!url.trim()}
                  className="btn-primary flex items-center justify-center gap-2 px-7 py-4 text-sm"
                  style={{ fontFamily: "'Syne', sans-serif", fontWeight: 700, minWidth: 140 }}>
                  <Terminal className="size-4" />
                  Analyze
                </button>
              </div>
              <p className="mt-2.5 text-xs" style={{ color: "var(--text-muted)", fontFamily: "'JetBrains Mono', monospace" }}>
                ↳ Supports URLs · Email addresses · Email body text · SMS messages
              </p>
            </motion.div>

            {/* Quick example links */}
            <motion.div
              initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.5 }}
              className="flex flex-wrap gap-2 mt-5">
              <span className="text-xs mr-1" style={{ color: "var(--text-muted)" }}>Try:</span>
              {["http://paypal-login.tk", "Dear customer, verify your account now!", "https://google.com"].map((ex) => (
                <button key={ex}
                  onClick={() => { setUrl(ex); }}
                  className="text-xs px-3 py-1 rounded-full transition-all"
                  style={{
                    fontFamily: "'JetBrains Mono', monospace",
                    color: "var(--accent-cyan)",
                    background: "rgba(0,212,255,0.05)",
                    border: "1px solid rgba(0,212,255,0.15)",
                  }}
                  onMouseEnter={e => (e.currentTarget.style.background = "rgba(0,212,255,0.1)")}
                  onMouseLeave={e => (e.currentTarget.style.background = "rgba(0,212,255,0.05)")}>
                  {ex.length > 32 ? ex.slice(0, 32) + "…" : ex}
                </button>
              ))}
            </motion.div>
          </div>

          {/* ── Live scan preview panel (right side on desktop) ── */}
          <motion.div
            initial={{ opacity: 0, x: 40 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: 0.4, duration: 0.7 }}
            className="absolute right-6 top-1/2 -translate-y-1/2 w-80 hidden xl:block">
            <div className="rounded-xl overflow-hidden"
              style={{ background: "var(--bg-card)", border: "1px solid var(--bg-border)" }}>
              {/* Terminal header */}
              <div className="flex items-center gap-2 px-4 py-3 border-b"
                style={{ borderColor: "var(--bg-border)", background: "rgba(0,0,0,0.3)" }}>
                <div className="flex gap-1.5">
                  <div className="w-3 h-3 rounded-full" style={{ background: "#ff5f57" }} />
                  <div className="w-3 h-3 rounded-full" style={{ background: "#febc2e" }} />
                  <div className="w-3 h-3 rounded-full" style={{ background: "#28c840" }} />
                </div>
                <span className="text-xs ml-2" style={{ color: "var(--text-muted)", fontFamily: "'JetBrains Mono', monospace" }}>
                  live_scan_feed.log
                </span>
              </div>
              {/* Scan entries */}
              <div className="p-3 space-y-2">
                {EXAMPLE_SCANS.map((scan, i) => {
                  const sc = statusColor(scan.status);
                  return (
                    <motion.div key={i}
                      initial={{ opacity: 0, x: 10 }} animate={{ opacity: 1, x: 0 }}
                      transition={{ delay: 0.6 + i * 0.15 }}
                      className="rounded-lg p-3"
                      style={{ background: "var(--bg-elevated)", border: `1px solid ${sc.border}` }}>
                      <div className="flex items-center justify-between mb-1.5">
                        <span className="text-xs font-bold px-2 py-0.5 rounded"
                          style={{ background: sc.bg, color: sc.color, fontFamily: "'JetBrains Mono', monospace", fontSize: 9, letterSpacing: "0.1em" }}>
                          {sc.label}
                        </span>
                        <span className="text-xs font-bold" style={{ color: sc.color, fontFamily: "'JetBrains Mono', monospace" }}>
                          {scan.score}/100
                        </span>
                      </div>
                      <p className="text-xs truncate" style={{ color: "var(--text-secondary)", fontFamily: "'JetBrains Mono', monospace", fontSize: 10 }}>
                        {scan.input}
                      </p>
                      {/* Mini score bar */}
                      <div className="mt-2 h-1 rounded-full" style={{ background: "var(--bg-border)" }}>
                        <div className="h-full rounded-full transition-all"
                          style={{ width: `${scan.score}%`, background: sc.color }} />
                      </div>
                    </motion.div>
                  );
                })}
              </div>
              <div className="px-4 py-2 border-t flex items-center gap-2"
                style={{ borderColor: "var(--bg-border)" }}>
                <div className="w-1.5 h-1.5 rounded-full safe-pulse" style={{ background: "var(--accent-green)" }} />
                <span className="text-xs" style={{ color: "var(--text-muted)", fontFamily: "'JetBrains Mono', monospace" }}>
                  engine active · 0ms latency
                </span>
              </div>
            </div>
          </motion.div>
        </div>
      </section>

      {/* ════════════════════════════════════════
          STATS BAR
      ════════════════════════════════════════ */}
      <section className="border-y" style={{ borderColor: "var(--bg-border)", background: "var(--bg-surface)" }}>
        <div className="max-w-6xl mx-auto px-6">
          <div className="grid grid-cols-2 md:grid-cols-4 divide-x" style={{ borderColor: "var(--bg-border)" }}>
            {stats.map((stat, i) => (
              <motion.div key={stat.label}
                initial={{ opacity: 0, y: 10 }} whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }} transition={{ delay: i * 0.07 }}
                className="flex flex-col items-center justify-center py-8 gap-1">
                <stat.icon className="size-4 mb-2" style={{ color: "var(--accent-green)" }} />
                <div className="text-2xl font-bold" style={{ color: "var(--text-primary)", fontFamily: "'Syne', sans-serif" }}>
                  {stat.value}
                </div>
                <div className="text-xs uppercase tracking-widest" style={{ color: "var(--text-muted)", fontFamily: "'JetBrains Mono', monospace" }}>
                  {stat.label}
                </div>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* ════════════════════════════════════════
          FEATURES GRID
      ════════════════════════════════════════ */}
      <section className="py-24 px-6">
        <div className="max-w-6xl mx-auto">

          <motion.div initial={{ opacity: 0, y: 20 }} whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }} className="mb-16">
            <div className="tag-green inline-flex mb-4">DETECTION MODULES</div>
            <h2 className="text-3xl md:text-4xl font-bold mb-4"
              style={{ fontFamily: "'Syne', sans-serif", color: "var(--text-primary)" }}>
              How We Catch Phishing
            </h2>
            <p className="text-base max-w-xl" style={{ color: "var(--text-secondary)" }}>
              Nine layers of real-world detection — from URL structure analysis to social engineering pattern recognition.
            </p>
          </motion.div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {features.map((f, i) => (
              <motion.div key={f.title}
                initial={{ opacity: 0, y: 20 }} whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }} transition={{ delay: i * 0.06 }}
                className="group card p-6 transition-all duration-300 cursor-default"
                style={{ background: "var(--bg-card)" }}
                onMouseEnter={e => {
                  (e.currentTarget as HTMLDivElement).style.borderColor = "rgba(0,255,136,0.2)";
                  (e.currentTarget as HTMLDivElement).style.background = "var(--bg-hover)";
                }}
                onMouseLeave={e => {
                  (e.currentTarget as HTMLDivElement).style.borderColor = "var(--bg-border)";
                  (e.currentTarget as HTMLDivElement).style.background = "var(--bg-card)";
                }}>

                <div className="flex items-start justify-between mb-4">
                  <div className="w-10 h-10 rounded-lg flex items-center justify-center"
                    style={{ background: "rgba(0,255,136,0.06)", border: "1px solid rgba(0,255,136,0.12)" }}>
                    <f.icon className="size-5" style={{ color: "var(--accent-green)" }} strokeWidth={1.8} />
                  </div>
                  <span className="text-xs px-2 py-0.5 rounded font-bold"
                    style={{
                      fontFamily: "'JetBrains Mono', monospace",
                      letterSpacing: "0.1em",
                      background: f.tag === "NEW" ? "rgba(0,212,255,0.08)" : "rgba(0,255,136,0.06)",
                      color: f.tag === "NEW" ? "var(--accent-cyan)" : "var(--accent-green)",
                      border: f.tag === "NEW" ? "1px solid rgba(0,212,255,0.2)" : "1px solid rgba(0,255,136,0.15)",
                    }}>
                    {f.tag}
                  </span>
                </div>

                <h3 className="font-semibold mb-2" style={{ color: "var(--text-primary)", fontFamily: "'Syne', sans-serif" }}>
                  {f.title}
                </h3>
                <p className="text-sm leading-relaxed" style={{ color: "var(--text-secondary)" }}>
                  {f.description}
                </p>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* ════════════════════════════════════════
          HOW IT WORKS — terminal steps
      ════════════════════════════════════════ */}
      <section className="py-20 px-6 border-t" style={{ borderColor: "var(--bg-border)", background: "var(--bg-surface)" }}>
        <div className="max-w-6xl mx-auto">
          <div className="grid md:grid-cols-2 gap-16 items-center">

            <motion.div initial={{ opacity: 0, x: -20 }} whileInView={{ opacity: 1, x: 0 }}
              viewport={{ once: true }}>
              <div className="tag-green inline-flex mb-4">HOW IT WORKS</div>
              <h2 className="text-3xl font-bold mb-4"
                style={{ fontFamily: "'Syne', sans-serif", color: "var(--text-primary)" }}>
                From Input to Verdict<br />in Milliseconds
              </h2>
              <p className="text-sm leading-relaxed mb-6" style={{ color: "var(--text-secondary)" }}>
                Three analysis engines run in parallel — URL structure, text content, and
                email address validation — then combine scores into a final risk verdict.
              </p>
              <button onClick={() => navigate("/scan")}
                className="btn-primary flex items-center gap-2 px-6 py-3 text-sm"
                style={{ fontFamily: "'Syne', sans-serif" }}>
                Try a Scan <ChevronRight className="size-4" />
              </button>
            </motion.div>

            {/* Terminal-style steps */}
            <motion.div initial={{ opacity: 0, x: 20 }} whileInView={{ opacity: 1, x: 0 }}
              viewport={{ once: true }} transition={{ delay: 0.1 }}
              className="rounded-xl overflow-hidden"
              style={{ background: "var(--bg-card)", border: "1px solid var(--bg-border)" }}>
              {/* Terminal bar */}
              <div className="flex items-center gap-2 px-4 py-3 border-b"
                style={{ borderColor: "var(--bg-border)", background: "rgba(0,0,0,0.4)" }}>
                <div className="flex gap-1.5">
                  <div className="w-3 h-3 rounded-full" style={{ background: "#ff5f57" }} />
                  <div className="w-3 h-3 rounded-full" style={{ background: "#febc2e" }} />
                  <div className="w-3 h-3 rounded-full" style={{ background: "#28c840" }} />
                </div>
                <span className="text-xs ml-2" style={{ color: "var(--text-muted)", fontFamily: "'JetBrains Mono', monospace" }}>
                  detection_pipeline.sh
                </span>
              </div>
              {/* Steps */}
              <div className="p-5 space-y-3 font-mono text-sm" style={{ fontFamily: "'JetBrains Mono', monospace" }}>
                {[
                  { cmd: "$ detect --input", out: "→ classifying input type...", color: "var(--accent-cyan)" },
                  { cmd: "$ run url_engine", out: "→ 16 URL checks passed", color: "var(--accent-green)" },
                  { cmd: "$ run text_engine", out: "→ NLP analysis complete", color: "var(--accent-green)" },
                  { cmd: "$ run email_engine", out: "→ sender domain verified", color: "var(--accent-green)" },
                  { cmd: "$ score --aggregate", out: "→ risk score: 87/100", color: "#f5a623" },
                  { cmd: "$ verdict", out: "→ ⚠ PHISHING DETECTED", color: "#ff4444" },
                ].map((step, i) => (
                  <motion.div key={i}
                    initial={{ opacity: 0, x: -10 }} whileInView={{ opacity: 1, x: 0 }}
                    viewport={{ once: true }} transition={{ delay: 0.2 + i * 0.08 }}>
                    <div style={{ color: "var(--text-muted)", fontSize: 12 }}>{step.cmd}</div>
                    <div style={{ color: step.color, fontSize: 11, marginLeft: 12 }}>{step.out}</div>
                  </motion.div>
                ))}
              </div>
            </motion.div>
          </div>
        </div>
      </section>

      {/* ════════════════════════════════════════
          CTA BANNER
      ════════════════════════════════════════ */}
      <section className="py-20 px-6">
        <div className="max-w-6xl mx-auto">
          <motion.div
            initial={{ opacity: 0, y: 20 }} whileInView={{ opacity: 1, y: 0 }} viewport={{ once: true }}
            className="relative rounded-2xl overflow-hidden p-12 text-center hex-pattern"
            style={{ background: "linear-gradient(135deg, rgba(0,255,136,0.06) 0%, rgba(124,58,237,0.06) 100%)", border: "1px solid rgba(0,255,136,0.15)" }}>
            <div className="absolute inset-0 pointer-events-none"
              style={{ background: "radial-gradient(circle at 50% 50%, rgba(0,255,136,0.05), transparent 70%)" }} />
            <div className="relative">
              <CheckCircle className="size-12 mx-auto mb-5" style={{ color: "var(--accent-green)" }} />
              <h2 className="text-3xl font-bold mb-3"
                style={{ fontFamily: "'Syne', sans-serif", color: "var(--text-primary)" }}>
                Don't Get Hooked.
              </h2>
              <p className="mb-8 text-base max-w-md mx-auto" style={{ color: "var(--text-secondary)" }}>
                Paste any URL or message right now. Free. Instant. No account needed.
              </p>
              <button onClick={() => navigate("/scan")}
                className="btn-primary inline-flex items-center gap-2 px-8 py-4 text-base"
                style={{ fontFamily: "'Syne', sans-serif", fontWeight: 700 }}>
                <Terminal className="size-5" /> Start Scanning Free
              </button>
            </div>
          </motion.div>
        </div>
      </section>

    </div>
  );
}