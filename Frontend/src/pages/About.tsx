import { motion } from "motion/react";
import { Shield, Brain, Lock, Code, Terminal, ChevronRight, Cpu, Eye, Zap } from "lucide-react";

export default function About() {
  const technologies = [
    { icon: Brain,    title: "AI & Pattern Recognition", description: "Rule-based AI with Levenshtein distance matching, homoglyph detection, and fuzzy brand matching that catches attacks even outside known databases." },
    { icon: Shield,   title: "Cybersecurity Techniques",  description: "Domain validation, DNS structure analysis, TLD risk scoring, punycode/IDN detection, URL redirect tracking, and open-redirect detection." },
    { icon: Lock,     title: "NLP Text Analysis",         description: "Natural language processing scans email bodies, subject lines, and SMS messages for 60+ phishing phrases, OTP requests, and social engineering tactics." },
    { icon: Code,     title: "Web Technologies",          description: "React + TypeScript frontend, Node.js + Express backend, MongoDB with Mongoose, real-time REST API communication between all layers." },
  ];

  const steps = [
    { n: "01", title: "Input Received",      desc: "User submits a URL, email address, or message text to the scanner." },
    { n: "02", title: "Type Classification", desc: "System auto-detects if input is a URL, email address, or text message and routes to the correct engine." },
    { n: "03", title: "Parallel Analysis",   desc: "URL engine (16 checks), text engine (15 checks), and email engine (5 checks) run simultaneously." },
    { n: "04", title: "Score Aggregation",   desc: "Signals are weighted and combined: High-risk (OTP request = +40), medium-risk (urgency language = +20), low-risk (HTTPS missing = +10)." },
    { n: "05", title: "Verdict + Report",    desc: "Score 0–25 = Safe, 26–65 = Suspicious, 66–100 = Phishing. All detected issues are logged with explanations." },
  ];

  const scoring = [
    ["OTP / credential request", "+40", "high"],
    ["High-confidence phishing phrase", "+20–50", "high"],
    ["Brand spoofing / typosquatting", "+28–40", "high"],
    ["Social engineering tactic", "+20–35", "high"],
    ["IP address as domain", "+35", "high"],
    ["Malicious attachment indicator", "+30", "medium"],
    ["Punycode / IDN domain", "+30", "medium"],
    ["Multiple subdomains", "+12–25", "medium"],
    ["Urgency manipulation", "+10–30", "medium"],
    ["Suspicious TLD (.tk/.ml/.ga)", "+15–25", "medium"],
    ["URL shortener detected", "+20", "medium"],
    ["Excessive hyphens in URL", "+10–20", "low"],
    ["No HTTPS", "+10", "low"],
    ["Generic greeting (Dear Customer)", "+15", "low"],
    ["Excessive capitalization", "+12", "low"],
  ];

  const scoringColor = (level: string) =>
    level === "high" ? "#ff4444" : level === "medium" ? "#f5a623" : "#00ff88";

  return (
    <div className="min-h-full py-12 px-6" style={{ background: "var(--bg-base)" }}>
      <div className="max-w-5xl mx-auto">

        {/* ── HEADER ── */}
        <motion.div initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} className="mb-16">
          <div className="tag-green inline-flex mb-4">
            <Terminal className="size-3" /> SYSTEM INFO
          </div>
          <h1 className="text-4xl font-bold mb-3"
              style={{ fontFamily: "'Syne', sans-serif", color: "var(--text-primary)" }}>
            About PhishGuard
          </h1>
          <p className="text-base max-w-xl" style={{ color: "var(--text-secondary)" }}>
            An AI-powered phishing detection system built with real-world cybersecurity
            techniques — not just keyword matching.
          </p>
        </motion.div>

        {/* ── WHAT IS PHISHING ── */}
        <motion.div initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }}
                    className="rounded-xl p-7 mb-6"
                    style={{ background: "var(--bg-card)", border: "1px solid var(--bg-border)" }}>
          <div className="flex items-center gap-3 mb-5">
            <div className="w-9 h-9 rounded-lg flex items-center justify-center"
                 style={{ background: "rgba(0,255,136,0.06)", border: "1px solid rgba(0,255,136,0.15)" }}>
              <Shield className="size-5" style={{ color: "var(--accent-green)" }} />
            </div>
            <h2 className="text-xl font-bold" style={{ fontFamily: "'Syne', sans-serif", color: "var(--text-primary)" }}>
              What is Phishing?
            </h2>
          </div>
          <div className="space-y-3 text-sm leading-relaxed" style={{ color: "var(--text-secondary)" }}>
            <p><span style={{ color: "var(--text-primary)", fontWeight: 600 }}>Phishing</span> is a cyberattack where malicious actors trick people into revealing sensitive information — passwords, OTPs, credit card numbers, or personal data.</p>
            <p>Attacks arrive as <span style={{ color: "var(--text-primary)" }}>deceptive emails</span>, <span style={{ color: "var(--text-primary)" }}>fake login pages</span>, or <span style={{ color: "var(--text-primary)" }}>cloned brand websites</span>. They're designed to look exactly like the real thing.</p>
            <p>Modern phishing uses <span style={{ color: "var(--text-primary)" }}>typosquatting</span>, <span style={{ color: "var(--text-primary)" }}>homoglyph characters</span>, and <span style={{ color: "var(--text-primary)" }}>social engineering psychology</span> — far beyond simple fake links.</p>
          </div>
        </motion.div>

        {/* ── HOW IT WORKS ── */}
        <motion.div initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.15 }}
                    className="rounded-xl overflow-hidden mb-6"
                    style={{ background: "var(--bg-card)", border: "1px solid var(--bg-border)" }}>
          <div className="flex items-center gap-2 px-5 py-4 border-b"
               style={{ borderColor: "var(--bg-border)", background: "rgba(0,0,0,0.3)" }}>
            <div className="flex gap-1.5">
              <div className="w-2.5 h-2.5 rounded-full" style={{ background: "#ff5f57" }} />
              <div className="w-2.5 h-2.5 rounded-full" style={{ background: "#febc2e" }} />
              <div className="w-2.5 h-2.5 rounded-full" style={{ background: "#28c840" }} />
            </div>
            <span className="text-xs ml-1" style={{ color: "var(--text-muted)", fontFamily: "'JetBrains Mono', monospace" }}>
              detection_pipeline.md
            </span>
          </div>
          <div className="p-6 space-y-5">
            {steps.map((s, i) => (
              <motion.div key={s.n}
                initial={{ opacity: 0, x: -10 }} animate={{ opacity: 1, x: 0 }}
                transition={{ delay: 0.2 + i * 0.08 }}
                className="flex gap-4">
                <div className="flex-shrink-0 w-10 h-10 rounded-lg flex items-center justify-center text-sm font-bold"
                     style={{ background: "rgba(0,255,136,0.06)", border: "1px solid rgba(0,255,136,0.15)", color: "var(--accent-green)", fontFamily: "'JetBrains Mono', monospace" }}>
                  {s.n}
                </div>
                <div className="flex-1 pt-1">
                  <div className="font-semibold mb-1 text-sm" style={{ color: "var(--text-primary)", fontFamily: "'Syne', sans-serif" }}>
                    {s.title}
                  </div>
                  <div className="text-sm" style={{ color: "var(--text-secondary)" }}>{s.desc}</div>
                </div>
              </motion.div>
            ))}
          </div>
        </motion.div>

        {/* ── RISK SCORING TABLE ── */}
        <motion.div initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.2 }}
                    className="rounded-xl overflow-hidden mb-6"
                    style={{ background: "var(--bg-card)", border: "1px solid var(--bg-border)" }}>
          <div className="px-6 py-5 border-b flex items-center gap-3"
               style={{ borderColor: "var(--bg-border)" }}>
            <Cpu className="size-5" style={{ color: "var(--accent-green)" }} />
            <h2 className="text-lg font-bold" style={{ fontFamily: "'Syne', sans-serif", color: "var(--text-primary)" }}>
              Risk Scoring System
            </h2>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full data-table">
              <thead>
                <tr>
                  <th className="text-left">Signal</th>
                  <th className="text-left">Score Added</th>
                  <th className="text-left">Severity</th>
                </tr>
              </thead>
              <tbody>
                {scoring.map(([signal, score, level]) => (
                  <tr key={signal}>
                    <td className="text-sm" style={{ color: "var(--text-secondary)" }}>{signal}</td>
                    <td>
                      <span className="text-xs font-bold" style={{ color: scoringColor(level), fontFamily: "'JetBrains Mono', monospace" }}>
                        {score}
                      </span>
                    </td>
                    <td>
                      <span className="text-xs px-2 py-0.5 rounded"
                            style={{
                              fontFamily: "'JetBrains Mono', monospace",
                              color: scoringColor(level),
                              background: `${scoringColor(level)}12`,
                              border: `1px solid ${scoringColor(level)}30`,
                              textTransform: "uppercase",
                              letterSpacing: "0.06em",
                            }}>
                        {level}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {/* Verdict thresholds */}
          <div className="px-6 py-4 border-t grid grid-cols-3 gap-3" style={{ borderColor: "var(--bg-border)" }}>
            {[["0–25", "SAFE", "#00ff88"], ["26–65", "SUSPICIOUS", "#f5a623"], ["66–100", "PHISHING", "#ff4444"]].map(([range, label, color]) => (
              <div key={label} className="text-center rounded-lg py-3"
                   style={{ background: `${color}08`, border: `1px solid ${color}20` }}>
                <div className="text-base font-bold" style={{ color, fontFamily: "'Syne', sans-serif" }}>{range}</div>
                <div className="text-xs mt-0.5" style={{ color: "var(--text-muted)", fontFamily: "'JetBrains Mono', monospace" }}>{label}</div>
              </div>
            ))}
          </div>
        </motion.div>

        {/* ── TECHNOLOGIES ── */}
        <motion.div initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.25 }}
                    className="mb-6">
          <h2 className="text-xl font-bold mb-5"
              style={{ fontFamily: "'Syne', sans-serif", color: "var(--text-primary)" }}>
            Technologies Used
          </h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {technologies.map((t, i) => (
              <motion.div key={t.title}
                initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.3 + i * 0.07 }}
                className="rounded-xl p-5 transition-all card"
                onMouseEnter={e => (e.currentTarget as HTMLDivElement).style.borderColor = "rgba(0,255,136,0.2)"}
                onMouseLeave={e => (e.currentTarget as HTMLDivElement).style.borderColor = "var(--bg-border)"}>
                <div className="flex items-start gap-4">
                  <div className="w-10 h-10 rounded-lg flex-shrink-0 flex items-center justify-center"
                       style={{ background: "rgba(0,255,136,0.06)", border: "1px solid rgba(0,255,136,0.12)" }}>
                    <t.icon className="size-5" style={{ color: "var(--accent-green)" }} strokeWidth={1.8} />
                  </div>
                  <div>
                    <div className="font-semibold mb-1.5 text-sm"
                         style={{ color: "var(--text-primary)", fontFamily: "'Syne', sans-serif" }}>
                      {t.title}
                    </div>
                    <p className="text-xs leading-relaxed" style={{ color: "var(--text-secondary)" }}>
                      {t.description}
                    </p>
                  </div>
                </div>
              </motion.div>
            ))}
          </div>
        </motion.div>

        {/* ── DISCLAIMER ── */}
        <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.4 }}
                    className="rounded-xl p-5 flex items-start gap-4"
                    style={{ background: "rgba(0,255,136,0.04)", border: "1px solid rgba(0,255,136,0.15)" }}>
          <Eye className="size-5 flex-shrink-0 mt-0.5" style={{ color: "var(--accent-green)" }} />
          <p className="text-sm leading-relaxed" style={{ color: "var(--text-secondary)" }}>
            PhishGuard is designed for <span style={{ color: "var(--text-primary)", fontWeight: 600 }}>educational purposes</span> and <span style={{ color: "var(--text-primary)", fontWeight: 600 }}>real-world cybersecurity awareness</span>. Always verify suspicious links through multiple sources. Practice safe browsing. Stay vigilant.
          </p>
        </motion.div>

      </div>
    </div>
  );
}