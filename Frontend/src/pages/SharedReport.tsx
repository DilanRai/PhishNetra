// FILE: src/pages/SharedReport.tsx
// Public shareable scan report — no login required

import { useEffect, useState } from "react";
import { useParams, useNavigate } from "react-router";
import { motion } from "motion/react";
import {
  Shield, XCircle, TriangleAlert as AlertTriangle,
  CircleCheck as CheckCircle, ExternalLink,
  ChevronRight, Brain, Globe, Terminal,
} from "lucide-react";
import { API_BASE } from "../config";

const STATUS_CFG = {
  safe:       { color:"#00ff88", bg:"rgba(0,255,136,0.07)", border:"rgba(0,255,136,0.25)", label:"SAFE",       icon:CheckCircle   },
  suspicious: { color:"#f5a623", bg:"rgba(245,166,35,0.07)", border:"rgba(245,166,35,0.25)", label:"SUSPICIOUS", icon:AlertTriangle  },
  phishing:   { color:"#ff4444", bg:"rgba(255,68,68,0.07)",  border:"rgba(255,68,68,0.25)",  label:"PHISHING",   icon:XCircle       },
};

export default function SharedReport() {
  const { shareId } = useParams();
  const navigate    = useNavigate();
  const [scan,    setScan]    = useState<any | null>(null);
  const [loading, setLoading] = useState(true);
  const [error,   setError]   = useState<string | null>(null);

  useEffect(() => {
    if (!shareId) return;
    fetch(`${API_BASE}/api/scan/report/${shareId}`)
      .then(r => r.ok ? r.json() : Promise.reject("Not found"))
      .then(setScan)
      .catch(() => setError("Report not found or this link has expired."))
      .finally(() => setLoading(false));
  }, [shareId]);

  if (loading) return (
    <div className="min-h-screen flex items-center justify-center" style={{ background:"var(--bg-base)" }}>
      <div className="text-center">
        <div className="w-10 h-10 border-2 rounded-full animate-spin mx-auto mb-4"
             style={{ borderColor:"var(--accent-green)", borderTopColor:"transparent" }} />
        <p style={{ color:"var(--text-muted)", fontFamily:"'JetBrains Mono', monospace", fontSize:12 }}>
          Loading report...
        </p>
      </div>
    </div>
  );

  if (error || !scan) return (
    <div className="min-h-screen flex items-center justify-center px-6" style={{ background:"var(--bg-base)" }}>
      <div className="text-center max-w-sm">
        <Shield className="size-12 mx-auto mb-4" style={{ color:"var(--text-muted)" }} />
        <h2 className="text-xl font-bold mb-2" style={{ fontFamily:"'Syne', sans-serif", color:"var(--text-primary)" }}>
          Report Not Found
        </h2>
        <p className="text-sm mb-6" style={{ color:"var(--text-secondary)" }}>
          {error || "This report link is invalid or has expired."}
        </p>
        <button onClick={() => navigate("/")}
                className="btn-primary px-6 py-3 text-sm"
                style={{ fontFamily:"'Syne', sans-serif", fontWeight:700 }}>
          Go to PhishGuard
        </button>
      </div>
    </div>
  );

  const c    = STATUS_CFG[scan.status as keyof typeof STATUS_CFG] || STATUS_CFG.safe;
  const Icon = c.icon;

  return (
    <div className="min-h-screen py-10 px-6" style={{ background:"var(--bg-base)" }}>
      <div className="max-w-2xl mx-auto">

        {/* Branding header */}
        <div className="flex items-center justify-between mb-8">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-xl flex items-center justify-center"
                 style={{ background:"rgba(0,255,136,0.08)", border:"1px solid rgba(0,255,136,0.2)" }}>
              <Shield className="size-5" style={{ color:"var(--accent-green)" }} />
            </div>
            <div>
              <div className="text-sm font-bold" style={{ fontFamily:"'Syne', sans-serif", color:"var(--text-primary)" }}>
                PhishGuard AI
              </div>
              <div style={{ fontSize:9, color:"var(--accent-green)", fontFamily:"'JetBrains Mono', monospace", letterSpacing:"0.15em" }}>
                THREAT ANALYSIS REPORT
              </div>
            </div>
          </div>
          <div className="text-xs" style={{ color:"var(--text-muted)", fontFamily:"'JetBrains Mono', monospace" }}>
            {new Date(scan.createdAt).toLocaleString()}
          </div>
        </div>

        {/* Main card */}
        <motion.div initial={{ opacity:0, y:16 }} animate={{ opacity:1, y:0 }}
                    className="rounded-2xl overflow-hidden mb-4"
                    style={{ background:"var(--bg-card)", border:`2px solid ${c.border}`,
                             boxShadow:`0 0 40px ${c.bg}` }}>

          {/* Verdict */}
          <div className="px-6 py-5 flex items-center gap-4"
               style={{ background:c.bg, borderBottom:`1px solid ${c.border}` }}>
            <div className="w-14 h-14 rounded-2xl flex items-center justify-center"
                 style={{ background:c.bg, border:`2px solid ${c.border}` }}>
              <Icon className="size-8" style={{ color:c.color }} strokeWidth={2} />
            </div>
            <div className="flex-1">
              <div className="text-2xl font-black mb-1"
                   style={{ color:c.color, fontFamily:"'Syne', sans-serif" }}>
                {c.label}
              </div>
              <div className="text-sm" style={{ color:"var(--text-secondary)" }}>
                {scan.status === "phishing"   ? "This is a confirmed phishing attempt. Do not interact." :
                 scan.status === "suspicious" ? "Exercise caution — potential threat detected." :
                 "No threats detected. This appears safe."}
              </div>
            </div>
            <div className="text-right">
              <div className="text-3xl font-black" style={{ color:c.color, fontFamily:"'Syne', sans-serif" }}>
                {scan.riskScore}
              </div>
              <div className="text-xs" style={{ color:"var(--text-muted)", fontFamily:"'JetBrains Mono', monospace" }}>
                / 100
              </div>
            </div>
          </div>

          {/* Scanned input */}
          <div className="px-6 py-4 border-b" style={{ borderColor:"var(--bg-border)" }}>
            <div className="text-xs mb-1"
                 style={{ color:"var(--text-muted)", fontFamily:"'JetBrains Mono', monospace" }}>
              SCANNED INPUT · {scan.inputType?.toUpperCase()}
            </div>
            <div className="flex items-center gap-2">
              <code className="text-sm break-all flex-1"
                    style={{ color:"var(--accent-cyan)", fontFamily:"'JetBrains Mono', monospace" }}>
                {scan.input}
              </code>
            </div>
          </div>

          {/* Risk bar */}
          <div className="px-6 py-4 border-b" style={{ borderColor:"var(--bg-border)" }}>
            <div className="flex justify-between text-xs mb-2"
                 style={{ color:"var(--text-muted)", fontFamily:"'JetBrains Mono', monospace" }}>
              <span>RISK SCORE</span>
              <span style={{ color:c.color }}>{scan.riskScore}/100</span>
            </div>
            <div className="h-2 rounded-full overflow-hidden" style={{ background:"var(--bg-border)" }}>
              <div className="h-full rounded-full"
                   style={{ width:`${scan.riskScore}%`, background:c.color,
                            boxShadow:`0 0 8px ${c.color}60` }} />
            </div>
          </div>

          {/* Meta badges */}
          <div className="px-6 py-3 border-b flex flex-wrap gap-2"
               style={{ borderColor:"var(--bg-border)" }}>
            {[
              { label:"Confidence", val:(scan.confidence||"low").toUpperCase() },
              { label:"Detection",  val:`v${scan.detectionVersion||"3.0"}` },
              { label:"ML Engine",  val:scan.mlEnabled ? `${scan.mlScore}/100` : "Rules only" },
            ].map(({ label, val }) => (
              <div key={label} className="flex items-center gap-1.5 text-xs px-2.5 py-1 rounded-lg"
                   style={{ background:"var(--bg-elevated)", border:"1px solid var(--bg-border)",
                            fontFamily:"'JetBrains Mono', monospace" }}>
                <span style={{ color:"var(--text-muted)" }}>{label}:</span>
                <span style={{ color:"var(--text-secondary)" }}>{val}</span>
              </div>
            ))}
          </div>

          {/* Issues */}
          {scan.issues?.length > 0 && (
            <div className="px-6 py-4 border-b" style={{ borderColor:"var(--bg-border)" }}>
              <div className="text-xs uppercase tracking-widest mb-3"
                   style={{ color:"var(--text-muted)", fontFamily:"'JetBrains Mono', monospace" }}>
                Detected Issues ({scan.issues.length})
              </div>
              <div className="space-y-2">
                {scan.issues.map((issue: string, i: number) => (
                  <div key={i} className="flex items-start gap-3 px-3 py-2.5 rounded-lg"
                       style={{ background:"var(--bg-elevated)", border:"1px solid var(--bg-border)" }}>
                    <ChevronRight className="size-3.5 mt-0.5 flex-shrink-0" style={{ color:"#f5a623" }} />
                    <span className="text-xs" style={{ color:"var(--text-secondary)" }}>{issue}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* MITRE */}
          {scan.mitre && (
            <div className="px-6 py-4 border-b" style={{ borderColor:"var(--bg-border)" }}>
              <div className="text-xs uppercase tracking-widest mb-2"
                   style={{ color:"#a78bfa", fontFamily:"'JetBrains Mono', monospace" }}>
                MITRE ATT&CK
              </div>
              <div className="text-xs px-3 py-2 rounded-lg mb-1"
                   style={{ color:"#a78bfa", background:"rgba(124,58,237,0.08)",
                            border:"1px solid rgba(124,58,237,0.2)", fontFamily:"'JetBrains Mono', monospace" }}>
                {scan.mitre.tactic}
              </div>
              <div className="text-xs px-3 py-2 rounded-lg"
                   style={{ color:"var(--text-secondary)", background:"rgba(124,58,237,0.04)",
                            border:"1px solid rgba(124,58,237,0.12)", fontFamily:"'JetBrains Mono', monospace" }}>
                {scan.mitre.technique}
              </div>
            </div>
          )}

          {/* PhishDNA */}
          {scan.dna?.fingerprint && (
            <div className="px-6 py-4 border-b" style={{ borderColor:"var(--bg-border)" }}>
              <div className="text-xs uppercase tracking-widest mb-2"
                   style={{ color:"#a78bfa", fontFamily:"'JetBrains Mono', monospace" }}>
                🧬 PhishDNA Fingerprint
              </div>
              <div className="flex flex-wrap gap-3">
                <span className="text-sm font-bold px-3 py-1 rounded"
                      style={{ color:"#a78bfa", background:"rgba(163,120,251,0.1)",
                               border:"1px solid rgba(163,120,251,0.25)", fontFamily:"'JetBrains Mono', monospace" }}>
                  #{scan.dna.fingerprint}
                </span>
                {scan.dna.brand && scan.dna.brand !== "unknown" && (
                  <span className="text-xs px-2 py-1 rounded capitalize"
                        style={{ color:"var(--text-secondary)", background:"var(--bg-elevated)",
                                 border:"1px solid var(--bg-border)" }}>
                    Brand: {scan.dna.brand}
                  </span>
                )}
                {scan.dna.technique && (
                  <span className="text-xs px-2 py-1 rounded capitalize"
                        style={{ color:"var(--text-secondary)", background:"var(--bg-elevated)",
                                 border:"1px solid var(--bg-border)" }}>
                    {scan.dna.technique.replace(/_/g," ")}
                  </span>
                )}
              </div>
            </div>
          )}

          {/* Footer */}
          <div className="px-6 py-4 flex items-center justify-between"
               style={{ background:"rgba(0,0,0,0.2)" }}>
            <div className="text-xs" style={{ color:"var(--text-muted)", fontFamily:"'JetBrains Mono', monospace" }}>
              Generated by PhishGuard AI v4.0 · SentinelCore SIEM
            </div>
            <button onClick={() => navigate("/scan")}
                    className="flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-lg transition-all"
                    style={{ color:"var(--accent-green)", background:"rgba(0,255,136,0.08)",
                             border:"1px solid rgba(0,255,136,0.2)", fontFamily:"'JetBrains Mono', monospace" }}>
              <Terminal className="size-3" /> Scan Your Own URL
            </button>
          </div>
        </motion.div>

        {/* Disclaimer */}
        <p className="text-xs text-center" style={{ color:"var(--text-muted)" }}>
          This report was shared publicly. PhishGuard AI · Educational & Professional Use
        </p>
      </div>
    </div>
  );
}