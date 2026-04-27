// FILE: src/pages/Admin.tsx

import { useEffect, useState, useCallback } from "react";
import { motion } from "motion/react";
import { useNavigate } from "react-router";
import {
  Activity, Shield, TriangleAlert as AlertTriangle,
  XCircle, CheckCircle, Brain, Cpu, RefreshCw,
  TrendingUp, Globe, Mail, FileText, Clock,
  ChevronRight, Terminal, Zap, Database, Eye,
  ShieldAlert, Link as LinkIcon,
} from "lucide-react";

// ── Types ──
interface DayData    { _id: string; total: number; phishing: number; safe: number }
interface RecentScan { id: string; input: string; status: string; riskScore: number; inputType: string; createdAt: string }
interface Stats {
  total: number;
  breakdown:    { phishing: number; suspicious: number; safe: number };
  threatRate:   number;
  avgRiskScore: number;
  byInputType:  Record<string, number>;
  byConfidence: Record<string, number>;
  mlScanned:    number;
  mlCoverage:   number;
  siemEnabled:  boolean;
  last7Days:    DayData[];
  recentScans:  RecentScan[];
}
interface SiemOverview {
  overview: { totalAlerts: number; openAlerts: number; criticalAlerts: number; events24h: number };
}

// ── Helpers ──
const statusColor  = (s: string) => s === "phishing" ? "#ff4444" : s === "suspicious" ? "#f5a623" : "#00ff88";
const statusBg     = (s: string) => s === "phishing" ? "rgba(255,68,68,0.08)" : s === "suspicious" ? "rgba(245,166,35,0.08)" : "rgba(0,255,136,0.08)";
const statusBorder = (s: string) => s === "phishing" ? "rgba(255,68,68,0.25)" : s === "suspicious" ? "rgba(245,166,35,0.25)" : "rgba(0,255,136,0.25)";

const InputIcon = ({ type }: { type: string }) => {
  if (type === "url")   return <Globe    className="size-3" />;
  if (type === "email") return <Mail     className="size-3" />;
  return                       <FileText className="size-3" />;
};

export default function Admin() {
  const navigate = useNavigate();
  const [stats,       setStats]       = useState<Stats | null>(null);
  const [siem,        setSiem]        = useState<SiemOverview | null>(null);
  const [loading,     setLoading]     = useState(true);
  const [error,       setError]       = useState<string | null>(null);
  const [mlStatus,    setMlStatus]    = useState<any>(null);
  const [lastRefresh, setLastRefresh] = useState(new Date());

  const fetchData = useCallback(async () => {
    setLoading(true); setError(null);
    try {
      const [statsRes, mlRes] = await Promise.all([
        fetch("http://localhost:5000/api/scan/stats"),
        fetch("http://localhost:5000/api/scan/ml-status"),
      ]);
      if (!statsRes.ok) throw new Error("Backend offline — start your server");
      const [s, ml] = await Promise.all([statsRes.json(), mlRes.json()]);
      setStats(s); setMlStatus(ml);

      // Try SIEM stats (optional)
      try {
        const siemRes = await fetch("http://localhost:5000/api/siem/stats");
        if (siemRes.ok) setSiem(await siemRes.json());
      } catch { /* SIEM not wired yet — skip */ }

      setLastRefresh(new Date());
    } catch (e: any) {
      setError(e.message);
    } finally { setLoading(false); }
  }, []);

  useEffect(() => { fetchData(); }, [fetchData]);
  useEffect(() => { const t = setInterval(fetchData, 30000); return () => clearInterval(t); }, [fetchData]);

  // ── Bar chart ──
  const BarChart = ({ data }: { data: DayData[] }) => {
    const max = Math.max(...data.map((d) => d.total), 1);
    return (
      <div className="flex items-end gap-1.5 h-16">
        {data.map((d) => {
          const h  = Math.max((d.total / max) * 56, 2);
          const ph = d.total > 0 ? (d.phishing / d.total) * h : 0;
          const sh = h - ph;
          return (
            <div key={d._id} className="flex-1 flex flex-col items-center gap-1">
              <div className="w-full flex flex-col justify-end" style={{ height: 56 }}>
                {ph > 0 && <div style={{ height: ph, background: "#ff4444", borderRadius: "2px 2px 0 0" }} />}
                {sh > 0 && <div style={{ height: sh, background: "var(--accent-green)", opacity: 0.5 }} />}
              </div>
              <span style={{ fontSize: 8, color: "var(--text-muted)", fontFamily: "'JetBrains Mono', monospace" }}>
                {d._id.slice(5)}
              </span>
            </div>
          );
        })}
      </div>
    );
  };

  // ── Donut chart ──
  const DonutChart = ({ value, total, color }: { value: number; total: number; color: string }) => {
    const pct  = total > 0 ? (value / total) * 100 : 0;
    const r    = 28;
    const circ = 2 * Math.PI * r;
    const dash = (pct / 100) * circ;
    return (
      <div className="relative">
        <svg width="72" height="72" viewBox="0 0 72 72">
          <circle cx="36" cy="36" r={r} fill="none" stroke="var(--bg-border)" strokeWidth="7" />
          <circle cx="36" cy="36" r={r} fill="none" stroke={color} strokeWidth="7"
                  strokeDasharray={`${dash} ${circ - dash}`} strokeLinecap="round"
                  transform="rotate(-90 36 36)"
                  style={{ transition: "stroke-dasharray 1s ease", filter: `drop-shadow(0 0 4px ${color}80)` }} />
          <text x="36" y="40" textAnchor="middle" fill={color} fontSize="13"
                fontWeight="700" fontFamily="'Syne', sans-serif">
            {Math.round(pct)}%
          </text>
        </svg>
      </div>
    );
  };

  if (loading && !stats) return (
    <div className="min-h-full flex items-center justify-center" style={{ background: "var(--bg-base)" }}>
      <div className="text-center">
        <div className="w-10 h-10 border-2 rounded-full mx-auto mb-4 animate-spin"
             style={{ borderColor: "var(--accent-green)", borderTopColor: "transparent" }} />
        <p style={{ color: "var(--text-muted)", fontFamily: "'JetBrains Mono', monospace", fontSize: 12 }}>
          Loading analytics...
        </p>
      </div>
    </div>
  );

  if (error) return (
    <div className="min-h-full flex items-center justify-center px-6" style={{ background: "var(--bg-base)" }}>
      <div className="text-center max-w-sm">
        <XCircle className="size-12 mx-auto mb-4" style={{ color: "#ff4444" }} />
        <h2 className="text-xl font-bold mb-2" style={{ fontFamily: "'Syne', sans-serif", color: "var(--text-primary)" }}>
          Backend Offline
        </h2>
        <p className="text-sm mb-6" style={{ color: "var(--text-secondary)" }}>{error}</p>
        <button onClick={fetchData} className="btn-primary flex items-center gap-2 mx-auto px-6 py-3 text-sm"
                style={{ fontFamily: "'Syne', sans-serif", fontWeight: 700 }}>
          <RefreshCw className="size-4" /> Retry
        </button>
      </div>
    </div>
  );

  if (!stats) return null;
  const { total, breakdown, threatRate, avgRiskScore, byInputType, mlScanned, mlCoverage, last7Days, recentScans } = stats;

  return (
    <div className="min-h-full py-10 px-6" style={{ background: "var(--bg-base)" }}>
      <div className="max-w-6xl mx-auto">

        {/* ── HEADER ── */}
        <motion.div initial={{ opacity:0, y:16 }} animate={{ opacity:1, y:0 }}
                    className="flex items-start justify-between mb-10 flex-wrap gap-4">
          <div>
            <div className="tag-green inline-flex mb-4"><Terminal className="size-3" /> ADMIN CONSOLE</div>
            <h1 className="text-4xl font-bold mb-1"
                style={{ fontFamily:"'Syne', sans-serif", color:"var(--text-primary)" }}>
              Analytics Dashboard
            </h1>
            <p className="text-sm flex items-center gap-2"
               style={{ color:"var(--text-muted)", fontFamily:"'JetBrains Mono', monospace" }}>
              <Clock className="size-3" />
              Updated {lastRefresh.toLocaleTimeString()} · auto-refresh 30s
            </p>
          </div>
          <div className="flex items-center gap-3">
            {siem && (
              <button onClick={() => navigate("/siem")}
                      className="flex items-center gap-2 px-4 py-2.5 rounded-xl text-sm font-medium transition-all"
                      style={{ background:"rgba(124,58,237,0.08)", border:"1px solid rgba(124,58,237,0.25)",
                               color:"#a78bfa", fontFamily:"'DM Sans', sans-serif" }}>
                <ShieldAlert className="size-4" /> SIEM Console
              </button>
            )}
            <button onClick={fetchData} disabled={loading}
                    className="btn-ghost flex items-center gap-2 px-4 py-2.5 text-sm"
                    style={{ fontFamily:"'DM Sans', sans-serif" }}>
              <RefreshCw className={`size-4 ${loading ? "animate-spin" : ""}`} /> Refresh
            </button>
          </div>
        </motion.div>

        {/* ── TOP STAT CARDS ── */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
          {[
            { icon: Database,      label:"Total Scans",  value: total,               color:"var(--accent-green)", sub:"all time"                                                },
            { icon: XCircle,       label:"Phishing",     value: breakdown.phishing,  color:"#ff4444",             sub:`${threatRate}% threat rate`                              },
            { icon: AlertTriangle, label:"Suspicious",   value: breakdown.suspicious,color:"#f5a623",             sub:`${total > 0 ? Math.round((breakdown.suspicious/total)*100) : 0}% of scans` },
            { icon: CheckCircle,   label:"Safe",         value: breakdown.safe,      color:"#00ff88",             sub:`${total > 0 ? Math.round((breakdown.safe/total)*100) : 0}% of scans`      },
          ].map((card, i) => (
            <motion.div key={card.label}
              initial={{ opacity:0, y:16 }} animate={{ opacity:1, y:0 }} transition={{ delay: i*0.07 }}
              className="card p-5" style={{ background:"var(--bg-card)" }}>
              <div className="flex items-center justify-between mb-3">
                <div className="w-9 h-9 rounded-lg flex items-center justify-center"
                     style={{ background:`${card.color}10`, border:`1px solid ${card.color}25` }}>
                  <card.icon className="size-4" style={{ color: card.color }} />
                </div>
                <span className="text-xs" style={{ color:"var(--text-muted)", fontFamily:"'JetBrains Mono', monospace" }}>
                  {card.sub}
                </span>
              </div>
              <div className="text-3xl font-bold mb-1"
                   style={{ color: card.color, fontFamily:"'Syne', sans-serif" }}>
                {card.value.toLocaleString()}
              </div>
              <div className="text-xs" style={{ color:"var(--text-muted)" }}>{card.label}</div>
            </motion.div>
          ))}
        </div>

        {/* ── SIEM mini-cards (shown only when SIEM is active) ── */}
        {siem?.overview && (
          <motion.div initial={{ opacity:0, y:10 }} animate={{ opacity:1, y:0 }} transition={{ delay:0.2 }}
                      className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-6">
            {[
              { label:"SIEM Alerts",    value: siem.overview.totalAlerts,    color:"#a78bfa", icon: ShieldAlert },
              { label:"Open Alerts",    value: siem.overview.openAlerts,     color:"#f5a623", icon: AlertTriangle },
              { label:"Critical",       value: siem.overview.criticalAlerts, color:"#ff4444", icon: XCircle },
              { label:"Events (24h)",   value: siem.overview.events24h,      color:"var(--accent-cyan)", icon: Activity },
            ].map((card) => (
              <div key={card.label}
                   className="card px-4 py-3 flex items-center gap-3 cursor-pointer transition-all"
                   style={{ background:"rgba(124,58,237,0.05)", borderColor:"rgba(124,58,237,0.2)" }}
                   onClick={() => navigate("/siem")}>
                <card.icon className="size-4 flex-shrink-0" style={{ color: card.color }} />
                <div>
                  <div className="text-lg font-bold" style={{ color: card.color, fontFamily:"'Syne', sans-serif" }}>
                    {card.value}
                  </div>
                  <div className="text-xs" style={{ color:"var(--text-muted)", fontFamily:"'JetBrains Mono', monospace" }}>
                    {card.label}
                  </div>
                </div>
              </div>
            ))}
          </motion.div>
        )}

        {/* ── ROW 2: Chart + Donut + Avg Score ── */}
        <div className="grid md:grid-cols-3 gap-4 mb-6">

          {/* 7-Day Bar Chart */}
          <motion.div initial={{ opacity:0, y:16 }} animate={{ opacity:1, y:0 }} transition={{ delay:0.2 }}
                      className="md:col-span-2 card p-5" style={{ background:"var(--bg-card)" }}>
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-2">
                <TrendingUp className="size-4" style={{ color:"var(--accent-green)" }} />
                <span className="text-sm font-semibold"
                      style={{ color:"var(--text-primary)", fontFamily:"'Syne', sans-serif" }}>
                  7-Day Scan Activity
                </span>
              </div>
              <div className="flex items-center gap-3 text-xs" style={{ fontFamily:"'JetBrains Mono', monospace" }}>
                <span style={{ color:"var(--accent-green)" }}>■ Safe</span>
                <span style={{ color:"#ff4444" }}>■ Phishing</span>
              </div>
            </div>
            {last7Days.length > 0
              ? <BarChart data={last7Days} />
              : <div className="h-16 flex items-center justify-center text-xs"
                     style={{ color:"var(--text-muted)", fontFamily:"'JetBrains Mono', monospace" }}>
                  No scan data yet — run some scans first
                </div>
            }
          </motion.div>

          {/* Threat donut */}
          <motion.div initial={{ opacity:0, y:16 }} animate={{ opacity:1, y:0 }} transition={{ delay:0.25 }}
                      className="card p-5" style={{ background:"var(--bg-card)" }}>
            <div className="flex items-center gap-2 mb-4">
              <Activity className="size-4" style={{ color:"var(--accent-green)" }} />
              <span className="text-sm font-semibold"
                    style={{ color:"var(--text-primary)", fontFamily:"'Syne', sans-serif" }}>
                Threat Breakdown
              </span>
            </div>
            <div className="flex items-center justify-center mb-4">
              <DonutChart value={breakdown.phishing} total={total} color="#ff4444" />
            </div>
            <div className="space-y-2">
              {[
                { label:"Phishing",   val: breakdown.phishing,   color:"#ff4444" },
                { label:"Suspicious", val: breakdown.suspicious, color:"#f5a623" },
                { label:"Safe",       val: breakdown.safe,       color:"#00ff88" },
              ].map((item) => (
                <div key={item.label} className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <div className="w-2 h-2 rounded-full" style={{ background: item.color }} />
                    <span className="text-xs" style={{ color:"var(--text-secondary)" }}>{item.label}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <div className="w-16 h-1 rounded-full" style={{ background:"var(--bg-border)" }}>
                      <div className="h-full rounded-full"
                           style={{ width:`${total > 0 ? (item.val/total)*100 : 0}%`, background: item.color }} />
                    </div>
                    <span className="text-xs font-bold w-6 text-right"
                          style={{ color: item.color, fontFamily:"'JetBrains Mono', monospace" }}>
                      {item.val}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </motion.div>
        </div>

        {/* ── ROW 3: ML Engine + Input Types + Avg Score ── */}
        <div className="grid md:grid-cols-3 gap-4 mb-6">

          {/* ML Engine status */}
          <motion.div initial={{ opacity:0, y:16 }} animate={{ opacity:1, y:0 }} transition={{ delay:0.3 }}
                      className="card p-5" style={{ background:"var(--bg-card)" }}>
            <div className="flex items-center gap-2 mb-5">
              <Brain className="size-4" style={{ color:"var(--accent-cyan)" }} />
              <span className="text-sm font-semibold"
                    style={{ color:"var(--text-primary)", fontFamily:"'Syne', sans-serif" }}>
                ML Engine
              </span>
            </div>
            <div className="space-y-3">
              {[
                { label:"Status",       val: mlStatus?.mlEnabled ? "ONLINE" : "OFFLINE",
                  color: mlStatus?.mlEnabled ? "var(--accent-green)" : "#ff4444",
                  bg: mlStatus?.mlEnabled ? "rgba(0,255,136,0.08)" : "rgba(255,68,68,0.08)",
                  border: mlStatus?.mlEnabled ? "rgba(0,255,136,0.2)" : "rgba(255,68,68,0.2)",
                  isBadge: true },
                { label:"Architecture",  val:"18→14→8→1",          color:"var(--accent-cyan)", isBadge:false },
                { label:"ML Scans",      val:`${mlScanned} (${mlCoverage}%)`, color:"var(--text-primary)", isBadge:false },
                { label:"Weights",       val:"ML 45% + Rules 55%",  color:"var(--text-muted)",  isBadge:false },
                { label:"SIEM",          val: siem ? "ACTIVE" : "NOT WIRED",
                  color: siem ? "#a78bfa" : "var(--text-muted)",
                  bg: siem ? "rgba(124,58,237,0.08)" : "transparent",
                  border: siem ? "rgba(124,58,237,0.2)" : "var(--bg-border)",
                  isBadge: true },
              ].map((row) => (
                <div key={row.label} className="flex items-center justify-between">
                  <span className="text-xs" style={{ color:"var(--text-muted)" }}>{row.label}</span>
                  {row.isBadge ? (
                    <span className="text-xs px-2 py-0.5 rounded font-bold"
                          style={{ color: row.color, background: (row as any).bg,
                                   border:`1px solid ${(row as any).border}`,
                                   fontFamily:"'JetBrains Mono', monospace" }}>
                      {row.val}
                    </span>
                  ) : (
                    <span className="text-xs" style={{ color: row.color, fontFamily:"'JetBrains Mono', monospace" }}>
                      {row.val}
                    </span>
                  )}
                </div>
              ))}
            </div>
          </motion.div>

          {/* Input type distribution */}
          <motion.div initial={{ opacity:0, y:16 }} animate={{ opacity:1, y:0 }} transition={{ delay:0.35 }}
                      className="card p-5" style={{ background:"var(--bg-card)" }}>
            <div className="flex items-center gap-2 mb-5">
              <Cpu className="size-4" style={{ color:"var(--accent-green)" }} />
              <span className="text-sm font-semibold"
                    style={{ color:"var(--text-primary)", fontFamily:"'Syne', sans-serif" }}>
                Input Types
              </span>
            </div>
            <div className="space-y-4">
              {[
                { key:"url",   label:"URLs",     icon: Globe,    color:"var(--accent-cyan)" },
                { key:"text",  label:"Messages", icon: FileText, color:"var(--accent-green)" },
                { key:"email", label:"Emails",   icon: Mail,     color:"#a78bfa" },
              ].map(({ key, label, icon: Icon, color }) => {
                const count = byInputType[key] || 0;
                const pct   = total > 0 ? Math.round((count/total)*100) : 0;
                return (
                  <div key={key}>
                    <div className="flex items-center justify-between mb-1.5">
                      <div className="flex items-center gap-1.5">
                        <Icon className="size-3" style={{ color }} />
                        <span className="text-xs" style={{ color:"var(--text-secondary)" }}>{label}</span>
                      </div>
                      <span className="text-xs font-bold"
                            style={{ color, fontFamily:"'JetBrains Mono', monospace" }}>
                        {count} <span style={{ color:"var(--text-muted)", fontWeight:400 }}>({pct}%)</span>
                      </span>
                    </div>
                    <div className="h-2 rounded-full overflow-hidden" style={{ background:"var(--bg-border)" }}>
                      <motion.div className="h-full rounded-full"
                        initial={{ width:0 }} animate={{ width:`${pct}%` }}
                        transition={{ duration:1, ease:"easeOut", delay:0.5 }}
                        style={{ background: color, boxShadow:`0 0 6px ${color}50` }} />
                    </div>
                  </div>
                );
              })}
            </div>

            {/* Confidence breakdown */}
            {stats.byConfidence && (
              <div className="mt-5 pt-4 border-t" style={{ borderColor:"var(--bg-border)" }}>
                <div className="flex items-center gap-2 mb-3">
                  <Eye className="size-3" style={{ color:"var(--text-muted)" }} />
                  <span className="text-xs uppercase tracking-widest"
                        style={{ color:"var(--text-muted)", fontFamily:"'JetBrains Mono', monospace" }}>
                    Confidence
                  </span>
                </div>
                <div className="flex gap-2">
                  {[
                    { key:"high",   color:"#00ff88" },
                    { key:"medium", color:"#f5a623" },
                    { key:"low",    color:"#8b95a8" },
                  ].map(({ key, color }) => {
                    const cnt = stats.byConfidence[key] || 0;
                    const pct = total > 0 ? Math.round((cnt/total)*100) : 0;
                    return (
                      <div key={key} className="flex-1 text-center rounded-lg py-2"
                           style={{ background:`${color}08`, border:`1px solid ${color}20` }}>
                        <div className="text-sm font-bold" style={{ color, fontFamily:"'Syne', sans-serif" }}>
                          {pct}%
                        </div>
                        <div className="text-xs capitalize" style={{ color:"var(--text-muted)", fontSize:9,
                                                                      fontFamily:"'JetBrains Mono', monospace" }}>
                          {key}
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            )}
          </motion.div>

          {/* Avg risk score */}
          <motion.div initial={{ opacity:0, y:16 }} animate={{ opacity:1, y:0 }} transition={{ delay:0.4 }}
                      className="card p-5 flex flex-col items-center justify-center" style={{ background:"var(--bg-card)" }}>
            <div className="flex items-center gap-2 mb-4 self-start">
              <Zap className="size-4" style={{ color:"var(--accent-green)" }} />
              <span className="text-sm font-semibold"
                    style={{ color:"var(--text-primary)", fontFamily:"'Syne', sans-serif" }}>
                Avg Risk Score
              </span>
            </div>
            {/* Big number */}
            <div className="text-7xl font-black mb-2"
                 style={{ fontFamily:"'Syne', sans-serif",
                          color: avgRiskScore >= 66 ? "#ff4444" : avgRiskScore >= 33 ? "#f5a623" : "#00ff88",
                          textShadow: avgRiskScore >= 66 ? "0 0 30px rgba(255,68,68,0.4)" : avgRiskScore >= 33 ? "0 0 30px rgba(245,166,35,0.3)" : "0 0 30px rgba(0,255,136,0.3)" }}>
              {avgRiskScore}
            </div>
            <div className="text-xs mb-5" style={{ color:"var(--text-muted)", fontFamily:"'JetBrains Mono', monospace" }}>
              out of 100 · {total} scans
            </div>
            {/* Segmented bar */}
            <div className="w-full relative h-3 rounded-full overflow-hidden" style={{ background:"var(--bg-border)" }}>
              <div className="absolute top-0 left-0 h-full opacity-20" style={{ width:"25%", background:"#00ff88" }} />
              <div className="absolute top-0 h-full opacity-20" style={{ left:"25%", width:"40%", background:"#f5a623" }} />
              <div className="absolute top-0 h-full opacity-20" style={{ left:"65%", width:"35%", background:"#ff4444" }} />
              <motion.div className="absolute top-0 left-0 h-full rounded-full"
                initial={{ width:0 }} animate={{ width:`${avgRiskScore}%` }}
                transition={{ duration:1.2, ease:"easeOut" }}
                style={{ background: avgRiskScore >= 66 ? "linear-gradient(90deg,#cc0000,#ff4444)" : avgRiskScore >= 33 ? "linear-gradient(90deg,#e08b00,#f5a623)" : "linear-gradient(90deg,#00c960,#00ff88)" }} />
            </div>
            <div className="flex justify-between w-full mt-1.5 text-xs"
                 style={{ color:"var(--text-muted)", fontFamily:"'JetBrains Mono', monospace", fontSize:9 }}>
              <span>Safe</span><span>Suspicious</span><span>Phishing</span>
            </div>
          </motion.div>
        </div>

        {/* ── RECENT SCANS TABLE ── */}
        <motion.div initial={{ opacity:0, y:16 }} animate={{ opacity:1, y:0 }} transition={{ delay:0.45 }}
                    className="card overflow-hidden" style={{ background:"var(--bg-card)" }}>
          {/* Terminal header */}
          <div className="flex items-center justify-between px-5 py-3 border-b"
               style={{ borderColor:"var(--bg-border)", background:"rgba(0,0,0,0.3)" }}>
            <div className="flex items-center gap-2">
              <div className="flex gap-1.5">
                <div className="w-2.5 h-2.5 rounded-full" style={{ background:"#ff5f57" }} />
                <div className="w-2.5 h-2.5 rounded-full" style={{ background:"#febc2e" }} />
                <div className="w-2.5 h-2.5 rounded-full" style={{ background:"#28c840" }} />
              </div>
              <span className="text-xs ml-1"
                    style={{ color:"var(--text-muted)", fontFamily:"'JetBrains Mono', monospace" }}>
                recent_scans.log — last 10 entries
              </span>
            </div>
            <div className="flex items-center gap-3">
              <div className="flex items-center gap-1.5">
                <div className="w-1.5 h-1.5 rounded-full safe-pulse" style={{ background:"var(--accent-green)" }} />
                <span className="text-xs" style={{ color:"var(--text-muted)", fontFamily:"'JetBrains Mono', monospace" }}>live</span>
              </div>
              <button onClick={() => navigate("/history")}
                      className="flex items-center gap-1 text-xs transition-colors"
                      style={{ color:"var(--accent-green)", fontFamily:"'JetBrains Mono', monospace" }}>
                View all <ChevronRight className="size-3" />
              </button>
            </div>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full data-table">
              <thead>
                <tr>
                  <th className="text-left">Input</th>
                  <th className="text-left">Type</th>
                  <th className="text-left">Verdict</th>
                  <th className="text-left">Risk Score</th>
                  <th className="text-left">Time</th>
                </tr>
              </thead>
              <tbody>
                {recentScans.length === 0 ? (
                  <tr>
                    <td colSpan={5} className="text-center py-10"
                        style={{ color:"var(--text-muted)", fontFamily:"'JetBrains Mono', monospace", fontSize:12 }}>
                      No scans yet — go scan something!
                    </td>
                  </tr>
                ) : recentScans.map((scan, i) => (
                  <motion.tr key={scan.id}
                    initial={{ opacity:0, y:6 }} animate={{ opacity:1, y:0 }}
                    transition={{ delay: 0.5 + i * 0.04 }}>
                    <td style={{ maxWidth:220 }}>
                      <span className="truncate block text-xs"
                            style={{ color:"var(--text-primary)", fontFamily:"'JetBrains Mono', monospace", fontSize:11 }}>
                        {scan.input}
                      </span>
                    </td>
                    <td>
                      <div className="flex items-center gap-1.5 text-xs"
                           style={{ color:"var(--text-muted)", fontFamily:"'JetBrains Mono', monospace" }}>
                        <InputIcon type={scan.inputType} />
                        {scan.inputType}
                      </div>
                    </td>
                    <td>
                      <span className="text-xs font-bold px-2 py-0.5 rounded"
                            style={{ color:statusColor(scan.status), background:statusBg(scan.status),
                                     border:`1px solid ${statusBorder(scan.status)}`,
                                     fontFamily:"'JetBrains Mono', monospace", letterSpacing:"0.06em" }}>
                        {scan.status.toUpperCase()}
                      </span>
                    </td>
                    <td>
                      <div className="flex items-center gap-2">
                        {/* Color-coded mini bar */}
                        <div className="relative w-20 h-2 rounded-full overflow-hidden" style={{ background:"var(--bg-border)" }}>
                          <div className="absolute top-0 left-0 h-full opacity-15" style={{ width:"25%", background:"#00ff88" }} />
                          <div className="absolute top-0 h-full opacity-15" style={{ left:"25%", width:"40%", background:"#f5a623" }} />
                          <div className="absolute top-0 h-full opacity-15" style={{ left:"65%", width:"35%", background:"#ff4444" }} />
                          <div className="absolute top-0 left-0 h-full rounded-full"
                               style={{ width:`${scan.riskScore}%`, background:statusColor(scan.status) }} />
                        </div>
                        <span className="text-xs font-bold"
                              style={{ color:statusColor(scan.status), fontFamily:"'JetBrains Mono', monospace" }}>
                          {scan.riskScore}
                        </span>
                      </div>
                    </td>
                    <td>
                      <span className="text-xs" style={{ color:"var(--text-muted)", fontFamily:"'JetBrains Mono', monospace" }}>
                        {new Date(scan.createdAt).toLocaleTimeString()}
                      </span>
                    </td>
                  </motion.tr>
                ))}
              </tbody>
            </table>
          </div>
        </motion.div>

      </div>
    </div>
  );
}