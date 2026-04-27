// FILE: src/pages/SIEM.tsx
// SentinelCore SIEM Dashboard

import { useEffect, useState, useCallback, Fragment } from "react";
import { motion, AnimatePresence } from "motion/react";
import {
  Shield, AlertTriangle, Activity, Zap, Terminal,
  ChevronDown, ChevronUp, RefreshCw, CheckCircle,
  XCircle, Clock, Globe, Brain, Eye, Filter,
  TrendingUp, Database, Link as LinkIcon, Cpu,
} from "lucide-react";

// ── Types ──
interface SiemAlert {
  alertId: string; title: string; description: string;
  category: string; ruleId: string; severity: number;
  severityLabel: string; eventCount: number; status: string;
  target: { url?: string; domain?: string; ip?: string };
  mitre: { tactic?: string; technique?: string };
  riskScore: number; firstSeen: string; lastSeen: string;
  isCorrelated: boolean; tags: string[];
}
interface Stats {
  overview: { totalEvents: number; totalAlerts: number; openAlerts: number; criticalAlerts: number; events24h: number; alerts24h: number; correlatedAlerts: number };
  severity: Record<string, number>;
  byCategory: Record<string, number>;
  topTargets: { domain: string; count: number; maxSeverity: number }[];
  alertTrend: { _id: string; total: number; critical: number; high: number }[];
  mitreTactics: { tactic: string; count: number }[];
}

// ── Severity config ──
const SEV = {
  5: { label: "CRITICAL", color: "#ff4444", bg: "rgba(255,68,68,0.08)",  border: "rgba(255,68,68,0.25)",  ring: "rgba(255,68,68,0.5)"  },
  4: { label: "HIGH",     color: "#f97316", bg: "rgba(249,115,22,0.08)", border: "rgba(249,115,22,0.25)", ring: "rgba(249,115,22,0.5)" },
  3: { label: "MEDIUM",   color: "#f5a623", bg: "rgba(245,166,35,0.08)", border: "rgba(245,166,35,0.25)", ring: "rgba(245,166,35,0.5)" },
  2: { label: "LOW",      color: "#00d4ff", bg: "rgba(0,212,255,0.08)",  border: "rgba(0,212,255,0.25)",  ring: "rgba(0,212,255,0.5)"  },
  1: { label: "INFO",     color: "#8b95a8", bg: "rgba(139,149,168,0.08)",border: "rgba(139,149,168,0.2)", ring: "rgba(139,149,168,0.3)" },
} as const;

const CATEGORY_ICONS: Record<string, any> = {
  phishing: Shield, brute_force: Zap, anomaly: Activity,
  network: Globe, auth: Eye, system: Cpu, reconnaissance: Eye, data_exfil: Database,
};

const STATUS_COLORS: Record<string, string> = {
  open: "#ff4444", investigating: "#f5a623", resolved: "#00ff88",
  false_positive: "#8b95a8", suppressed: "#4a5568",
};

export default function SIEM() {
  const [stats,         setStats]         = useState<Stats | null>(null);
  const [alerts,        setAlerts]        = useState<SiemAlert[]>([]);
  const [loading,       setLoading]       = useState(true);
  const [error,         setError]         = useState<string | null>(null);
  const [expandedAlert, setExpandedAlert] = useState<string | null>(null);
  const [statusFilter,  setStatusFilter]  = useState("open");
  const [sevFilter,     setSevFilter]     = useState<number | "">("");
  const [activeTab,     setActiveTab]     = useState<"alerts"|"rules"|"topology">("alerts");
  const [rules,         setRules]         = useState<any[]>([]);
  const [correlating,   setCorrelating]   = useState(false);
  const [lastRefresh,   setLastRefresh]   = useState(new Date());

  const fetchData = useCallback(async () => {
    setLoading(true); setError(null);
    try {
      const params = new URLSearchParams({ status: statusFilter, limit: "30" });
      if (sevFilter) params.set("severity", String(sevFilter));

      const [statsRes, alertsRes, rulesRes] = await Promise.all([
        fetch("http://localhost:5000/api/siem/stats"),
        fetch(`http://localhost:5000/api/siem/alerts?${params}`),
        fetch("http://localhost:5000/api/siem/rules"),
      ]);
      if (!statsRes.ok) throw new Error("Backend offline");
      const [s, a, r] = await Promise.all([statsRes.json(), alertsRes.json(), rulesRes.json()]);
      setStats(s); setAlerts(a.alerts || []); setRules(r.rules || []);
      setLastRefresh(new Date());
    } catch (e: any) {
      setError(e.message);
    } finally { setLoading(false); }
  }, [statusFilter, sevFilter]);

  useEffect(() => { fetchData(); }, [fetchData]);
  useEffect(() => { const t = setInterval(fetchData, 30000); return () => clearInterval(t); }, [fetchData]);

  const updateAlertStatus = async (alertId: string, status: string) => {
    await fetch(`http://localhost:5000/api/siem/alerts/${alertId}`, {
      method: "PATCH", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ status }),
    });
    fetchData();
  };

  const triggerCorrelation = async () => {
    setCorrelating(true);
    await fetch("http://localhost:5000/api/siem/correlate", { method: "POST" });
    await fetchData();
    setCorrelating(false);
  };

  // ── Mini bar chart for alert trend ──
  const TrendChart = ({ data }: { data: Stats["alertTrend"] }) => {
    const max = Math.max(...data.map((d) => d.total), 1);
    return (
      <div className="flex items-end gap-1.5" style={{ height: 48 }}>
        {data.map((d) => (
          <div key={d._id} className="flex-1 flex flex-col gap-0.5 items-center">
            <div className="w-full flex flex-col justify-end" style={{ height: 40 }}>
              <div style={{ height: `${(d.critical / max) * 40}px`, background: "#ff4444", borderRadius: "2px 2px 0 0", minHeight: d.critical ? 2 : 0 }} />
              <div style={{ height: `${(d.high     / max) * 40}px`, background: "#f97316", minHeight: d.high ? 2 : 0 }} />
              <div style={{ height: `${((d.total - d.critical - d.high) / max) * 40}px`, background: "#f5a623", minHeight: 0 }} />
            </div>
            <span style={{ fontSize: 8, color: "var(--text-muted)", fontFamily: "'JetBrains Mono', monospace" }}>
              {d._id.slice(5)}
            </span>
          </div>
        ))}
      </div>
    );
  };

  if (error) return (
    <div className="min-h-full flex items-center justify-center px-6" style={{ background: "var(--bg-base)" }}>
      <div className="text-center">
        <XCircle className="size-10 mx-auto mb-3" style={{ color: "#ff4444" }} />
        <h2 className="text-xl font-bold mb-2" style={{ fontFamily: "'Syne', sans-serif", color: "var(--text-primary)" }}>Backend Offline</h2>
        <p className="text-sm mb-5" style={{ color: "var(--text-secondary)" }}>{error}</p>
        <button onClick={fetchData} className="btn-primary px-6 py-2.5 text-sm flex items-center gap-2 mx-auto"
                style={{ fontFamily: "'Syne', sans-serif", fontWeight: 700 }}>
          <RefreshCw className="size-4" /> Retry
        </button>
      </div>
    </div>
  );

  return (
    <div className="min-h-full py-10 px-6" style={{ background: "var(--bg-base)" }}>
      <div className="max-w-7xl mx-auto">

        {/* ── HEADER ── */}
        <motion.div initial={{ opacity:0, y:16 }} animate={{ opacity:1, y:0 }}
                    className="flex flex-col md:flex-row items-start justify-between gap-4 mb-10">
          <div>
            <div className="tag-green inline-flex mb-4">
              <Terminal className="size-3" /> SENTINELCORE SIEM
            </div>
            <h1 className="text-4xl font-bold mb-1"
                style={{ fontFamily:"'Syne', sans-serif", color:"var(--text-primary)" }}>
              Security Operations
            </h1>
            <p className="text-sm flex items-center gap-2"
               style={{ color:"var(--text-muted)", fontFamily:"'JetBrains Mono', monospace" }}>
              <Clock className="size-3" />
              Updated {lastRefresh.toLocaleTimeString()} · Auto-refresh 30s
            </p>
          </div>
          <div className="flex items-center gap-3">
            <button onClick={triggerCorrelation} disabled={correlating}
                    className="btn-ghost flex items-center gap-2 px-4 py-2 text-sm"
                    style={{ borderColor: "rgba(124,58,237,0.4)", color: "#a78bfa" }}>
              <Brain className={`size-4 ${correlating ? "animate-pulse" : ""}`} />
              {correlating ? "Correlating..." : "Run Correlation"}
            </button>
            <button onClick={fetchData} disabled={loading}
                    className="btn-ghost flex items-center gap-2 px-4 py-2 text-sm">
              <RefreshCw className={`size-4 ${loading ? "animate-spin" : ""}`} />
              Refresh
            </button>
          </div>
        </motion.div>

        {/* ── CRITICAL ALERT BANNER ── */}
        {stats && stats.overview.criticalAlerts > 0 && (
          <motion.div initial={{ opacity:0, y:-8 }} animate={{ opacity:1, y:0 }}
                      className="mb-6 p-4 rounded-xl flex items-center gap-4"
                      style={{ background:"rgba(255,68,68,0.08)", border:"2px solid rgba(255,68,68,0.4)" }}>
            <div className="w-3 h-3 rounded-full threat-pulse flex-shrink-0" style={{ background:"#ff4444" }} />
            <div>
              <span className="font-bold" style={{ color:"#ff4444", fontFamily:"'Syne', sans-serif" }}>
                {stats.overview.criticalAlerts} CRITICAL ALERT{stats.overview.criticalAlerts > 1 ? "S" : ""} OPEN
              </span>
              <span className="text-xs ml-3" style={{ color:"var(--text-muted)", fontFamily:"'JetBrains Mono', monospace" }}>
                Immediate attention required
              </span>
            </div>
          </motion.div>
        )}

        {/* ── OVERVIEW CARDS ── */}
        {stats && (
          <div className="grid grid-cols-2 md:grid-cols-4 xl:grid-cols-7 gap-3 mb-6">
            {[
              { label:"Total Events",   value: stats.overview.totalEvents,   color:"var(--accent-green)", icon: Database },
              { label:"Total Alerts",   value: stats.overview.totalAlerts,   color:"var(--accent-cyan)",  icon: Activity },
              { label:"Open Alerts",    value: stats.overview.openAlerts,    color:"#f5a623",             icon: AlertTriangle },
              { label:"Critical",       value: stats.overview.criticalAlerts,color:"#ff4444",             icon: XCircle },
              { label:"Events 24h",     value: stats.overview.events24h,     color:"var(--accent-green)", icon: TrendingUp },
              { label:"Alerts 24h",     value: stats.overview.alerts24h,     color:"#f97316",             icon: Zap },
              { label:"Attack Chains",  value: stats.overview.correlatedAlerts, color:"#a78bfa",          icon: LinkIcon },
            ].map((card, i) => (
              <motion.div key={card.label}
                initial={{ opacity:0, y:16 }} animate={{ opacity:1, y:0 }} transition={{ delay: i*0.05 }}
                className="card p-4 text-center" style={{ background:"var(--bg-card)" }}>
                <card.icon className="size-4 mx-auto mb-2" style={{ color: card.color }} />
                <div className="text-2xl font-bold" style={{ color: card.color, fontFamily:"'Syne', sans-serif" }}>
                  {loading ? "—" : card.value}
                </div>
                <div className="text-xs mt-0.5 uppercase tracking-widest"
                     style={{ color:"var(--text-muted)", fontFamily:"'JetBrains Mono', monospace" }}>
                  {card.label}
                </div>
              </motion.div>
            ))}
          </div>
        )}

        {/* ── ROW 2: Trend + MITRE + Severity ── */}
        {stats && (
          <div className="grid md:grid-cols-3 gap-4 mb-6">

            {/* Alert Trend */}
            <div className="card p-5" style={{ background:"var(--bg-card)" }}>
              <div className="flex items-center gap-2 mb-3">
                <TrendingUp className="size-4" style={{ color:"var(--accent-green)" }} />
                <span className="text-sm font-semibold" style={{ color:"var(--text-primary)", fontFamily:"'Syne', sans-serif" }}>
                  7-Day Alert Trend
                </span>
              </div>
              {stats.alertTrend.length > 0
                ? <TrendChart data={stats.alertTrend} />
                : <div className="h-12 flex items-center justify-center text-xs"
                       style={{ color:"var(--text-muted)", fontFamily:"'JetBrains Mono', monospace" }}>
                    No data yet
                  </div>
              }
              <div className="flex gap-3 mt-3 text-xs" style={{ fontFamily:"'JetBrains Mono', monospace" }}>
                <span style={{ color:"#ff4444" }}>■ Critical</span>
                <span style={{ color:"#f97316" }}>■ High</span>
                <span style={{ color:"#f5a623" }}>■ Med</span>
              </div>
            </div>

            {/* MITRE ATT&CK Coverage */}
            <div className="card p-5" style={{ background:"var(--bg-card)" }}>
              <div className="flex items-center gap-2 mb-3">
                <Shield className="size-4" style={{ color:"#a78bfa" }} />
                <span className="text-sm font-semibold" style={{ color:"var(--text-primary)", fontFamily:"'Syne', sans-serif" }}>
                  MITRE ATT&CK
                </span>
              </div>
              {stats.mitreTactics.length > 0 ? (
                <div className="space-y-2">
                  {stats.mitreTactics.slice(0, 4).map((m) => {
                    const tacticCode = m.tactic?.split(" ")[0] || "?";
                    const tacticName = m.tactic?.split(" - ")[1] || m.tactic || "Unknown";
                    const max = stats.mitreTactics[0]?.count || 1;
                    return (
                      <div key={m.tactic}>
                        <div className="flex justify-between text-xs mb-1"
                             style={{ fontFamily:"'JetBrains Mono', monospace" }}>
                          <span style={{ color:"var(--text-secondary)" }}>{tacticCode}</span>
                          <span style={{ color:"#a78bfa" }}>{tacticName.slice(0, 18)}</span>
                          <span style={{ color:"var(--text-muted)" }}>{m.count}</span>
                        </div>
                        <div className="h-1 rounded-full" style={{ background:"var(--bg-border)" }}>
                          <div className="h-full rounded-full"
                               style={{ width:`${(m.count/max)*100}%`, background:"#a78bfa" }} />
                        </div>
                      </div>
                    );
                  })}
                </div>
              ) : (
                <p className="text-xs" style={{ color:"var(--text-muted)", fontFamily:"'JetBrains Mono', monospace" }}>
                  No MITRE data yet
                </p>
              )}
            </div>

            {/* Top Targets */}
            <div className="card p-5" style={{ background:"var(--bg-card)" }}>
              <div className="flex items-center gap-2 mb-3">
                <Globe className="size-4" style={{ color:"var(--accent-cyan)" }} />
                <span className="text-sm font-semibold" style={{ color:"var(--text-primary)", fontFamily:"'Syne', sans-serif" }}>
                  Top Targeted Domains
                </span>
              </div>
              {stats.topTargets.length > 0 ? (
                <div className="space-y-2">
                  {stats.topTargets.slice(0, 5).map((t, i) => {
                    const s = SEV[t.maxSeverity as keyof typeof SEV] || SEV[1];
                    return (
                      <div key={t.domain} className="flex items-center justify-between">
                        <div className="flex items-center gap-2 min-w-0">
                          <span className="text-xs w-4 text-center flex-shrink-0"
                                style={{ color:"var(--text-muted)", fontFamily:"'JetBrains Mono', monospace" }}>
                            {i+1}
                          </span>
                          <span className="text-xs truncate"
                                style={{ color:"var(--text-secondary)", fontFamily:"'JetBrains Mono', monospace" }}>
                            {t.domain}
                          </span>
                        </div>
                        <div className="flex items-center gap-2 flex-shrink-0">
                          <span className="text-xs px-1.5 py-0.5 rounded"
                                style={{ color: s.color, background: s.bg, border:`1px solid ${s.border}`,
                                         fontFamily:"'JetBrains Mono', monospace", fontSize:9 }}>
                            {s.label}
                          </span>
                          <span className="text-xs font-bold" style={{ color:"var(--text-primary)", fontFamily:"'JetBrains Mono', monospace" }}>
                            {t.count}
                          </span>
                        </div>
                      </div>
                    );
                  })}
                </div>
              ) : (
                <p className="text-xs" style={{ color:"var(--text-muted)", fontFamily:"'JetBrains Mono', monospace" }}>
                  No target data yet
                </p>
              )}
            </div>
          </div>
        )}

        {/* ── TABS ── */}
        <div className="flex items-center gap-1 mb-4 p-1 rounded-xl w-fit"
             style={{ background:"var(--bg-card)", border:"1px solid var(--bg-border)" }}>
          {(["alerts","rules","topology"] as const).map((tab) => (
            <button key={tab} onClick={() => setActiveTab(tab)}
                    className="px-5 py-2 rounded-lg text-sm font-medium transition-all"
                    style={{
                      fontFamily:"'DM Sans', sans-serif",
                      color: activeTab === tab ? "#080b10" : "var(--text-secondary)",
                      background: activeTab === tab ? "var(--accent-green)" : "transparent",
                      fontWeight: activeTab === tab ? 700 : 400,
                    }}>
              {tab.charAt(0).toUpperCase() + tab.slice(1)}
            </button>
          ))}
        </div>

        {/* ═══════════════════════════ ALERTS TAB ═══════════════════════════ */}
        {activeTab === "alerts" && (
          <motion.div initial={{ opacity:0 }} animate={{ opacity:1 }}>

            {/* Filter bar */}
            <div className="flex flex-wrap items-center gap-3 mb-4">
              <Filter className="size-4" style={{ color:"var(--text-muted)" }} />

              {/* Status filter */}
              {["open","investigating","resolved","false_positive"].map((s) => (
                <button key={s} onClick={() => setStatusFilter(s)}
                        className="text-xs px-3 py-1.5 rounded-lg transition-all"
                        style={{
                          fontFamily:"'JetBrains Mono', monospace",
                          background: statusFilter === s ? "var(--accent-green)" : "var(--bg-card)",
                          color: statusFilter === s ? "#080b10" : "var(--text-muted)",
                          border:`1px solid ${statusFilter === s ? "var(--accent-green)" : "var(--bg-border)"}`,
                          fontWeight: statusFilter === s ? 700 : 400,
                        }}>
                  {s.replace("_"," ")}
                </button>
              ))}

              {/* Severity filter */}
              <select value={sevFilter} onChange={(e) => setSevFilter(e.target.value ? Number(e.target.value) : "")}
                      className="text-xs px-3 py-1.5 rounded-lg"
                      style={{ background:"var(--bg-card)", border:"1px solid var(--bg-border)",
                               color:"var(--text-secondary)", fontFamily:"'JetBrains Mono', monospace",
                               outline:"none" }}>
                <option value="">All severities</option>
                <option value="5">CRITICAL</option>
                <option value="4">HIGH</option>
                <option value="3">MEDIUM</option>
                <option value="2">LOW</option>
                <option value="1">INFO</option>
              </select>
            </div>

            {/* Alerts list */}
            <div className="card overflow-hidden" style={{ background:"var(--bg-card)" }}>
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
                    alert_feed.log — {alerts.length} records
                  </span>
                </div>
                <div className="flex items-center gap-1.5">
                  <div className="w-1.5 h-1.5 rounded-full safe-pulse" style={{ background:"var(--accent-green)" }} />
                  <span className="text-xs" style={{ color:"var(--text-muted)", fontFamily:"'JetBrains Mono', monospace" }}>live</span>
                </div>
              </div>

              {alerts.length === 0 ? (
                <div className="py-16 text-center">
                  <CheckCircle className="size-10 mx-auto mb-3" style={{ color:"var(--accent-green)" }} />
                  <p className="text-sm font-semibold" style={{ color:"var(--text-secondary)", fontFamily:"'Syne', sans-serif" }}>
                    No alerts found
                  </p>
                  <p className="text-xs mt-1" style={{ color:"var(--text-muted)" }}>
                    {statusFilter === "open" ? "System is clean" : `No ${statusFilter} alerts`}
                  </p>
                </div>
              ) : (
                <div className="divide-y" style={{ borderColor:"rgba(30,39,54,0.6)" }}>
                  {alerts.map((alert) => {
                    const sev       = SEV[alert.severity as keyof typeof SEV] || SEV[1];
                    const isExp     = expandedAlert === alert.alertId;
                    const CatIcon   = CATEGORY_ICONS[alert.category] || Activity;

                    return (
                      <Fragment key={alert.alertId}>
                        <motion.div
                          initial={{ opacity:0, y:4 }} animate={{ opacity:1, y:0 }}
                          className="px-5 py-4 cursor-pointer transition-all"
                          style={{ background: isExp ? "var(--bg-elevated)" : "transparent" }}
                          onMouseEnter={e => !isExp && ((e.currentTarget as HTMLDivElement).style.background = "var(--bg-hover)")}
                          onMouseLeave={e => !isExp && ((e.currentTarget as HTMLDivElement).style.background = "transparent")}
                          onClick={() => setExpandedAlert(isExp ? null : alert.alertId)}>

                          <div className="flex items-start gap-4">
                            {/* Severity indicator */}
                            <div className="flex-shrink-0 flex flex-col items-center gap-1.5 mt-0.5">
                              <div className="w-2.5 h-2.5 rounded-full"
                                   style={{ background: sev.color, boxShadow: alert.severity >= 4 ? `0 0 8px ${sev.ring}` : "none" }} />
                            </div>

                            {/* Alert info */}
                            <div className="flex-1 min-w-0">
                              <div className="flex items-center gap-2 flex-wrap mb-1">
                                <span className="text-xs px-2 py-0.5 rounded font-bold"
                                      style={{ color: sev.color, background: sev.bg, border:`1px solid ${sev.border}`,
                                               fontFamily:"'JetBrains Mono', monospace", letterSpacing:"0.06em" }}>
                                  {sev.label}
                                </span>
                                <span className="text-xs px-2 py-0.5 rounded"
                                      style={{ color:"var(--text-muted)", background:"var(--bg-elevated)",
                                               border:"1px solid var(--bg-border)", fontFamily:"'JetBrains Mono', monospace" }}>
                                  {alert.ruleId}
                                </span>
                                {alert.isCorrelated && (
                                  <span className="text-xs px-2 py-0.5 rounded"
                                        style={{ color:"#a78bfa", background:"rgba(124,58,237,0.08)",
                                                 border:"1px solid rgba(124,58,237,0.25)", fontFamily:"'JetBrains Mono', monospace" }}>
                                    CHAIN
                                  </span>
                                )}
                                {alert.eventCount > 1 && (
                                  <span className="text-xs px-2 py-0.5 rounded"
                                        style={{ color:"var(--accent-cyan)", background:"rgba(0,212,255,0.06)",
                                                 border:"1px solid rgba(0,212,255,0.15)", fontFamily:"'JetBrains Mono', monospace" }}>
                                    ×{alert.eventCount}
                                  </span>
                                )}
                              </div>
                              <div className="flex items-center gap-2 mb-1">
                                <CatIcon className="size-3.5 flex-shrink-0" style={{ color: sev.color }} />
                                <p className="text-sm font-semibold truncate"
                                   style={{ color:"var(--text-primary)", fontFamily:"'Syne', sans-serif" }}>
                                  {alert.title}
                                </p>
                              </div>
                              <p className="text-xs truncate" style={{ color:"var(--text-secondary)" }}>
                                {alert.description}
                              </p>
                              {alert.target?.domain && (
                                <p className="text-xs mt-1" style={{ color:"var(--accent-cyan)", fontFamily:"'JetBrains Mono', monospace" }}>
                                  → {alert.target.domain}
                                </p>
                              )}
                            </div>

                            {/* Right: time + status + chevron */}
                            <div className="flex-shrink-0 flex flex-col items-end gap-2">
                              <span className="text-xs" style={{ color:"var(--text-muted)", fontFamily:"'JetBrains Mono', monospace" }}>
                                {new Date(alert.firstSeen).toLocaleTimeString()}
                              </span>
                              <span className="text-xs px-2 py-0.5 rounded"
                                    style={{ color: STATUS_COLORS[alert.status] || "#8b95a8",
                                             background: `${STATUS_COLORS[alert.status] || "#8b95a8"}12`,
                                             border:`1px solid ${STATUS_COLORS[alert.status] || "#8b95a8"}30`,
                                             fontFamily:"'JetBrains Mono', monospace" }}>
                                {alert.status.replace("_"," ")}
                              </span>
                              {isExp ? <ChevronUp className="size-4" style={{ color:"var(--accent-green)" }} />
                                     : <ChevronDown className="size-4" style={{ color:"var(--text-muted)" }} />}
                            </div>
                          </div>
                        </motion.div>

                        {/* Expanded detail panel */}
                        <AnimatePresence>
                          {isExp && (
                            <motion.div key={`exp-${alert.alertId}`}
                              initial={{ opacity:0, height:0 }} animate={{ opacity:1, height:"auto" }}
                              exit={{ opacity:0, height:0 }}
                              className="px-6 pb-5 border-b"
                              style={{ borderColor:"var(--bg-border)", background:"var(--bg-elevated)" }}>

                              <div className="grid md:grid-cols-2 gap-5 pt-4">
                                {/* MITRE */}
                                <div>
                                  <div className="text-xs uppercase tracking-widest mb-2"
                                       style={{ color:"var(--text-muted)", fontFamily:"'JetBrains Mono', monospace" }}>
                                    MITRE ATT&CK
                                  </div>
                                  {alert.mitre?.tactic ? (
                                    <div className="space-y-1">
                                      <div className="text-xs p-2 rounded"
                                           style={{ background:"rgba(124,58,237,0.08)", border:"1px solid rgba(124,58,237,0.2)",
                                                    color:"#a78bfa", fontFamily:"'JetBrains Mono', monospace" }}>
                                        {alert.mitre.tactic}
                                      </div>
                                      {alert.mitre.technique && (
                                        <div className="text-xs p-2 rounded"
                                             style={{ background:"rgba(124,58,237,0.04)", border:"1px solid rgba(124,58,237,0.12)",
                                                      color:"var(--text-secondary)", fontFamily:"'JetBrains Mono', monospace" }}>
                                          {alert.mitre.technique}
                                        </div>
                                      )}
                                    </div>
                                  ) : (
                                    <p className="text-xs" style={{ color:"var(--text-muted)" }}>Not mapped</p>
                                  )}
                                </div>

                                {/* Alert metadata */}
                                <div>
                                  <div className="text-xs uppercase tracking-widest mb-2"
                                       style={{ color:"var(--text-muted)", fontFamily:"'JetBrains Mono', monospace" }}>
                                    METADATA
                                  </div>
                                  <div className="space-y-1 text-xs" style={{ fontFamily:"'JetBrains Mono', monospace" }}>
                                    {[
                                      ["Alert ID",   alert.alertId],
                                      ["Rule ID",    alert.ruleId],
                                      ["Events",     alert.eventCount],
                                      ["Risk Score", `${alert.riskScore}/100`],
                                      ["First Seen", new Date(alert.firstSeen).toLocaleString()],
                                      ["Last Seen",  new Date(alert.lastSeen).toLocaleString()],
                                    ].map(([k, v]) => (
                                      <div key={String(k)} className="flex justify-between">
                                        <span style={{ color:"var(--text-muted)" }}>{k}</span>
                                        <span style={{ color:"var(--text-secondary)" }}>{v}</span>
                                      </div>
                                    ))}
                                  </div>
                                </div>
                              </div>

                              {/* Action buttons */}
                              <div className="flex flex-wrap gap-2 mt-4">
                                {alert.status === "open" && (
                                  <button onClick={() => updateAlertStatus(alert.alertId, "investigating")}
                                          className="text-xs px-3 py-1.5 rounded-lg transition-all"
                                          style={{ background:"rgba(245,166,35,0.08)", color:"#f5a623",
                                                   border:"1px solid rgba(245,166,35,0.3)", fontFamily:"'JetBrains Mono', monospace" }}>
                                    → Investigate
                                  </button>
                                )}
                                {(alert.status === "open" || alert.status === "investigating") && (
                                  <button onClick={() => updateAlertStatus(alert.alertId, "resolved")}
                                          className="text-xs px-3 py-1.5 rounded-lg transition-all"
                                          style={{ background:"rgba(0,255,136,0.06)", color:"var(--accent-green)",
                                                   border:"1px solid rgba(0,255,136,0.2)", fontFamily:"'JetBrains Mono', monospace" }}>
                                    ✓ Mark Resolved
                                  </button>
                                )}
                                <button onClick={() => updateAlertStatus(alert.alertId, "false_positive")}
                                        className="text-xs px-3 py-1.5 rounded-lg transition-all"
                                        style={{ background:"rgba(139,149,168,0.06)", color:"var(--text-muted)",
                                                 border:"1px solid var(--bg-border)", fontFamily:"'JetBrains Mono', monospace" }}>
                                  False Positive
                                </button>
                              </div>
                            </motion.div>
                          )}
                        </AnimatePresence>
                      </Fragment>
                    );
                  })}
                </div>
              )}
            </div>
          </motion.div>
        )}

        {/* ═══════════════════════════ RULES TAB ═══════════════════════════ */}
        {activeTab === "rules" && (
          <motion.div initial={{ opacity:0 }} animate={{ opacity:1 }}
                      className="card overflow-hidden" style={{ background:"var(--bg-card)" }}>
            <div className="px-5 py-3 border-b flex items-center justify-between"
                 style={{ borderColor:"var(--bg-border)", background:"rgba(0,0,0,0.3)" }}>
              <span className="text-xs" style={{ color:"var(--text-muted)", fontFamily:"'JetBrains Mono', monospace" }}>
                detection_rules.json — {rules.length} rules loaded
              </span>
              <span className="text-xs px-2 py-0.5 rounded"
                    style={{ color:"var(--accent-green)", background:"rgba(0,255,136,0.06)",
                             border:"1px solid rgba(0,255,136,0.2)", fontFamily:"'JetBrains Mono', monospace" }}>
                ALL ACTIVE
              </span>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full data-table">
                <thead>
                  <tr>
                    <th className="text-left">Rule ID</th>
                    <th className="text-left">Name</th>
                    <th className="text-left">Category</th>
                    <th className="text-left">Severity</th>
                    <th className="text-left">MITRE Tactic</th>
                  </tr>
                </thead>
                <tbody>
                  {rules.map((rule, i) => {
                    const sev = SEV[rule.severity as keyof typeof SEV] || SEV[1];
                    return (
                      <motion.tr key={rule.id}
                        initial={{ opacity:0, y:4 }} animate={{ opacity:1, y:0 }}
                        transition={{ delay: i * 0.03 }}>
                        <td>
                          <span className="text-xs font-bold" style={{ color:"var(--accent-cyan)", fontFamily:"'JetBrains Mono', monospace" }}>
                            {rule.id}
                          </span>
                        </td>
                        <td>
                          <span className="text-sm" style={{ color:"var(--text-primary)" }}>{rule.name}</span>
                        </td>
                        <td>
                          <span className="text-xs" style={{ color:"var(--text-secondary)", fontFamily:"'JetBrains Mono', monospace" }}>
                            {rule.category}
                          </span>
                        </td>
                        <td>
                          <span className="text-xs px-2 py-0.5 rounded font-bold"
                                style={{ color: sev.color, background: sev.bg, border:`1px solid ${sev.border}`,
                                         fontFamily:"'JetBrains Mono', monospace" }}>
                            {sev.label}
                          </span>
                        </td>
                        <td>
                          <span className="text-xs" style={{ color:"#a78bfa", fontFamily:"'JetBrains Mono', monospace" }}>
                            {rule.mitre?.tactic?.split(" - ")[0] || "—"}
                          </span>
                        </td>
                      </motion.tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </motion.div>
        )}

        {/* ═══════════════════════════ TOPOLOGY TAB ═══════════════════════════ */}
        {activeTab === "topology" && (
          <motion.div initial={{ opacity:0 }} animate={{ opacity:1 }}
                      className="card p-8" style={{ background:"var(--bg-card)", minHeight:320 }}>
            <h3 className="text-lg font-bold mb-6"
                style={{ fontFamily:"'Syne', sans-serif", color:"var(--text-primary)" }}>
              Detection Pipeline Topology
            </h3>
            <div className="flex flex-col md:flex-row items-center justify-center gap-0">
              {[
                { label:"Event Sources",    sub:"Scanner · Extension · API",          color:"var(--accent-cyan)",  icon:"📡" },
                { label:"Event Engine",     sub:"Normalize · Classify · Score",        color:"var(--accent-green)", icon:"⚙️" },
                { label:"Rule Engine",      sub:`${rules.length} rules · JSON-based`,  color:"#f5a623",             icon:"📋" },
                { label:"Correlation",      sub:"Attack chains · Time windows",        color:"#a78bfa",             icon:"🔗" },
                { label:"Alert Engine",     sub:"Dedup · Severity · Workflow",         color:"#ff4444",             icon:"🚨" },
                { label:"SIEM Dashboard",   sub:"SentinelCore UI",                     color:"var(--accent-green)", icon:"🖥️" },
              ].map((node, i, arr) => (
                <Fragment key={node.label}>
                  <div className="flex flex-col items-center text-center p-5 rounded-xl min-w-[130px]"
                       style={{ background:`${node.color}08`, border:`1px solid ${node.color}20` }}>
                    <div className="text-2xl mb-2">{node.icon}</div>
                    <div className="text-xs font-bold mb-1"
                         style={{ color: node.color, fontFamily:"'Syne', sans-serif" }}>
                      {node.label}
                    </div>
                    <div className="text-xs" style={{ color:"var(--text-muted)", fontFamily:"'JetBrains Mono', monospace" }}>
                      {node.sub}
                    </div>
                  </div>
                  {i < arr.length - 1 && (
                    <div className="text-xl mx-2 hidden md:block" style={{ color:"var(--text-muted)" }}>→</div>
                  )}
                </Fragment>
              ))}
            </div>
            <div className="mt-8 grid grid-cols-2 md:grid-cols-4 gap-3">
              {[
                { k:"Event Schema Fields",    v:"18+" },
                { k:"Alert Schema Fields",    v:"15+" },
                { k:"Detection Rules",        v:String(rules.length) },
                { k:"Correlation Patterns",   v:"3" },
                { k:"MITRE Techniques",       v:"8" },
                { k:"Compliance Standards",   v:"PCI-DSS · GDPR · NIST" },
                { k:"Dedup Window",           v:"2–30 min" },
                { k:"Real-time Processing",   v:"<100ms" },
              ].map((item) => (
                <div key={item.k} className="p-3 rounded-xl"
                     style={{ background:"var(--bg-elevated)", border:"1px solid var(--bg-border)" }}>
                  <div className="text-xs mb-1" style={{ color:"var(--text-muted)", fontFamily:"'JetBrains Mono', monospace" }}>
                    {item.k}
                  </div>
                  <div className="text-sm font-bold" style={{ color:"var(--accent-green)", fontFamily:"'Syne', sans-serif" }}>
                    {item.v}
                  </div>
                </div>
              ))}
            </div>
          </motion.div>
        )}

      </div>
    </div>
  );
}