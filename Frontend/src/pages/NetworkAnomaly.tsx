// ════════════════════════════════════════════════════════════════
// FILE: src/pages/NetworkAnomaly.tsx
// AI-Based Network Anomaly Detection
// ════════════════════════════════════════════════════════════════
import { useState, useEffect, useCallback } from "react";
import { motion, AnimatePresence } from "motion/react";
import { Activity, RefreshCw, AlertTriangle, CheckCircle, Filter, Cpu, Plus, Terminal } from "lucide-react";
import { useRole } from "../hooks/useRole";
import { API_BASE } from "../config";

const authHeader = () => ({
  "Content-Type": "application/json",
  Authorization: `Bearer ${localStorage.getItem("pg_token")}`,
});

const TYPE_META: Record<string, { icon: string; color: string; label: string }> = {
  impossible_travel:    { icon:"✈️", color:"#f87171", label:"Impossible Travel"      },
  unusual_time:         { icon:"🕐", color:"#fbbf24", label:"Unusual Login Time"     },
  high_volume:          { icon:"📊", color:"#fb923c", label:"High Volume"            },
  lateral_movement:     { icon:"🔗", color:"#f87171", label:"Lateral Movement"       },
  data_exfiltration:    { icon:"📤", color:"#f87171", label:"Data Exfiltration"      },
  c2_beaconing:         { icon:"📡", color:"#f87171", label:"C2 Beaconing"           },
  port_scan:            { icon:"🔍", color:"#fb923c", label:"Port Scan"              },
  dns_tunneling:        { icon:"🌐", color:"#fb923c", label:"DNS Tunneling"          },
  privilege_escalation: { icon:"⬆️", color:"#f87171", label:"Privilege Escalation"  },
  new_device:           { icon:"💻", color:"#fbbf24", label:"New Device"             },
  credential_stuffing:  { icon:"🔑", color:"#f87171", label:"Credential Stuffing"    },
  other:                { icon:"⚠️", color:"#64748b", label:"Anomaly"               },
};

const LOG_EVENT_TYPES = [
  "failed_login","successful_login","suspicious_process","dns_query",
  "powershell_execution","network_connection","c2_beacon_detected",
  "privilege_escalation","usb_activity",
];

export default function NetworkAnomaly() {
  const { canWrite } = useRole();
  const [anomalies,  setAnomalies]  = useState<any[]>([]);
  const [stats,      setStats]      = useState<any>(null);
  const [loading,    setLoading]    = useState(true);
  const [filterType, setFilterType] = useState("all");
  const [filterStatus,setFilterStatus] = useState("open");
  const [total,      setTotal]      = useState(0);
  const [page,       setPage]       = useState(1);
  const [showIngest, setShowIngest] = useState(false);
  const [ingestResult, setIngestResult] = useState<any>(null);
  const [ingestForm, setIngestForm] = useState({
    logType:"failed_login", sourceUser:"", sourceHost:"", sourceIp:"",
    commandLine:"", attemptCount:"", queriedDomain:"", bytesSent:"",
  });
  const [ingesting, setIngesting] = useState(false);

  const fetchData = useCallback(async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams({
        ...(filterType   !== "all" ? { type:   filterType   } : {}),
        ...(filterStatus !== "all" ? { status: filterStatus } : {}),
        page: String(page), limit:"50",
      });
      const [listRes, statsRes] = await Promise.all([
        fetch(`${API_BASE}/api/network-anomaly?${params}`,  { headers: authHeader() }),
        fetch(`${API_BASE}/api/network-anomaly/stats`,       { headers: authHeader() }),
      ]);
      if (listRes.ok)  { const d = await listRes.json(); setAnomalies(d.anomalies||[]); setTotal(d.total||0); }
      if (statsRes.ok) setStats(await statsRes.json());
    } catch {}
    finally { setLoading(false); }
  }, [filterType, filterStatus, page]);

  useEffect(() => { fetchData(); }, [fetchData]);

  const updateStatus = async (id: string, status: string) => {
    await fetch(`${API_BASE}/api/network-anomaly/${id}/status`, {
      method:"PATCH", headers: authHeader(), body: JSON.stringify({ status }),
    });
    fetchData();
  };

  const ingestLogEvent = async () => {
    setIngesting(true); setIngestResult(null);
    try {
      const rawData: any = {};
      if (ingestForm.commandLine) rawData.commandLine = ingestForm.commandLine;
      if (ingestForm.attemptCount) rawData.attemptCount = parseInt(ingestForm.attemptCount);
      if (ingestForm.queriedDomain) rawData.queriedDomain = ingestForm.queriedDomain;
      if (ingestForm.bytesSent) rawData.bytesSent = parseInt(ingestForm.bytesSent) * 1024 * 1024;
      const res = await fetch(`${API_BASE}/api/network-anomaly/analyze`, {
        method:"POST", headers: { "Content-Type":"application/json", Authorization:`Bearer ${localStorage.getItem("pg_token")}` },
        body: JSON.stringify({
          logType: ingestForm.logType,
          sourceUser: ingestForm.sourceUser || null,
          sourceHost: ingestForm.sourceHost || null,
          sourceIp:   ingestForm.sourceIp   || null,
          rawData,
          timestamp: new Date().toISOString(),
        }),
      });
      const data = await res.json();
      setIngestResult(data);
      if (data.count > 0) fetchData();
    } catch {}
    finally { setIngesting(false); }
  };

  const SEV_COLOR = (s: number) =>
    s >= 5 ? "#f87171" : s >= 4 ? "#fb923c" : s >= 3 ? "#fbbf24" : "#60a5fa";

  return (
    <div className="min-h-full py-10 px-6" style={{ background:"var(--bg-base)" }}>
      <div className="max-w-6xl mx-auto">

        <motion.div initial={{ opacity:0,y:16 }} animate={{ opacity:1,y:0 }} className="mb-8">
          <div className="tag-blue inline-flex mb-3"><Cpu className="size-3" /> NETWORK ANOMALY</div>
          <div className="flex items-start justify-between flex-wrap gap-4">
            <div>
              <h1 className="font-display text-4xl mb-1.5" style={{ color:"var(--text-primary)" }}>
                AI Network Anomaly Detection
              </h1>
              <p style={{ color:"var(--text-muted)", fontSize:14 }}>
                Behavioral baseline · Z-score deviation · Lateral movement · DNS tunneling · C2 beaconing
              </p>
            </div>
            <div className="flex gap-2">
                <button onClick={fetchData} className="btn-ghost flex items-center gap-2 px-3.5 py-2 text-sm">
                  <RefreshCw className={`size-4 ${loading?"animate-spin":""}`} /> Refresh
                </button>
                {canWrite && (
                  <button onClick={() => setShowIngest(s => !s)}
                          className="flex items-center gap-2 px-4 py-2 rounded-xl text-sm font-semibold"
                          style={{ background:"var(--accent)", color:"#fff" }}>
                    <Plus className="size-4" /> Ingest Log Event
                  </button>
                )}
              </div>
          </div>
        </motion.div>

        {/* Manual log event ingest panel */}
        <AnimatePresence>
          {showIngest && (
            <motion.div initial={{ opacity:0, height:0 }} animate={{ opacity:1, height:"auto" }} exit={{ opacity:0, height:0 }}
                        style={{ overflow:"hidden" }} className="mb-4">
              <div className="card p-5">
                <div className="flex items-center gap-2 mb-4">
                  <Terminal className="size-4" style={{ color:"var(--accent)" }} />
                  <span className="text-sm font-semibold" style={{ color:"var(--text-primary)" }}>Ingest Manual Log Event</span>
                  <span className="text-xs" style={{ color:"var(--text-muted)" }}>— Simulate a log event to test anomaly detection</span>
                </div>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-3">
                  <div>
                    <div className="label-caps mb-1">Log Type</div>
                    <select value={ingestForm.logType} onChange={e => setIngestForm(f => ({...f, logType: e.target.value}))}
                            className="w-full px-3 py-2 rounded-xl text-xs"
                            style={{ background:"var(--bg-elevated)", border:"1px solid var(--bg-border)", color:"var(--text-secondary)" }}>
                      {LOG_EVENT_TYPES.map(t => <option key={t} value={t}>{t.replace(/_/g," ")}</option>)}
                    </select>
                  </div>
                  <div>
                    <div className="label-caps mb-1">User</div>
                    <input value={ingestForm.sourceUser} onChange={e => setIngestForm(f => ({...f, sourceUser:e.target.value}))}
                           placeholder="e.g. jsmith"
                           className="w-full px-3 py-2 rounded-xl text-xs"
                           style={{ background:"var(--bg-elevated)", border:"1px solid var(--bg-border)", color:"var(--text-primary)", outline:"none" }} />
                  </div>
                  <div>
                    <div className="label-caps mb-1">Host</div>
                    <input value={ingestForm.sourceHost} onChange={e => setIngestForm(f => ({...f, sourceHost:e.target.value}))}
                           placeholder="e.g. WORKSTATION-01"
                           className="w-full px-3 py-2 rounded-xl text-xs"
                           style={{ background:"var(--bg-elevated)", border:"1px solid var(--bg-border)", color:"var(--text-primary)", outline:"none" }} />
                  </div>
                  <div>
                    <div className="label-caps mb-1">Source IP</div>
                    <input value={ingestForm.sourceIp} onChange={e => setIngestForm(f => ({...f, sourceIp:e.target.value}))}
                           placeholder="e.g. 192.168.1.100"
                           className="w-full px-3 py-2 rounded-xl text-xs"
                           style={{ background:"var(--bg-elevated)", border:"1px solid var(--bg-border)", color:"var(--text-primary)", outline:"none" }} />
                  </div>
                </div>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-3">
                  <div>
                    <div className="label-caps mb-1">Command Line</div>
                    <input value={ingestForm.commandLine} onChange={e => setIngestForm(f => ({...f, commandLine:e.target.value}))}
                           placeholder="e.g. vssadmin delete shadows"
                           className="w-full px-3 py-2 rounded-xl text-xs"
                           style={{ background:"var(--bg-elevated)", border:"1px solid var(--bg-border)", color:"var(--text-primary)", outline:"none", fontFamily:"var(--font-mono)" }} />
                  </div>
                  <div>
                    <div className="label-caps mb-1">Attempt Count</div>
                    <input value={ingestForm.attemptCount} onChange={e => setIngestForm(f => ({...f, attemptCount:e.target.value}))}
                           placeholder="e.g. 25" type="number"
                           className="w-full px-3 py-2 rounded-xl text-xs"
                           style={{ background:"var(--bg-elevated)", border:"1px solid var(--bg-border)", color:"var(--text-primary)", outline:"none" }} />
                  </div>
                  <div>
                    <div className="label-caps mb-1">DNS Query Domain</div>
                    <input value={ingestForm.queriedDomain} onChange={e => setIngestForm(f => ({...f, queriedDomain:e.target.value}))}
                           placeholder="e.g. abc.xyz.evil.top"
                           className="w-full px-3 py-2 rounded-xl text-xs"
                           style={{ background:"var(--bg-elevated)", border:"1px solid var(--bg-border)", color:"var(--text-primary)", outline:"none", fontFamily:"var(--font-mono)" }} />
                  </div>
                  <div>
                    <div className="label-caps mb-1">Bytes Sent (MB)</div>
                    <input value={ingestForm.bytesSent} onChange={e => setIngestForm(f => ({...f, bytesSent:e.target.value}))}
                           placeholder="e.g. 500" type="number"
                           className="w-full px-3 py-2 rounded-xl text-xs"
                           style={{ background:"var(--bg-elevated)", border:"1px solid var(--bg-border)", color:"var(--text-primary)", outline:"none" }} />
                  </div>
                </div>
                <div className="flex items-center gap-3">
                  <button onClick={ingestLogEvent} disabled={ingesting}
                          className="flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-semibold"
                          style={{ background:"var(--accent)", color:"#fff", opacity: ingesting ? 0.7 : 1 }}>
                    {ingesting ? <RefreshCw className="size-3.5 animate-spin" /> : <Activity className="size-3.5" />}
                    {ingesting ? "Analyzing..." : "Analyze Event"}
                  </button>
                  {ingestResult && (
                    <span className="text-xs" style={{ color: ingestResult.count > 0 ? "#f87171" : "var(--safe)" }}>
                      {ingestResult.count > 0
                        ? `⚠️ ${ingestResult.count} anomaly${ingestResult.count>1?"ies":""} detected`
                        : "✓ No anomalies detected for this event"}
                    </span>
                  )}
                </div>
              </div>
            </motion.div>
          )}
        </AnimatePresence>

        {/* Stats */}
        {stats && (
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-6">
            {[
              { label:"Total Anomalies", value:stats.total,    color:"var(--accent)"      },
              { label:"Open",            value:stats.open,     color:"#f87171"             },
              { label:"Critical",        value:stats.critical, color:"#f87171"             },
              { label:"Types Detected",  value:Object.keys(stats.byType||{}).length, color:"#fbbf24" },
            ].map(s => (
              <div key={s.label} className="card p-4 stat-card">
                <div className="text-2xl font-bold font-display" style={{ color:s.color }}>{s.value}</div>
                <div className="label-caps mt-1">{s.label}</div>
              </div>
            ))}
          </div>
        )}

        {/* Type breakdown */}
        {stats?.byType && Object.keys(stats.byType).length > 0 && (
          <div className="card p-4 mb-6">
            <div className="label-caps mb-3">Anomaly Types Detected</div>
            <div className="flex flex-wrap gap-2">
              {Object.entries(stats.byType).map(([type, count]:any) => {
                const tm = TYPE_META[type]||TYPE_META.other;
                return (
                  <button key={type}
                          onClick={() => setFilterType(filterType===type?"all":type)}
                          className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs transition-all"
                          style={{
                            background: filterType===type ? `${tm.color}15` : "var(--bg-elevated)",
                            border:     filterType===type ? `1px solid ${tm.color}35` : "1px solid var(--bg-border)",
                            color:      filterType===type ? tm.color : "var(--text-secondary)",
                          }}>
                    <span>{tm.icon}</span>
                    {tm.label}
                    <span className="font-bold" style={{ color:tm.color }}>{count}</span>
                  </button>
                );
              })}
            </div>
          </div>
        )}

        {/* Filters */}
        <div className="flex gap-2 mb-4 flex-wrap">
          <div className="flex gap-1 p-1 rounded-xl" style={{ background:"var(--bg-elevated)", border:"1px solid var(--bg-border)" }}>
            {["open","investigating","resolved","all"].map(s => (
              <button key={s} onClick={() => setFilterStatus(s)}
                      className="px-3 py-1.5 rounded-lg text-xs capitalize transition-all"
                      style={{
                        background: filterStatus===s ? "var(--accent-subtle)" : "transparent",
                        color:      filterStatus===s ? "var(--accent)" : "var(--text-muted)",
                      }}>
                {s}
              </button>
            ))}
          </div>
        </div>

        {/* Anomaly list */}
        {loading ? (
          <div className="flex items-center justify-center py-20">
            <RefreshCw className="size-6 animate-spin" style={{ color:"var(--text-muted)" }} />
          </div>
        ) : anomalies.length === 0 ? (
          <div className="text-center py-20">
            <CheckCircle className="size-12 mx-auto mb-3" style={{ color:"var(--safe)" }} />
            <p className="text-sm font-semibold" style={{ color:"var(--safe)" }}>No anomalies detected</p>
            <p className="text-xs mt-1" style={{ color:"var(--text-muted)" }}>
              Anomalies are detected automatically from Fluent Bit log events
            </p>
          </div>
        ) : (
          <div className="card overflow-hidden">
            <div className="divide-y" style={{ borderColor:"var(--bg-border)" }}>
              {anomalies.map((a:any) => {
                const tm   = TYPE_META[a.type] || TYPE_META.other;
                const sevc = SEV_COLOR(a.severity);
                return (
                  <div key={a._id} className="px-5 py-4 flex items-start gap-3">
                    <span className="text-xl flex-shrink-0 mt-0.5">{tm.icon}</span>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-1 flex-wrap">
                        <span className="text-xs font-bold" style={{ color:tm.color, fontFamily:"var(--font-mono)" }}>
                          {tm.label}
                        </span>
                        <span className="text-[9px] px-1.5 py-0.5 rounded font-bold"
                              style={{ color:sevc, background:`${sevc}12`, border:`1px solid ${sevc}25`, fontFamily:"var(--font-mono)" }}>
                          SEV-{a.severity}
                        </span>
                        {a.zScore && (
                          <span className="text-[9px] px-1.5 py-0.5 rounded"
                                style={{ color:"#a78bfa", background:"rgba(167,139,250,0.1)", fontFamily:"var(--font-mono)" }}>
                            z={a.zScore?.toFixed(1)}
                          </span>
                        )}
                        <span className="text-[9px] px-1.5 py-0.5 rounded"
                              style={{ color:"var(--text-muted)", background:"var(--bg-elevated)", fontFamily:"var(--font-mono)", textTransform:"uppercase" }}>
                          {a.status}
                        </span>
                      </div>
                      <p className="text-xs leading-relaxed" style={{ color:"var(--text-secondary)" }}>
                        {a.description}
                      </p>
                      <div className="flex items-center gap-3 mt-1 text-[10px]"
                           style={{ color:"var(--text-muted)", fontFamily:"var(--font-mono)" }}>
                        {a.host && <span>Host: {a.host}</span>}
                        {a.user && <span>User: {a.user}</span>}
                        {a.sourceIp && <span>IP: {a.sourceIp}</span>}
                        <span>{new Date(a.createdAt).toLocaleString()}</span>
                      </div>
                      {a.mitre && (
                        <div className="text-[10px] mt-1" style={{ color:"var(--accent)", fontFamily:"var(--font-mono)" }}>{a.mitre}</div>
                      )}
                    </div>
                    {canWrite && a.status === "open" && (
                      <div className="flex gap-1 flex-shrink-0">
                        <button onClick={() => updateStatus(a._id, "investigating")}
                                className="text-[10px] px-2 py-1 rounded-lg"
                                style={{ background:"rgba(251,191,36,0.1)", color:"#fbbf24", border:"1px solid rgba(251,191,36,0.2)" }}>
                          Investigate
                        </button>
                        <button onClick={() => updateStatus(a._id, "false_positive")}
                                className="text-[10px] px-2 py-1 rounded-lg"
                                style={{ background:"var(--bg-elevated)", color:"var(--text-muted)", border:"1px solid var(--bg-border)" }}>
                          FP
                        </button>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
            {total > 50 && (
              <div className="px-5 py-3 border-t flex items-center justify-between"
                   style={{ borderColor:"var(--bg-border)" }}>
                <button onClick={() => setPage(p => Math.max(1,p-1))} disabled={page===1}
                        className="text-xs btn-ghost px-3 py-1.5">← Prev</button>
                <span className="text-xs" style={{ color:"var(--text-muted)", fontFamily:"var(--font-mono)" }}>
                  Page {page} of {Math.ceil(total/50)}
                </span>
                <button onClick={() => setPage(p => p+1)} disabled={page>=Math.ceil(total/50)}
                        className="text-xs btn-ghost px-3 py-1.5">Next →</button>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
