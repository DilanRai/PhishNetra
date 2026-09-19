// FILE: src/pages/IncidentResponse.tsx
import { useState, useEffect, useCallback, useRef } from "react";
import { motion, AnimatePresence } from "motion/react";
import {
  Activity, Plus, RefreshCw, AlertTriangle, CheckCircle,
  ChevronDown, ChevronUp, Clock, Shield, Zap, Target,
  Database, Wifi, UserX, Package
} from "lucide-react";
import { useRole } from "../hooks/useRole";
import { API_BASE } from "../config";

const authHeader = () => ({
  "Content-Type": "application/json",
  Authorization: `Bearer ${localStorage.getItem("pg_token")}`,
});

const PHASE_COLORS: Record<string, string> = {
  detection:"#60a5fa", triage:"#fbbf24", containment:"#fb923c",
  eradication:"#f87171", recovery:"#34d399", lessons_learned:"#a78bfa",
};
const STATUS_COLORS: Record<string, string> = {
  detected:"#60a5fa", triage:"#fbbf24", containment:"#fb923c",
  eradication:"#f87171", recovery:"#34d399", post_incident:"#a78bfa", closed:"#64748b",
};
const SEV_COLOR = (s: number) =>
  s >= 5 ? "#f87171" : s >= 4 ? "#fb923c" : s >= 3 ? "#fbbf24" : "#60a5fa";

const CATEGORIES = [
  "phishing","ransomware","bec","data_breach","account_takeover",
  "malware","ddos","insider_threat","supply_chain","other",
];

const CAT_ICON: Record<string, React.ReactNode> = {
  phishing:       <Target className="size-3" />,
  ransomware:     <Zap className="size-3" />,
  bec:            <Shield className="size-3" />,
  data_breach:    <Database className="size-3" />,
  ddos:           <Wifi className="size-3" />,
  insider_threat: <UserX className="size-3" />,
  supply_chain:   <Package className="size-3" />,
};

// SLA hours by severity (mirrors backend calcSlaHours logic)
const SLA_HRS: Record<number,number> = { 5:6, 4:24, 3:72, 2:168, 1:336 };

/** Returns { label, color, pct } for time remaining until SLA breach */
function useSla(createdAt: string, severity: number) {
  const [remaining, setRemaining] = useState("");
  const [color, setColor]         = useState("var(--safe)");
  const [pct,   setPct]           = useState(100);
  const rafRef = useRef<number>(0);

  useEffect(() => {
    const totalMs = (SLA_HRS[severity] || 72) * 3600_000;
    const created = new Date(createdAt).getTime();

    const tick = () => {
      const now = Date.now();
      const elapsed = now - created;
      const left = totalMs - elapsed;
      const leftPct = Math.max(0, Math.min(100, (left / totalMs) * 100));
      setPct(leftPct);

      if (left <= 0) {
        setRemaining("BREACHED");
        setColor("#f87171");
        return;
      }
      const h = Math.floor(left / 3600_000);
      const m = Math.floor((left % 3600_000) / 60_000);
      setRemaining(h > 0 ? `${h}h ${m}m` : `${m}m`);
      setColor(leftPct < 25 ? "#f87171" : leftPct < 50 ? "#fbbf24" : "var(--safe)");
      rafRef.current = requestAnimationFrame(tick);
    };
    tick();
    return () => cancelAnimationFrame(rafRef.current);
  }, [createdAt, severity]);

  return { remaining, color, pct };
}

// ── IncidentRow sub-component (avoids re-mounting SLA hook in a list) ──
function IncidentRow({
  inc, expanded, onToggle, canWrite, onCompleteStep, onUpdateStatus, phasesOf,
}: {
  inc: any; expanded: boolean; onToggle: () => void;
  canWrite: boolean;
  onCompleteStep: (incId: string, stepId: string) => void;
  onUpdateStatus: (incId: string, status: string) => void;
  phasesOf: (inc: any) => { phase: string; steps: any[] }[];
}) {
  const sc   = STATUS_COLORS[inc.status] || "#64748b";
  const sevc = SEV_COLOR(inc.severity);
  const done = (inc.playbook || []).filter((s: any) => s.status === "done").length;
  const tot  = (inc.playbook || []).length;
  const pct  = tot > 0 ? Math.round((done / tot) * 100) : 0;

  // SLA countdown — only active when incident is not closed
  const closed = inc.status === "closed" || inc.status === "post_incident";
  const sla = useSla(inc.createdAt, inc.severity);

  // Phase progress timeline
  const PHASE_ORDER = ["detection","triage","containment","eradication","recovery","lessons_learned"];
  const phases = phasesOf(inc);
  const activePhaseIdx = PHASE_ORDER.findIndex(p => {
    const ph = phases.find(x => x.phase === p);
    return ph && !ph.steps.every((s: any) => s.status === "done" || s.status === "skipped");
  });

  return (
    <div className="card overflow-hidden">
      {/* ── Header row ── */}
      <div className="px-5 py-4 flex items-center gap-3 cursor-pointer"
           onClick={onToggle}>
        <div className="w-2 h-2 rounded-full flex-shrink-0" style={{ background: sevc }} />

        <div className="flex-1 min-w-0">
          {/* Badges */}
          <div className="flex items-center gap-2 mb-0.5 flex-wrap">
            <span className="text-xs font-bold" style={{ color:"var(--accent)", fontFamily:"var(--font-mono)" }}>
              {inc.incidentId}
            </span>
            <span className="text-xs px-1.5 py-0.5 rounded font-bold uppercase"
                  style={{ color:sc, background:`${sc}12`, border:`1px solid ${sc}25`, fontFamily:"var(--font-mono)" }}>
              {inc.status?.replace(/_/g," ")}
            </span>
            <span className="text-xs px-1.5 py-0.5 rounded"
                  style={{ color:sevc, background:`${sevc}12`, border:`1px solid ${sevc}25`, fontFamily:"var(--font-mono)" }}>
              SEV-{inc.severity}
            </span>
            <span className="flex items-center gap-1 text-xs capitalize" style={{ color:"var(--text-muted)" }}>
              {CAT_ICON[inc.category]}
              {inc.category?.replace(/_/g," ")}
            </span>
          </div>

          {/* Title */}
          <div className="font-semibold text-sm truncate" style={{ color:"var(--text-primary)" }}>
            {inc.title}
          </div>

          {/* Phase timeline strip */}
          <div className="flex items-center gap-0.5 mt-1.5">
            {PHASE_ORDER.map((ph, i) => {
              const found  = phases.find(x => x.phase === ph);
              const isDone = found ? found.steps.every((s:any) => s.status==="done"||s.status==="skipped") : false;
              const isAct  = i === activePhaseIdx;
              const phCol  = PHASE_COLORS[ph] || "var(--accent)";
              return (
                <div key={ph} title={ph.replace("_"," ")}
                     className="flex-1 rounded-full transition-all"
                     style={{
                       height: 3,
                       background: isDone ? phCol : isAct ? `${phCol}70` : "var(--bg-border)",
                     }} />
              );
            })}
          </div>

          {/* Playbook progress */}
          <div className="flex items-center gap-2 mt-1">
            <div className="flex-1 rounded-full overflow-hidden" style={{ height:2, background:"var(--bg-border)" }}>
              <div className="h-full rounded-full transition-all"
                   style={{ width:`${pct}%`, background: pct===100 ? "var(--safe)" : "var(--accent)" }} />
            </div>
            <span className="text-[10px]" style={{ color:"var(--text-muted)", fontFamily:"var(--font-mono)" }}>
              {done}/{tot}
            </span>
          </div>
        </div>

        {/* Right side — date, SLA, MTTR */}
        <div className="flex-shrink-0 text-right space-y-0.5">
          <div className="text-xs" style={{ color:"var(--text-muted)", fontFamily:"var(--font-mono)" }}>
            {new Date(inc.createdAt).toLocaleDateString()}
          </div>
          {!closed && (
            <div className="flex items-center justify-end gap-1">
              <Clock className="size-3" style={{ color: sla.color }} />
              <span className="text-[10px] font-bold" style={{ color: sla.color, fontFamily:"var(--font-mono)" }}>
                {sla.remaining}
              </span>
            </div>
          )}
          {inc.mttr && (
            <div className="text-[10px]" style={{ color:"var(--safe)", fontFamily:"var(--font-mono)" }}>
              MTTR: {inc.mttr}m
            </div>
          )}
        </div>

        {expanded
          ? <ChevronUp  className="size-4 flex-shrink-0" style={{ color:"var(--text-muted)" }} />
          : <ChevronDown className="size-4 flex-shrink-0" style={{ color:"var(--text-muted)" }} />}
      </div>

      {/* ── Expanded detail ── */}
      <AnimatePresence>
        {expanded && (
          <motion.div initial={{ height:0 }} animate={{ height:"auto" }} exit={{ height:0 }}
                      style={{ overflow:"hidden" }}>
            <div className="px-5 pb-5 border-t" style={{ borderColor:"var(--bg-border)" }}>

              {/* SLA bar */}
              {!closed && (
                <div className="mt-3 mb-3">
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-[10px] uppercase tracking-wider" style={{ color:"var(--text-muted)", fontFamily:"var(--font-mono)" }}>SLA</span>
                    <span className="text-[10px] font-bold" style={{ color: sla.color, fontFamily:"var(--font-mono)" }}>
                      {sla.remaining} remaining
                    </span>
                  </div>
                  <div className="rounded-full overflow-hidden" style={{ height:4, background:"var(--bg-border)" }}>
                    <div className="h-full rounded-full transition-all"
                         style={{ width:`${sla.pct}%`, background: sla.color }} />
                  </div>
                </div>
              )}

              {/* Status update */}
              {canWrite && (
                <div className="flex items-center gap-2 mb-4 flex-wrap">
                  <span className="text-xs" style={{ color:"var(--text-muted)" }}>Update status:</span>
                  <div className="flex gap-1 flex-wrap">
                    {["triage","containment","eradication","recovery","post_incident","closed"].map(s => (
                      <button key={s} onClick={() => onUpdateStatus(inc._id, s)}
                              className="px-2.5 py-1 rounded-lg text-[10px] capitalize transition-all"
                              style={{
                                background: inc.status===s ? `${STATUS_COLORS[s]}15` : "var(--bg-elevated)",
                                color:      inc.status===s ?  STATUS_COLORS[s]       : "var(--text-muted)",
                                border:     `1px solid ${inc.status===s ? STATUS_COLORS[s]+"35" : "var(--bg-border)"}`,
                              }}>
                        {s.replace(/_/g," ")}
                      </button>
                    ))}
                  </div>
                </div>
              )}

              {/* Playbook phases */}
              <div className="space-y-3">
                {phasesOf(inc).map(({ phase, steps }) => {
                  const phaseColor = PHASE_COLORS[phase] || "var(--accent)";
                  const phaseDone  = steps.every((s:any) => s.status==="done"||s.status==="skipped");
                  return (
                    <div key={phase}>
                      <div className="flex items-center gap-2 mb-2">
                        <div className="w-1.5 h-1.5 rounded-full" style={{ background:phaseColor }} />
                        <span className="text-xs font-bold uppercase tracking-wider"
                              style={{ color:phaseColor, fontFamily:"var(--font-mono)" }}>
                          {phase.replace(/_/g," ")} {phaseDone ? "✓" : ""}
                        </span>
                      </div>
                      <div className="space-y-1.5 ml-3.5">
                        {steps.map((step: any) => {
                          const isDone = step.status==="done"||step.status==="skipped";
                          const isImm  = step.priority==="immediate";
                          return (
                            <div key={step.stepId}
                                 className="flex items-start gap-3 px-3 py-2.5 rounded-xl"
                                 style={{
                                   background: isDone ? "rgba(52,211,153,0.05)" : isImm ? "rgba(248,113,113,0.05)" : "var(--bg-elevated)",
                                   border:     `1px solid ${isDone ? "rgba(52,211,153,0.15)" : isImm ? "rgba(248,113,113,0.15)" : "var(--bg-border)"}`,
                                 }}>
                              <div className="flex-shrink-0 mt-0.5">
                                {isDone
                                  ? <CheckCircle className="size-4" style={{ color:"var(--safe)" }} />
                                  : <div className="w-4 h-4 rounded-full border-2" style={{ borderColor: isImm ? "#f87171" : "var(--bg-border)" }} />}
                              </div>
                              <div className="flex-1 min-w-0">
                                <div className="flex items-center gap-2">
                                  <span className="text-xs font-semibold"
                                        style={{ color: isDone ? "var(--text-muted)" : "var(--text-primary)", textDecoration: isDone?"line-through":undefined }}>
                                    {step.title}
                                  </span>
                                  {isImm && !isDone && (
                                    <span className="text-[9px] px-1.5 py-0.5 rounded font-bold"
                                          style={{ color:"#f87171", background:"rgba(248,113,113,0.1)", border:"1px solid rgba(248,113,113,0.2)", fontFamily:"var(--font-mono)" }}>
                                      IMMEDIATE
                                    </span>
                                  )}
                                </div>
                                <p className="text-[11px] mt-0.5 leading-relaxed" style={{ color:"var(--text-muted)" }}>
                                  {step.description}
                                </p>
                                {step.completedBy && (
                                  <p className="text-[10px] mt-1" style={{ color:"var(--safe)", fontFamily:"var(--font-mono)" }}>
                                    ✓ {step.completedBy} · {new Date(step.completedAt).toLocaleString()}
                                  </p>
                                )}
                              </div>
                              {canWrite && !isDone && (
                                <button onClick={() => onCompleteStep(inc._id, step.stepId)}
                                        className="flex-shrink-0 px-2.5 py-1 rounded-lg text-[10px] font-semibold"
                                        style={{ background:"var(--accent)", color:"#fff" }}>
                                  Done
                                </button>
                              )}
                            </div>
                          );
                        })}
                      </div>
                    </div>
                  );
                })}
              </div>

              {/* MITRE tags */}
              {inc.mitreTechniques?.length > 0 && (
                <div className="mt-3 flex flex-wrap gap-1.5">
                  {inc.mitreTechniques.map((t:string) => (
                    <span key={t} className="text-[10px] px-2 py-0.5 rounded"
                          style={{ color:"var(--accent)", background:"var(--accent-subtle)", border:"1px solid var(--accent-border)", fontFamily:"var(--font-mono)" }}>
                      {t}
                    </span>
                  ))}
                </div>
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

export default function IncidentResponse() {
  const { canWrite, canDelete } = useRole();
  const [incidents,  setIncidents]  = useState<any[]>([]);
  const [stats,      setStats]      = useState<any>(null);
  const [loading,    setLoading]    = useState(true);
  const [expanded,   setExpanded]   = useState<string|null>(null);
  const [showCreate, setShowCreate] = useState(false);
  const [filterStatus,setFilterStatus] = useState("all");
  const [filterCat,  setFilterCat]  = useState("all");
  const [error,      setError]      = useState<string|null>(null);
  const [form, setForm] = useState({
    title:"", description:"", severity:"3", category:"phishing",
    affectedAssets:"", affectedUsers:"",
  });

  const fetchData = useCallback(async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams({
        ...(filterStatus !== "all" ? { status: filterStatus } : {}),
        ...(filterCat    !== "all" ? { category: filterCat  } : {}),
      });
      const [listRes, statsRes] = await Promise.all([
        fetch(`${API_BASE}/api/incidents?${params}`,    { headers: authHeader() }),
        fetch(`${API_BASE}/api/incidents/stats`,         { headers: authHeader() }),
      ]);
      if (listRes.ok)  { const d = await listRes.json(); setIncidents(d.incidents||[]); }
      if (statsRes.ok) setStats(await statsRes.json());
    } catch {}
    finally { setLoading(false); }
  }, [filterStatus, filterCat]);

  useEffect(() => { fetchData(); }, [fetchData]);

  const createIncident = async () => {
    if (!form.title.trim()) { setError("Title required"); return; }
    try {
      const res = await fetch(`${API_BASE}/api/incidents`, {
        method:"POST", headers: authHeader(),
        body: JSON.stringify({
          ...form,
          severity: Number(form.severity),
          affectedAssets: form.affectedAssets.split(",").map(s=>s.trim()).filter(Boolean),
          affectedUsers:  form.affectedUsers.split(",").map(s=>s.trim()).filter(Boolean),
        }),
      });
      if (!res.ok) { const d = await res.json(); throw new Error(d.error); }
      setShowCreate(false);
      setForm({ title:"",description:"",severity:"3",category:"phishing",affectedAssets:"",affectedUsers:"" });
      fetchData();
    } catch (err:any) { setError(err.message); }
  };

  const completeStep = async (incidentId: string, stepId: string, status="done", notes="") => {
    await fetch(`${API_BASE}/api/incidents/${incidentId}/step/${stepId}`, {
      method:"PATCH", headers: authHeader(), body: JSON.stringify({ status, notes }),
    });
    fetchData();
  };

  const updateStatus = async (incidentId: string, status: string) => {
    await fetch(`${API_BASE}/api/incidents/${incidentId}/status`, {
      method:"PATCH", headers: authHeader(), body: JSON.stringify({ status }),
    });
    fetchData();
  };

  const phasesOf = (incident: any) => {
    const phases = ["detection","triage","containment","eradication","recovery","lessons_learned"];
    return phases.map(phase => ({
      phase,
      steps: (incident.playbook||[]).filter((s:any) => s.phase === phase),
    })).filter(p => p.steps.length > 0);
  };

  return (
    <div className="min-h-full py-10 px-6" style={{ background:"var(--bg-base)" }}>
      <div className="max-w-6xl mx-auto">

        <motion.div initial={{ opacity:0,y:16 }} animate={{ opacity:1,y:0 }} className="mb-8">
          <div className="tag-red inline-flex mb-3"><Activity className="size-3" /> INCIDENT RESPONSE</div>
          <div className="flex items-start justify-between flex-wrap gap-4">
            <div>
              <h1 className="font-display text-4xl mb-1.5" style={{ color:"var(--text-primary)" }}>
                Incident Response Platform
              </h1>
              <p style={{ color:"var(--text-muted)", fontSize:14 }}>
                Structured IR playbooks · MITRE-mapped · Auto-generated from SIEM alerts
              </p>
            </div>
            <div className="flex gap-2">
              <button onClick={fetchData} className="btn-ghost flex items-center gap-2 px-3.5 py-2 text-sm">
                <RefreshCw className="size-4" /> Refresh
              </button>
              {canWrite && (
                <button onClick={() => setShowCreate(true)}
                        className="flex items-center gap-2 px-4 py-2 rounded-xl text-sm font-semibold"
                        style={{ background:"#f87171", color:"#fff" }}>
                  <Plus className="size-4" /> New Incident
                </button>
              )}
            </div>
          </div>
        </motion.div>

        {/* Stats */}
        {stats && (
          <div className="grid grid-cols-2 md:grid-cols-6 gap-3 mb-6">
            {[
              { label:"Total",         value:stats.total,                           color:"var(--accent)" },
              { label:"Open",          value:stats.open,                            color:"#f87171"       },
              { label:"Avg MTTR",      value:`${stats.avgMttr||0}m`,               color:"#fbbf24"       },
              { label:"Avg MTTC",      value:`${stats.avgMttc||0}m`,               color:"#fb923c"       },
              { label:"Ransomware",    value:stats.byCategory?.ransomware||0,       color:"#f87171"       },
              { label:"Data Breaches", value:stats.byCategory?.data_breach||0,      color:"#a78bfa"       },
            ].map(s => (
              <div key={s.label} className="card p-4 stat-card">
                <div className="text-xl font-bold font-display" style={{ color:s.color }}>{s.value}</div>
                <div className="label-caps mt-1">{s.label}</div>
              </div>
            ))}
          </div>
        )}

        {error && (
          <div className="flex items-center gap-2 px-4 py-2.5 rounded-xl mb-4"
               style={{ background:"rgba(248,113,113,0.08)", border:"1px solid rgba(248,113,113,0.2)" }}>
            <AlertTriangle className="size-4 flex-shrink-0" style={{ color:"var(--color-danger)" }} />
            <span className="text-xs flex-1" style={{ color:"var(--color-danger)" }}>{error}</span>
            <button onClick={() => setError(null)} style={{ background:"none",border:"none",cursor:"pointer",color:"var(--text-muted)" }}>✕</button>
          </div>
        )}

        {/* Filters */}
        <div className="flex gap-2 mb-4 flex-wrap">
          <select value={filterStatus} onChange={e => setFilterStatus(e.target.value)}
                  className="text-xs px-3 py-2 rounded-xl"
                  style={{ background:"var(--bg-elevated)", border:"1px solid var(--bg-border)", color:"var(--text-secondary)" }}>
            <option value="all">All Status</option>
            {["detected","triage","containment","eradication","recovery","post_incident","closed"].map(s => (
              <option key={s} value={s}>{s.replace("_"," ")}</option>
            ))}
          </select>
          <select value={filterCat} onChange={e => setFilterCat(e.target.value)}
                  className="text-xs px-3 py-2 rounded-xl"
                  style={{ background:"var(--bg-elevated)", border:"1px solid var(--bg-border)", color:"var(--text-secondary)" }}>
            <option value="all">All Categories</option>
            {CATEGORIES.map(c => <option key={c} value={c}>{c.replace(/_/g," ")}</option>)}
          </select>
        </div>

        {/* Incident list */}
        {loading ? (
          <div className="flex items-center justify-center py-20">
            <RefreshCw className="size-6 animate-spin" style={{ color:"var(--text-muted)" }} />
          </div>
        ) : incidents.length === 0 ? (
          <div className="text-center py-20">
            <Activity className="size-12 mx-auto mb-3" style={{ color:"var(--text-muted)" }} />
            <p className="text-sm" style={{ color:"var(--text-muted)" }}>No incidents — they auto-create from critical SIEM alerts</p>
          </div>
        ) : (
          <div className="space-y-3">
            {incidents.map((inc:any) => (
              <IncidentRow
                key={inc._id}
                inc={inc}
                expanded={expanded === inc._id}
                onToggle={() => setExpanded(expanded === inc._id ? null : inc._id)}
                canWrite={canWrite}
                onCompleteStep={completeStep}
                onUpdateStatus={updateStatus}
                phasesOf={phasesOf}
              />
            ))}

          </div>
        )}

        {/* Create modal (unchanged below) */}
        <AnimatePresence>
          {showCreate && (
            <motion.div initial={{ opacity:0 }} animate={{ opacity:1 }} exit={{ opacity:0 }}
                        className="fixed inset-0 flex items-center justify-center z-50 px-4"
                        style={{ background:"rgba(0,0,0,0.7)", backdropFilter:"blur(4px)" }}>
              <motion.div initial={{ scale:0.95 }} animate={{ scale:1 }} exit={{ scale:0.95 }}
                          className="card-glass p-6 max-w-lg w-full rounded-2xl">
                <h3 className="font-bold text-xl mb-4" style={{ color:"var(--text-primary)" }}>Create Incident</h3>
                <div className="space-y-3">
                  <input value={form.title} onChange={e => setForm(f=>({...f,title:e.target.value}))}
                         placeholder="Incident title"
                         className="w-full px-3 py-2.5 rounded-xl text-sm"
                         style={{ background:"var(--bg-elevated)", border:"1px solid var(--bg-border)", color:"var(--text-primary)", outline:"none" }} />
                  <textarea value={form.description} onChange={e => setForm(f=>({...f,description:e.target.value}))}
                            placeholder="Description..." rows={3}
                            className="w-full px-3 py-2.5 rounded-xl text-sm resize-none"
                            style={{ background:"var(--bg-elevated)", border:"1px solid var(--bg-border)", color:"var(--text-primary)", outline:"none" }} />
                  <div className="grid grid-cols-2 gap-3">
                    <select value={form.category} onChange={e => setForm(f=>({...f,category:e.target.value}))}
                            className="px-3 py-2 rounded-xl text-sm"
                            style={{ background:"var(--bg-elevated)", border:"1px solid var(--bg-border)", color:"var(--text-secondary)" }}>
                      {CATEGORIES.map(c => <option key={c} value={c}>{c.replace(/_/g," ")}</option>)}
                    </select>
                    <select value={form.severity} onChange={e => setForm(f=>({...f,severity:e.target.value}))}
                            className="px-3 py-2 rounded-xl text-sm"
                            style={{ background:"var(--bg-elevated)", border:"1px solid var(--bg-border)", color:"var(--text-secondary)" }}>
                      {[5,4,3,2,1].map(s => <option key={s} value={s}>Severity {s}{s===5?" (Critical)":s===4?" (High)":s===3?" (Medium)":""}</option>)}
                    </select>
                  </div>
                  <input value={form.affectedAssets} onChange={e => setForm(f=>({...f,affectedAssets:e.target.value}))}
                         placeholder="Affected assets (comma-separated)"
                         className="w-full px-3 py-2.5 rounded-xl text-sm"
                         style={{ background:"var(--bg-elevated)", border:"1px solid var(--bg-border)", color:"var(--text-primary)", outline:"none" }} />
                  <input value={form.affectedUsers} onChange={e => setForm(f=>({...f,affectedUsers:e.target.value}))}
                         placeholder="Affected users (comma-separated)"
                         className="w-full px-3 py-2.5 rounded-xl text-sm"
                         style={{ background:"var(--bg-elevated)", border:"1px solid var(--bg-border)", color:"var(--text-primary)", outline:"none" }} />
                </div>
                {error && <p className="text-xs mt-2" style={{ color:"var(--color-danger)" }}>{error}</p>}
                <div className="flex gap-2 justify-end mt-4">
                  <button onClick={() => { setShowCreate(false); setError(null); }}
                          className="px-4 py-2 rounded-xl text-sm"
                          style={{ background:"var(--bg-elevated)", color:"var(--text-secondary)", border:"1px solid var(--bg-border)" }}>Cancel</button>
                  <button onClick={createIncident}
                          className="px-5 py-2 rounded-xl text-sm font-semibold"
                          style={{ background:"#f87171", color:"#fff" }}>Create Incident</button>
                </div>
              </motion.div>
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </div>
  );
}