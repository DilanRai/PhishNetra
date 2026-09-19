// ════════════════════════════════════════════════════════════════
// FILE: src/pages/EvidenceVault.tsx
// Digital Evidence Collection & Chain of Custody
// ════════════════════════════════════════════════════════════════
import { useState, useEffect, useCallback } from "react";
import { motion, AnimatePresence } from "motion/react";
import { Lock, Plus, RefreshCw, Download, AlertTriangle, CheckCircle, FileText, ShieldCheck, Hash } from "lucide-react";
import { useRole } from "../hooks/useRole";
import { API_BASE } from "../config";

const evAuthHeader = () => ({
  "Content-Type": "application/json",
  Authorization: `Bearer ${localStorage.getItem("pg_token")}`,
});

const EVIDENCE_TYPES = [
  "screenshot","url_archive","email_export","file","log_export",
  "network_capture","chat_export","financial_record","other",
];

// Type colour palette for the stats panel
const TYPE_COLORS: Record<string,string> = {
  screenshot:"#60a5fa", url_archive:"#34d399", email_export:"#fbbf24",
  file:"#fb923c", log_export:"#a78bfa", network_capture:"#f87171",
  chat_export:"#38bdf8", financial_record:"#f472b6", other:"#94a3b8",
};

export default function EvidenceVault() {
  const { canWrite } = useRole();
  const [evidence,   setEvidence]   = useState<any[]>([]);
  const [stats,      setStats]      = useState<Record<string,number>>({});
  const [total,      setTotal]      = useState(0);
  const [loading,    setLoading]    = useState(true);
  const [showAdd,    setShowAdd]    = useState(false);
  const [filterType, setFilterType] = useState("all");
  const [report,     setReport]     = useState<any>(null);
  const [incidentId, setIncidentId] = useState("");
  const [error,      setError]      = useState<string|null>(null);
  const [verifying,  setVerifying]  = useState<string|null>(null);
  const [verified,   setVerified]   = useState<Record<string,boolean|null>>({});
  const [form, setForm] = useState({
    type:"screenshot", title:"", description:"", source:"",
    incidentId:"", complaintId:"", iocType:"", iocValue:"", tags:"",
  });

  const fetchData = useCallback(async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams({
        ...(filterType !== "all" ? { type:filterType } : {}),
        limit:"50",
      });
      const res = await fetch(`${API_BASE}/api/evidence?${params}`, { headers: evAuthHeader() });
      if (res.ok) {
        const d = await res.json();
        setEvidence(d.evidence || []);
        setTotal(d.total || 0);
        // Build per-type counts from the returned page (fast, no extra API call)
        const counts: Record<string,number> = {};
        for (const ev of (d.evidence || [])) {
          counts[ev.type] = (counts[ev.type] || 0) + 1;
        }
        setStats(counts);
      }
    } catch {}
    finally { setLoading(false); }
  }, [filterType]);

  /** Re-derive hash of the source URL/path and compare to stored SHA-256 */
  const verifyHash = async (ev: any) => {
    if (!ev.sha256Hash) return;
    setVerifying(ev._id);
    try {
      const res = await fetch(`${API_BASE}/api/evidence/${ev._id}/verify`, {
        method: "POST", headers: evAuthHeader(),
      });
      if (res.ok) {
        const d = await res.json();
        setVerified(v => ({ ...v, [ev._id]: d.match }));
      }
    } catch {}
    finally { setVerifying(null); }
  };

  useEffect(() => { fetchData(); }, [fetchData]);

  const addEvidence = async () => {
    if (!form.title.trim()) { setError("Title required"); return; }
    try {
      const res = await fetch(`${API_BASE}/api/evidence`, {
        method:"POST", headers: evAuthHeader(),
        body: JSON.stringify({ ...form, tags: form.tags.split(",").map(s=>s.trim()).filter(Boolean) }),
      });
      if (!res.ok) { const d = await res.json(); throw new Error(d.error); }
      setShowAdd(false);
      setForm({ type:"screenshot",title:"",description:"",source:"",incidentId:"",complaintId:"",iocType:"",iocValue:"",tags:"" });
      fetchData();
    } catch (err:any) { setError(err.message); }
  };

  const generateReport = async () => {
    if (!incidentId.trim()) return;
    const res = await fetch(`${API_BASE}/api/evidence/${incidentId}/report`, { headers: evAuthHeader() });
    if (res.ok) setReport(await res.json());
    else setError("No evidence found for this incident ID");
  };

  const downloadReport = () => {
    if (!report) return;
    const blob = new Blob([report.report], { type:"text/plain" });
    const a = document.createElement("a"); a.href = URL.createObjectURL(blob);
    a.download = `Evidence_Report_${incidentId}.txt`; a.click();
  };

  const TYPE_ICONS: Record<string,string> = {
    screenshot:"📸", url_archive:"🔗", email_export:"📧", file:"📄",
    log_export:"📋", network_capture:"🌐", chat_export:"💬",
    financial_record:"💰", other:"📦",
  };

  return (
    <div className="min-h-full py-10 px-6" style={{ background:"var(--bg-base)" }}>
      <div className="max-w-5xl mx-auto">
        <motion.div initial={{ opacity:0,y:16 }} animate={{ opacity:1,y:0 }} className="mb-8">
          <div className="tag-blue inline-flex mb-3"><Lock className="size-3" /> EVIDENCE VAULT</div>
          <div className="flex items-start justify-between flex-wrap gap-4">
            <div>
              <h1 className="font-display text-4xl mb-1.5" style={{ color:"var(--text-primary)" }}>
                Digital Evidence Vault
              </h1>
              <p style={{ color:"var(--text-muted)", fontSize:14 }}>
                SHA-256 integrity · Chain of custody · Court-admissible evidence reports · {total} items
              </p>
            </div>
            <div className="flex gap-2">
              <button onClick={fetchData} className="btn-ghost flex items-center gap-2 px-3.5 py-2 text-sm">
                <RefreshCw className="size-4" />
              </button>
              {canWrite && (
                <button onClick={() => setShowAdd(true)}
                        className="flex items-center gap-2 px-4 py-2 rounded-xl text-sm font-semibold"
                        style={{ background:"var(--accent)", color:"#fff" }}>
                  <Plus className="size-4" /> Add Evidence
                </button>
              )}
            </div>
          </div>
        </motion.div>

        {/* Evidence type stats panel */}
        {Object.keys(stats).length > 0 && (
          <div className="card p-5 mb-6">
            <div className="text-xs font-semibold uppercase tracking-wider mb-3"
                 style={{ color:"var(--text-muted)", fontFamily:"var(--font-mono)" }}>
              Evidence by Type
            </div>
            <div className="space-y-2">
              {EVIDENCE_TYPES.filter(t => (stats[t] || 0) > 0).map(t => {
                const count = stats[t] || 0;
                const max   = Math.max(...Object.values(stats));
                const pct   = max > 0 ? (count / max) * 100 : 0;
                const col   = TYPE_COLORS[t] || "#94a3b8";
                return (
                  <div key={t} className="flex items-center gap-3">
                    <span className="text-[10px] w-28 shrink-0 capitalize" style={{ color:"var(--text-muted)" }}>
                      {t.replace(/_/g," ")}
                    </span>
                    <div className="flex-1 rounded-full overflow-hidden" style={{ height:6, background:"var(--bg-border)" }}>
                      <div className="h-full rounded-full transition-all"
                           style={{ width:`${pct}%`, background: col }} />
                    </div>
                    <span className="text-[10px] w-6 text-right font-bold" style={{ color: col, fontFamily:"var(--font-mono)" }}>
                      {count}
                    </span>
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {/* Report generator */}
        <div className="card p-5 mb-6">
          <div className="text-sm font-semibold mb-3" style={{ color:"var(--text-primary)" }}>
            Generate Chain of Custody Report
          </div>
          <div className="flex gap-2">
            <input value={incidentId} onChange={e => setIncidentId(e.target.value)}
                   placeholder="Incident ID (e.g. INC-ABC123)"
                   className="flex-1 px-3 py-2 rounded-xl text-sm"
                   style={{ background:"var(--bg-elevated)", border:"1px solid var(--bg-border)", color:"var(--text-primary)", outline:"none" }} />
            <button onClick={generateReport}
                    className="flex items-center gap-1.5 px-4 py-2 rounded-xl text-sm font-semibold"
                    style={{ background:"var(--accent)", color:"#fff" }}>
              <FileText className="size-4" /> Generate
            </button>
          </div>
          {report && (
            <div className="mt-3 flex items-center gap-2">
              <CheckCircle className="size-4 flex-shrink-0" style={{ color:"var(--safe)" }} />
              <span className="text-xs" style={{ color:"var(--safe)" }}>{report.itemCount} evidence items found</span>
              <button onClick={downloadReport}
                      className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs ml-2"
                      style={{ background:"var(--accent-subtle)", color:"var(--accent)", border:"1px solid var(--accent-border)" }}>
                <Download className="size-3.5" /> Download Report
              </button>
            </div>
          )}
        </div>

        {error && (
          <div className="flex items-center gap-2 px-4 py-2.5 rounded-xl mb-4"
               style={{ background:"rgba(248,113,113,0.08)", border:"1px solid rgba(248,113,113,0.2)" }}>
            <AlertTriangle className="size-4" style={{ color:"var(--color-danger)" }} />
            <span className="text-xs flex-1" style={{ color:"var(--color-danger)" }}>{error}</span>
            <button onClick={() => setError(null)} style={{ background:"none",border:"none",cursor:"pointer",color:"var(--text-muted)" }}>✕</button>
          </div>
        )}

        {/* Filter */}
        <div className="flex gap-1 p-1 rounded-xl mb-4 flex-wrap"
             style={{ background:"var(--bg-elevated)", border:"1px solid var(--bg-border)" }}>
          {["all",...EVIDENCE_TYPES].map(t => (
            <button key={t} onClick={() => setFilterType(t)}
                    className="px-3 py-1.5 rounded-lg text-xs capitalize transition-all"
                    style={{
                      background: filterType===t ? "var(--accent-subtle)" : "transparent",
                      color:      filterType===t ? "var(--accent)" : "var(--text-muted)",
                    }}>
              {t==="all" ? "All" : t.replace(/_/g," ")}
            </button>
          ))}
        </div>

        {/* Evidence list */}
        {loading ? (
          <div className="flex items-center justify-center py-20">
            <RefreshCw className="size-6 animate-spin" style={{ color:"var(--text-muted)" }} />
          </div>
        ) : evidence.length === 0 ? (
          <div className="text-center py-20">
            <Lock className="size-12 mx-auto mb-3" style={{ color:"var(--text-muted)" }} />
            <p className="text-sm" style={{ color:"var(--text-muted)" }}>No evidence items yet</p>
            <p className="text-xs mt-1" style={{ color:"var(--text-muted)" }}>
              Evidence is auto-collected from phishing scans and can be added manually
            </p>
          </div>
        ) : (
          <div className="card overflow-hidden">
            <div className="divide-y" style={{ borderColor:"var(--bg-border)" }}>
              {evidence.map((ev:any) => {
                const hashStatus = verified[ev._id];   // true | false | undefined
                const typeCol    = TYPE_COLORS[ev.type] || "#94a3b8";
                return (
                  <div key={ev._id} className="px-5 py-4 flex items-start gap-3"
                       style={{ borderLeft:`3px solid ${typeCol}30` }}>
                    <span className="text-xl flex-shrink-0 mt-0.5">{TYPE_ICONS[ev.type]||"📦"}</span>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-0.5 flex-wrap">
                        <span className="text-xs font-bold" style={{ color:"var(--accent)", fontFamily:"var(--font-mono)" }}>
                          {ev.evidenceId}
                        </span>
                        <span className="text-[9px] px-1.5 py-0.5 rounded capitalize"
                              style={{ color: typeCol, background:`${typeCol}12`, border:`1px solid ${typeCol}30`, fontFamily:"var(--font-mono)" }}>
                          {ev.type?.replace(/_/g," ")}
                        </span>
                        {ev.admissible && (
                          <span className="text-[9px] px-1.5 py-0.5 rounded"
                                style={{ color:"var(--safe)", background:"rgba(52,211,153,0.08)", border:"1px solid rgba(52,211,153,0.2)", fontFamily:"var(--font-mono)" }}>
                            ADMISSIBLE
                          </span>
                        )}
                        {/* Hash verification badge */}
                        {hashStatus === true  && (
                          <span className="flex items-center gap-1 text-[9px] px-1.5 py-0.5 rounded"
                                style={{ color:"var(--safe)", background:"rgba(52,211,153,0.08)", border:"1px solid rgba(52,211,153,0.2)" }}>
                            <ShieldCheck className="size-2.5" /> HASH OK
                          </span>
                        )}
                        {hashStatus === false && (
                          <span className="flex items-center gap-1 text-[9px] px-1.5 py-0.5 rounded"
                                style={{ color:"#f87171", background:"rgba(248,113,113,0.08)", border:"1px solid rgba(248,113,113,0.2)" }}>
                            <AlertTriangle className="size-2.5" /> HASH MISMATCH
                          </span>
                        )}
                      </div>

                      <div className="font-medium text-sm" style={{ color:"var(--text-primary)" }}>{ev.title}</div>

                      {ev.source && (
                        <div className="text-xs mt-0.5 truncate" style={{ color:"var(--accent)", fontFamily:"var(--font-mono)" }}>
                          {ev.source}
                        </div>
                      )}

                      {ev.sha256Hash && (
                        <div className="flex items-center gap-2 mt-1">
                          <Hash className="size-3 flex-shrink-0" style={{ color:"var(--text-muted)" }} />
                          <span className="text-[10px] truncate" style={{ color:"var(--text-muted)", fontFamily:"var(--font-mono)" }}>
                            {ev.sha256Hash}
                          </span>
                          {canWrite && (
                            <button
                              onClick={() => verifyHash(ev)}
                              disabled={verifying === ev._id}
                              className="flex-shrink-0 flex items-center gap-1 px-1.5 py-0.5 rounded text-[9px] font-semibold"
                              style={{ background:"var(--accent-subtle)", color:"var(--accent)", border:"1px solid var(--accent-border)", opacity: verifying===ev._id ? 0.5 : 1 }}>
                              {verifying === ev._id
                                ? <RefreshCw className="size-2.5 animate-spin" />
                                : <ShieldCheck className="size-2.5" />}
                              {verifying === ev._id ? "Verifying…" : "Verify"}
                            </button>
                          )}
                        </div>
                      )}

                      <div className="flex items-center gap-3 mt-1 text-[10px]" style={{ color:"var(--text-muted)" }}>
                        <span>By: {ev.collectedBy}</span>
                        <span>{new Date(ev.collectedAt).toLocaleString()}</span>
                        {ev.toolUsed && <span>{ev.toolUsed}</span>}
                        {ev.tags?.length > 0 && (
                          <span>{ev.tags.slice(0,3).join(", ")}</span>
                        )}
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {/* Add evidence modal */}
        <AnimatePresence>
          {showAdd && (
            <motion.div initial={{ opacity:0 }} animate={{ opacity:1 }} exit={{ opacity:0 }}
                        className="fixed inset-0 flex items-center justify-center z-50 px-4"
                        style={{ background:"rgba(0,0,0,0.7)", backdropFilter:"blur(4px)" }}>
              <motion.div initial={{ scale:0.95 }} animate={{ scale:1 }} exit={{ scale:0.95 }}
                          className="card-glass p-6 max-w-lg w-full rounded-2xl max-h-[90vh] overflow-y-auto">
                <h3 className="font-bold text-xl mb-4" style={{ color:"var(--text-primary)" }}>Add Evidence Item</h3>
                <div className="space-y-3">
                  <select value={form.type} onChange={e => setForm(f=>({...f,type:e.target.value}))}
                          className="w-full px-3 py-2 rounded-xl text-sm"
                          style={{ background:"var(--bg-elevated)", border:"1px solid var(--bg-border)", color:"var(--text-secondary)" }}>
                    {EVIDENCE_TYPES.map(t => <option key={t} value={t}>{t.replace(/_/g," ")}</option>)}
                  </select>
                  <input value={form.title} onChange={e => setForm(f=>({...f,title:e.target.value}))}
                         placeholder="Evidence title"
                         className="w-full px-3 py-2.5 rounded-xl text-sm"
                         style={{ background:"var(--bg-elevated)", border:"1px solid var(--bg-border)", color:"var(--text-primary)", outline:"none" }} />
                  <input value={form.source} onChange={e => setForm(f=>({...f,source:e.target.value}))}
                         placeholder="Source URL / file path / device"
                         className="w-full px-3 py-2.5 rounded-xl text-sm"
                         style={{ background:"var(--bg-elevated)", border:"1px solid var(--bg-border)", color:"var(--text-primary)", outline:"none" }} />
                  <textarea value={form.description} onChange={e => setForm(f=>({...f,description:e.target.value}))}
                            placeholder="Description / notes..." rows={3} className="w-full px-3 py-2.5 rounded-xl text-sm resize-none"
                            style={{ background:"var(--bg-elevated)", border:"1px solid var(--bg-border)", color:"var(--text-primary)", outline:"none" }} />
                  <div className="grid grid-cols-2 gap-3">
                    <input value={form.incidentId} onChange={e => setForm(f=>({...f,incidentId:e.target.value}))}
                           placeholder="Incident ID (optional)"
                           className="px-3 py-2 rounded-xl text-sm"
                           style={{ background:"var(--bg-elevated)", border:"1px solid var(--bg-border)", color:"var(--text-primary)", outline:"none" }} />
                    <input value={form.complaintId} onChange={e => setForm(f=>({...f,complaintId:e.target.value}))}
                           placeholder="Complaint ID (optional)"
                           className="px-3 py-2 rounded-xl text-sm"
                           style={{ background:"var(--bg-elevated)", border:"1px solid var(--bg-border)", color:"var(--text-primary)", outline:"none" }} />
                  </div>
                  <input value={form.tags} onChange={e => setForm(f=>({...f,tags:e.target.value}))}
                         placeholder="Tags (comma-separated)"
                         className="w-full px-3 py-2 rounded-xl text-sm"
                         style={{ background:"var(--bg-elevated)", border:"1px solid var(--bg-border)", color:"var(--text-primary)", outline:"none" }} />
                </div>
                {error && <p className="text-xs mt-2" style={{ color:"var(--color-danger)" }}>{error}</p>}
                <div className="flex gap-2 justify-end mt-4">
                  <button onClick={() => { setShowAdd(false); setError(null); }}
                          className="px-4 py-2 rounded-xl text-sm"
                          style={{ background:"var(--bg-elevated)", color:"var(--text-secondary)", border:"1px solid var(--bg-border)" }}>Cancel</button>
                  <button onClick={addEvidence}
                          className="px-5 py-2 rounded-xl text-sm font-semibold"
                          style={{ background:"var(--accent)", color:"#fff" }}>Add Evidence</button>
                </div>
              </motion.div>
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </div>
  );
}
