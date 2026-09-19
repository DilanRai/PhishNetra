// FILE: src/pages/CyberComplaint.tsx
import { useState, useEffect, useCallback } from "react";
import { motion, AnimatePresence } from "motion/react";
import {
  FileText, Plus, Search, AlertTriangle, CheckCircle,
  RefreshCw, Download, ChevronDown, ChevronUp, Phone,
  Globe, CreditCard, User, MapPin, Calendar, Filter
} from "lucide-react";
import { useRole } from "../hooks/useRole";
import { API_BASE } from "../config";

const authHeader = () => ({
  "Content-Type": "application/json",
  Authorization: `Bearer ${localStorage.getItem("pg_token")}`,
});

const FRAUD_TYPES = [
  { value:"upi_fraud",           label:"UPI / Digital Payment Fraud" },
  { value:"bank_fraud",          label:"Bank Account / Net Banking Fraud" },
  { value:"investment_scam",     label:"Investment / Stock Market Scam" },
  { value:"job_scam",            label:"Job / Part-Time Work Scam" },
  { value:"romance_scam",        label:"Romance / Dating Scam" },
  { value:"sextortion",          label:"Sextortion / Blackmail" },
  { value:"ransomware",          label:"Ransomware Attack" },
  { value:"govt_impersonation",  label:"Government / Official Impersonation" },
  { value:"police_impersonation",label:"Police / CBI / Digital Arrest Scam" },
  { value:"courier_scam",        label:"Courier / Package Fraud" },
  { value:"electricity_scam",    label:"Electricity Bill Scam" },
  { value:"lottery_scam",        label:"Lottery / Prize Scam" },
  { value:"phishing",            label:"Phishing / Fake Website" },
  { value:"vishing",             label:"Vishing (Phone Call Fraud)" },
  { value:"smishing",            label:"Smishing (SMS Fraud)" },
  { value:"fake_ecommerce",      label:"Fake E-Commerce / Online Shopping" },
  { value:"aadhaar_fraud",       label:"Aadhaar OTP / Biometric Fraud" },
  { value:"sim_swap",            label:"SIM Swap Fraud" },
  { value:"cyber_bullying",      label:"Cyber Bullying / Harassment" },
  { value:"online_gaming_fraud", label:"Online Gaming / Fantasy App Fraud" },
  { value:"insurance_fraud",     label:"Fake Insurance Fraud" },
  { value:"tech_support_scam",   label:"Fake Tech Support Scam" },
  { value:"other",               label:"Other" },
];

const SEV_COLOR = (s: number) =>
  s >= 80 ? "#f87171" : s >= 60 ? "#fb923c" : s >= 40 ? "#fbbf24" : "#60a5fa";
const SEV_LABEL = (s: number) =>
  s >= 80 ? "CRITICAL" : s >= 60 ? "HIGH" : s >= 40 ? "MEDIUM" : "LOW";

const STATUS_COLORS: Record<string,string> = {
  new:"#60a5fa", investigating:"#fbbf24", escalated:"#f87171",
  resolved:"#34d399", closed:"#64748b",
};
const PRIORITY_COLORS: Record<string,string> = {
  low:"#64748b", medium:"#60a5fa", high:"#fbbf24", critical:"#f87171",
};

export default function CyberComplaint() {
  const { canWrite } = useRole();
  const [complaints, setComplaints]   = useState<any[]>([]);
  const [stats,      setStats]        = useState<any>(null);
  const [loading,    setLoading]      = useState(true);
  const [showForm,   setShowForm]     = useState(false);
  const [expanded,   setExpanded]     = useState<string|null>(null);
  const [search,     setSearch]       = useState("");
  const [filterStatus,setFilterStatus]= useState("all");
  const [filterType, setFilterType]   = useState("all");
  const [total,      setTotal]        = useState(0);
  const [submitting, setSubmitting]   = useState(false);
  const [submitResult,setSubmitResult]= useState<any>(null);
  const [error,      setError]        = useState<string|null>(null);
  const [ncrpDraft,  setNcrpDraft]    = useState<{id:string,draft:string}|null>(null);

  // Form state
  const [form, setForm] = useState({
    description:"", victimName:"", victimState:"", victimCity:"",
    victimContact:"", amountLost:"", currency:"INR",
    paymentMethod:"unknown", incidentDate:"",
  });

  const fetchData = useCallback(async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams({
        ...(filterStatus !== "all" ? { status: filterStatus } : {}),
        ...(filterType   !== "all" ? { fraudType: filterType } : {}),
        ...(search ? { search } : {}),
        limit:"50",
      });
      const [listRes, statsRes] = await Promise.all([
        fetch(`${API_BASE}/api/complaints?${params}`, { headers: authHeader() }),
        fetch(`${API_BASE}/api/complaints/stats`,     { headers: authHeader() }),
      ]);
      if (listRes.ok)  { const d = await listRes.json();  setComplaints(d.complaints||[]); setTotal(d.total||0); }
      if (statsRes.ok) setStats(await statsRes.json());
    } catch {}
    finally { setLoading(false); }
  }, [filterStatus, filterType, search]);

  useEffect(() => { fetchData(); }, [fetchData]);

  const handleSubmit = async () => {
    if (!form.description.trim()) { setError("Description is required"); return; }
    setSubmitting(true); setError(null);
    try {
      const res = await fetch(`${API_BASE}/api/complaints`, {
        method:"POST", headers: authHeader(),
        body: JSON.stringify({ ...form, amountLost: parseFloat(form.amountLost)||0 }),
      });
      if (!res.ok) { const d = await res.json(); throw new Error(d.error||"Submission failed"); }
      const data = await res.json();
      setSubmitResult(data);
      setShowForm(false);
      setForm({ description:"",victimName:"",victimState:"",victimCity:"",victimContact:"",amountLost:"",currency:"INR",paymentMethod:"unknown",incidentDate:"" });
      fetchData();
    } catch (err:any) { setError(err.message); }
    finally { setSubmitting(false); }
  };

  const fetchNCRPDraft = async (id:string) => {
    const res = await fetch(`${API_BASE}/api/complaints/${id}/ncrp-draft`, { headers: authHeader() });
    if (res.ok) { const d = await res.json(); setNcrpDraft({ id, draft:d.draft }); }
  };

  const updateStatus = async (id:string, status:string) => {
    await fetch(`${API_BASE}/api/complaints/${id}/status`, {
      method:"PATCH", headers: authHeader(), body: JSON.stringify({ status }),
    });
    fetchData();
  };

  const downloadDraft = () => {
    if (!ncrpDraft) return;
    const blob = new Blob([ncrpDraft.draft], { type:"text/plain" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `NCRP_Draft_${ncrpDraft.id}.txt`;
    a.click();
  };

  return (
    <div className="min-h-full py-10 px-6" style={{ background:"var(--bg-base)" }}>
      <div className="max-w-6xl mx-auto">

        {/* Header */}
        <motion.div initial={{ opacity:0,y:16 }} animate={{ opacity:1,y:0 }} className="mb-8">
          <div className="tag-red inline-flex mb-3"><FileText className="size-3" /> CYBERCRIME INTELLIGENCE</div>
          <div className="flex items-start justify-between flex-wrap gap-4">
            <div>
              <h1 className="font-display text-4xl mb-1.5" style={{ color:"var(--text-primary)" }}>
                Cybercrime Complaint Intelligence
              </h1>
              <p style={{ color:"var(--text-muted)", fontSize:14 }}>
                File, classify, and track cybercrime complaints · Auto-generates NCRP report · {total} complaints
              </p>
            </div>
            <div className="flex gap-2">
              <button onClick={fetchData} className="btn-ghost flex items-center gap-2 px-3.5 py-2 text-sm">
                <RefreshCw className="size-4" /> Refresh
              </button>
              {canWrite && (
                <button onClick={() => setShowForm(true)}
                        className="flex items-center gap-2 px-4 py-2 rounded-xl text-sm font-semibold"
                        style={{ background:"var(--color-danger)", color:"#fff" }}>
                  <Plus className="size-4" /> File Complaint
                </button>
              )}
            </div>
          </div>
        </motion.div>

        {/* Stats */}
        {stats && (
          <div className="grid grid-cols-2 md:grid-cols-6 gap-3 mb-4">
            {[
              { label:"Total Cases",  value:stats.total,                                                color:"var(--accent)"  },
              { label:"New",          value:stats.byStatus?.new||0,                                     color:"#60a5fa"        },
              { label:"Investigating",value:stats.byStatus?.investigating||0,                           color:"#fbbf24"        },
              { label:"Critical",     value:stats.byPriority?.critical||0,                              color:"#f87171"        },
              { label:"Total Losses", value:`₹${((stats.financial?.totalLost||0)/100000).toFixed(1)}L`, color:"#f87171"        },
              { label:"Last 7 Days",  value:stats.recent7d||0,                                          color:"var(--safe)"    },
            ].map(s => (
              <div key={s.label} className="card p-4 stat-card">
                <div className="text-xl font-bold font-display" style={{ color:s.color }}>{s.value}</div>
                <div className="label-caps mt-1">{s.label}</div>
              </div>
            ))}
          </div>
        )}

        {/* Top fraud types + top states */}
        {stats?.byType?.length > 0 && (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
            <div className="card p-4">
              <div className="label-caps mb-3">Top Fraud Types</div>
              <div className="space-y-1.5">
                {stats.byType.slice(0,6).map((t:any) => {
                  const maxCount = stats.byType[0]?.count || 1;
                  return (
                    <div key={t.type} className="flex items-center gap-2">
                      <span className="text-[10px] w-32 truncate" style={{ color:"var(--text-muted)" }}>
                        {t.type.replace(/_/g," ")}
                      </span>
                      <div className="flex-1 rounded-full overflow-hidden" style={{ height:6, background:"var(--bg-border)" }}>
                        <div className="h-full rounded-full" style={{ width:`${(t.count/maxCount)*100}%`, background:"#f87171" }} />
                      </div>
                      <span className="text-[10px] w-8 text-right font-bold" style={{ color:"var(--accent)", fontFamily:"var(--font-mono)" }}>{t.count}</span>
                      {t.totalLost > 0 && (
                        <span className="text-[10px] w-14 text-right" style={{ color:"#f87171", fontFamily:"var(--font-mono)" }}>
                          ₹{(t.totalLost/1000).toFixed(0)}K
                        </span>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
            {stats?.topStates?.length > 0 && (
              <div className="card p-4">
                <div className="label-caps mb-3">Top Affected States</div>
                <div className="space-y-1.5">
                  {stats.topStates.slice(0,6).map((s:any) => {
                    const maxCount = stats.topStates[0]?.count || 1;
                    return (
                      <div key={s.state} className="flex items-center gap-2">
                        <span className="text-[10px] w-28 truncate" style={{ color:"var(--text-muted)" }}>{s.state}</span>
                        <div className="flex-1 rounded-full overflow-hidden" style={{ height:6, background:"var(--bg-border)" }}>
                          <div className="h-full rounded-full" style={{ width:`${(s.count/maxCount)*100}%`, background:"#60a5fa" }} />
                        </div>
                        <span className="text-[10px] w-8 text-right font-bold" style={{ color:"var(--accent)", fontFamily:"var(--font-mono)" }}>{s.count}</span>
                      </div>
                    );
                  })}
                </div>
              </div>
            )}
          </div>
        )}

        {/* Error */}
        {error && (
          <div className="flex items-center gap-2 px-4 py-2.5 rounded-xl mb-4"
               style={{ background:"rgba(248,113,113,0.08)", border:"1px solid rgba(248,113,113,0.2)" }}>
            <AlertTriangle className="size-4" style={{ color:"var(--color-danger)" }} />
            <span className="text-xs flex-1" style={{ color:"var(--color-danger)" }}>{error}</span>
            <button onClick={() => setError(null)} style={{ background:"none",border:"none",cursor:"pointer",color:"var(--text-muted)" }}>✕</button>
          </div>
        )}

        {/* Success banner */}
        {submitResult && (
          <motion.div initial={{ opacity:0,y:-8 }} animate={{ opacity:1,y:0 }}
                      className="card p-5 mb-6"
                      style={{ background:"rgba(52,211,153,0.07)", border:"1px solid rgba(52,211,153,0.2)" }}>
            <div className="flex items-center gap-2 mb-2">
              <CheckCircle className="size-5" style={{ color:"var(--safe)" }} />
              <span className="font-semibold text-sm" style={{ color:"var(--safe)" }}>
                Complaint Filed: {submitResult.complaint?.complaintId}
              </span>
            </div>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs mb-3">
              <div><span style={{ color:"var(--text-muted)" }}>Classified As:</span> <strong style={{ color:"var(--text-primary)" }}>{submitResult.classification?.type?.replace(/_/g," ")}</strong></div>
              <div><span style={{ color:"var(--text-muted)" }}>Confidence:</span> <strong style={{ color:"var(--accent)" }}>{submitResult.classification?.confidence}%</strong></div>
              <div><span style={{ color:"var(--text-muted)" }}>Priority:</span> <strong style={{ color:PRIORITY_COLORS[submitResult.complaint?.priority] }}>{submitResult.complaint?.priority}</strong></div>
              <div><span style={{ color:"var(--text-muted)" }}>Related:</span> <strong style={{ color:"#fbbf24" }}>{submitResult.relatedComplaints?.length||0} similar</strong></div>
            </div>
            {/* IOCs extracted */}
            {Object.values(submitResult.iocs||{}).some((v:any) => v.length>0) && (
              <div className="mb-3">
                <div className="label-caps mb-1">Extracted IOCs</div>
                <div className="flex flex-wrap gap-1.5">
                  {(submitResult.iocs?.upiIds||[]).map((u:string) => <span key={u} className="text-[10px] px-2 py-0.5 rounded" style={{ background:"rgba(251,191,36,0.1)", color:"#fbbf24", fontFamily:"var(--font-mono)" }}>UPI: {u}</span>)}
                  {(submitResult.iocs?.phones||[]).map((p:string) => <span key={p} className="text-[10px] px-2 py-0.5 rounded" style={{ background:"rgba(96,165,250,0.1)", color:"#60a5fa", fontFamily:"var(--font-mono)" }}>📞 {p}</span>)}
                  {(submitResult.iocs?.urls||[]).map((u:string) => <span key={u} className="text-[10px] px-2 py-0.5 rounded truncate max-w-xs" style={{ background:"rgba(248,113,113,0.1)", color:"#f87171", fontFamily:"var(--font-mono)" }}>🔗 {u}</span>)}
                </div>
              </div>
            )}
            <div className="flex gap-2">
              <button onClick={() => fetchNCRPDraft(submitResult.complaint?._id)}
                      className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs"
                      style={{ background:"var(--accent-subtle)", color:"var(--accent)", border:"1px solid var(--accent-border)" }}>
                <Download className="size-3.5" /> Generate NCRP Draft
              </button>
              <button onClick={() => setSubmitResult(null)}
                      className="text-xs" style={{ color:"var(--text-muted)", background:"none", border:"none", cursor:"pointer" }}>
                Dismiss
              </button>
            </div>
          </motion.div>
        )}

        {/* NCRP Draft modal */}
        <AnimatePresence>
          {ncrpDraft && (
            <motion.div initial={{ opacity:0 }} animate={{ opacity:1 }} exit={{ opacity:0 }}
                        className="fixed inset-0 flex items-center justify-center z-50 px-4"
                        style={{ background:"rgba(0,0,0,0.7)", backdropFilter:"blur(4px)" }}>
              <motion.div initial={{ scale:0.95 }} animate={{ scale:1 }} exit={{ scale:0.95 }}
                          className="card-glass p-6 max-w-2xl w-full rounded-2xl max-h-[80vh] overflow-hidden flex flex-col">
                <div className="flex items-center justify-between mb-4">
                  <h3 className="font-bold text-lg" style={{ color:"var(--text-primary)" }}>NCRP Complaint Draft</h3>
                  <div className="flex gap-2">
                    <button onClick={downloadDraft}
                            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs"
                            style={{ background:"var(--accent)", color:"#fff" }}>
                      <Download className="size-3.5" /> Download
                    </button>
                    <button onClick={() => setNcrpDraft(null)}
                            className="text-xs px-3 py-1.5 rounded-lg"
                            style={{ background:"var(--bg-elevated)", color:"var(--text-muted)", border:"1px solid var(--bg-border)" }}>
                      Close
                    </button>
                  </div>
                </div>
                <pre className="flex-1 overflow-y-auto text-xs leading-relaxed p-4 rounded-xl"
                     style={{ background:"var(--bg-base)", color:"var(--text-secondary)",
                              fontFamily:"var(--font-mono)", whiteSpace:"pre-wrap" }}>
                  {ncrpDraft.draft}
                </pre>
                <div className="mt-3 flex items-center gap-2 text-xs" style={{ color:"#60a5fa" }}>
                  <Globe className="size-3.5" />
                  Submit at: <a href="https://cybercrime.gov.in" target="_blank" rel="noreferrer"
                               style={{ color:"#60a5fa", textDecoration:"underline" }}>cybercrime.gov.in</a>
                  <span style={{ color:"var(--text-muted)" }}>· Helpline: 1930</span>
                </div>
              </motion.div>
            </motion.div>
          )}
        </AnimatePresence>

        {/* Filters */}
        <div className="flex gap-3 mb-4 flex-wrap">
          <div className="relative flex-1 min-w-48">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 size-4" style={{ color:"var(--text-muted)" }} />
            <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search complaints..."
                   className="w-full pl-9 pr-4 py-2 rounded-xl text-sm"
                   style={{ background:"var(--bg-elevated)", border:"1px solid var(--bg-border)", color:"var(--text-primary)", outline:"none" }} />
          </div>
          <select value={filterStatus} onChange={e => setFilterStatus(e.target.value)}
                  className="text-xs px-3 py-2 rounded-xl"
                  style={{ background:"var(--bg-elevated)", border:"1px solid var(--bg-border)", color:"var(--text-secondary)" }}>
            <option value="all">All Status</option>
            {["new","investigating","escalated","resolved","closed"].map(s => (
              <option key={s} value={s}>{s}</option>
            ))}
          </select>
          <select value={filterType} onChange={e => setFilterType(e.target.value)}
                  className="text-xs px-3 py-2 rounded-xl"
                  style={{ background:"var(--bg-elevated)", border:"1px solid var(--bg-border)", color:"var(--text-secondary)" }}>
            <option value="all">All Types</option>
            {FRAUD_TYPES.map(t => <option key={t.value} value={t.value}>{t.label}</option>)}
          </select>
        </div>

        {/* Complaint list */}
        {loading ? (
          <div className="flex items-center justify-center py-20">
            <RefreshCw className="size-6 animate-spin" style={{ color:"var(--text-muted)" }} />
          </div>
        ) : complaints.length === 0 ? (
          <div className="text-center py-20">
            <FileText className="size-12 mx-auto mb-3" style={{ color:"var(--text-muted)" }} />
            <p className="text-sm" style={{ color:"var(--text-muted)" }}>No complaints filed yet</p>
          </div>
        ) : (
          <div className="space-y-2">
            {complaints.map((c:any) => {
              const sc  = STATUS_COLORS[c.status]||"#64748b";
              const pc  = PRIORITY_COLORS[c.priority]||"#64748b";
              const sev = c.severityScore || 0;
              const exp = expanded === c._id;
              const totalIocs = Object.values(c.iocs||{}).reduce((a:number,v:any)=>a+(v?.length||0),0) as number;
              return (
                <div key={c._id} className="card overflow-hidden"
                     style={{ borderLeft: sev >= 80 ? "3px solid #f87171" : sev >= 60 ? "3px solid #fb923c" : undefined }}>
                  <div className="px-5 py-4 flex items-center gap-3 cursor-pointer"
                       onClick={() => setExpanded(exp ? null : c._id)}>
                    <div className="w-2 h-2 rounded-full flex-shrink-0" style={{ background:sc }} />
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-0.5 flex-wrap">
                        <span className="text-xs font-bold" style={{ color:"var(--accent)", fontFamily:"var(--font-mono)" }}>{c.complaintId}</span>
                        <span className="text-xs px-1.5 py-0.5 rounded uppercase font-bold"
                              style={{ color:sc, background:`${sc}12`, border:`1px solid ${sc}25`, fontFamily:"var(--font-mono)" }}>
                          {c.status}
                        </span>
                        <span className="text-xs px-1.5 py-0.5 rounded uppercase font-bold"
                              style={{ color:pc, background:`${pc}12`, border:`1px solid ${pc}25`, fontFamily:"var(--font-mono)" }}>
                          {c.priority}
                        </span>
                        {sev > 0 && (
                          <span className="text-[10px] px-1.5 py-0.5 rounded font-bold"
                                style={{ color:SEV_COLOR(sev), background:`${SEV_COLOR(sev)}12`, border:`1px solid ${SEV_COLOR(sev)}25`, fontFamily:"var(--font-mono)" }}>
                            SEV: {sev}
                          </span>
                        )}
                        <span className="text-xs" style={{ color:"var(--text-muted)" }}>
                          {c.fraudType?.replace(/_/g," ")}
                        </span>
                        {totalIocs > 0 && (
                          <span className="text-[10px] px-1.5 py-0.5 rounded"
                                style={{ color:"#a78bfa", background:"rgba(167,139,250,0.08)", fontFamily:"var(--font-mono)" }}>
                            {totalIocs} IOC{totalIocs>1?"s":""}
                          </span>
                        )}
                      </div>
                      <p className="text-sm truncate" style={{ color:"var(--text-secondary)" }}>
                        {c.description?.substring(0,120)}...
                      </p>
                    </div>
                    <div className="flex-shrink-0 text-right">
                      {c.amountLost > 0 && (
                        <div className="text-sm font-bold" style={{ color:"#f87171", fontFamily:"var(--font-mono)" }}>
                          ₹{c.amountLost.toLocaleString("en-IN")}
                        </div>
                      )}
                      <div className="text-xs mt-0.5" style={{ color:"var(--text-muted)", fontFamily:"var(--font-mono)" }}>
                        {new Date(c.createdAt).toLocaleDateString("en-IN")}
                      </div>
                    </div>
                    {exp ? <ChevronUp className="size-4 flex-shrink-0" style={{ color:"var(--text-muted)" }} /> :
                           <ChevronDown className="size-4 flex-shrink-0" style={{ color:"var(--text-muted)" }} />}
                  </div>

                  <AnimatePresence>
                    {exp && (
                      <motion.div initial={{ height:0 }} animate={{ height:"auto" }} exit={{ height:0 }}
                                  style={{ overflow:"hidden" }}>
                        <div className="px-5 pb-4 border-t" style={{ borderColor:"var(--bg-border)" }}>
                          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mt-3 text-xs mb-4">
                            {[
                              ["Victim",    c.victimName||"Anonymous",                User],
                              ["Location",  `${c.victimCity||""}${c.victimState?", "+c.victimState:""}`.trim()||"—", MapPin],
                              ["Payment",   c.paymentMethod,                           CreditCard],
                              ["Incident",  new Date(c.incidentDate).toLocaleDateString("en-IN"), Calendar],
                            ].map(([label,value,Icon]:any) => (
                              <div key={label}>
                                <div className="label-caps mb-1">{label}</div>
                                <div className="flex items-center gap-1.5" style={{ color:"var(--text-secondary)" }}>
                                  <Icon className="size-3 flex-shrink-0" />
                                  {value}
                                </div>
                              </div>
                            ))}
                          </div>

                          {/* Severity score bar */}
                          {sev > 0 && (
                            <div className="mb-3">
                              <div className="flex items-center justify-between mb-1">
                                <span className="label-caps">Severity Score</span>
                                <span className="text-xs font-bold" style={{ color:SEV_COLOR(sev), fontFamily:"var(--font-mono)" }}>
                                  {sev}/100 — {SEV_LABEL(sev)}
                                </span>
                              </div>
                              <div className="rounded-full overflow-hidden" style={{ height:5, background:"var(--bg-border)" }}>
                                <div className="h-full rounded-full transition-all" style={{ width:`${sev}%`, background:SEV_COLOR(sev) }} />
                              </div>
                              {c.slaDeadlineHours && (
                                <div className="text-[10px] mt-1" style={{ color:"var(--text-muted)" }}>
                                  SLA: Resolve within {c.slaDeadlineHours}h of report
                                </div>
                              )}
                            </div>
                          )}

                          {/* IOCs — enhanced display */}
                          {totalIocs > 0 && (
                            <div className="mb-3">
                              <div className="label-caps mb-2">Extracted IOCs ({totalIocs} indicators)</div>
                              <div className="flex flex-wrap gap-1.5">
                                {c.iocs?.upiIds?.map((u:string)    => <span key={u} className="text-[10px] px-2 py-0.5 rounded" style={{ color:"#fbbf24",background:"rgba(251,191,36,0.08)",border:"1px solid rgba(251,191,36,0.2)",fontFamily:"var(--font-mono)" }}>UPI: {u}</span>)}
                                {c.iocs?.phones?.map((p:string)    => <span key={p} className="text-[10px] px-2 py-0.5 rounded" style={{ color:"#60a5fa",background:"rgba(96,165,250,0.08)",border:"1px solid rgba(96,165,250,0.2)",fontFamily:"var(--font-mono)" }}>📞 {p}</span>)}
                                {c.iocs?.emails?.map((e:string)    => <span key={e} className="text-[10px] px-2 py-0.5 rounded" style={{ color:"#a78bfa",background:"rgba(167,139,250,0.08)",border:"1px solid rgba(167,139,250,0.2)",fontFamily:"var(--font-mono)" }}>✉ {e}</span>)}
                                {c.iocs?.urls?.map((u:string)      => <span key={u} className="text-[10px] px-2 py-0.5 rounded truncate max-w-xs" style={{ color:"#f87171",background:"rgba(248,113,113,0.08)",border:"1px solid rgba(248,113,113,0.2)",fontFamily:"var(--font-mono)" }}>🔗 {u}</span>)}
                                {c.iocs?.bankAccounts?.map((b:string)=>  <span key={b} className="text-[10px] px-2 py-0.5 rounded" style={{ color:"#fb923c",background:"rgba(251,146,60,0.08)",border:"1px solid rgba(251,146,60,0.2)",fontFamily:"var(--font-mono)" }}>🏦 {b}</span>)}
                                {c.iocs?.walletAddrs?.map((w:string) => <span key={w} className="text-[10px] px-2 py-0.5 rounded truncate max-w-xs" style={{ color:"#34d399",background:"rgba(52,211,153,0.08)",border:"1px solid rgba(52,211,153,0.2)",fontFamily:"var(--font-mono)" }}>₿ {w.substring(0,20)}…</span>)}
                                {(c.iocs?.aadhaarNums?.length > 0) && <span className="text-[10px] px-2 py-0.5 rounded" style={{ color:"#f87171",background:"rgba(248,113,113,0.08)",fontFamily:"var(--font-mono)" }}>🔏 {c.iocs.aadhaarNums.length} Aadhaar [REDACTED]</span>}
                                {(c.iocs?.panNums?.length > 0)      && <span className="text-[10px] px-2 py-0.5 rounded" style={{ color:"#f87171",background:"rgba(248,113,113,0.08)",fontFamily:"var(--font-mono)" }}>🆔 {c.iocs.panNums.length} PAN [REDACTED]</span>}
                              </div>
                            </div>
                          )}

                          {/* MITRE */}
                          {c.mitre && (
                            <div className="mb-3 text-xs px-3 py-2 rounded-lg"
                                 style={{ background:"var(--bg-elevated)", fontFamily:"var(--font-mono)", color:"var(--accent)" }}>
                              MITRE: {c.mitre}
                            </div>
                          )}

                          {/* Classification confidence */}
                          {c.classificationConfidence > 0 && (
                            <div className="mb-3 text-xs flex items-center gap-2" style={{ color:"var(--text-muted)" }}>
                              <span>AI Classification:</span>
                              <span style={{ color:"var(--accent)", fontFamily:"var(--font-mono)" }}>{c.classificationConfidence}% confidence</span>
                              {c.mlTags?.length > 0 && (
                                <div className="flex gap-1">
                                  {c.mlTags.slice(0,3).map((t:string) => (
                                    <span key={t} className="text-[9px] px-1.5 py-0.5 rounded"
                                          style={{ background:"var(--bg-elevated)", color:"var(--text-muted)", border:"1px solid var(--bg-border)" }}>
                                      {t.replace(/_/g," ")}
                                    </span>
                                  ))}
                                </div>
                              )}
                            </div>
                          )}

                          {/* Actions */}
                          <div className="flex gap-2 flex-wrap mt-3">
                            <button onClick={() => fetchNCRPDraft(c._id)}
                                    className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs"
                                    style={{ background:"var(--accent-subtle)", color:"var(--accent)", border:"1px solid var(--accent-border)" }}>
                              <Download className="size-3.5" /> NCRP Draft
                            </button>
                            {canWrite && (
                              <select onChange={e => updateStatus(c._id, e.target.value)} defaultValue={c.status}
                                      className="text-xs px-2.5 py-1.5 rounded-lg"
                                      style={{ background:"var(--bg-elevated)", border:"1px solid var(--bg-border)", color:"var(--text-secondary)" }}>
                                {["new","investigating","escalated","resolved","closed"].map(s => <option key={s} value={s}>{s}</option>)}
                              </select>
                            )}
                            {c.linkedComplaints?.length > 0 && (
                              <span className="flex items-center gap-1.5 text-xs px-2.5 py-1.5 rounded-lg"
                                    style={{ background:"rgba(248,113,113,0.08)", color:"#f87171", border:"1px solid rgba(248,113,113,0.2)" }}>
                                🔗 {c.linkedComplaints.length} linked complaint{c.linkedComplaints.length>1?"s":" — same IOC"}
                              </span>
                            )}
                          </div>
                        </div>
                      </motion.div>
                    )}
                  </AnimatePresence>
                </div>
              );
            })}
          </div>
        )}

        {/* File complaint modal */}
        <AnimatePresence>
          {showForm && (
            <motion.div initial={{ opacity:0 }} animate={{ opacity:1 }} exit={{ opacity:0 }}
                        className="fixed inset-0 flex items-center justify-center z-50 px-4"
                        style={{ background:"rgba(0,0,0,0.7)", backdropFilter:"blur(4px)" }}>
              <motion.div initial={{ scale:0.95,y:20 }} animate={{ scale:1,y:0 }} exit={{ scale:0.95 }}
                          className="card-glass p-6 max-w-2xl w-full rounded-2xl max-h-[90vh] overflow-y-auto">
                <h3 className="font-bold text-xl mb-5" style={{ color:"var(--text-primary)" }}>
                  File Cybercrime Complaint
                </h3>

                <div className="space-y-3">
                  <textarea value={form.description} onChange={e => setForm(f=>({...f,description:e.target.value}))}
                            placeholder="Describe the cybercrime in detail — what happened, how you were contacted, what you were told to do..."
                            rows={5} className="w-full px-4 py-3 rounded-xl text-sm resize-none"
                            style={{ background:"var(--bg-elevated)", border:"1px solid var(--bg-border)", color:"var(--text-primary)", outline:"none" }} />

                  <div className="grid grid-cols-2 gap-3">
                    <input value={form.victimName} onChange={e => setForm(f=>({...f,victimName:e.target.value}))}
                           placeholder="Your name (optional)"
                           className="px-3 py-2 rounded-xl text-sm"
                           style={{ background:"var(--bg-elevated)", border:"1px solid var(--bg-border)", color:"var(--text-primary)", outline:"none" }} />
                    <input value={form.victimContact} onChange={e => setForm(f=>({...f,victimContact:e.target.value}))}
                           placeholder="Phone / Email (optional)"
                           className="px-3 py-2 rounded-xl text-sm"
                           style={{ background:"var(--bg-elevated)", border:"1px solid var(--bg-border)", color:"var(--text-primary)", outline:"none" }} />
                    <input value={form.victimState} onChange={e => setForm(f=>({...f,victimState:e.target.value}))}
                           placeholder="State"
                           className="px-3 py-2 rounded-xl text-sm"
                           style={{ background:"var(--bg-elevated)", border:"1px solid var(--bg-border)", color:"var(--text-primary)", outline:"none" }} />
                    <input value={form.victimCity} onChange={e => setForm(f=>({...f,victimCity:e.target.value}))}
                           placeholder="City"
                           className="px-3 py-2 rounded-xl text-sm"
                           style={{ background:"var(--bg-elevated)", border:"1px solid var(--bg-border)", color:"var(--text-primary)", outline:"none" }} />
                  </div>

                  <div className="grid grid-cols-3 gap-3">
                    <input value={form.amountLost} onChange={e => setForm(f=>({...f,amountLost:e.target.value}))}
                           placeholder="Amount lost (₹)" type="number"
                           className="px-3 py-2 rounded-xl text-sm"
                           style={{ background:"var(--bg-elevated)", border:"1px solid var(--bg-border)", color:"var(--text-primary)", outline:"none" }} />
                    <select value={form.paymentMethod} onChange={e => setForm(f=>({...f,paymentMethod:e.target.value}))}
                            className="px-3 py-2 rounded-xl text-sm"
                            style={{ background:"var(--bg-elevated)", border:"1px solid var(--bg-border)", color:"var(--text-secondary)" }}>
                      {["unknown","upi","neft","rtgs","card","crypto","wallet","cash","other"].map(m => <option key={m} value={m}>{m.toUpperCase()}</option>)}
                    </select>
                    <input value={form.incidentDate} onChange={e => setForm(f=>({...f,incidentDate:e.target.value}))}
                           type="date" className="px-3 py-2 rounded-xl text-sm"
                           style={{ background:"var(--bg-elevated)", border:"1px solid var(--bg-border)", color:"var(--text-primary)", outline:"none" }} />
                  </div>
                  {/* Fraud type manual override */}
                  <select value={(form as any).fraudType || ""} onChange={e => setForm(f=>({...f,fraudType:e.target.value}))}
                          className="w-full px-3 py-2 rounded-xl text-sm"
                          style={{ background:"var(--bg-elevated)", border:"1px solid var(--bg-border)", color:"var(--text-secondary)" }}>
                    <option value="">Auto-classify fraud type (AI)</option>
                    {FRAUD_TYPES.map(t => <option key={t.value} value={t.value}>{t.label}</option>)}
                  </select>
                  <div className="text-xs px-3 py-2 rounded-xl"
                       style={{ background:"rgba(96,165,250,0.07)", color:"var(--text-muted)", border:"1px solid rgba(96,165,250,0.15)" }}>
                    💡 The AI will auto-classify the fraud type from your description. IOCs (UPI IDs, phone numbers, URLs) are automatically extracted.
                  </div>
                </div>

                {error && <p className="text-xs mt-3" style={{ color:"var(--color-danger)" }}>{error}</p>}

                <div className="flex gap-2 mt-5 justify-end">
                  <button onClick={() => { setShowForm(false); setError(null); }}
                          className="px-4 py-2 rounded-xl text-sm"
                          style={{ background:"var(--bg-elevated)", color:"var(--text-secondary)", border:"1px solid var(--bg-border)" }}>
                    Cancel
                  </button>
                  <button onClick={handleSubmit} disabled={submitting || !form.description.trim()}
                          className="px-5 py-2 rounded-xl text-sm font-semibold"
                          style={{ background:"var(--color-danger)", color:"#fff", opacity: submitting ? 0.7 : 1 }}>
                    {submitting ? "Filing..." : "File Complaint"}
                  </button>
                </div>
              </motion.div>
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </div>
  );
}