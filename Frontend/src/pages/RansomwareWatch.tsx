// FILE: src/pages/RansomwareWatch.tsx
import { useState, useEffect, useCallback } from "react";
import { motion, AnimatePresence } from "motion/react";
import {
  Shield, AlertTriangle, RefreshCw, Plus, Search,
  Activity, CheckCircle, Zap, Eye, Database
} from "lucide-react";
import { useRole } from "../hooks/useRole";
import { API_BASE } from "../config";

const authHeader = () => ({
  "Content-Type": "application/json",
  Authorization: `Bearer ${localStorage.getItem("pg_token")}`,
});

const TYPE_META: Record<string, { icon: string; color: string; label: string }> = {
  honeypot_triggered:           { icon:"🚨", color:"#f87171", label:"Honeypot Triggered"     },
  known_extension:              { icon:"🔒", color:"#f87171", label:"Known Extension"         },
  ransom_note_detected:         { icon:"📋", color:"#f87171", label:"Ransom Note Detected"    },
  c2_domain:                    { icon:"🌐", color:"#fb923c", label:"C2 Domain"               },
  delivery_email:               { icon:"📧", color:"#fb923c", label:"Delivery Email"          },
  shadow_copy_deletion:         { icon:"💀", color:"#f87171", label:"Shadow Copy Deletion"    },
  known_family:                 { icon:"🦠", color:"#f87171", label:"Known Family"            },
  suspicious_encryption_rate:   { icon:"⚡", color:"#fbbf24", label:"Encryption Rate Spike"  },
  network_spread:               { icon:"🔗", color:"#fb923c", label:"Network Spread"          },
};

export default function RansomwareWatch() {
  const { canWrite, canDelete } = useRole();
  const [events,    setEvents]    = useState<any[]>([]);
  const [honeypots, setHoneypots] = useState<any[]>([]);
  const [stats,     setStats]     = useState<any>(null);
  const [loading,   setLoading]   = useState(true);
  const [analyzing, setAnalyzing] = useState(false);
  const [analyzeInput, setAnalyzeInput] = useState("");
  const [analyzeResult, setAnalyzeResult] = useState<any>(null);
  const [showHoneypot, setShowHoneypot] = useState(false);
  const [hpForm, setHpForm] = useState({ host:"", share:"", path:"", fileName:"" });
  const [error,  setError]  = useState<string|null>(null);
  const [activeTab, setActiveTab] = useState<"events"|"honeypots"|"analyze"|"lolbins">("events");

  const fetchData = useCallback(async () => {
    setLoading(true);
    try {
      const [eventsRes, hpRes, statsRes] = await Promise.all([
        fetch(`${API_BASE}/api/ransomware/events`,    { headers: authHeader() }),
        fetch(`${API_BASE}/api/ransomware/honeypots`, { headers: authHeader() }),
        fetch(`${API_BASE}/api/ransomware/stats`,     { headers: authHeader() }),
      ]);
      if (eventsRes.ok) setEvents(await eventsRes.json());
      if (hpRes.ok)     setHoneypots(await hpRes.json());
      if (statsRes.ok)  setStats(await statsRes.json());
    } catch {}
    finally { setLoading(false); }
  }, []);

  useEffect(() => { fetchData(); }, [fetchData]);

  const analyze = async () => {
    if (!analyzeInput.trim()) return;
    setAnalyzing(true); setAnalyzeResult(null); setError(null);
    try {
      const res = await fetch(`${API_BASE}/api/ransomware/analyze`, {
        method:"POST", headers: authHeader(),
        body: JSON.stringify({ input: analyzeInput }),
      });
      if (!res.ok) throw new Error("Analysis failed");
      setAnalyzeResult(await res.json());
    } catch (err:any) { setError(err.message); }
    finally { setAnalyzing(false); }
  };

  const addHoneypot = async () => {
    if (!hpForm.host || !hpForm.path || !hpForm.fileName) { setError("Host, path and filename required"); return; }
    try {
      const res = await fetch(`${API_BASE}/api/ransomware/honeypot`, {
        method:"POST", headers: authHeader(), body: JSON.stringify(hpForm),
      });
      if (!res.ok) throw new Error("Failed to add honeypot");
      setShowHoneypot(false);
      setHpForm({ host:"", share:"", path:"", fileName:"" });
      fetchData();
    } catch (err:any) { setError(err.message); }
  };

  const triggeredEvents = events.filter(e => e.type === "honeypot_triggered");

  return (
    <div className="min-h-full py-10 px-6" style={{ background:"var(--bg-base)" }}>
      <div className="max-w-6xl mx-auto">

        <motion.div initial={{ opacity:0,y:16 }} animate={{ opacity:1,y:0 }} className="mb-8">
          <div className="tag-red inline-flex mb-3"><Shield className="size-3" /> RANSOMWARE WATCH</div>
          <div className="flex items-start justify-between flex-wrap gap-4">
            <div>
              <h1 className="font-display text-4xl mb-1.5" style={{ color:"var(--text-primary)" }}>
                Ransomware Early Warning
              </h1>
              <p style={{ color:"var(--text-muted)", fontSize:14 }}>
                Honeypot file monitoring · Known extension detection · Shadow copy deletion alerts
              </p>
            </div>
            <div className="flex gap-2">
              <button onClick={fetchData} className="btn-ghost flex items-center gap-2 px-3.5 py-2 text-sm">
                <RefreshCw className={`size-4 ${loading?"animate-spin":""}`} />
              </button>
              {canDelete && (
                <button onClick={() => setShowHoneypot(true)}
                        className="flex items-center gap-2 px-4 py-2 rounded-xl text-sm font-semibold"
                        style={{ background:"#f87171", color:"#fff" }}>
                  <Plus className="size-4" /> Add Honeypot
                </button>
              )}
            </div>
          </div>
        </motion.div>

        {/* Critical alert banner */}
        {triggeredEvents.length > 0 && (
          <motion.div initial={{ opacity:0,y:-8 }} animate={{ opacity:1,y:0 }}
                      className="flex items-center gap-3 px-5 py-4 rounded-xl mb-6"
                      style={{ background:"rgba(248,113,113,0.1)", border:"2px solid rgba(248,113,113,0.4)" }}>
            <span className="text-2xl">🚨</span>
            <div>
              <div className="font-bold text-base" style={{ color:"#f87171" }}>
                RANSOMWARE HONEYPOT TRIGGERED — IMMEDIATE ACTION REQUIRED
              </div>
              <div className="text-sm mt-0.5" style={{ color:"var(--text-secondary)" }}>
                {triggeredEvents.length} honeypot file(s) modified — active ransomware encryption detected.
                ISOLATE affected hosts immediately. Call 1930.
              </div>
            </div>
          </motion.div>
        )}

        {/* Stats */}
        {stats && (
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-6">
            {[
              { label:"Total Events",  value:stats.total,     color:"var(--accent)"      },
              { label:"Active",        value:stats.active,    color:"#f87171"             },
              { label:"Honeypots",     value:stats.honeypots, color:"#fbbf24"             },
              { label:"Last 24h",      value:stats.recent?.length||0, color:"var(--safe)" },
            ].map(s => (
              <div key={s.label} className="card p-4 stat-card">
                <div className="text-2xl font-bold font-display" style={{ color:s.color }}>{s.value}</div>
                <div className="label-caps mt-1">{s.label}</div>
              </div>
            ))}
          </div>
        )}

        {/* Tabs */}
        <div className="flex gap-1 p-1 rounded-xl mb-6"
             style={{ background:"var(--bg-elevated)", border:"1px solid var(--bg-border)" }}>
          {[
            { id:"events",   label:"Events",    icon:Activity },
            { id:"honeypots",label:"Honeypots", icon:Database },
            { id:"analyze",  label:"Analyze",   icon:Search   },
            { id:"lolbins",  label:"LOLBins",   icon:Zap      },
          ].map(t => {
            const Icon = t.icon;
            return (
              <button key={t.id} onClick={() => setActiveTab(t.id as any)}
                      className="flex-1 flex items-center justify-center gap-1.5 py-2 rounded-lg text-xs font-medium transition-all"
                      style={{
                        background: activeTab===t.id ? "var(--accent-subtle)" : "transparent",
                        color:      activeTab===t.id ? "var(--accent)" : "var(--text-muted)",
                        border:     activeTab===t.id ? "1px solid var(--accent-border)" : "1px solid transparent",
                      }}>
                <Icon className="size-3.5" /> {t.label}
              </button>
            );
          })}
        </div>

        {error && (
          <div className="flex items-center gap-2 px-4 py-2.5 rounded-xl mb-4"
               style={{ background:"rgba(248,113,113,0.08)", border:"1px solid rgba(248,113,113,0.2)" }}>
            <AlertTriangle className="size-4" style={{ color:"var(--color-danger)" }} />
            <span className="text-xs flex-1" style={{ color:"var(--color-danger)" }}>{error}</span>
            <button onClick={() => setError(null)} style={{ background:"none",border:"none",cursor:"pointer",color:"var(--text-muted)" }}>✕</button>
          </div>
        )}

        {/* Events tab */}
        {activeTab === "events" && (
          <div className="card overflow-hidden">
            <div className="px-5 py-3 border-b flex items-center justify-between"
                 style={{ borderColor:"var(--bg-border)", background:"var(--bg-elevated)" }}>
              <span className="text-sm font-semibold" style={{ color:"var(--text-primary)" }}>
                Ransomware Detection Events
              </span>
              <span className="text-xs" style={{ color:"var(--text-muted)", fontFamily:"var(--font-mono)" }}>
                {events.length} events
              </span>
            </div>
            {events.length === 0 ? (
              <div className="py-16 text-center">
                <Shield className="size-10 mx-auto mb-3" style={{ color:"var(--safe)" }} />
                <p className="text-sm font-semibold" style={{ color:"var(--safe)" }}>No ransomware events detected</p>
                <p className="text-xs mt-1" style={{ color:"var(--text-muted)" }}>
                  Add honeypot files and scan suspicious content to monitor for ransomware
                </p>
              </div>
            ) : (
              <div className="divide-y" style={{ borderColor:"var(--bg-border)" }}>
                {events.map((ev:any) => {
                  const tm = TYPE_META[ev.type] || { icon:"⚠️", color:"#fbbf24", label:ev.type };
                  return (
                    <div key={ev._id} className="px-5 py-4 flex items-start gap-3">
                      <span className="text-xl flex-shrink-0">{tm.icon}</span>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 mb-1">
                          <span className="text-xs font-bold" style={{ color:tm.color, fontFamily:"var(--font-mono)" }}>
                            {tm.label}
                          </span>
                          {ev.family && (
                            <span className="text-[9px] px-1.5 py-0.5 rounded font-bold"
                                  style={{ color:"#f87171", background:"rgba(248,113,113,0.1)", border:"1px solid rgba(248,113,113,0.2)", fontFamily:"var(--font-mono)" }}>
                              {ev.family}
                            </span>
                          )}
                          <span className="text-[9px] px-1.5 py-0.5 rounded"
                                style={{ color:"#60a5fa", background:"rgba(96,165,250,0.1)", fontFamily:"var(--font-mono)" }}>
                            {ev.confidence}% confidence
                          </span>
                        </div>
                        <p className="text-xs leading-relaxed" style={{ color:"var(--text-secondary)" }}>
                          {ev.description}
                        </p>
                        {ev.mitre && (
                          <p className="text-[10px] mt-1" style={{ color:"var(--accent)", fontFamily:"var(--font-mono)" }}>
                            {ev.mitre}
                          </p>
                        )}
                        <p className="text-[10px] mt-1" style={{ color:"var(--text-muted)", fontFamily:"var(--font-mono)" }}>
                          {ev.host && `Host: ${ev.host} · `}{new Date(ev.createdAt).toLocaleString()}
                        </p>
                      </div>
                      <div className="text-[9px] px-1.5 py-0.5 rounded flex-shrink-0"
                           style={{ color: ev.status==="active"?"#f87171":"var(--safe)",
                                    background: ev.status==="active"?"rgba(248,113,113,0.1)":"rgba(52,211,153,0.1)",
                                    fontFamily:"var(--font-mono)", textTransform:"uppercase" }}>
                        {ev.status}
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        )}

        {/* Honeypots tab */}
        {activeTab === "honeypots" && (
          <div className="card overflow-hidden">
            <div className="px-5 py-3 border-b"
                 style={{ borderColor:"var(--bg-border)", background:"var(--bg-elevated)" }}>
              <span className="text-sm font-semibold" style={{ color:"var(--text-primary)" }}>
                Active Honeypot Files
              </span>
            </div>
            <div className="p-5">
              <div className="text-sm mb-4 p-4 rounded-xl"
                   style={{ background:"rgba(251,191,36,0.07)", border:"1px solid rgba(251,191,36,0.2)", color:"var(--text-secondary)" }}>
                <strong style={{ color:"#fbbf24" }}>How honeypots work:</strong> Place decoy files on your Windows network shares.
                PhishNetra monitors their SHA-256 hash via Fluent Bit. If ransomware modifies them, you get an
                immediate critical alert — catching ransomware <em>before</em> it encrypts all your real files.
              </div>
              {honeypots.length === 0 ? (
                <div className="text-center py-10">
                  <Database className="size-10 mx-auto mb-3" style={{ color:"var(--text-muted)" }} />
                  <p className="text-sm" style={{ color:"var(--text-muted)" }}>No honeypot files registered</p>
                  <p className="text-xs mt-1" style={{ color:"var(--text-muted)" }}>
                    Add honeypots on network shares to detect ransomware early
                  </p>
                </div>
              ) : (
                <div className="space-y-2">
                  {honeypots.map((hp:any) => (
                    <div key={hp._id} className="flex items-center gap-3 px-4 py-3 rounded-xl"
                         style={{ background:"var(--bg-elevated)", border:`1px solid ${hp.triggered?"rgba(248,113,113,0.3)":"var(--bg-border)"}` }}>
                      <span className="text-lg">{hp.triggered ? "🚨" : "🛡️"}</span>
                      <div className="flex-1 min-w-0">
                        <div className="text-sm font-medium truncate" style={{ color:"var(--text-primary)" }}>
                          {hp.path}\\{hp.fileName}
                        </div>
                        <div className="text-xs mt-0.5" style={{ color:"var(--text-muted)", fontFamily:"var(--font-mono)" }}>
                          Host: {hp.host}{hp.share ? ` · Share: ${hp.share}` : ""}
                        </div>
                      </div>
                      <div className="text-[9px] px-2 py-0.5 rounded font-bold"
                           style={{ color: hp.triggered?"#f87171":"var(--safe)",
                                    background: hp.triggered?"rgba(248,113,113,0.1)":"rgba(52,211,153,0.1)",
                                    fontFamily:"var(--font-mono)", textTransform:"uppercase" }}>
                        {hp.triggered ? "TRIGGERED" : "MONITORING"}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}

        {/* Analyze tab */}
        {activeTab === "analyze" && (
          <div className="card p-5">
            <div className="text-sm font-semibold mb-3" style={{ color:"var(--text-primary)" }}>
              Analyze Content for Ransomware Indicators
            </div>
            <p className="text-xs mb-4" style={{ color:"var(--text-muted)" }}>
              Paste email content, file names, log entries, or command lines to check for ransomware indicators.
            </p>
            <textarea value={analyzeInput} onChange={e => setAnalyzeInput(e.target.value)}
                      placeholder={"Examples:\n• Paste ransom note content\n• File names like 'report.pdf.WNCRY'\n• PowerShell: 'vssadmin delete shadows'\n• Email with 'your files have been encrypted'"}
                      rows={6} className="w-full px-4 py-3 rounded-xl text-sm resize-none mb-3"
                      style={{ background:"var(--bg-elevated)", border:"1px solid var(--bg-border)", color:"var(--text-primary)", outline:"none", fontFamily:"var(--font-mono)" }} />
            <button onClick={analyze} disabled={analyzing || !analyzeInput.trim()}
                    className="flex items-center gap-2 px-5 py-2.5 rounded-xl text-sm font-semibold"
                    style={{ background: analyzing?"var(--bg-elevated)":"#f87171", color:"#fff", opacity:analyzing?0.7:1 }}>
              {analyzing ? <RefreshCw className="size-4 animate-spin" /> : <Search className="size-4" />}
              {analyzing ? "Analyzing..." : "Analyze for Ransomware"}
            </button>

            {analyzeResult && (
              <motion.div initial={{ opacity:0,y:8 }} animate={{ opacity:1,y:0 }} className="mt-4">
                <div className="px-5 py-4 rounded-xl"
                     style={{
                       background: analyzeResult.isRansomware ? "rgba(248,113,113,0.08)" : "rgba(52,211,153,0.07)",
                       border:     `1px solid ${analyzeResult.isRansomware?"rgba(248,113,113,0.25)":"rgba(52,211,153,0.2)"}`,
                     }}>
                  <div className="flex items-center gap-2 mb-3">
                    {analyzeResult.isRansomware
                      ? <AlertTriangle className="size-5" style={{ color:"#f87171" }} />
                      : <CheckCircle  className="size-5" style={{ color:"var(--safe)" }} />}
                    <span className="font-bold" style={{ color: analyzeResult.isRansomware?"#f87171":"var(--safe)" }}>
                      {analyzeResult.isRansomware
                        ? `🚨 Ransomware Indicators Detected — ${analyzeResult.family || "Unknown Family"}`
                        : "✓ No Ransomware Indicators Found"}
                    </span>
                  </div>
                  {analyzeResult.isRansomware && (
                    <>
                      <div className="grid grid-cols-3 gap-3 mb-3">
                        <div><div className="label-caps mb-1">Confidence</div><div className="font-bold" style={{ color:"#f87171" }}>{analyzeResult.confidence}%</div></div>
                        <div><div className="label-caps mb-1">Max Severity</div><div className="font-bold" style={{ color:"#f87171" }}>SEV-{analyzeResult.maxSeverity}</div></div>
                        <div><div className="label-caps mb-1">Family</div><div className="font-bold" style={{ color:"#fbbf24" }}>{analyzeResult.family||"Unknown"}</div></div>
                      </div>
                      <div className="space-y-2">
                        {analyzeResult.detections?.map((d:any,i:number) => (
                          <div key={i} className="px-3 py-2 rounded-lg text-xs"
                               style={{ background:"var(--bg-base)", border:"1px solid var(--bg-border)" }}>
                            <div className="font-semibold mb-0.5" style={{ color:"#f87171" }}>{d.type?.replace(/_/g," ")}</div>
                            <div style={{ color:"var(--text-secondary)" }}>{d.description}</div>
                            {d.mitre && <div className="mt-1" style={{ color:"var(--accent)", fontFamily:"var(--font-mono)", fontSize:10 }}>{d.mitre}</div>}
                          </div>
                        ))}
                      </div>
                    </>
                  )}
                </div>
              </motion.div>
            )}
          </div>
        )}

        {/* LOLBins reference tab */}
        {activeTab === "lolbins" && (
          <div className="card p-5">
            <div className="text-sm font-semibold mb-1" style={{ color:"var(--text-primary)" }}>
              LOLBins & Pre-Encryption Commands
            </div>
            <p className="text-xs mb-4" style={{ color:"var(--text-muted)" }}>
              These Windows built-in tools (LOLBins) are commonly abused by ransomware operators before and during encryption.
              Detecting them in process logs gives early warning before files are encrypted.
            </p>
            <div className="space-y-2">
              {[
                { cmd:"vssadmin delete shadows",          mitre:"T1490", severity:5, label:"Shadow Copy Deletion",         desc:"Deletes Volume Shadow Copies to prevent file recovery. #1 ransomware indicator." },
                { cmd:"wmic shadowcopy delete",           mitre:"T1490", severity:5, label:"VSS Deletion via WMIC",        desc:"Alternative method to delete shadow copies. Same impact as vssadmin." },
                { cmd:"bcdedit /set recoveryenabled no",  mitre:"T1490", severity:5, label:"Disable Boot Recovery",        desc:"Prevents Windows from booting into recovery mode after ransomware runs." },
                { cmd:"wbadmin delete catalog",           mitre:"T1490", severity:5, label:"Windows Backup Deletion",      desc:"Removes Windows Server Backup catalog, preventing backup restoration." },
                { cmd:"certutil -urlcache -split -f",     mitre:"T1105", severity:5, label:"LOLBin File Download",         desc:"Uses built-in certutil to download ransomware payloads without web browsers." },
                { cmd:"powershell -enc/-nop -w hidden",   mitre:"T1059.001", severity:5, label:"Encoded/Hidden PowerShell",desc:"Ransomware delivery via obfuscated PowerShell to evade signature detection." },
                { cmd:"net use \\\\ / psexec",            mitre:"T1570", severity:5, label:"Lateral Movement",            desc:"Spreads ransomware across network shares using built-in or Sysinternals tools." },
                { cmd:"icacls * /reset",                  mitre:"T1222", severity:5, label:"Permission Reset",             desc:"Resets file permissions so ransomware can encrypt all files including locked ones." },
                { cmd:"taskkill /f /im",                  mitre:"T1562", severity:4, label:"AV/Backup Process Kill",       desc:"Kills antivirus, backup agents, and database processes before encryption." },
                { cmd:"bitsadmin /transfer",              mitre:"T1197", severity:4, label:"BITS Job Transfer",            desc:"Uses Windows BITS service to download C2 payloads, bypasses firewalls." },
                { cmd:"mshta.exe / rundll32.exe",         mitre:"T1218", severity:4, label:"LOLBin Execution",             desc:"Executes malicious scripts via trusted Windows processes to bypass AppLocker." },
                { cmd:"mimikatz / sekurlsa::logonpasswords", mitre:"T1003", severity:5, label:"Credential Dumping",        desc:"Dumps password hashes for lateral movement across domain before encryption." },
              ].map((lb, i) => (
                <div key={i} className="flex items-start gap-3 px-4 py-3 rounded-xl"
                     style={{ background:"var(--bg-elevated)", border:`1px solid ${lb.severity===5?"rgba(248,113,113,0.2)":"rgba(251,146,60,0.2)"}` }}>
                  <div className="flex-shrink-0 mt-0.5">
                    <div className="text-[9px] px-1.5 py-0.5 rounded font-bold"
                         style={{ color:lb.severity===5?"#f87171":"#fb923c", background:lb.severity===5?"rgba(248,113,113,0.1)":"rgba(251,146,60,0.1)", fontFamily:"var(--font-mono)" }}>
                      SEV-{lb.severity}
                    </div>
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-0.5">
                      <span className="text-xs font-semibold" style={{ color:"var(--text-primary)" }}>{lb.label}</span>
                      <span className="text-[9px] px-1.5 py-0.5 rounded"
                            style={{ color:"var(--accent)", background:"var(--accent-subtle)", fontFamily:"var(--font-mono)" }}>
                        {lb.mitre}
                      </span>
                    </div>
                    <code className="text-[10px] block mb-1 px-2 py-1 rounded"
                          style={{ background:"var(--bg-base)", color:"#f87171", fontFamily:"var(--font-mono)" }}>
                      {lb.cmd}
                    </code>
                    <p className="text-[11px]" style={{ color:"var(--text-muted)" }}>{lb.desc}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Add honeypot modal */}
        <AnimatePresence>
          {showHoneypot && (
            <motion.div initial={{ opacity:0 }} animate={{ opacity:1 }} exit={{ opacity:0 }}
                        className="fixed inset-0 flex items-center justify-center z-50 px-4"
                        style={{ background:"rgba(0,0,0,0.7)", backdropFilter:"blur(4px)" }}>
              <motion.div initial={{ scale:0.95 }} animate={{ scale:1 }} exit={{ scale:0.95 }}
                          className="card-glass p-6 max-w-md w-full rounded-2xl">
                <h3 className="font-bold text-lg mb-4" style={{ color:"var(--text-primary)" }}>Register Honeypot File</h3>
                <div className="space-y-3">
                  {[
                    { key:"host",     placeholder:"Hostname (e.g. WORKSTATION-01)"         },
                    { key:"share",    placeholder:"Network share (e.g. \\\\server\\data)"  },
                    { key:"path",     placeholder:"Full path (e.g. C:\\shares\\data)"      },
                    { key:"fileName", placeholder:"Honeypot filename (e.g. _important.docx)"},
                  ].map(f => (
                    <input key={f.key} value={(hpForm as any)[f.key]}
                           onChange={e => setHpForm(p => ({...p,[f.key]:e.target.value}))}
                           placeholder={f.placeholder}
                           className="w-full px-3 py-2.5 rounded-xl text-sm"
                           style={{ background:"var(--bg-elevated)", border:"1px solid var(--bg-border)", color:"var(--text-primary)", outline:"none" }} />
                  ))}
                </div>
                <p className="text-xs mt-3" style={{ color:"var(--text-muted)" }}>
                  Create an empty file with this name on your network share.
                  PhishNetra monitors it via Fluent Bit — any modification triggers a Critical alert.
                </p>
                {error && <p className="text-xs mt-2" style={{ color:"var(--color-danger)" }}>{error}</p>}
                <div className="flex gap-2 justify-end mt-4">
                  <button onClick={() => setShowHoneypot(false)}
                          className="px-4 py-2 rounded-xl text-sm"
                          style={{ background:"var(--bg-elevated)", color:"var(--text-secondary)", border:"1px solid var(--bg-border)" }}>Cancel</button>
                  <button onClick={addHoneypot}
                          className="px-4 py-2 rounded-xl text-sm font-semibold"
                          style={{ background:"#f87171", color:"#fff" }}>Register</button>
                </div>
              </motion.div>
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </div>
  );
}