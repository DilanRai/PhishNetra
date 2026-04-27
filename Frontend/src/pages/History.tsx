import { useState, useEffect, Fragment } from "react";
import { useNavigate } from "react-router";
import { motion, AnimatePresence } from "motion/react";
import {
  CircleCheck as CheckCircle, TriangleAlert as AlertTriangle,
  XCircle, Clock, History as HistoryIcon, Trash2, Search,
  ChevronDown, ChevronUp, Terminal, Activity, Filter
} from "lucide-react";
import type { HistoryItem } from "../types";

export default function History() {
  const navigate = useNavigate();
  const [history, setHistory] = useState<HistoryItem[]>([]);
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [filter, setFilter] = useState<"all" | "safe" | "suspicious" | "phishing">("all");

  const fetchHistory = async () => {
    try {
      const res = await fetch("http://localhost:5000/api/scan/history");
      if (!res.ok) { setHistory([]); return; }
      const data = await res.json();
      if (Array.isArray(data)) {
        setHistory(data.map((item: any) => ({
          _id: item._id || item.id,
          input: item.input || "Unknown",
          status: item.status || "unknown",
          riskScore: item.riskScore || 0,
          issues: item.issues || [],
          createdAt: item.createdAt || new Date().toISOString(),
        })));
      }
    } catch { setHistory([]); }
  };

  useEffect(() => { fetchHistory(); }, []);

  const handleClearHistory = async () => {
    setHistory([]); setExpandedId(null);
    await fetch("http://localhost:5000/api/scan/history", { method: "DELETE" });
    await fetchHistory();
  };

  const handleDeleteItem = async (id: string) => {
    setHistory((p) => p.filter((i) => i._id !== id));
    await fetch(`http://localhost:5000/api/scan/history/${id}`, { method: "DELETE" });
    await fetchHistory();
  };

  const cfg = (s: string) => {
    if (s === "safe")       return { icon: CheckCircle,   color: "#00ff88", bg: "rgba(0,255,136,0.06)",  border: "rgba(0,255,136,0.2)",  bar: "#00ff88", label: "SAFE" };
    if (s === "suspicious") return { icon: AlertTriangle, color: "#f5a623", bg: "rgba(245,166,35,0.06)", border: "rgba(245,166,35,0.2)", bar: "#f5a623", label: "SUSPICIOUS" };
    if (s === "phishing")   return { icon: XCircle,       color: "#ff4444", bg: "rgba(255,68,68,0.06)",  border: "rgba(255,68,68,0.2)",  bar: "#ff4444", label: "PHISHING" };
    return                         { icon: Clock,         color: "#8b95a8", bg: "rgba(139,149,168,0.06)", border: "rgba(139,149,168,0.2)", bar: "#8b95a8", label: "UNKNOWN" };
  };

  const filtered = filter === "all" ? history : history.filter((h) => h.status === filter);

  const counts = {
    safe:       history.filter((h) => h.status === "safe").length,
    suspicious: history.filter((h) => h.status === "suspicious").length,
    phishing:   history.filter((h) => h.status === "phishing").length,
  };

  return (
    <div className="min-h-full py-12 px-6" style={{ background: "var(--bg-base)" }}>
      <div className="max-w-6xl mx-auto">

        {/* ── HEADER ── */}
        <motion.div initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }}
                    className="flex flex-col md:flex-row md:items-start justify-between gap-6 mb-10">
          <div>
            <div className="tag-green inline-flex mb-4">
              <Activity className="size-3" /> SCAN LOGS
            </div>
            <h1 className="text-4xl font-bold mb-2"
                style={{ fontFamily: "'Syne', sans-serif", color: "var(--text-primary)" }}>
              Scan History
            </h1>
            <p className="text-sm" style={{ color: "var(--text-secondary)" }}>
              Full log of all analyzed URLs and messages
            </p>
          </div>

          {history.length > 0 && (
            <button onClick={handleClearHistory}
                    className="flex items-center gap-2 px-4 py-2.5 rounded-lg text-sm transition-all self-start"
                    style={{ background: "rgba(255,68,68,0.06)", border: "1px solid rgba(255,68,68,0.2)", color: "#ff4444", fontFamily: "'DM Sans', sans-serif" }}
                    onMouseEnter={e => (e.currentTarget.style.background = "rgba(255,68,68,0.12)")}
                    onMouseLeave={e => (e.currentTarget.style.background = "rgba(255,68,68,0.06)")}>
              <Trash2 className="size-4" /> Clear All Logs
            </button>
          )}
        </motion.div>

        {/* ── EMPTY STATE ── */}
        {history.length === 0 ? (
          <motion.div initial={{ opacity: 0, scale: 0.97 }} animate={{ opacity: 1, scale: 1 }}
                      className="rounded-xl overflow-hidden"
                      style={{ background: "var(--bg-card)", border: "1px solid var(--bg-border)" }}>
            {/* Terminal bar */}
            <div className="flex items-center gap-2 px-4 py-3 border-b"
                 style={{ borderColor: "var(--bg-border)", background: "rgba(0,0,0,0.3)" }}>
              <div className="flex gap-1.5">
                <div className="w-2.5 h-2.5 rounded-full" style={{ background: "#ff5f57" }} />
                <div className="w-2.5 h-2.5 rounded-full" style={{ background: "#febc2e" }} />
                <div className="w-2.5 h-2.5 rounded-full" style={{ background: "#28c840" }} />
              </div>
              <span className="text-xs ml-1" style={{ color: "var(--text-muted)", fontFamily: "'JetBrains Mono', monospace" }}>
                scan_history.log
              </span>
            </div>
            <div className="py-20 text-center">
              <Clock className="size-10 mx-auto mb-4" style={{ color: "var(--text-muted)" }} />
              <div className="text-sm font-bold mb-2" style={{ color: "var(--text-secondary)", fontFamily: "'Syne', sans-serif" }}>
                No scan logs yet
              </div>
              <p className="text-xs mb-8" style={{ color: "var(--text-muted)" }}>
                Scan history will appear here after your first analysis
              </p>
              <button onClick={() => navigate("/scan")}
                      className="btn-primary inline-flex items-center gap-2 px-6 py-3 text-sm"
                      style={{ fontFamily: "'Syne', sans-serif", fontWeight: 700 }}>
                <Terminal className="size-4" /> Start Scanning
              </button>
            </div>
          </motion.div>
        ) : (
          <motion.div initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }}>

            {/* ── SUMMARY STATS ── */}
            <div className="grid grid-cols-3 gap-3 mb-6">
              {(["safe", "suspicious", "phishing"] as const).map((s) => {
                const c = cfg(s);
                return (
                  <button key={s}
                          onClick={() => setFilter(filter === s ? "all" : s)}
                          className="rounded-xl p-4 text-center transition-all"
                          style={{
                            background: filter === s ? c.bg : "var(--bg-card)",
                            border: `1px solid ${filter === s ? c.border : "var(--bg-border)"}`,
                            cursor: "pointer",
                          }}>
                    <div className="text-2xl font-bold mb-1" style={{ color: c.color, fontFamily: "'Syne', sans-serif" }}>
                      {counts[s]}
                    </div>
                    <div className="text-xs uppercase tracking-widest"
                         style={{ color: "var(--text-muted)", fontFamily: "'JetBrains Mono', monospace" }}>
                      {s}
                    </div>
                  </button>
                );
              })}
            </div>

            {/* ── FILTER BAR ── */}
            {filter !== "all" && (
              <div className="flex items-center gap-2 mb-4 px-1">
                <Filter className="size-3.5" style={{ color: "var(--accent-cyan)" }} />
                <span className="text-xs" style={{ color: "var(--text-muted)", fontFamily: "'JetBrains Mono', monospace" }}>
                  Showing {filter} only ({filtered.length} records) ·
                </span>
                <button className="text-xs" style={{ color: "var(--accent-cyan)" }} onClick={() => setFilter("all")}>
                  clear filter
                </button>
              </div>
            )}

            {/* ── TABLE ── */}
            <div className="rounded-xl overflow-hidden"
                 style={{ background: "var(--bg-card)", border: "1px solid var(--bg-border)" }}>

              {/* Terminal header */}
              <div className="flex items-center justify-between px-5 py-3 border-b"
                   style={{ borderColor: "var(--bg-border)", background: "rgba(0,0,0,0.3)" }}>
                <div className="flex items-center gap-2">
                  <div className="flex gap-1.5">
                    <div className="w-2.5 h-2.5 rounded-full" style={{ background: "#ff5f57" }} />
                    <div className="w-2.5 h-2.5 rounded-full" style={{ background: "#febc2e" }} />
                    <div className="w-2.5 h-2.5 rounded-full" style={{ background: "#28c840" }} />
                  </div>
                  <span className="text-xs ml-1" style={{ color: "var(--text-muted)", fontFamily: "'JetBrains Mono', monospace" }}>
                    scan_history.log — {filtered.length} records
                  </span>
                </div>
                <div className="flex items-center gap-1.5">
                  <div className="w-1.5 h-1.5 rounded-full safe-pulse" style={{ background: "var(--accent-green)" }} />
                  <span className="text-xs" style={{ color: "var(--text-muted)", fontFamily: "'JetBrains Mono', monospace" }}>live</span>
                </div>
              </div>

              <div className="overflow-x-auto">
                <table className="w-full data-table">
                  <thead>
                    <tr>
                      <th className="text-left">Input / Target</th>
                      <th className="text-left">Verdict</th>
                      <th className="text-left hidden md:table-cell">Risk Score</th>
                      <th className="text-left hidden lg:table-cell">Timestamp</th>
                      <th className="text-left">Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    <AnimatePresence>
                      {filtered.map((item) => {
                        const c = cfg(item.status);
                        const isExp = expandedId === item._id;
                        return (
                          <Fragment key={`item-${item._id}`}>
                            <motion.tr
                              initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }}
                              exit={{ opacity: 0, x: -20 }}
                              onClick={() => setExpandedId(isExp ? null : item._id)}
                              style={{ cursor: "pointer", background: isExp ? "var(--bg-elevated)" : "transparent" }}>
                              <td style={{ maxWidth: 220 }}>
                                <p className="truncate text-sm"
                                   style={{ color: "var(--text-primary)", fontFamily: "'JetBrains Mono', monospace", fontSize: 12 }}>
                                  {item.input}
                                </p>
                              </td>
                              <td>
                                <span className="inline-flex items-center gap-1.5 text-xs font-bold px-2.5 py-1 rounded"
                                      style={{
                                        background: c.bg, color: c.color,
                                        border: `1px solid ${c.border}`,
                                        fontFamily: "'JetBrains Mono', monospace",
                                        letterSpacing: "0.06em",
                                      }}>
                                  {c.label}
                                </span>
                              </td>
                              <td className="hidden md:table-cell">
                                <div className="flex items-center gap-3">
                                  <div className="w-20 h-1.5 rounded-full overflow-hidden" style={{ background: "var(--bg-border)" }}>
                                    <div className="h-full rounded-full" style={{ width: `${item.riskScore}%`, background: c.bar }} />
                                  </div>
                                  <span className="text-xs font-bold" style={{ color: c.color, fontFamily: "'JetBrains Mono', monospace" }}>
                                    {item.riskScore}
                                  </span>
                                </div>
                              </td>
                              <td className="hidden lg:table-cell">
                                <span className="text-xs" style={{ color: "var(--text-muted)", fontFamily: "'JetBrains Mono', monospace" }}>
                                  {new Date(item.createdAt).toLocaleString()}
                                </span>
                              </td>
                              <td>
                                <div className="flex items-center gap-2">
                                  <button onClick={(e) => { e.stopPropagation(); handleDeleteItem(item._id); }}
                                          className="p-1.5 rounded-lg transition-all"
                                          style={{ color: "var(--text-muted)" }}
                                          title="Delete"
                                          onMouseEnter={e => { (e.currentTarget as HTMLButtonElement).style.color = "#ff4444"; (e.currentTarget as HTMLButtonElement).style.background = "rgba(255,68,68,0.08)"; }}
                                          onMouseLeave={e => { (e.currentTarget as HTMLButtonElement).style.color = "var(--text-muted)"; (e.currentTarget as HTMLButtonElement).style.background = "transparent"; }}>
                                    <Trash2 className="size-3.5" />
                                  </button>
                                  {isExp
                                    ? <ChevronUp className="size-3.5" style={{ color: "var(--accent-green)" }} />
                                    : <ChevronDown className="size-3.5" style={{ color: "var(--text-muted)" }} />}
                                </div>
                              </td>
                            </motion.tr>

                            {/* Expanded row */}
                            <AnimatePresence>
                              {isExp && (
                                <motion.tr key={`exp-${item._id}`}
                                  initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}>
                                  <td colSpan={5} style={{ background: "var(--bg-elevated)", borderBottom: "1px solid var(--bg-border)", padding: "12px 20px 16px" }}>
                                    {item.issues?.length > 0 ? (
                                      <div className="space-y-1.5">
                                        <div className="text-xs mb-3 uppercase tracking-widest"
                                             style={{ color: "var(--text-muted)", fontFamily: "'JetBrains Mono', monospace" }}>
                                          ↳ Detected Issues:
                                        </div>
                                        {item.issues.map((issue, i) => (
                                          <div key={i} className="flex items-center gap-2.5 text-xs"
                                               style={{ color: "var(--text-secondary)", fontFamily: "'DM Sans', sans-serif" }}>
                                            <div className="w-1 h-1 rounded-full flex-shrink-0" style={{ background: "#f5a623" }} />
                                            {issue}
                                          </div>
                                        ))}
                                      </div>
                                    ) : (
                                      <div className="flex items-center gap-2 text-xs" style={{ color: "var(--accent-green)" }}>
                                        <Search className="size-3" />
                                        No issues detected — classified as safe.
                                      </div>
                                    )}
                                  </td>
                                </motion.tr>
                              )}
                            </AnimatePresence>
                          </Fragment>
                        );
                      })}
                    </AnimatePresence>
                  </tbody>
                </table>
              </div>
            </div>
          </motion.div>
        )}

      </div>
    </div>
  );
}