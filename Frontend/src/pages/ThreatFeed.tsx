// FILE: src/pages/ThreatFeed.tsx

import { useEffect, useState, useCallback } from "react";
import { motion, AnimatePresence } from "motion/react";
import { useSocket }  from "../hooks/useSocket";
import {
  Activity, Shield, Globe, Terminal,
  RefreshCw, Clock, Zap, TrendingUp,
  Link as LinkIcon, Mail, FileText,
  Brain, AlertTriangle, XCircle,
} from "lucide-react";
import { API_BASE } from "../config";
import type { ThreatFeedData, ThreatFeedItem } from "../types";

const statusColor  = (s: string) => s === "phishing" ? "#ff4444" : "#f5a623";
const statusBg     = (s: string) => s === "phishing" ? "rgba(255,68,68,0.08)"  : "rgba(245,166,35,0.08)";
const statusBorder = (s: string) => s === "phishing" ? "rgba(255,68,68,0.25)"  : "rgba(245,166,35,0.25)";

const InputIcon = ({ type }: { type: string }) => {
  if (type === "url")   return <LinkIcon className="size-3" />;
  if (type === "email") return <Mail     className="size-3" />;
  return                       <FileText className="size-3" />;
};

const TECHNIQUE_LABELS: Record<string, string> = {
  credential_harvest:   "Credential Harvest",
  typosquatting:        "Typosquatting",
  brand_impersonation:  "Brand Impersonation",
  redirect_chain:       "Redirect Chain",
  homograph:            "Homograph Attack",
  social_engineering:   "Social Engineering",
  financial_scam:       "Financial Scam",
  malicious_attachment: "Malicious Attachment",
  generic_phishing:     "Generic Phishing",
};

export default function ThreatFeed() {
  const [feed,        setFeed]        = useState<ThreatFeedData | null>(null);
  const [loading,     setLoading]     = useState(true);
  const [error,       setError]       = useState<string | null>(null);
  const [newItems,    setNewItems]    = useState<string[]>([]);  // IDs of newly pushed items
  const [lastRefresh, setLastRefresh] = useState(new Date());
  const [autoRefresh, setAutoRefresh] = useState(true);

  const fetchFeed = useCallback(async () => {
    setError(null);
    try {
      const res = await fetch(`${API_BASE}/api/feed`);
      if (!res.ok) throw new Error("Backend offline");
      setFeed(await res.json());
      setLastRefresh(new Date());
    } catch (e: any) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { fetchFeed(); }, [fetchFeed]);

  // Auto-refresh every 60 seconds
  useEffect(() => {
    if (!autoRefresh) return;
    const t = setInterval(fetchFeed, 60000);
    return () => clearInterval(t);
  }, [fetchFeed, autoRefresh]);

  // WebSocket — highlight new items as they arrive live
  useSocket({
    threat_detected: (data) => {
      fetchFeed();
      if (data.input) setNewItems((prev) => [data.input.slice(0, 55), ...prev].slice(0, 5));
      setTimeout(() => setNewItems((prev) => prev.slice(1)), 5000);
    },
  });

  // Sparkline component (pure CSS bars)
  const Sparkline = ({ data }: { data: ThreatFeedData["hourlySpike"] }) => {
    const max = Math.max(...data.map((d) => d.total), 1);
    return (
      <div className="flex items-end gap-0.5 h-10">
        {data.map((d) => {
          const h  = Math.max((d.total   / max) * 38, 2);
          const ph = Math.max((d.phishing / max) * 38, d.phishing ? 1 : 0);
          return (
            <div key={d._id} className="flex-1 flex flex-col justify-end" style={{ height: 38 }}>
              <div style={{ height: ph,     background: "#ff4444", opacity: 0.8, borderRadius: "1px 1px 0 0" }} />
              <div style={{ height: h - ph, background: "var(--accent-green)", opacity: 0.35 }} />
            </div>
          );
        })}
      </div>
    );
  };

  if (error) return (
    <div className="min-h-full flex items-center justify-center px-6" style={{ background: "var(--bg-base)" }}>
      <div className="text-center">
        <XCircle className="size-10 mx-auto mb-3" style={{ color: "#ff4444" }} />
        <p className="text-sm mb-4" style={{ color: "var(--text-secondary)" }}>{error}</p>
        <button onClick={fetchFeed} className="btn-primary px-6 py-2.5 text-sm flex items-center gap-2 mx-auto"
                style={{ fontFamily: "'Syne', sans-serif", fontWeight: 700 }}>
          <RefreshCw className="size-4" /> Retry
        </button>
      </div>
    </div>
  );

  return (
    <div className="min-h-full py-10 px-6" style={{ background: "var(--bg-base)" }}>
      <div className="max-w-6xl mx-auto">

        {/* ── HEADER ── */}
        <motion.div initial={{ opacity:0, y:16 }} animate={{ opacity:1, y:0 }}
                    className="flex flex-col md:flex-row items-start justify-between gap-4 mb-10">
          <div>
            <div className="tag-green inline-flex mb-4">
              <Activity className="size-3" /> PHISHFEED™ LIVE
            </div>
            <h1 className="text-4xl font-bold mb-1"
                style={{ fontFamily:"'Syne', sans-serif", color:"var(--text-primary)" }}>
              Threat Intelligence Feed
            </h1>
            <p className="text-sm flex items-center gap-2"
               style={{ color:"var(--text-muted)", fontFamily:"'JetBrains Mono', monospace" }}>
              <Clock className="size-3" />
              Updated {lastRefresh.toLocaleTimeString()} · auto-refresh 60s
              <span className="ml-2 w-1.5 h-1.5 rounded-full safe-pulse inline-block"
                    style={{ background: "var(--accent-green)" }} />
            </p>
          </div>
          <div className="flex items-center gap-3">
            <button onClick={() => setAutoRefresh((v) => !v)}
                    className="btn-ghost px-4 py-2 text-sm flex items-center gap-2"
                    style={{ color: autoRefresh ? "var(--accent-green)" : "var(--text-muted)" }}>
              <Activity className="size-4" />
              {autoRefresh ? "Live" : "Paused"}
            </button>
            <button onClick={fetchFeed} disabled={loading}
                    className="btn-ghost px-4 py-2 text-sm flex items-center gap-2">
              <RefreshCw className={`size-4 ${loading ? "animate-spin" : ""}`} />
              Refresh
            </button>
          </div>
        </motion.div>

        {/* ── SUMMARY CARDS ── */}
        {feed && (
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
            {[
              { label:"Scans Today",      value: feed.summary.totalToday,      color:"var(--accent-green)", icon: Shield },
              { label:"Phishing Today",   value: feed.summary.phishingToday,   color:"#ff4444",             icon: XCircle },
              { label:"Threat Rate",      value: `${feed.summary.threatRate}%`, color:"#f5a623",             icon: TrendingUp },
              { label:"Active Campaigns", value: feed.summary.activeCampaigns, color:"#a78bfa",             icon: Brain },
            ].map((c, i) => (
              <motion.div key={c.label}
                initial={{ opacity:0, y:16 }} animate={{ opacity:1, y:0 }} transition={{ delay: i*0.07 }}
                className="card p-5 text-center" style={{ background:"var(--bg-card)" }}>
                <c.icon className="size-4 mx-auto mb-2" style={{ color: c.color }} />
                <div className="text-2xl font-bold"
                     style={{ color: c.color, fontFamily:"'Syne', sans-serif" }}>
                  {c.value}
                </div>
                <div className="text-xs mt-0.5 uppercase tracking-widest"
                     style={{ color:"var(--text-muted)", fontFamily:"'JetBrains Mono', monospace" }}>
                  {c.label}
                </div>
              </motion.div>
            ))}
          </div>
        )}

        {/* ── ROW 2: Sparkline + Trending Brands + Techniques ── */}
        {feed && (
          <div className="grid md:grid-cols-3 gap-4 mb-6">

            {/* 24h Sparkline */}
            <div className="card p-5" style={{ background:"var(--bg-card)" }}>
              <div className="flex items-center gap-2 mb-3">
                <TrendingUp className="size-4" style={{ color:"var(--accent-green)" }} />
                <span className="text-sm font-semibold"
                      style={{ color:"var(--text-primary)", fontFamily:"'Syne', sans-serif" }}>
                  24h Activity
                </span>
                <div className="flex gap-2 ml-auto text-xs"
                     style={{ fontFamily:"'JetBrains Mono', monospace" }}>
                  <span style={{ color:"#ff4444" }}>■ Phish</span>
                  <span style={{ color:"var(--accent-green)" }}>■ Total</span>
                </div>
              </div>
              {feed.hourlySpike.length > 0
                ? <Sparkline data={feed.hourlySpike} />
                : <div className="h-10 flex items-center justify-center text-xs"
                       style={{ color:"var(--text-muted)", fontFamily:"'JetBrains Mono', monospace" }}>
                    No activity yet
                  </div>
              }
            </div>

            {/* Trending Brands */}
            <div className="card p-5" style={{ background:"var(--bg-card)" }}>
              <div className="flex items-center gap-2 mb-4">
                <Shield className="size-4" style={{ color:"#ff4444" }} />
                <span className="text-sm font-semibold"
                      style={{ color:"var(--text-primary)", fontFamily:"'Syne', sans-serif" }}>
                  Most Targeted
                </span>
                <span className="text-xs ml-auto" style={{ color:"var(--text-muted)",
                      fontFamily:"'JetBrains Mono', monospace" }}>24h</span>
              </div>
              {feed.trendingBrands.length > 0 ? (
                <div className="space-y-2">
                  {feed.trendingBrands.slice(0, 5).map((b, i) => {
                    const max = feed.trendingBrands[0]?.count || 1;
                    return (
                      <div key={b.brand}>
                        <div className="flex items-center justify-between mb-1">
                          <div className="flex items-center gap-2">
                            <span className="text-xs w-4 text-center"
                                  style={{ color:"var(--text-muted)", fontFamily:"'JetBrains Mono', monospace" }}>
                              {i + 1}
                            </span>
                            <span className="text-xs capitalize font-medium"
                                  style={{ color:"var(--text-secondary)" }}>
                              {b.brand}
                            </span>
                          </div>
                          <span className="text-xs font-bold"
                                style={{ color:"#ff4444", fontFamily:"'JetBrains Mono', monospace" }}>
                            {b.count}
                          </span>
                        </div>
                        <div className="h-1 rounded-full" style={{ background:"var(--bg-border)" }}>
                          <div className="h-full rounded-full"
                               style={{ width:`${(b.count/max)*100}%`, background:"#ff4444", opacity:0.7 }} />
                        </div>
                      </div>
                    );
                  })}
                </div>
              ) : (
                <p className="text-xs" style={{ color:"var(--text-muted)", fontFamily:"'JetBrains Mono', monospace" }}>
                  No brand targeting yet
                </p>
              )}
            </div>

            {/* Attack Techniques */}
            <div className="card p-5" style={{ background:"var(--bg-card)" }}>
              <div className="flex items-center gap-2 mb-4">
                <Zap className="size-4" style={{ color:"#f5a623" }} />
                <span className="text-sm font-semibold"
                      style={{ color:"var(--text-primary)", fontFamily:"'Syne', sans-serif" }}>
                  Attack Techniques
                </span>
                <span className="text-xs ml-auto" style={{ color:"var(--text-muted)",
                      fontFamily:"'JetBrains Mono', monospace" }}>24h</span>
              </div>
              {feed.trendingTechniques.length > 0 ? (
                <div className="space-y-2">
                  {feed.trendingTechniques.map((t) => {
                    const max   = feed.trendingTechniques[0]?.count || 1;
                    const label = TECHNIQUE_LABELS[t.technique] || t.technique.replace(/_/g, " ");
                    return (
                      <div key={t.technique} className="flex items-center justify-between gap-2">
                        <span className="text-xs truncate capitalize"
                              style={{ color:"var(--text-secondary)" }}>
                          {label}
                        </span>
                        <div className="flex items-center gap-2 flex-shrink-0">
                          <div className="w-12 h-1 rounded-full" style={{ background:"var(--bg-border)" }}>
                            <div className="h-full rounded-full"
                                 style={{ width:`${(t.count/max)*100}%`, background:"#f5a623" }} />
                          </div>
                          <span className="text-xs font-bold w-4 text-right"
                                style={{ color:"#f5a623", fontFamily:"'JetBrains Mono', monospace" }}>
                            {t.count}
                          </span>
                        </div>
                      </div>
                    );
                  })}
                </div>
              ) : (
                <p className="text-xs" style={{ color:"var(--text-muted)", fontFamily:"'JetBrains Mono', monospace" }}>
                  No technique data yet
                </p>
              )}
            </div>
          </div>
        )}

        {/* ── LIVE THREAT FEED TABLE ── */}
        {feed && (
          <motion.div initial={{ opacity:0, y:16 }} animate={{ opacity:1, y:0 }} transition={{ delay:0.3 }}
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
                  phishfeed_live.log — {feed.recentThreats.length} threats
                </span>
              </div>
              <div className="flex items-center gap-1.5">
                <div className="w-1.5 h-1.5 rounded-full safe-pulse" style={{ background:"var(--accent-green)" }} />
                <span className="text-xs" style={{ color:"var(--text-muted)", fontFamily:"'JetBrains Mono', monospace" }}>
                  live
                </span>
              </div>
            </div>

            {feed.recentThreats.length === 0 ? (
              <div className="py-16 text-center">
                <Globe className="size-10 mx-auto mb-3" style={{ color:"var(--text-muted)" }} />
                <p className="text-sm font-semibold"
                   style={{ color:"var(--text-secondary)", fontFamily:"'Syne', sans-serif" }}>
                  Feed is clean
                </p>
                <p className="text-xs mt-1" style={{ color:"var(--text-muted)" }}>
                  No threats detected recently. Start scanning to populate the feed.
                </p>
              </div>
            ) : (
              <div className="divide-y" style={{ borderColor:"rgba(30,39,54,0.5)" }}>
                <AnimatePresence>
                  {feed.recentThreats.map((item, i) => {
                    const isNew = newItems.includes(item.input);
                    return (
                      <motion.div key={item.id}
                        initial={{ opacity: 0, x: -10 }} animate={{ opacity: 1, x: 0 }}
                        transition={{ delay: i * 0.03 }}
                        className="px-5 py-3.5 flex items-center gap-4 transition-all"
                        style={{
                          background: isNew
                            ? `${statusBg(item.status)}` : "transparent",
                          borderLeft: isNew
                            ? `3px solid ${statusColor(item.status)}` : "3px solid transparent",
                        }}>

                        {/* Status badge */}
                        <span className="flex-shrink-0 text-xs font-bold px-2 py-0.5 rounded w-24 text-center"
                              style={{ color:statusColor(item.status), background:statusBg(item.status),
                                       border:`1px solid ${statusBorder(item.status)}`,
                                       fontFamily:"'JetBrains Mono', monospace", letterSpacing:"0.06em" }}>
                          {item.status.toUpperCase()}
                        </span>

                        {/* Input */}
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-1.5 mb-0.5">
                            <span style={{ color:"var(--text-muted)" }}>
                              <InputIcon type={item.inputType} />
                            </span>
                            <p className="text-xs truncate font-mono"
                               style={{ color:"var(--text-primary)", fontFamily:"'JetBrains Mono', monospace" }}>
                              {item.input}
                            </p>
                          </div>
                          {item.issue && (
                            <p className="text-xs truncate"
                               style={{ color:"var(--text-muted)" }}>
                              {item.issue}
                            </p>
                          )}
                        </div>

                        {/* DNA tag */}
                        {item.fingerprint && (
                          <span className="flex-shrink-0 text-xs px-2 py-0.5 rounded hidden md:inline"
                                style={{ color:"#a78bfa", background:"rgba(163,120,251,0.08)",
                                         border:"1px solid rgba(163,120,251,0.2)",
                                         fontFamily:"'JetBrains Mono', monospace" }}>
                            🧬 #{item.fingerprint}
                          </span>
                        )}

                        {/* Score */}
                        <div className="flex-shrink-0 text-right">
                          <div className="text-sm font-bold"
                               style={{ color:statusColor(item.status), fontFamily:"'JetBrains Mono', monospace" }}>
                            {item.riskScore}
                          </div>
                          <div className="text-xs" style={{ color:"var(--text-muted)", fontSize:9 }}>/ 100</div>
                        </div>

                        {/* Time */}
                        <div className="flex-shrink-0 text-xs hidden lg:block"
                             style={{ color:"var(--text-muted)", fontFamily:"'JetBrains Mono', monospace" }}>
                          {new Date(item.createdAt).toLocaleTimeString()}
                        </div>
                      </motion.div>
                    );
                  })}
                </AnimatePresence>
              </div>
            )}
          </motion.div>
        )}

        {/* ── TRENDING TLDs ── */}
        {feed && feed.trendingTLDs.length > 0 && (
          <motion.div initial={{ opacity:0, y:12 }} animate={{ opacity:1, y:0 }} transition={{ delay:0.4 }}
                      className="mt-4 card p-5" style={{ background:"var(--bg-card)" }}>
            <div className="flex items-center gap-2 mb-4">
              <Globe className="size-4" style={{ color:"var(--accent-cyan)" }} />
              <span className="text-sm font-semibold"
                    style={{ color:"var(--text-primary)", fontFamily:"'Syne', sans-serif" }}>
                Trending Malicious TLDs
              </span>
              <span className="text-xs ml-2" style={{ color:"var(--text-muted)",
                    fontFamily:"'JetBrains Mono', monospace" }}>last 7 days</span>
            </div>
            <div className="flex flex-wrap gap-2">
              {feed.trendingTLDs.map((t) => (
                <span key={t.tld}
                      className="text-xs px-3 py-1.5 rounded-lg font-bold"
                      style={{ fontFamily:"'JetBrains Mono', monospace", color:"var(--accent-cyan)",
                               background:"rgba(0,212,255,0.08)", border:"1px solid rgba(0,212,255,0.2)" }}>
                  {t.tld}
                  <span className="ml-2 font-normal" style={{ color:"var(--text-muted)" }}>
                    ×{t.count}
                  </span>
                </span>
              ))}
            </div>
          </motion.div>
        )}

      </div>
    </div>
  );
}