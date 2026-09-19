// FILE: src/pages/CampaignTracker.tsx

import { useEffect, useState, useCallback } from "react";
import { motion, AnimatePresence } from "motion/react";
import {
  Brain,
  RefreshCw,
  Activity,
  Clock,
  Shield,
  ChevronDown,
  ChevronUp,
  Mail,
  Plus,
} from "lucide-react";
import { API_BASE } from "../config";
import { useSocket } from "../hooks/useSocket";
import { useRole } from "../hooks/useRole";

// ── Auth header helper ────────────────────────────────────────
const authHeader = () => ({
  "Content-Type": "application/json",
  Authorization: `Bearer ${localStorage.getItem("pg_token")}`,
});

interface Campaign {
  _id: string;
  name?: string;
  count: number;
  brand: string;
  technique: string;
  tld: string;
  severity: string;
  lastSeen: string;
  firstSeen: string;
}

interface CampaignDetail {
  fingerprint: string;
  totalScans: number;
  firstSeen: string;
  lastSeen: string;
  timeline: { hour: string; count: number; maxScore: number }[];
  predictedTarget: string | null;
  uniqueIPs: number;
  peakScore: number;
}

const SEV_COLOR = (s: string) =>
  s === "critical"
    ? "#ff4444"
    : s === "high"
      ? "#f97316"
      : s === "medium"
        ? "#f5a623"
        : "#00ff88";

const TECHNIQUE_LABEL = (t: string) => (t || "").replace(/_/g, " ");

function timeAgo(iso: string) {
  const diff = Date.now() - new Date(iso).getTime();
  const m = Math.floor(diff / 60000);
  const h = Math.floor(m / 60);
  const d = Math.floor(h / 24);
  if (d > 0) return `${d}d ago`;
  if (h > 0) return `${h}h ago`;
  if (m > 0) return `${m}m ago`;
  return "just now";
}

function isActive(lastSeen: string) {
  return Date.now() - new Date(lastSeen).getTime() < 2 * 60 * 60 * 1000;
}

export default function CampaignTracker() {
  // ── URL campaign state ──────────────────────────────────────
  const [campaigns, setCampaigns] = useState<Campaign[]>([]);
  const [loading, setLoading] = useState(true);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [detail, setDetail] = useState<Record<string, CampaignDetail>>({});
  const [detailLoad, setDetailLoad] = useState<string | null>(null);
  const [filterSev, setFilterSev] = useState<string>("all");
  const [lastRefresh, setLastRefresh] = useState(new Date());

  // ── Email case state ────────────────────────────────────────
  const { canWrite } = useRole();
  const [activeTab, setActiveTab] = useState<"url" | "email">("url");
  const [emailCases, setEmailCases] = useState<any[]>([]);
  const [emailCaseStats, setEmailCaseStats] = useState<any>(null);
  const [emailClusters, setEmailClusters] = useState<any[]>([]);
  const [caseLoading, setCaseLoading] = useState(false);
  const [expandedCase, setExpandedCase] = useState<string | null>(null);
  const [caseDetail, setCaseDetail] = useState<Record<string, any>>({});
  const [showCreateCase, setShowCreateCase] = useState(false);
  const [createForm, setCreateForm] = useState({
    name: "",
    description: "",
    clusterId: "",
    campaignType: "phishing",
    priority: "medium",
    severity: "3",
    targetBrands: "",
  });
  const [filterStatus, setFilterStatus] = useState("all");
  const [caseSearch, setCaseSearch] = useState("");

  // ── URL campaign fetchers ───────────────────────────────────
  const fetchCampaigns = useCallback(async () => {
    setLoading(true);
    try {
      const res = await fetch(`${API_BASE}/api/scan/dna/stats`);
      if (res.ok) {
        const data = await res.json();
        setCampaigns(data.topFingerprints || []);
        setLastRefresh(new Date());
      }
    } catch {
      /* offline */
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchCampaigns();
  }, [fetchCampaigns]);

  useSocket({ threat_detected: () => fetchCampaigns() });

  const fetchDetail = async (fingerprint: string) => {
    if (detail[fingerprint]) {
      setExpanded(expanded === fingerprint ? null : fingerprint);
      return;
    }
    setDetailLoad(fingerprint);
    try {
      const res = await fetch(
        `${API_BASE}/api/scan/dna/campaign/${fingerprint}`,
      );
      if (res.ok) {
        const d = await res.json();
        setDetail((prev) => ({ ...prev, [fingerprint]: d }));
      }
    } catch {
      /* offline */
    } finally {
      setDetailLoad(null);
    }
    setExpanded(fingerprint);
  };

  // ── Email case fetchers ─────────────────────────────────────
  const fetchEmailCases = useCallback(async () => {
    setCaseLoading(true);
    try {
      const params = new URLSearchParams({
        ...(filterStatus !== "all" ? { status: filterStatus } : {}),
        ...(caseSearch ? { search: caseSearch } : {}),
        limit: "50",
      });
      const [casesRes, statsRes, clustersRes] = await Promise.all([
        fetch(`${API_BASE}/api/email-cases?${params}`, {
          headers: authHeader(),
        }),
        fetch(`${API_BASE}/api/email-cases/stats`, { headers: authHeader() }),
        fetch(`${API_BASE}/api/email-clusters?minSize=2`, {
          headers: authHeader(),
        }),
      ]);
      if (casesRes.ok) {
        const d = await casesRes.json();
        setEmailCases(d.cases || []);
      }
      if (statsRes.ok) setEmailCaseStats(await statsRes.json());
      if (clustersRes.ok) {
        const d = await clustersRes.json();
        setEmailClusters(d.clusters || []);
      }
    } catch {
      /* offline */
    } finally {
      setCaseLoading(false);
    }
  }, [filterStatus, caseSearch]);

  useEffect(() => {
    if (activeTab === "email") fetchEmailCases();
  }, [activeTab, fetchEmailCases]);

  const fetchCaseDetail = async (caseId: string) => {
    if (caseDetail[caseId]) {
      setExpandedCase(expandedCase === caseId ? null : caseId);
      return;
    }
    try {
      const res = await fetch(`${API_BASE}/api/email-cases/${caseId}`, {
        headers: authHeader(),
      });
      if (res.ok) {
        const d = await res.json();
        setCaseDetail((prev) => ({ ...prev, [caseId]: d }));
      }
    } catch {
      /* offline */
    }
    setExpandedCase(caseId);
  };

  const createEmailCase = async () => {
    if (!createForm.name.trim()) return;
    try {
      const res = await fetch(`${API_BASE}/api/email-cases`, {
        method: "POST",
        headers: authHeader(),
        body: JSON.stringify({
          ...createForm,
          severity: Number(createForm.severity),
          targetBrands: createForm.targetBrands
            .split(",")
            .map((s) => s.trim())
            .filter(Boolean),
        }),
      });
      if (res.ok) {
        setShowCreateCase(false);
        setCreateForm({
          name: "",
          description: "",
          clusterId: "",
          campaignType: "phishing",
          priority: "medium",
          severity: "3",
          targetBrands: "",
        });
        fetchEmailCases();
      }
    } catch {
      /* offline */
    }
  };

  const updateCaseStatus = async (
    caseId: string,
    status: string,
    note?: string,
  ) => {
    try {
      await fetch(`${API_BASE}/api/email-cases/${caseId}`, {
        method: "PATCH",
        headers: authHeader(),
        body: JSON.stringify({ status, note }),
      });
      // Invalidate cached detail so it reloads on next expand
      setCaseDetail((prev) => {
        const next = { ...prev };
        delete next[caseId];
        return next;
      });
      fetchEmailCases();
    } catch {
      /* offline */
    }
  };

  // ── Derived ─────────────────────────────────────────────────
  const filtered =
    filterSev === "all"
      ? campaigns
      : campaigns.filter((c) => c.severity === filterSev);

  const activeCampaigns = campaigns.filter((c) => isActive(c.lastSeen)).length;

  // ── Render ───────────────────────────────────────────────────
  return (
    <div
      className="min-h-full py-10 px-6"
      style={{ background: "var(--bg-base)" }}
    >
      <div className="max-w-5xl mx-auto">
        {/* Header */}
        <motion.div
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          className="flex items-start justify-between mb-6 flex-wrap gap-4"
        >
          <div>
            <div className="tag-green inline-flex mb-4">
              <Brain className="size-3" /> CAMPAIGN TRACKER
            </div>
            <h1
              className="text-4xl font-bold mb-1"
              style={{
                fontFamily: "'Syne', sans-serif",
                color: "var(--text-primary)",
              }}
            >
              Phishing Campaign Board
            </h1>
            <p
              className="text-sm flex items-center gap-3"
              style={{
                color: "var(--text-muted)",
                fontFamily: "'JetBrains Mono', monospace",
              }}
            >
              <Clock className="size-3" />
              {lastRefresh.toLocaleTimeString()}
              {activeCampaigns > 0 && (
                <span
                  className="flex items-center gap-1.5 text-xs px-2 py-0.5 rounded"
                  style={{
                    color: "#ff4444",
                    background: "rgba(255,68,68,0.1)",
                    border: "1px solid rgba(255,68,68,0.3)",
                  }}
                >
                  <div
                    className="w-1.5 h-1.5 rounded-full threat-pulse"
                    style={{ background: "#ff4444" }}
                  />
                  {activeCampaigns} ACTIVE
                </span>
              )}
            </p>
          </div>
          <button
            onClick={activeTab === "url" ? fetchCampaigns : fetchEmailCases}
            disabled={loading || caseLoading}
            className="btn-ghost flex items-center gap-2 px-4 py-2.5 text-sm"
          >
            <RefreshCw
              className={`size-4 ${loading || caseLoading ? "animate-spin" : ""}`}
            />{" "}
            Refresh
          </button>
        </motion.div>

        {/* ── Tab bar ─────────────────────────────────────────── */}
        <div
          className="flex gap-1 p-1 rounded-xl mb-8"
          style={{
            background: "var(--bg-elevated)",
            border: "1px solid var(--bg-border)",
          }}
        >
          <button
            onClick={() => setActiveTab("url")}
            className="flex-1 flex items-center justify-center gap-1.5 py-2 rounded-lg text-xs font-medium transition-all"
            style={{
              background:
                activeTab === "url" ? "var(--accent-subtle)" : "transparent",
              color:
                activeTab === "url" ? "var(--accent)" : "var(--text-muted)",
              border:
                activeTab === "url"
                  ? "1px solid var(--accent-border)"
                  : "1px solid transparent",
            }}
          >
            <Brain className="size-3.5" /> URL Campaigns
          </button>
          <button
            onClick={() => setActiveTab("email")}
            className="flex-1 flex items-center justify-center gap-1.5 py-2 rounded-lg text-xs font-medium transition-all"
            style={{
              background:
                activeTab === "email" ? "var(--accent-subtle)" : "transparent",
              color:
                activeTab === "email" ? "var(--accent)" : "var(--text-muted)",
              border:
                activeTab === "email"
                  ? "1px solid var(--accent-border)"
                  : "1px solid transparent",
            }}
          >
            <Mail className="size-3.5" /> Email Cases
            {(emailCaseStats?.open ?? 0) > 0 && (
              <span
                className="text-[9px] px-1.5 py-0.5 rounded-full font-bold"
                style={{ color: "#fff", background: "#f87171" }}
              >
                {emailCaseStats.open}
              </span>
            )}
          </button>
        </div>

        {/* ══════════════════════════════════════════════════════
            TAB: URL Campaigns (existing content)
        ══════════════════════════════════════════════════════ */}
        {activeTab === "url" && (
          <>
            {/* Summary stats */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
              {[
                {
                  label: "Total Campaigns",
                  value: campaigns.length,
                  color: "var(--accent-green)",
                },
                {
                  label: "Active (2h)",
                  value: activeCampaigns,
                  color: "#ff4444",
                },
                {
                  label: "Critical",
                  value: campaigns.filter((c) => c.severity === "critical")
                    .length,
                  color: "#ff4444",
                },
                {
                  label: "Unique Brands",
                  value: new Set(
                    campaigns
                      .map((c) => c.brand)
                      .filter((b) => b !== "unknown"),
                  ).size,
                  color: "var(--accent-cyan)",
                },
              ].map((s, i) => (
                <motion.div
                  key={s.label}
                  initial={{ opacity: 0, y: 12 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: i * 0.06 }}
                  className="card p-4 text-center"
                  style={{ background: "var(--bg-card)" }}
                >
                  <div
                    className="text-2xl font-bold"
                    style={{ color: s.color, fontFamily: "'Syne', sans-serif" }}
                  >
                    {s.value}
                  </div>
                  <div
                    className="text-xs mt-0.5 uppercase tracking-widest"
                    style={{
                      color: "var(--text-muted)",
                      fontFamily: "'JetBrains Mono', monospace",
                    }}
                  >
                    {s.label}
                  </div>
                </motion.div>
              ))}
            </div>

            {/* Filter */}
            <div className="flex items-center gap-2 mb-4 flex-wrap">
              {["all", "critical", "high", "medium", "low"].map((f) => (
                <button
                  key={f}
                  onClick={() => setFilterSev(f)}
                  className="text-xs px-3 py-1.5 rounded-lg transition-all capitalize"
                  style={{
                    fontFamily: "'JetBrains Mono', monospace",
                    background:
                      filterSev === f ? SEV_COLOR(f) : "var(--bg-card)",
                    color: filterSev === f ? "#080b10" : "var(--text-muted)",
                    border: `1px solid ${filterSev === f ? SEV_COLOR(f) : "var(--bg-border)"}`,
                    fontWeight: filterSev === f ? 700 : 400,
                  }}
                >
                  {f === "all" ? "All" : f}
                </button>
              ))}
            </div>

            {/* Campaign cards */}
            {loading && campaigns.length === 0 ? (
              <div className="py-16 text-center">
                <div
                  className="w-8 h-8 border-2 rounded-full animate-spin mx-auto mb-4"
                  style={{
                    borderColor: "var(--accent-green)",
                    borderTopColor: "transparent",
                  }}
                />
                <p
                  style={{
                    color: "var(--text-muted)",
                    fontFamily: "'JetBrains Mono', monospace",
                    fontSize: 12,
                  }}
                >
                  Loading campaigns...
                </p>
              </div>
            ) : filtered.length === 0 ? (
              <div
                className="card py-16 text-center"
                style={{ background: "var(--bg-card)" }}
              >
                <Shield
                  className="size-10 mx-auto mb-3"
                  style={{ color: "var(--text-muted)" }}
                />
                <p
                  className="text-sm font-semibold"
                  style={{
                    color: "var(--text-secondary)",
                    fontFamily: "'Syne', sans-serif",
                  }}
                >
                  No campaigns yet
                </p>
                <p
                  className="text-xs mt-1"
                  style={{ color: "var(--text-muted)" }}
                >
                  Scan phishing URLs to build campaign clusters via PhishDNA
                </p>
              </div>
            ) : (
              <div className="space-y-3">
                {filtered.map((c, i) => {
                  const active = isActive(c.lastSeen);
                  const sevColor = SEV_COLOR(c.severity);
                  const isExpanded = expanded === c._id;
                  const d = detail[c._id];

                  return (
                    <motion.div
                      key={c._id}
                      initial={{ opacity: 0, y: 8 }}
                      animate={{ opacity: 1, y: 0 }}
                      transition={{ delay: i * 0.04 }}
                      className="card overflow-hidden"
                      style={{
                        background: "var(--bg-card)",
                        borderColor: active
                          ? `${sevColor}40`
                          : "var(--bg-border)",
                        boxShadow: active ? `0 0 20px ${sevColor}08` : "none",
                      }}
                    >
                      <div
                        className="px-5 py-4 flex items-center gap-4 cursor-pointer"
                        onClick={() => fetchDetail(c._id)}
                      >
                        <div className="flex flex-col items-center gap-1.5 flex-shrink-0">
                          <div
                            className={`w-3 h-3 rounded-full ${active ? "threat-pulse" : ""}`}
                            style={{
                              background: active
                                ? sevColor
                                : "var(--bg-border)",
                            }}
                          />
                          <span
                            className="text-xs"
                            style={{
                              color: active ? sevColor : "var(--text-muted)",
                              fontFamily: "'JetBrains Mono', monospace",
                              fontSize: 8,
                            }}
                          >
                            {active ? "LIVE" : "DEAD"}
                          </span>
                        </div>

                        <div className="flex-shrink-0">
                          <div
                            className="text-sm font-bold px-2.5 py-1.5 rounded-lg"
                            style={{
                              color: "#a78bfa",
                              background: "rgba(163,120,251,0.1)",
                              border: "1px solid rgba(163,120,251,0.25)",
                              fontFamily: "'JetBrains Mono', monospace",
                            }}
                          >
                            {c.name ||
                              c._id?.substring(0, 12) ||
                              "Unknown Campaign"}
                          </div>
                        </div>

                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 mb-1 flex-wrap">
                            <span
                              className="text-sm font-semibold capitalize"
                              style={{
                                color: "var(--text-primary)",
                                fontFamily: "'Syne', sans-serif",
                              }}
                            >
                              {TECHNIQUE_LABEL(c.technique)}
                              {c.brand &&
                                c.brand !== "unknown" &&
                                ` → ${c.brand}`}
                            </span>
                            <span
                              className="text-xs px-2 py-0.5 rounded font-bold uppercase"
                              style={{
                                color: sevColor,
                                background: `${sevColor}12`,
                                border: `1px solid ${sevColor}30`,
                                fontFamily: "'JetBrains Mono', monospace",
                              }}
                            >
                              {c.severity}
                            </span>
                            {c.tld &&
                              c.tld !== "unknown" &&
                              c.tld !== "n/a" && (
                                <span
                                  className="text-xs px-2 py-0.5 rounded"
                                  style={{
                                    color: "var(--accent-cyan)",
                                    background: "rgba(0,212,255,0.06)",
                                    border: "1px solid rgba(0,212,255,0.15)",
                                    fontFamily: "'JetBrains Mono', monospace",
                                  }}
                                >
                                  {c.tld}
                                </span>
                              )}
                          </div>
                          <div
                            className="flex items-center gap-4 text-xs flex-wrap"
                            style={{
                              fontFamily: "'JetBrains Mono', monospace",
                              color: "var(--text-muted)",
                            }}
                          >
                            <span className="flex items-center gap-1">
                              <Activity className="size-3" /> {c.count}{" "}
                              detections
                            </span>
                            <span>First: {timeAgo(c.firstSeen)}</span>
                            <span>Last: {timeAgo(c.lastSeen)}</span>
                          </div>
                        </div>

                        <div className="flex items-center gap-3 flex-shrink-0">
                          <div className="text-right">
                            <div
                              className="text-2xl font-black"
                              style={{
                                color: sevColor,
                                fontFamily: "'Syne', sans-serif",
                              }}
                            >
                              {c.count}
                            </div>
                            <div
                              className="text-xs"
                              style={{
                                color: "var(--text-muted)",
                                fontFamily: "'JetBrains Mono', monospace",
                              }}
                            >
                              hits
                            </div>
                          </div>
                          {detailLoad === c._id ? (
                            <div
                              className="w-4 h-4 border-2 rounded-full animate-spin"
                              style={{
                                borderColor: "var(--accent-green)",
                                borderTopColor: "transparent",
                              }}
                            />
                          ) : isExpanded ? (
                            <ChevronUp
                              className="size-4"
                              style={{ color: "var(--accent-green)" }}
                            />
                          ) : (
                            <ChevronDown
                              className="size-4"
                              style={{ color: "var(--text-muted)" }}
                            />
                          )}
                        </div>
                      </div>

                      {/* Expanded detail */}
                      <AnimatePresence>
                        {isExpanded && d && (
                          <motion.div
                            initial={{ opacity: 0, height: 0 }}
                            animate={{ opacity: 1, height: "auto" }}
                            exit={{ opacity: 0, height: 0 }}
                            className="border-t px-5 py-4"
                            style={{
                              borderColor: "var(--bg-border)",
                              background: "rgba(0,0,0,0.2)",
                            }}
                          >
                            <div className="grid md:grid-cols-3 gap-4 mb-4">
                              {[
                                {
                                  label: "Unique IPs",
                                  value: d.uniqueIPs,
                                  color: "var(--accent-cyan)",
                                },
                                {
                                  label: "Peak Risk Score",
                                  value: `${d.peakScore}/100`,
                                  color: sevColor,
                                },
                                {
                                  label: "Predicted Target",
                                  value: d.predictedTarget || "Unknown",
                                  color: "#a78bfa",
                                },
                              ].map(({ label, value, color }) => (
                                <div
                                  key={label}
                                  className="rounded-xl px-4 py-3"
                                  style={{
                                    background: "var(--bg-elevated)",
                                    border: "1px solid var(--bg-border)",
                                  }}
                                >
                                  <div
                                    className="text-xs mb-1"
                                    style={{
                                      color: "var(--text-muted)",
                                      fontFamily: "'JetBrains Mono', monospace",
                                    }}
                                  >
                                    {label}
                                  </div>
                                  <div
                                    className="text-sm font-bold capitalize"
                                    style={{
                                      color,
                                      fontFamily: "'Syne', sans-serif",
                                    }}
                                  >
                                    {value}
                                  </div>
                                </div>
                              ))}
                            </div>

                            {d.timeline?.length > 0 && (
                              <div>
                                <div
                                  className="text-xs mb-2"
                                  style={{
                                    color: "var(--text-muted)",
                                    fontFamily: "'JetBrains Mono', monospace",
                                  }}
                                >
                                  ACTIVITY TIMELINE
                                </div>
                                <div className="flex items-end gap-1 h-10">
                                  {d.timeline.map((t: any, ti: number) => {
                                    const max = Math.max(
                                      ...d.timeline.map((x: any) => x.count),
                                      1,
                                    );
                                    const h = Math.max((t.count / max) * 36, 2);
                                    return (
                                      <div
                                        key={ti}
                                        className="flex-1 rounded-t-sm"
                                        style={{
                                          height: h,
                                          background: sevColor,
                                          opacity: 0.6,
                                        }}
                                        title={`${t.hour}: ${t.count} detections`}
                                      />
                                    );
                                  })}
                                </div>
                              </div>
                            )}
                          </motion.div>
                        )}
                      </AnimatePresence>
                    </motion.div>
                  );
                })}
              </div>
            )}
          </>
        )}

        {/* ══════════════════════════════════════════════════════
            TAB: Email Cases
        ══════════════════════════════════════════════════════ */}
        {activeTab === "email" && (
          <div>
            {/* Stats */}
            {emailCaseStats && (
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-6">
                {[
                  {
                    label: "Total Cases",
                    value: emailCaseStats.total || 0,
                    color: "var(--accent)",
                  },
                  {
                    label: "Open",
                    value: emailCaseStats.open || 0,
                    color: "#f87171",
                  },
                  {
                    label: "Investigating",
                    value: emailCaseStats.investigating || 0,
                    color: "#fbbf24",
                  },
                  {
                    label: "Email Clusters",
                    value: emailClusters.length,
                    color: "#a78bfa",
                  },
                ].map((s) => (
                  <div key={s.label} className="card p-4 stat-card">
                    <div
                      className="text-2xl font-bold font-display"
                      style={{ color: s.color }}
                    >
                      {s.value}
                    </div>
                    <div className="label-caps mt-1">{s.label}</div>
                  </div>
                ))}
              </div>
            )}

            {/* Auto-detected clusters awaiting promotion */}
            {emailClusters.filter(
              (c) => !emailCases.some((ec) => ec.clusterId === c.clusterId),
            ).length > 0 && (
              <div className="card p-4 mb-4">
                <div
                  className="text-xs font-bold mb-3"
                  style={{
                    color: "#fbbf24",
                    fontFamily: "var(--font-mono)",
                    textTransform: "uppercase",
                  }}
                >
                  ⚡ Auto-Detected Email Clusters — Promote to Case
                </div>
                <div className="space-y-2">
                  {emailClusters
                    .filter(
                      (c) =>
                        !emailCases.some((ec) => ec.clusterId === c.clusterId),
                    )
                    .slice(0, 5)
                    .map((cluster: any) => (
                      <div
                        key={cluster.clusterId}
                        className="flex items-center gap-3 px-4 py-3 rounded-xl"
                        style={{
                          background: "var(--bg-elevated)",
                          border: "1px solid var(--bg-border)",
                        }}
                      >
                        <div className="flex-1 min-w-0">
                          <div
                            className="text-sm font-semibold truncate"
                            style={{ color: "var(--text-primary)" }}
                          >
                            {cluster.label}
                          </div>
                          <div
                            className="text-xs mt-0.5"
                            style={{
                              color: "var(--text-muted)",
                              fontFamily: "var(--font-mono)",
                            }}
                          >
                            {cluster.scanCount} scans · {cluster.phishingCount}{" "}
                            phishing · {cluster.sourceIPs?.length} unique IP
                            {cluster.sourceIPs?.length !== 1 ? "s" : ""} · Last:{" "}
                            {new Date(cluster.lastSeen).toLocaleDateString()}
                          </div>
                        </div>
                        <div
                          className="text-xs px-2 py-0.5 rounded font-bold capitalize"
                          style={{
                            color:
                              cluster.threatLevel === "critical"
                                ? "#f87171"
                                : cluster.threatLevel === "high"
                                  ? "#fb923c"
                                  : "#fbbf24",
                            background:
                              cluster.threatLevel === "critical"
                                ? "rgba(248,113,113,0.1)"
                                : "rgba(251,146,60,0.1)",
                            fontFamily: "var(--font-mono)",
                          }}
                        >
                          {cluster.threatLevel}
                        </div>
                        {canWrite && (
                          <button
                            onClick={() => {
                              setCreateForm((f) => ({
                                ...f,
                                name: cluster.label,
                                clusterId: cluster.clusterId,
                              }));
                              setShowCreateCase(true);
                            }}
                            className="text-xs px-3 py-1.5 rounded-lg flex-shrink-0"
                            style={{
                              background: "var(--accent)",
                              color: "#fff",
                            }}
                          >
                            + Case
                          </button>
                        )}
                      </div>
                    ))}
                </div>
              </div>
            )}

            {/* Filters + search */}
            <div className="flex gap-2 mb-4 flex-wrap">
              <div
                className="flex gap-1 p-1 rounded-xl"
                style={{
                  background: "var(--bg-elevated)",
                  border: "1px solid var(--bg-border)",
                }}
              >
                {["all", "open", "investigating", "escalated", "closed"].map(
                  (s) => (
                    <button
                      key={s}
                      onClick={() => setFilterStatus(s)}
                      className="px-3 py-1.5 rounded-lg text-xs capitalize transition-all"
                      style={{
                        background:
                          filterStatus === s
                            ? "var(--accent-subtle)"
                            : "transparent",
                        color:
                          filterStatus === s
                            ? "var(--accent)"
                            : "var(--text-muted)",
                      }}
                    >
                      {s}
                    </button>
                  ),
                )}
              </div>
              <input
                value={caseSearch}
                onChange={(e) => setCaseSearch(e.target.value)}
                placeholder="Search cases..."
                className="flex-1 min-w-32 px-3 py-1.5 rounded-xl text-xs"
                style={{
                  background: "var(--bg-elevated)",
                  border: "1px solid var(--bg-border)",
                  color: "var(--text-primary)",
                  outline: "none",
                }}
              />
              {canWrite && (
                <button
                  onClick={() => setShowCreateCase(true)}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-semibold"
                  style={{ background: "var(--accent)", color: "#fff" }}
                >
                  <Plus className="size-3.5" /> New Case
                </button>
              )}
            </div>

            {/* Cases list */}
            {caseLoading ? (
              <div className="flex items-center justify-center py-16">
                <RefreshCw
                  className="size-5 animate-spin"
                  style={{ color: "var(--text-muted)" }}
                />
              </div>
            ) : emailCases.length === 0 ? (
              <div className="text-center py-16">
                <Mail
                  className="size-10 mx-auto mb-3"
                  style={{ color: "var(--text-muted)" }}
                />
                <p className="text-sm" style={{ color: "var(--text-muted)" }}>
                  No email cases yet
                </p>
                <p
                  className="text-xs mt-1"
                  style={{ color: "var(--text-muted)" }}
                >
                  Scan email headers to auto-detect clusters, then promote them
                  to cases
                </p>
              </div>
            ) : (
              <div className="space-y-2">
                {emailCases.map((ec: any) => {
                  const isExp = expandedCase === ec.caseId;
                  const det = caseDetail[ec.caseId];
                  const sc =
                    ec.status === "open"
                      ? "#60a5fa"
                      : ec.status === "investigating"
                        ? "#fbbf24"
                        : ec.status === "escalated"
                          ? "#f87171"
                          : ec.status === "closed"
                            ? "#34d399"
                            : "#64748b";
                  const pc =
                    ec.priority === "critical"
                      ? "#f87171"
                      : ec.priority === "high"
                        ? "#fb923c"
                        : ec.priority === "medium"
                          ? "#fbbf24"
                          : "#64748b";

                  return (
                    <div key={ec.caseId} className="card overflow-hidden">
                      {/* Case header row */}
                      <div
                        className="px-5 py-4 flex items-center gap-3 cursor-pointer"
                        onClick={() => fetchCaseDetail(ec.caseId)}
                      >
                        <div
                          className="w-2 h-2 rounded-full flex-shrink-0"
                          style={{ background: sc }}
                        />
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 mb-0.5 flex-wrap">
                            <span
                              className="text-xs font-bold"
                              style={{
                                color: "var(--accent)",
                                fontFamily: "var(--font-mono)",
                              }}
                            >
                              {ec.caseId}
                            </span>
                            <span
                              className="text-[9px] px-1.5 py-0.5 rounded uppercase font-bold"
                              style={{
                                color: sc,
                                background: `${sc}12`,
                                border: `1px solid ${sc}25`,
                                fontFamily: "var(--font-mono)",
                              }}
                            >
                              {ec.status}
                            </span>
                            <span
                              className="text-[9px] px-1.5 py-0.5 rounded uppercase font-bold"
                              style={{
                                color: pc,
                                background: `${pc}12`,
                                border: `1px solid ${pc}25`,
                                fontFamily: "var(--font-mono)",
                              }}
                            >
                              {ec.priority}
                            </span>
                            <span
                              className="text-xs capitalize"
                              style={{ color: "var(--text-muted)" }}
                            >
                              {ec.campaignType?.replace(/_/g, " ")}
                            </span>
                          </div>
                          <div
                            className="font-semibold text-sm truncate"
                            style={{ color: "var(--text-primary)" }}
                          >
                            {ec.name}
                          </div>
                          <div
                            className="text-xs mt-0.5"
                            style={{
                              color: "var(--text-muted)",
                              fontFamily: "var(--font-mono)",
                            }}
                          >
                            {ec.emailCount || 0} emails ·{" "}
                            {ec.phishingCount || 0} phishing ·{" "}
                            {ec.uniqueIPs || 0} IPs ·{" "}
                            {ec.actorCountries?.slice(0, 3).join(", ") || "—"}
                            {ec.targetBrands?.length > 0 &&
                              ` · targeting: ${ec.targetBrands.slice(0, 2).join(", ")}`}
                          </div>
                        </div>
                        <div className="text-right flex-shrink-0">
                          <div
                            className="text-xs"
                            style={{
                              color: "var(--text-muted)",
                              fontFamily: "var(--font-mono)",
                            }}
                          >
                            {ec.lastSeen
                              ? new Date(ec.lastSeen).toLocaleDateString()
                              : new Date(ec.createdAt).toLocaleDateString()}
                          </div>
                          {ec.avgRiskScore > 0 && (
                            <div
                              className="text-sm font-bold mt-0.5"
                              style={{
                                color:
                                  ec.avgRiskScore >= 70
                                    ? "#f87171"
                                    : ec.avgRiskScore >= 40
                                      ? "#fbbf24"
                                      : "var(--safe)",
                              }}
                            >
                              avg {ec.avgRiskScore}/100
                            </div>
                          )}
                        </div>
                        {isExp ? (
                          <ChevronUp
                            className="size-4 flex-shrink-0"
                            style={{ color: "var(--text-muted)" }}
                          />
                        ) : (
                          <ChevronDown
                            className="size-4 flex-shrink-0"
                            style={{ color: "var(--text-muted)" }}
                          />
                        )}
                      </div>

                      {/* Expanded case detail */}
                      {isExp && det && (
                        <div
                          className="px-5 pb-5 border-t"
                          style={{ borderColor: "var(--bg-border)" }}
                        >
                          {det.description && (
                            <p
                              className="text-xs mt-3 mb-3"
                              style={{ color: "var(--text-muted)" }}
                            >
                              {det.description}
                            </p>
                          )}

                          {/* Actor infrastructure */}
                          {(det.actorIPs?.length > 0 ||
                            det.actorDomains?.length > 0) && (
                            <div className="mb-3">
                              <div className="label-caps mb-1.5">
                                Actor Infrastructure
                              </div>
                              <div className="flex flex-wrap gap-1.5">
                                {det.actorIPs?.slice(0, 5).map((ip: string) => (
                                  <span
                                    key={ip}
                                    className="text-[10px] px-2 py-0.5 rounded"
                                    style={{
                                      color: "#f87171",
                                      background: "rgba(248,113,113,0.08)",
                                      border: "1px solid rgba(248,113,113,0.2)",
                                      fontFamily: "var(--font-mono)",
                                    }}
                                  >
                                    {ip}
                                  </span>
                                ))}
                                {det.actorDomains
                                  ?.slice(0, 5)
                                  .map((d: string) => (
                                    <span
                                      key={d}
                                      className="text-[10px] px-2 py-0.5 rounded"
                                      style={{
                                        color: "#fbbf24",
                                        background: "rgba(251,191,36,0.08)",
                                        border:
                                          "1px solid rgba(251,191,36,0.2)",
                                        fontFamily: "var(--font-mono)",
                                      }}
                                    >
                                      {d}
                                    </span>
                                  ))}
                              </div>
                            </div>
                          )}

                          {/* Email scan timeline */}
                          {det.timeline?.length > 0 && (
                            <div className="mb-3">
                              <div className="label-caps mb-1.5">
                                Email Scan Timeline ({det.timeline.length})
                              </div>
                              <div className="space-y-1">
                                {det.timeline
                                  .slice(0, 8)
                                  .map((scan: any, i: number) => {
                                    const sc2 =
                                      scan.status === "phishing"
                                        ? "#f87171"
                                        : scan.status === "suspicious"
                                          ? "#fbbf24"
                                          : "#34d399";
                                    return (
                                      <div
                                        key={i}
                                        className="flex items-center gap-2 px-3 py-1.5 rounded-lg text-[10px]"
                                        style={{
                                          background: "var(--bg-elevated)",
                                          border: "1px solid var(--bg-border)",
                                        }}
                                      >
                                        <div
                                          className="w-1.5 h-1.5 rounded-full flex-shrink-0"
                                          style={{ background: sc2 }}
                                        />
                                        <span
                                          style={{
                                            color: "var(--accent)",
                                            fontFamily: "var(--font-mono)",
                                            minWidth: 120,
                                          }}
                                        >
                                          {scan.fromDomain || "unknown"}
                                        </span>
                                        <span
                                          style={{
                                            color: "var(--text-muted)",
                                            fontFamily: "var(--font-mono)",
                                          }}
                                        >
                                          {scan.sourceIP || "—"}
                                        </span>
                                        {scan.spfResult && (
                                          <span
                                            style={{
                                              color:
                                                scan.spfResult === "pass"
                                                  ? "#34d399"
                                                  : "#f87171",
                                              fontFamily: "var(--font-mono)",
                                            }}
                                          >
                                            SPF {scan.spfResult}
                                          </span>
                                        )}
                                        <span
                                          className="ml-auto"
                                          style={{ color: "var(--text-muted)" }}
                                        >
                                          {new Date(
                                            scan.createdAt,
                                          ).toLocaleString()}
                                        </span>
                                        <span
                                          className="font-bold"
                                          style={{ color: sc2 }}
                                        >
                                          {scan.riskScore}/100
                                        </span>
                                      </div>
                                    );
                                  })}
                              </div>
                            </div>
                          )}

                          {/* Analyst notes */}
                          {det.notes?.length > 0 && (
                            <div className="mb-3">
                              <div className="label-caps mb-1.5">
                                Analyst Notes ({det.notes.length})
                              </div>
                              {det.notes.slice(-3).map((n: any, i: number) => (
                                <div
                                  key={i}
                                  className="px-3 py-2 rounded-lg mb-1.5 text-xs"
                                  style={{
                                    background: "var(--bg-elevated)",
                                    border: "1px solid var(--bg-border)",
                                  }}
                                >
                                  <div className="flex items-center gap-1.5 mb-0.5">
                                    <span
                                      className="font-semibold"
                                      style={{ color: "var(--accent)" }}
                                    >
                                      {n.addedBy}
                                    </span>
                                    <span
                                      className="text-[9px] capitalize px-1.5 py-0.5 rounded"
                                      style={{
                                        color: "var(--text-muted)",
                                        background: "var(--bg-base)",
                                        fontFamily: "var(--font-mono)",
                                      }}
                                    >
                                      {n.noteType}
                                    </span>
                                    <span
                                      className="ml-auto"
                                      style={{
                                        color: "var(--text-muted)",
                                        fontFamily: "var(--font-mono)",
                                        fontSize: 9,
                                      }}
                                    >
                                      {new Date(n.addedAt).toLocaleString()}
                                    </span>
                                  </div>
                                  <div
                                    style={{ color: "var(--text-secondary)" }}
                                  >
                                    {n.content}
                                  </div>
                                </div>
                              ))}
                            </div>
                          )}

                          {/* Status actions */}
                          {canWrite && (
                            <div className="flex gap-2 flex-wrap mt-2">
                              <select
                                defaultValue={ec.status}
                                onChange={(e) =>
                                  updateCaseStatus(ec.caseId, e.target.value)
                                }
                                className="text-xs px-2.5 py-1.5 rounded-lg"
                                style={{
                                  background: "var(--bg-elevated)",
                                  border: "1px solid var(--bg-border)",
                                  color: "var(--text-secondary)",
                                }}
                              >
                                {[
                                  "open",
                                  "investigating",
                                  "escalated",
                                  "closed",
                                  "false_positive",
                                ].map((s) => (
                                  <option key={s} value={s}>
                                    {s.replace("_", " ")}
                                  </option>
                                ))}
                              </select>
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            )}

            {/* Create case modal */}
            {showCreateCase && (
              <div
                className="fixed inset-0 flex items-center justify-center z-50 px-4"
                style={{
                  background: "rgba(0,0,0,0.7)",
                  backdropFilter: "blur(4px)",
                }}
              >
                <div className="card-glass p-6 max-w-lg w-full rounded-2xl">
                  <h3
                    className="font-bold text-xl mb-4"
                    style={{ color: "var(--text-primary)" }}
                  >
                    Create Email Campaign Case
                  </h3>
                  <div className="space-y-3">
                    <input
                      value={createForm.name}
                      onChange={(e) =>
                        setCreateForm((f) => ({ ...f, name: e.target.value }))
                      }
                      placeholder="Case name (e.g. SBI Phishing Wave Jan 2024)"
                      className="w-full px-3 py-2.5 rounded-xl text-sm"
                      style={{
                        background: "var(--bg-elevated)",
                        border: "1px solid var(--bg-border)",
                        color: "var(--text-primary)",
                        outline: "none",
                      }}
                    />
                    <textarea
                      value={createForm.description}
                      onChange={(e) =>
                        setCreateForm((f) => ({
                          ...f,
                          description: e.target.value,
                        }))
                      }
                      placeholder="Description..."
                      rows={2}
                      className="w-full px-3 py-2.5 rounded-xl text-sm resize-none"
                      style={{
                        background: "var(--bg-elevated)",
                        border: "1px solid var(--bg-border)",
                        color: "var(--text-primary)",
                        outline: "none",
                      }}
                    />
                    <div className="grid grid-cols-2 gap-2">
                      <select
                        value={createForm.campaignType}
                        onChange={(e) =>
                          setCreateForm((f) => ({
                            ...f,
                            campaignType: e.target.value,
                          }))
                        }
                        className="px-3 py-2 rounded-xl text-xs"
                        style={{
                          background: "var(--bg-elevated)",
                          border: "1px solid var(--bg-border)",
                          color: "var(--text-secondary)",
                        }}
                      >
                        {[
                          "phishing",
                          "bec",
                          "credential_harvest",
                          "malware_delivery",
                          "brand_impersonation",
                          "govt_impersonation",
                          "financial_fraud",
                          "other",
                        ].map((t) => (
                          <option key={t} value={t}>
                            {t.replace(/_/g, " ")}
                          </option>
                        ))}
                      </select>
                      <select
                        value={createForm.priority}
                        onChange={(e) =>
                          setCreateForm((f) => ({
                            ...f,
                            priority: e.target.value,
                          }))
                        }
                        className="px-3 py-2 rounded-xl text-xs"
                        style={{
                          background: "var(--bg-elevated)",
                          border: "1px solid var(--bg-border)",
                          color: "var(--text-secondary)",
                        }}
                      >
                        {["low", "medium", "high", "critical"].map((p) => (
                          <option key={p} value={p}>
                            {p}
                          </option>
                        ))}
                      </select>
                    </div>
                    {emailClusters.length > 0 && (
                      <select
                        value={createForm.clusterId}
                        onChange={(e) =>
                          setCreateForm((f) => ({
                            ...f,
                            clusterId: e.target.value,
                          }))
                        }
                        className="w-full px-3 py-2 rounded-xl text-xs"
                        style={{
                          background: "var(--bg-elevated)",
                          border: "1px solid var(--bg-border)",
                          color: "var(--text-secondary)",
                        }}
                      >
                        <option value="">
                          — Link to email cluster (optional) —
                        </option>
                        {emailClusters.map((c: any) => (
                          <option key={c.clusterId} value={c.clusterId}>
                            {c.label} ({c.scanCount} scans)
                          </option>
                        ))}
                      </select>
                    )}
                    <input
                      value={createForm.targetBrands}
                      onChange={(e) =>
                        setCreateForm((f) => ({
                          ...f,
                          targetBrands: e.target.value,
                        }))
                      }
                      placeholder="Target brands (comma-separated: SBI, IRCTC, PayPal)"
                      className="w-full px-3 py-2 rounded-xl text-xs"
                      style={{
                        background: "var(--bg-elevated)",
                        border: "1px solid var(--bg-border)",
                        color: "var(--text-primary)",
                        outline: "none",
                      }}
                    />
                  </div>
                  <div className="flex gap-2 justify-end mt-4">
                    <button
                      onClick={() => setShowCreateCase(false)}
                      className="px-4 py-2 rounded-xl text-sm"
                      style={{
                        background: "var(--bg-elevated)",
                        color: "var(--text-secondary)",
                        border: "1px solid var(--bg-border)",
                      }}
                    >
                      Cancel
                    </button>
                    <button
                      onClick={createEmailCase}
                      disabled={!createForm.name.trim()}
                      className="px-5 py-2 rounded-xl text-sm font-semibold"
                      style={{
                        background: "var(--accent)",
                        color: "#fff",
                        opacity: createForm.name.trim() ? 1 : 0.5,
                      }}
                    >
                      Create Case
                    </button>
                  </div>
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
