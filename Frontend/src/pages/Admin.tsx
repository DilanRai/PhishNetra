// FILE: src/pages/Admin.tsx — PhishNetra v5 Redesign
// Logic unchanged — only visual design updated
// Design: Clean analytics dashboard, desaturated colors, no neon glows

import { useEffect, useState, useCallback } from "react";
import { motion, AnimatePresence } from "motion/react";
import { useNavigate } from "react-router";
import { useSocket } from "../hooks/useSocket";
import {
  Activity,
  Shield,
  AlertTriangle,
  XCircle,
  CheckCircle,
  Brain,
  RefreshCw,
  TrendingUp,
  Globe,
  Mail,
  FileText,
  Clock,
  Terminal,
  Zap,
  Database,
  ShieldAlert,
  Play,
  Cpu,
  Trash2,
  Plus,
  Link,
} from "lucide-react";
import { API_BASE } from "../config";

interface DayData {
  _id: string;
  total: number;
  phishing: number;
  safe: number;
}
interface RecentScan {
  id: string;
  input: string;
  status: string;
  riskScore: number;
  inputType: string;
  createdAt: string;
}
interface Stats {
  total: number;
  breakdown: { phishing: number; suspicious: number; safe: number };
  threatRate: number;
  avgRiskScore: number;
  byInputType: Record<string, number>;
  byConfidence: Record<string, number>;
  mlScanned: number;
  mlCoverage: number;
  siemEnabled: boolean;
  sandboxPhishingCount?: number;
  last7Days: DayData[];
  recentScans: RecentScan[];
}
interface SiemOverview {
  overview: {
    totalAlerts: number;
    openAlerts: number;
    criticalAlerts: number;
    events24h: number;
  };
}

interface HoneypotTrap {
  id: string;
  label: string;
  path: string;
  fullUrl: string;
  hits: number;
  createdAt: string;
  lastHit: any | null;
}

interface ThreatActors {
  actors: any[];
  campaignSpikes: any[];
}

interface Forecast {
  riskScore: number;
  trend: string;
  predictions: { label: string; predicted: number }[];
  topCampaigns: { fingerprint: string; count: number }[];
  spikeRisk: number;
  insight: string;
}

interface DatasetStats {
  isLoaded: boolean;
  totalEntries: number;
  files: { name: string; rows: number }[];
}

const sc = (s: string) =>
  s === "phishing" ? "#f87171" : s === "suspicious" ? "#fbbf24" : "#34d399";
const sb = (s: string) =>
  s === "phishing"
    ? "rgba(248,113,113,0.08)"
    : s === "suspicious"
      ? "rgba(251,191,36,0.08)"
      : "rgba(52,211,153,0.08)";
const sbo = (s: string) =>
  s === "phishing"
    ? "rgba(248,113,113,0.2)"
    : s === "suspicious"
      ? "rgba(251,191,36,0.2)"
      : "rgba(52,211,153,0.18)";

const InputIcon = ({ type }: { type: string }) => {
  if (type === "url") return <Globe className="size-3" />;
  if (type === "email") return <Mail className="size-3" />;
  return <FileText className="size-3" />;
};

// ── SVG Pie Chart (pure SVG, no chart libs) ──
function PieChart({
  data,
}: {
  data: { label: string; value: number; color: string }[];
}) {
  const total = data.reduce((s, d) => s + d.value, 0);
  if (!total)
    return (
      <div
        className="w-32 h-32 rounded-full"
        style={{ background: "var(--bg-border)" }}
      />
    );
  let angle = -Math.PI / 2;
  const slices = data.map((d) => {
    const pct = d.value / total;
    const a0 = angle;
    angle += pct * 2 * Math.PI;
    const x1 = 70 + 52 * Math.cos(a0);
    const y1 = 70 + 52 * Math.sin(a0);
    const x2 = 70 + 52 * Math.cos(angle);
    const y2 = 70 + 52 * Math.sin(angle);
    const large = pct > 0.5 ? 1 : 0;
    return {
      ...d,
      pct,
      path: `M70,70 L${x1},${y1} A52,52 0 ${large},1 ${x2},${y2} Z`,
    };
  });
  return (
    <div className="flex items-center gap-5">
      <svg width="140" height="140" viewBox="0 0 140 140">
        <circle cx="70" cy="70" r="52" fill="var(--bg-elevated)" />
        {slices.map((s, i) => (
          <path key={i} d={s.path} fill={s.color} opacity="0.9" />
        ))}
        <circle cx="70" cy="70" r="32" fill="var(--bg-card)" />
        <text
          x="70"
          y="66"
          textAnchor="middle"
          fill="var(--text-primary)"
          fontSize="15"
          fontWeight="700"
          fontFamily="var(--font-sans)"
        >
          {total.toLocaleString()}
        </text>
        <text
          x="70"
          y="80"
          textAnchor="middle"
          fill="var(--text-muted)"
          fontSize="8"
          fontFamily="var(--font-mono)"
        >
          TOTAL
        </text>
      </svg>
      <div className="space-y-2">
        {slices.map((s, i) => (
          <div key={i} className="flex items-center gap-2">
            <div
              className="w-2 h-2 rounded-full flex-shrink-0"
              style={{ background: s.color }}
            />
            <span
              className="text-xs"
              style={{
                color: "var(--text-muted)",
                fontFamily: "var(--font-mono)",
              }}
            >
              {s.label}
            </span>
            <span
              className="text-xs font-semibold ml-auto"
              style={{ color: s.color, fontFamily: "var(--font-mono)" }}
            >
              {s.value}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

// ── SVG Bar Chart ──
function BarChart({ days }: { days: DayData[] }) {
  const maxV = Math.max(...days.map((d) => d.total), 1);
  return (
    <svg
      width="100%"
      height="80"
      viewBox="0 0 300 80"
      preserveAspectRatio="none"
    >
      {days.slice(-14).map((d, i, arr) => {
        const x = (i / arr.length) * 300;
        const w = 300 / arr.length - 3;
        const hTot = (d.total / maxV) * 64;
        const hPhi = (d.phishing / maxV) * 64;
        const label = new Date(d._id).toLocaleDateString("en", {
          month: "short",
          day: "numeric",
        });
        return (
          <g key={i}>
            <rect
              x={x}
              y={80 - hTot}
              width={w}
              height={hTot}
              fill="rgba(96,165,250,0.15)"
              rx="2"
            />
            <rect
              x={x}
              y={80 - hPhi}
              width={w}
              height={hPhi}
              fill="#f87171"
              opacity="0.7"
              rx="2"
            />
          </g>
        );
      })}
    </svg>
  );
}

export default function Admin() {
  const navigate = useNavigate();
  const [stats, setStats] = useState<Stats | null>(null);
  const [siem, setSiem] = useState<SiemOverview | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [mlStatus, setMlStatus] = useState<any>(null);
  const [liveEvent, setLiveEvent] = useState<any | null>(null);
  const [lastRefresh, setLastRefresh] = useState(new Date());
  const [liveMode, setLiveMode] = useState(
    () => sessionStorage.getItem("admin_liveMode") === "true",
  );
  const [liveData, setLiveData] = useState<any | null>(null);
  const [scanHistory, setScanHistory] = useState<number[]>([]);
  const [liveCount, setLiveCount] = useState(0);
  const [mlTraining, setMlTraining] = useState<any | null>(null);
  const [retraining, setRetraining] = useState(false);
  const [honeypots, setHoneypots] = useState<HoneypotTrap[]>([]);
  const [honeyLabel, setHoneyLabel] = useState("");
  const [threatActors, setThreatActors] = useState<ThreatActors | null>(null);
  const [forecast, setForecast] = useState<Forecast | null>(null);
  const [datasets, setDatasets] = useState<DatasetStats | null>(null);
  const [logStats, setLogStats] = useState<any>(null);
  const [reloadingDS, setReloadingDS] = useState(false);

  const fetchData = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const token = localStorage.getItem("pg_token");
      const headers: Record<string, string> = token
        ? { Authorization: `Bearer ${token}` }
        : {};
      const [statsRes, mlRes] = await Promise.all([
        fetch(`${API_BASE}/api/scan/stats`, { headers }),
        fetch(`${API_BASE}/api/scan/ml-status`, { headers }),
      ]);
      if (!statsRes.ok)
        throw new Error("Backend offline — run: cd backend && npm run dev");
      const [s, ml] = await Promise.all([statsRes.json(), mlRes.json()]);
      setStats(s);
      setMlStatus(ml);
      try {
        const siemRes = await fetch(`${API_BASE}/api/siem/stats`);
        if (siemRes.ok) setSiem(await siemRes.json());
      } catch {}
      setLastRefresh(new Date());
    } catch (e: any) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }, []);

  const fetchLive = useCallback(async () => {
    try {
      const res = await fetch(`${API_BASE}/api/scan/live`);
      if (res.ok) {
        const data = await res.json();
        setLiveData(data);
        setScanHistory((p) => [...p.slice(-59), data.scansPerMin]);
      }
    } catch {}
  }, []);

  // ── Fetch ML training status ──
  const fetchMlTraining = useCallback(async () => {
    try {
      const token = localStorage.getItem("pg_token");
      const res = await fetch(`${API_BASE}/api/scan/ml-training-status`, {
        headers: token ? { Authorization: `Bearer ${token}` } : {},
      });
      if (res.ok) setMlTraining(await res.json());
    } catch {}
  }, []);

  // ── Trigger ML retrain ─-
  const triggerRetrain = async () => {
    setRetraining(true);
    try {
      const token = localStorage.getItem("pg_token");
      await fetch(`${API_BASE}/api/scan/ml-retrain`, {
        method: "POST",
        headers: { Authorization: `Bearer ${token || ""}` },
      });
      // Poll training status every 3s for 30s
      let polls = 0;
      const iv = setInterval(async () => {
        await fetchMlTraining();
        if (++polls >= 10) {
          clearInterval(iv);
          setRetraining(false);
        }
      }, 3000);
    } catch {
      setRetraining(false);
    }
  };

  // ── Honeypot helpers ──
  const fetchHoneypots = useCallback(async () => {
    try {
      const token = localStorage.getItem("pg_token");
      const res = await fetch(`${API_BASE}/api/honeypot/traps`, {
        headers: token ? { Authorization: `Bearer ${token}` } : {},
      });
      if (res.ok) setHoneypots(await res.json());
    } catch {}
  }, []);

  const generateHoneypot = async () => {
    try {
      const token = localStorage.getItem("pg_token");
      await fetch(`${API_BASE}/api/honeypot/generate`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
        body: JSON.stringify({
          label: honeyLabel || undefined,
        }),
      });
      setHoneyLabel("");
      fetchHoneypots();
    } catch {}
  };

  const deleteHoneypot = async (id: string) => {
    try {
      const token = localStorage.getItem("pg_token");
      await fetch(`${API_BASE}/api/honeypot/traps/${id}`, {
        method: "DELETE",
        headers: token ? { Authorization: `Bearer ${token}` } : {},
      });
      fetchHoneypots();
    } catch {}
  };

  // ── Dataset helpers ──
  const fetchDatasets = useCallback(async () => {
    try {
      const res = await fetch(`${API_BASE}/api/scan/datasets`);
      if (res.ok) setDatasets(await res.json());
    } catch {}
  }, []);

  const reloadDatasets = async () => {
    setReloadingDS(true);
    try {
      const res = await fetch(`${API_BASE}/api/scan/datasets/reload`, {
        method: "POST",
      });
      if (res.ok) setDatasets((await res.json()).stats);
    } catch {
    } finally {
      setReloadingDS(false);
    }
  };

  // ── Fetch threat actors ──
  const fetchThreatActors = useCallback(async () => {
    try {
      const res = await fetch(`${API_BASE}/api/scan/threat-actors`);
      if (res.ok) setThreatActors(await res.json());
    } catch {}
  }, []);

  // ── Fetch forecast ──
  const fetchForecast = useCallback(async () => {
    try {
      const res = await fetch(`${API_BASE}/api/scan/forecast`);
      if (res.ok) setForecast(await res.json());
    } catch {}
  }, []);

  useEffect(() => {
    fetchData();
    fetchMlTraining();
    fetchHoneypots();
    fetchDatasets();
    fetchThreatActors();
    fetchForecast();
    fetch(`${API_BASE}/api/logs/stats`, {
      headers: {
        Authorization: `Bearer ${localStorage.getItem("pg_token") || ""}`,
      },
    })
      .then((r) => (r.ok ? r.json() : null))
      .then((data) => setLogStats(data))
      .catch(() => {});
  }, [
    fetchData,
    fetchMlTraining,
    fetchHoneypots,
    fetchDatasets,
    fetchThreatActors,
    fetchForecast,
  ]);
  useEffect(() => {
    const t = setInterval(fetchData, 5 * 60 * 1000);
    return () => clearInterval(t);
  }, [fetchData]);
  useEffect(() => {
    sessionStorage.setItem("admin_liveMode", String(liveMode));
    if (!liveMode) return;
    fetchLive();
    const t = setInterval(fetchLive, 3000);
    return () => clearInterval(t);
  }, [liveMode, fetchLive]);

  useSocket({
    threat_detected: (data) => {
      setLiveEvent(data);
      setLiveCount((c) => c + 1);
      fetchData();
      setTimeout(() => setLiveEvent(null), 6000);
    },
    honeypot_triggered: () => {
      fetchHoneypots();
    },
  });

  if (loading && !stats)
    return (
      <div
        className="min-h-full flex items-center justify-center"
        style={{ background: "var(--bg-base)" }}
      >
        <div className="text-center">
          <div
            className="w-8 h-8 border-2 rounded-full mx-auto mb-4 animate-spin"
            style={{
              borderColor: "var(--accent)",
              borderTopColor: "transparent",
            }}
          />
          <p
            className="text-xs"
            style={{
              color: "var(--text-muted)",
              fontFamily: "var(--font-mono)",
            }}
          >
            Loading analytics...
          </p>
        </div>
      </div>
    );

  if (error)
    return (
      <div
        className="min-h-full flex items-center justify-center px-6"
        style={{ background: "var(--bg-base)" }}
      >
        <div className="text-center max-w-sm">
          <XCircle
            className="size-10 mx-auto mb-4"
            style={{ color: "var(--color-danger)" }}
          />
          <h2
            className="text-xl font-bold mb-2 font-display"
            style={{ color: "var(--text-primary)" }}
          >
            Backend Offline
          </h2>
          <p
            className="text-sm mb-6"
            style={{ color: "var(--text-secondary)" }}
          >
            {error}
          </p>
          <button
            onClick={fetchData}
            className="btn-primary flex items-center gap-2 mx-auto px-6 py-2.5 text-sm"
          >
            <RefreshCw className="size-4" /> Retry
          </button>
        </div>
      </div>
    );

  if (!stats) return null;
  const {
    total,
    breakdown,
    threatRate,
    avgRiskScore,
    byInputType,
    mlScanned,
    mlCoverage,
    last7Days,
    recentScans,
  } = stats;
  const pieData = [
    { label: "Phishing", value: breakdown.phishing, color: "#f87171" },
    { label: "Suspicious", value: breakdown.suspicious, color: "#fbbf24" },
    { label: "Safe", value: breakdown.safe, color: "#34d399" },
  ];

  return (
    <div
      className="min-h-full py-10 px-6"
      style={{ background: "var(--bg-base)" }}
    >
      <div className="max-w-6xl mx-auto">
        {/* ── HEADER ── */}
        <motion.div
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          className="flex items-start justify-between mb-10 flex-wrap gap-4"
        >
          <div>
            <div className="tag-green inline-flex mb-4">
              <Terminal className="size-3" /> Analytics
            </div>
            <h1
              className="font-display text-4xl mb-1.5"
              style={{ color: "var(--text-primary)" }}
            >
              Dashboard
            </h1>
            <div className="flex items-center gap-3 flex-wrap">
              <span
                className="text-sm flex items-center gap-1.5"
                style={{
                  color: "var(--text-muted)",
                  fontFamily: "var(--font-mono)",
                }}
              >
                <Clock className="size-3" />
                {lastRefresh.toLocaleTimeString()}
              </span>
              {mlStatus && (
                <span className="tag">
                  <Brain className="size-3" />
                  ML {mlStatus.modelLoaded ? "Active" : "Rules"}
                </span>
              )}
            </div>
          </div>
          <div className="flex items-center gap-2 flex-wrap">
            <button
              onClick={() => {
                setLiveMode(!liveMode);
                if (!liveMode) fetchLive();
              }}
              className="flex items-center gap-2 px-3.5 py-2 rounded-lg text-sm font-medium transition-colors"
              style={{
                background: liveMode
                  ? "rgba(248,113,113,0.08)"
                  : "var(--bg-elevated)",
                border: liveMode
                  ? "1px solid rgba(248,113,113,0.25)"
                  : "1px solid var(--bg-border)",
                color: liveMode
                  ? "var(--color-danger)"
                  : "var(--text-secondary)",
              }}
            >
              <div
                className={`w-1.5 h-1.5 rounded-full ${liveMode ? "threat-pulse" : ""}`}
                style={{
                  background: liveMode
                    ? "var(--color-danger)"
                    : "var(--text-muted)",
                }}
              />
              {liveMode ? "LIVE" : "Live Mode"}
            </button>
            <button
              onClick={fetchData}
              disabled={loading}
              className="btn-ghost flex items-center gap-2 px-3.5 py-2 text-sm"
            >
              <RefreshCw
                className={`size-4 ${loading ? "animate-spin" : ""}`}
              />{" "}
              Refresh
            </button>
          </div>
        </motion.div>

        {/* ── LIVE ALERT BANNER ── */}
        <AnimatePresence>
          {liveEvent && (
            <motion.div
              initial={{ opacity: 0, y: -8, height: 0 }}
              animate={{ opacity: 1, y: 0, height: "auto" }}
              exit={{ opacity: 0, y: -8, height: 0 }}
              className="mb-5"
            >
              <div
                className="rounded-xl px-5 py-3 flex items-center gap-3"
                style={{
                  background: "rgba(248,113,113,0.07)",
                  border: "1px solid rgba(248,113,113,0.2)",
                }}
              >
                <div
                  className="w-2 h-2 rounded-full threat-pulse flex-shrink-0"
                  style={{ background: "var(--color-danger)" }}
                />
                <span
                  className="text-sm font-medium"
                  style={{ color: "var(--color-danger)" }}
                >
                  Threat detected: {liveEvent.input?.substring(0, 60)}
                </span>
                <span
                  className="ml-auto text-xs"
                  style={{
                    color: "var(--text-muted)",
                    fontFamily: "var(--font-mono)",
                  }}
                >
                  Score: {liveEvent.riskScore}/100
                </span>
              </div>
            </motion.div>
          )}
        </AnimatePresence>

        {/* ── LIVE MODE PANEL ── */}
        <AnimatePresence>
          {liveMode && (
            <motion.div
              initial={{ opacity: 0, y: -8, height: 0 }}
              animate={{ opacity: 1, y: 0, height: "auto" }}
              exit={{ opacity: 0, y: -8, height: 0 }}
              className="mb-6"
            >
              <div
                className="card overflow-hidden"
                style={{ borderColor: "rgba(248,113,113,0.2)" }}
              >
                <div
                  className="px-5 py-3 flex items-center gap-2"
                  style={{
                    background: "rgba(248,113,113,0.06)",
                    borderBottom: "1px solid rgba(248,113,113,0.15)",
                  }}
                >
                  <div
                    className="w-1.5 h-1.5 rounded-full threat-pulse"
                    style={{ background: "var(--color-danger)" }}
                  />
                  <span
                    className="text-xs font-semibold"
                    style={{
                      color: "var(--color-danger)",
                      fontFamily: "var(--font-mono)",
                      letterSpacing: "0.08em",
                    }}
                  >
                    LIVE MONITORING — 3s intervals
                  </span>
                  <span
                    className="ml-auto text-xs"
                    style={{
                      color: "var(--text-muted)",
                      fontFamily: "var(--font-mono)",
                    }}
                  >
                    Session: {liveCount} threats
                  </span>
                </div>
                <div className="p-5 grid grid-cols-2 md:grid-cols-4 gap-4">
                  {[
                    {
                      label: "Scans/min",
                      value: liveData?.scansPerMin ?? "—",
                      color: "var(--accent)",
                    },
                    {
                      label: "Phishing/min",
                      value: liveData?.phishingPerMin ?? "—",
                      color: "var(--color-danger)",
                    },
                    {
                      label: "Threat Vel.",
                      value: liveData ? `${liveData.threatVelocity}%` : "—",
                      color: "var(--color-warning)",
                    },
                    {
                      label: "Top Attack",
                      value:
                        liveData?.topAttacks?.[0]?.technique?.replace(
                          /_/g,
                          " ",
                        ) || "—",
                      color: "var(--color-info)",
                    },
                  ].map((c) => (
                    <div key={c.label} className="text-center">
                      <div
                        className="text-2xl font-bold font-display"
                        style={{ color: c.color }}
                      >
                        {c.value}
                      </div>
                      <div className="label-caps mt-1">{c.label}</div>
                    </div>
                  ))}
                </div>
                {scanHistory.length > 1 && (
                  <div
                    className="px-5 pb-4 border-t"
                    style={{ borderColor: "var(--bg-border)" }}
                  >
                    <div className="label-caps mb-2 mt-3">
                      Scan Rate — last 3 minutes
                    </div>
                    <div className="flex items-end gap-0.5 h-10">
                      {scanHistory.map((v, i) => {
                        const max = Math.max(...scanHistory, 1);
                        const h = Math.max((v / max) * 36, 1);
                        return (
                          <div
                            key={i}
                            className="flex-1 rounded-t-sm transition-all duration-300"
                            style={{
                              height: h,
                              background:
                                v > 0 ? "var(--accent)" : "var(--bg-border)",
                              opacity: 0.4 + (i / scanHistory.length) * 0.6,
                            }}
                          />
                        );
                      })}
                    </div>
                  </div>
                )}
              </div>
            </motion.div>
          )}
        </AnimatePresence>

        {/* ── STAT CARDS ROW ── */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-6">
          {[
            {
              icon: Database,
              label: "Total Scans",
              value: total.toLocaleString(),
              color: "var(--accent)",
              trend: null,
            },
            {
              icon: AlertTriangle,
              label: "Threat Rate",
              value: `${threatRate}%`,
              color: "var(--color-danger)",
              trend: threatRate > 30 ? "high" : "ok",
            },
            {
              icon: Activity,
              label: "Avg Risk Score",
              value: String(avgRiskScore),
              color: "var(--color-warning)",
              trend: null,
            },
            {
              icon: Brain,
              label: "ML Coverage",
              value: `${mlCoverage}%`,
              color: "var(--color-info)",
              trend: null,
            },
          ].map((s, i) => (
            <motion.div
              key={s.label}
              initial={{ opacity: 0, y: 12 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: i * 0.06 }}
              className="card stat-card p-5"
            >
              <div className="flex items-start justify-between mb-3">
                <div
                  className="w-8 h-8 rounded-lg flex items-center justify-center"
                  style={{
                    background: `${s.color}14`,
                    border: `1px solid ${s.color}28`,
                  }}
                >
                  <s.icon className="size-4" style={{ color: s.color }} />
                </div>
                {s.trend === "high" && (
                  <span
                    className="text-[9px] px-1.5 py-0.5 rounded font-semibold"
                    style={{
                      color: "var(--color-danger)",
                      background: "rgba(248,113,113,0.08)",
                      fontFamily: "var(--font-mono)",
                    }}
                  >
                    HIGH
                  </span>
                )}
              </div>
              <div
                className="text-2xl font-bold font-display mb-0.5"
                style={{ color: s.color }}
              >
                {s.value}
              </div>
              <div className="label-caps">{s.label}</div>
            </motion.div>
          ))}
          <div
            className="rounded-xl p-4"
            style={{
              background: "var(--bg-card)",
              border: "1px solid var(--bg-border)",
            }}
          >
            <div
              className="text-xs uppercase tracking-widest mb-1"
              style={{
                color: "var(--text-muted)",
                fontFamily: "'JetBrains Mono', monospace",
              }}
            >
              Sandbox Confirms
            </div>
            <div
              className="text-2xl font-black"
              style={{ color: "#f97316", fontFamily: "'Syne', sans-serif" }}
            >
              {stats?.sandboxPhishingCount ?? "—"}
            </div>
            <div
              className="text-xs mt-0.5"
              style={{ color: "var(--text-muted)" }}
            >
              Credential harvesters confirmed by sandbox
            </div>
          </div>
        </div>

        {logStats && (
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3 mb-6">
            <div
              className="card p-5 stat-card"
              style={{ borderColor: "rgba(96,165,250,0.2)" }}
            >
              <div
                className="label-caps mb-2"
                style={{ color: "var(--color-info)" }}
              >
                Log Events (24h)
              </div>
              <div
                className="text-3xl font-bold mb-1"
                style={{
                  color: "var(--color-info)",
                  fontFamily: "var(--font-mono)",
                }}
              >
                {logStats.logs24h}
              </div>
              <div className="text-xs" style={{ color: "var(--text-muted)" }}>
                {logStats.totalLogs} total · auto-expire 30d
              </div>
            </div>

            <div
              className="card p-5 stat-card"
              style={{ borderColor: "rgba(248,113,113,0.2)" }}
            >
              <div
                className="label-caps mb-2"
                style={{ color: "var(--color-danger)" }}
              >
                Brute Force (24h)
              </div>
              <div
                className="text-3xl font-bold mb-1"
                style={{
                  color:
                    logStats.bruteForceCount24h > 0
                      ? "var(--color-danger)"
                      : "var(--text-muted)",
                  fontFamily: "var(--font-mono)",
                }}
              >
                {logStats.bruteForceCount24h}
              </div>
              <div className="text-xs" style={{ color: "var(--text-muted)" }}>
                {logStats.byType?.multiple_login_attempts || 0} login attack
                patterns
              </div>
            </div>

            <div
              className="card p-5 stat-card"
              style={{ borderColor: "rgba(167,139,250,0.2)" }}
            >
              <div className="label-caps mb-2" style={{ color: "#a78bfa" }}>
                PowerShell Alerts
              </div>
              <div
                className="text-3xl font-bold mb-1"
                style={{
                  color:
                    (logStats.byType?.powershell_execution || 0) > 0
                      ? "#a78bfa"
                      : "var(--text-muted)",
                  fontFamily: "var(--font-mono)",
                }}
              >
                {logStats.byType?.powershell_execution || 0}
              </div>
              <div className="text-xs" style={{ color: "var(--text-muted)" }}>
                {logStats.byType?.dns_malicious || 0} malicious DNS queries
              </div>
            </div>
          </div>
        )}

        {/* ── SIEM MINI CARDS ── */}
        {siem && (
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-6">
            {[
              {
                label: "Total Alerts",
                value: siem.overview.totalAlerts,
                color: "var(--color-info)",
              },
              {
                label: "Open Alerts",
                value: siem.overview.openAlerts,
                color: "var(--color-warning)",
              },
              {
                label: "Critical",
                value: siem.overview.criticalAlerts,
                color: "var(--color-danger)",
              },
              {
                label: "Events 24h",
                value: siem.overview.events24h,
                color: "var(--accent)",
              },
            ].map((s, i) => (
              <motion.div
                key={s.label}
                initial={{ opacity: 0, y: 8 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.25 + i * 0.05 }}
                className="card p-4 stat-card cursor-pointer"
                onClick={() => navigate("/siem")}
              >
                <div className="flex items-center gap-2 mb-2">
                  <ShieldAlert
                    className="size-3.5"
                    style={{ color: s.color }}
                  />
                  <span className="label-caps">SIEM</span>
                </div>
                <div
                  className="text-xl font-bold font-display"
                  style={{ color: s.color }}
                >
                  {s.value}
                </div>
                <div className="label-caps mt-0.5">{s.label}</div>
              </motion.div>
            ))}
          </div>
        )}

        {/* ── CHARTS ROW ── */}
        <div className="grid md:grid-cols-2 gap-4 mb-6">
          {/* Pie chart */}
          <motion.div
            initial={{ opacity: 0, y: 12 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.35 }}
            className="card p-6"
          >
            <div className="flex items-center gap-2 mb-5">
              <Shield className="size-4" style={{ color: "var(--accent)" }} />
              <span
                className="text-sm font-semibold"
                style={{ color: "var(--text-primary)" }}
              >
                Verdict Distribution
              </span>
            </div>
            <PieChart data={pieData} />
          </motion.div>

          {/* Bar chart */}
          <motion.div
            initial={{ opacity: 0, y: 12 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.4 }}
            className="card p-6"
          >
            <div className="flex items-center gap-2 mb-5">
              <TrendingUp
                className="size-4"
                style={{ color: "var(--accent)" }}
              />
              <span
                className="text-sm font-semibold"
                style={{ color: "var(--text-primary)" }}
              >
                7-Day Activity
              </span>
            </div>
            <BarChart days={last7Days} />
            <div className="flex items-center gap-4 mt-3">
              {[
                { c: "rgba(96,165,250,0.4)", l: "Total" },
                { c: "#f87171", l: "Phishing" },
              ].map((d) => (
                <div key={d.l} className="flex items-center gap-1.5">
                  <div
                    className="w-2 h-2 rounded-sm"
                    style={{ background: d.c }}
                  />
                  <span
                    className="text-xs"
                    style={{
                      color: "var(--text-muted)",
                      fontFamily: "var(--font-mono)",
                    }}
                  >
                    {d.l}
                  </span>
                </div>
              ))}
            </div>
          </motion.div>
        </div>

        {/* ── RECENT SCANS TABLE ── */}
        <motion.div
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.45 }}
          className="card overflow-hidden"
        >
          <div className="terminal-chrome">
            <div className="terminal-dot" style={{ background: "#ff5f57" }} />
            <div className="terminal-dot" style={{ background: "#febc2e" }} />
            <div className="terminal-dot" style={{ background: "#28c840" }} />
            <span
              className="ml-3 text-xs"
              style={{
                color: "var(--text-muted)",
                fontFamily: "var(--font-mono)",
              }}
            >
              recent_scans.log — {recentScans?.length || 0} entries
            </span>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full data-table">
              <thead>
                <tr>
                  <th className="text-left">Input</th>
                  <th className="text-left">Type</th>
                  <th className="text-left">Verdict</th>
                  <th className="text-left">Score</th>
                  <th className="text-left hidden md:table-cell">Time</th>
                </tr>
              </thead>
              <tbody>
                {recentScans?.slice(0, 10).map((s, i) => (
                  <tr key={s.id || i}>
                    <td>
                      <code
                        className="text-xs truncate max-w-[200px] block"
                        style={{
                          color: "var(--text-secondary)",
                          fontFamily: "var(--font-mono)",
                        }}
                      >
                        {s.input?.substring(0, 55)}
                        {s.input?.length > 55 ? "…" : ""}
                      </code>
                    </td>
                    <td>
                      <span
                        className="flex items-center gap-1.5 text-xs"
                        style={{ color: "var(--text-muted)" }}
                      >
                        <InputIcon type={s.inputType} />
                        {s.inputType}
                      </span>
                    </td>
                    <td>
                      <span
                        className="text-[10px] font-semibold px-2 py-0.5 rounded capitalize"
                        style={{
                          color: sc(s.status),
                          background: sb(s.status),
                          border: `1px solid ${sbo(s.status)}`,
                          fontFamily: "var(--font-mono)",
                        }}
                      >
                        {s.status}
                      </span>
                    </td>
                    <td>
                      <span
                        className="text-sm font-bold"
                        style={{
                          color: sc(s.status),
                          fontFamily: "var(--font-mono)",
                        }}
                      >
                        {s.riskScore}
                      </span>
                    </td>
                    <td className="hidden md:table-cell">
                      <span
                        className="text-xs"
                        style={{
                          color: "var(--text-muted)",
                          fontFamily: "var(--font-mono)",
                        }}
                      >
                        {new Date(s.createdAt).toLocaleTimeString()}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </motion.div>

        {/* ── ML TRAINING STATUS + RETRAIN ── */}
        <motion.div
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.5 }}
          className="card p-5 mt-4"
          style={{ background: "var(--bg-card)" }}
        >
          <div className="flex items-center justify-between mb-4 flex-wrap gap-2">
            <div className="flex items-center gap-2">
              <Cpu className="size-4" style={{ color: "#a78bfa" }} />
              <span
                className="text-sm font-semibold"
                style={{ color: "var(--text-primary)" }}
              >
                ML Training Status
              </span>
              {mlTraining?.state && (
                <span
                  className="text-[10px] px-2 py-0.5 rounded font-bold"
                  style={{
                    color:
                      mlTraining.state === "training"
                        ? "#fbbf24"
                        : mlTraining.state === "complete"
                          ? "#34d399"
                          : "var(--text-muted)",
                    background:
                      mlTraining.state === "training"
                        ? "rgba(251,191,36,0.08)"
                        : mlTraining.state === "complete"
                          ? "rgba(52,211,153,0.08)"
                          : "var(--bg-elevated)",
                    border: `1px solid ${mlTraining.state === "training" ? "rgba(251,191,36,0.3)" : mlTraining.state === "complete" ? "rgba(52,211,153,0.2)" : "var(--bg-border)"}`,
                    fontFamily: "var(--font-mono)",
                  }}
                >
                  {mlTraining.state.toUpperCase()}
                </span>
              )}
            </div>
            <button
              onClick={triggerRetrain}
              disabled={retraining}
              className="btn-ghost flex items-center gap-2 px-4 py-2 text-xs"
              style={{ color: "#a78bfa", borderColor: "rgba(167,139,250,0.3)" }}
            >
              {retraining ? (
                <>
                  <div
                    className="w-3 h-3 border-2 rounded-full animate-spin"
                    style={{
                      borderColor: "#a78bfa",
                      borderTopColor: "transparent",
                    }}
                  />{" "}
                  Retraining...
                </>
              ) : (
                <>
                  <Play className="size-3.5" /> Trigger Retrain
                </>
              )}
            </button>
          </div>
          {mlTraining && (
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs">
              {[
                {
                  label: "Accuracy",
                  value:
                    mlTraining.accuracy != null
                      ? `${Math.round(mlTraining.accuracy * 100)}%`
                      : "—",
                  color: "#34d399",
                },
                {
                  label: "Samples",
                  value: mlTraining.samples ?? "—",
                  color: "var(--accent)",
                },
                {
                  label: "Last Trained",
                  value: mlTraining.lastTrained
                    ? new Date(mlTraining.lastTrained).toLocaleString()
                    : "—",
                  color: "var(--text-muted)",
                },
                {
                  label: "Model",
                  value: mlTraining.model ?? "—",
                  color: "#a78bfa",
                },
              ].map((c) => (
                <div
                  key={c.label}
                  className="rounded-lg p-3"
                  style={{
                    background: "var(--bg-elevated)",
                    border: "1px solid var(--bg-border)",
                  }}
                >
                  <div
                    style={{
                      color: "var(--text-muted)",
                      fontFamily: "var(--font-mono)",
                      marginBottom: 2,
                    }}
                  >
                    {c.label}
                  </div>
                  <div
                    className="font-bold"
                    style={{ color: c.color, fontFamily: "var(--font-mono)" }}
                  >
                    {String(c.value)}
                  </div>
                </div>
              ))}
            </div>
          )}
        </motion.div>

        {/* ── THREAT ACTORS ── */}
        {threatActors &&
          (threatActors.actors.length > 0 ||
            threatActors.campaignSpikes.length > 0) && (
            <motion.div
              initial={{ opacity: 0, y: 12 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.65 }}
              className="card p-5 mt-4"
              style={{ background: "var(--bg-card)" }}
            >
              <div className="flex items-center gap-2 mb-4">
                <Shield className="size-4" style={{ color: "#f87171" }} />
                <span
                  className="text-sm font-semibold"
                  style={{ color: "var(--text-primary)" }}
                >
                  Active Threat Actors
                </span>
                <span
                  className="text-xs ml-auto"
                  style={{
                    color: "var(--text-muted)",
                    fontFamily: "var(--font-mono)",
                  }}
                >
                  {threatActors.actors.length} actor
                  {threatActors.actors.length !== 1 ? "s" : ""}
                </span>
              </div>
              <div className="space-y-2">
                {threatActors.actors
                  .slice(0, 5)
                  .map((actor: any, i: number) => (
                    <div
                      key={i}
                      className="flex items-center gap-3 px-3 py-2.5 rounded-xl"
                      style={{
                        background: "var(--bg-elevated)",
                        border: "1px solid var(--bg-border)",
                      }}
                    >
                      <div
                        className="w-2 h-2 rounded-full flex-shrink-0"
                        style={{ background: "#f87171" }}
                      />
                      <span
                        className="text-xs font-mono"
                        style={{ color: "var(--text-secondary)" }}
                      >
                        {actor.ip || actor.actorId || "Unknown"}
                      </span>
                      {actor.phishingCount && (
                        <span
                          className="text-xs"
                          style={{
                            color: "#f87171",
                            fontFamily: "var(--font-mono)",
                          }}
                        >
                          {actor.phishingCount} phishing
                        </span>
                      )}
                      {actor.riskLevel && (
                        <span
                          className="text-xs ml-auto px-2 py-0.5 rounded font-bold uppercase"
                          style={{
                            color: "#f87171",
                            background: "rgba(248,113,113,0.08)",
                            fontFamily: "var(--font-mono)",
                          }}
                        >
                          {actor.riskLevel}
                        </span>
                      )}
                    </div>
                  ))}
              </div>
              {threatActors.campaignSpikes.length > 0 && (
                <div
                  className="mt-3 pt-3 border-t"
                  style={{ borderColor: "var(--bg-border)" }}
                >
                  <div className="label-caps mb-2">Campaign Spikes</div>
                  <div className="flex flex-wrap gap-2">
                    {threatActors.campaignSpikes
                      .slice(0, 4)
                      .map((spike: any, i: number) => (
                        <span
                          key={i}
                          className="text-xs px-2 py-1 rounded"
                          style={{
                            color: "#fbbf24",
                            background: "rgba(251,191,36,0.07)",
                            border: "1px solid rgba(251,191,36,0.2)",
                            fontFamily: "var(--font-mono)",
                          }}
                        >
                          {spike.fingerprint
                            ? `#${spike.fingerprint}`
                            : `Spike ${i + 1}`}{" "}
                          — {spike.count || spike.spike || "N/A"}
                        </span>
                      ))}
                  </div>
                </div>
              )}
            </motion.div>
          )}
      </div>
    </div>
  );
}
