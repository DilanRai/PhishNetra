// FILE: src/pages/SIEM.tsx
// SentinelCore SIEM Dashboard — PhishGuard AI

import { useCallback, useEffect, useState } from "react";
import { motion, AnimatePresence } from "motion/react";
import {
  Shield,
  AlertTriangle,
  Activity,
  Zap,
  Terminal,
  ChevronDown,
  ChevronUp,
  RefreshCw,
  CheckCircle,
  XCircle,
  Clock,
  Globe,
  Brain,
  Eye,
  Filter,
  TrendingUp,
  Database,
  Link as LinkIcon,
  Cpu,
  Trash2,
  TriangleAlert,
} from "lucide-react";
import { useSocket } from "../hooks/useSocket";
import { API_BASE } from "../config";
import { Link } from "react-router-dom";

interface DetectionRule {
  rule_name: string;
  rule_link: string;
  platform: string;
  tech_id: string;
}

interface SiemAlert {
  alertId: string;
  title: string;
  description: string;
  category: string;
  ruleId: string;
  severity: number;
  severityLabel: string;
  eventCount: number;
  status: string;
  target: {
    url?: string;
    domain?: string;
    ip?: string;
    email?: string;
    text?: string;
    rawInput?: string;
    inputType?: "url" | "email" | "sms" | "text";
  };
  rawData?: { input?: string };
  mitre?: { tactic?: string; technique?: string };
  riskScore: number;
  firstSeen: string;
  lastSeen: string;
  isCorrelated: boolean;
  tags: string[];
  assignee?: string;
  slaDeadline?: string;
  comments?: { author: string; text: string; timestamp: string }[];
  sigmaRules?: DetectionRule[];
  splunkRules?: DetectionRule[];
  hasDetectionRules?: boolean;
}

interface AlertTrendDay {
  _id: string;
  total: number;
  critical: number;
  high: number;
}

interface TopTarget {
  domain: string;
  count: number;
  maxSeverity: number;
}

interface MitreTactic {
  tactic: string;
  count: number;
}

interface Stats {
  overview: {
    totalEvents: number;
    totalAlerts: number;
    openAlerts: number;
    criticalAlerts: number;
    events24h: number;
    alerts24h: number;
    correlatedAlerts: number;
  };
  severity: Record<string, number>;
  byCategory: Record<string, number>;
  topTargets: TopTarget[];
  alertTrend: AlertTrendDay[];
  mitreTactics: MitreTactic[];
}

interface Rule {
  id: string;
  name: string;
  category: string;
  severity: number;
  severityLabel: string;
  mitre?: { tactic?: string; technique?: string };
  compliance: string[];
  cve?: string;
}

interface BaselineData {
  baseline: {
    avgScansPerHour: number;
    avgPhishingRate: number;
    sampleHours: number;
  } | null;
  current: {
    total: number;
    phishing: number;
    suspicious: number;
    phishingRate: number;
  };
  healthy: boolean;
}

interface ThreatActor {
  ip: string;
  threatLevel: "low" | "medium" | "high" | "critical";
  phishingCount: number;
  phishingRate: number;
  avgScore: number;
  targetedBrands: string[];
  lastSeen: string;
}

interface CampaignSpike {
  brand: string;
  count: number;
  uniqueIPs: number;
  isCampaign: boolean;
}

interface Trap {
  id: string;
  label: string;
  fullUrl: string;
  hits: number;
  createdAt: string;
}

interface LiveAlert {
  status: "phishing" | "suspicious";
  riskScore: number;
  input: string;
  confidence?: string;
  dna?: { fingerprint?: string; technique?: string } | null;
}

const SIEM_API = `${API_BASE}/api/siem`;
const SCAN_API = `${API_BASE}/api/scan`;
const HONEYPOT_API = `${API_BASE}/api/honeypot`;
const LOGS_API = `${API_BASE}/api/logs`;

const SEV: Record<
  number,
  { color: string; bg: string; border: string; label: string; dot: string }
> = {
  5: {
    color: "#f87171",
    bg: "rgba(248,113,113,0.07)",
    border: "rgba(248,113,113,0.2)",
    label: "CRITICAL",
    dot: "#f87171",
  },
  4: {
    color: "#fb923c",
    bg: "rgba(251,146,60,0.07)",
    border: "rgba(251,146,60,0.18)",
    label: "HIGH",
    dot: "#fb923c",
  },
  3: {
    color: "#fbbf24",
    bg: "rgba(251,191,36,0.07)",
    border: "rgba(251,191,36,0.18)",
    label: "MEDIUM",
    dot: "#fbbf24",
  },
  2: {
    color: "#34d399",
    bg: "rgba(52,211,153,0.06)",
    border: "rgba(52,211,153,0.15)",
    label: "LOW",
    dot: "#34d399",
  },
  1: {
    color: "#64748b",
    bg: "rgba(100,116,139,0.05)",
    border: "rgba(100,116,139,0.12)",
    label: "INFO",
    dot: "#64748b",
  },
};

function TrendBars({ data }: { data: AlertTrendDay[] }) {
  const max = Math.max(...data.map((d) => d.total), 1);
  return (
    <div className="flex items-end gap-1.5" style={{ height: 52 }}>
      {data.map((d) => {
        const h = Math.max((d.total / max) * 44, 2);
        const critH = d.total > 0 ? (d.critical / d.total) * h : 0;
        const highH = d.total > 0 ? (d.high / d.total) * h : 0;
        const otherH = h - critH - highH;
        return (
          <div
            key={d._id}
            className="flex-1 flex flex-col items-center gap-0.5"
          >
            <div
              className="w-full flex flex-col justify-end"
              style={{ height: 44 }}
            >
              {critH > 0 && (
                <div
                  style={{
                    height: critH,
                    background: "#E1251B",
                    borderRadius: "2px 2px 0 0",
                    minHeight: 2,
                  }}
                />
              )}
              {highH > 0 && (
                <div
                  style={{ height: highH, background: "#f97316", minHeight: 2 }}
                />
              )}
              {otherH > 0 && (
                <div
                  style={{
                    height: otherH,
                    background: "#f5a623",
                    minHeight: 2,
                  }}
                />
              )}
            </div>
            <span
              style={{
                fontSize: 8,
                color: "var(--text-muted)",
                fontFamily: "'JetBrains Mono', monospace",
              }}
            >
              {d._id.slice(5)}
            </span>
          </div>
        );
      })}
    </div>
  );
}

function SLATimer({ deadline }: { deadline: string }) {
  const [remaining, setRemaining] = useState("");
  const [isBreached, setIsBreached] = useState(false);

  useEffect(() => {
    const update = () => {
      const diff = new Date(deadline).getTime() - Date.now();
      if (diff <= 0) {
        setIsBreached(true);
        setRemaining("SLA BREACHED");
        return;
      }
      const h = Math.floor(diff / 3600000);
      const m = Math.floor((diff % 3600000) / 60000);
      setRemaining(`${h}h ${m}m remaining`);
      setIsBreached(false);
    };
    update();
    const t = setInterval(update, 60000);
    return () => clearInterval(t);
  }, [deadline]);

  return (
    <span
      className="text-xs px-2 py-0.5 rounded"
      style={{
        fontFamily: "'JetBrains Mono', monospace",
        color: isBreached ? "#E1251B" : "#f5a623",
        background: isBreached
          ? "rgba(255,68,68,0.08)"
          : "rgba(245,166,35,0.08)",
        border: `1px solid ${isBreached ? "rgba(255,68,68,0.2)" : "rgba(245,166,35,0.2)"}`,
      }}
    >
      ⏱ {remaining}
    </span>
  );
}

// ── Alert target helpers ──────────────────────────────────────────────
const getAlertTarget = (alert: any): string =>
  alert.target?.domain ||
  alert.target?.rawInput ||
  alert.target?.url ||
  alert.target?.email ||
  alert.target?.text ||
  alert.target?.ip ||
  alert.rawData?.input ||
  "Unknown target";

const getInputTypeLabel = (alert: any): string => {
  const t = alert.target?.inputType;
  if (t === "url") return "URL";
  if (t === "email") return "Email";
  if (t === "sms") return "SMS";
  if (t === "text") return "Text";
  // Infer from available fields if inputType wasn't stored
  if (alert.target?.url || alert.target?.domain) return "URL";
  if (alert.target?.email) return "Email";
  if (alert.target?.text) return "SMS/Text";
  return "";
};

export default function SIEM() {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [stats, setStats] = useState<Stats | null>(null);
  const [alerts, setAlerts] = useState<SiemAlert[]>([]);
  const [statusFilter, setStatusFilter] = useState<
    "open" | "investigating" | "resolved" | "false_positive"
  >("open");
  const [severityFilter, setSeverityFilter] = useState<number>(0);
  const [rules, setRules] = useState<Rule[]>([]);
  const [baseline, setBaseline] = useState<BaselineData | null>(null);
  const [actors, setActors] = useState<ThreatActor[]>([]);
  const [spikes, setSpikes] = useState<CampaignSpike[]>([]);
  const [traps, setTraps] = useState<Trap[]>([]);

  const [newTrap, setNewTrap] = useState("");
  const [trapLabel, setTrapLabel] = useState("");
  const [correlating, setCorrelating] = useState(false);
  const [runningBaseline, setRunningBaseline] = useState(false);

  // Custom Rules state
  const [customRules, setCustomRules] = useState<any[]>([]);
  const [newRuleName, setNewRuleName] = useState("");
  const [newRuleSev, setNewRuleSev] = useState(3);
  const [newRuleCat, setNewRuleCat] = useState("phishing");
  const [newRuleScore, setNewRuleScore] = useState(70);
  const [newRuleStatus, setNewRuleStatus] = useState("");
  const [newRuleIssue, setNewRuleIssue] = useState("");
  const [showCreate, setShowCreate] = useState(false);

  // Shift Notes state
  const [shiftNotes, setShiftNotes] = useState<any[]>([]);
  const [newNoteText, setNewNoteText] = useState("");
  const [newNotePriority, setNewNotePriority] = useState("normal");
  const [newNotePinned, setNewNotePinned] = useState(false);
  const [noteAlertRefs, setNoteAlertRefs] = useState("");

  const [activeTab, setActiveTab] = useState<
    | "alerts"
    | "rules"
    | "topology"
    | "baseline"
    | "behavior"
    | "honeypot"
    | "custom-rules"
    | "shift"
    | "logs"
    | "ioc"
  >("alerts");

  // IOC state
  const [iocStats, setIocStats] = useState<any>(null);
  const [iocs, setIocs] = useState<any[]>([]);
  const [iocTotal, setIocTotal] = useState(0);
  const [iocPage, setIocPage] = useState(1);
  const [iocLoading, setIocLoading] = useState(false);
  const [iocFilter, setIocFilter] = useState<{
    type: string;
    severity: number;
    status: string;
  }>({ type: "", severity: 0, status: "active" });
  const [expandedAlert, setExpandedAlert] = useState<string | null>(null);
  const [commentText, setCommentText] = useState<Record<string, string>>({});
  const [showComments, setShowComments] = useState<string | null>(null);
  const [liveAlert, setLiveAlert] = useState<LiveAlert | null>(null);
  const [liveCount, setLiveCount] = useState(0);
  const [slidingOut, setSlidingOut] = useState<string | null>(null);

  // ── Toast state ──
  const [toasts, setToasts] = useState<
    { id: number; type: "success" | "error"; msg: string }[]
  >([]);
  const addToast = (type: "success" | "error", msg: string) => {
    const id = Date.now();
    setToasts((t) => [...t, { id, type, msg }]);
    setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), 4000);
  };

  // ── Delete confirmation modal state ──
  const [deleteModal, setDeleteModal] = useState<{
    type: "events" | "alerts" | null;
    loading: boolean;
  }>({ type: null, loading: false });

  // ── Logs tab state ──
  const [logEvents, setLogEvents] = useState<any[]>([]);
  const [logStats, setLogStats] = useState<any>(null);
  const [logsLoading, setLogsLoading] = useState(false);

  const authHeader = useCallback(
    () => ({
      "Content-Type": "application/json",
      Authorization: `Bearer ${localStorage.getItem("pg_token") || ""}`,
    }),
    [],
  );

  const fetchData = useCallback(async () => {
    try {
      const [s, a, r, baselineRes] = await Promise.all([
        fetch(`${SIEM_API}/stats`, { headers: authHeader() }),
        fetch(
          `${SIEM_API}/alerts?${new URLSearchParams({
            status: statusFilter,
            ...(severityFilter > 0 ? { severity: String(severityFilter) } : {}),
            limit: "100",
          })}`,
          { headers: authHeader() },
        ),
        fetch(`${SIEM_API}/rules`, { headers: authHeader() }),
        fetch(`${SIEM_API}/baseline`, { headers: authHeader() }),
      ]);

      // Collect errors with endpoint names for a useful diagnostic message
      const failures: string[] = [];
      if (!s.ok) {
        const body = await s.json().catch(() => ({}));
        failures.push(
          `stats (${s.status}${body?.error ? `: ${body.error}` : ""})`,
        );
      }
      if (!a.ok) {
        const body = await a.json().catch(() => ({}));
        failures.push(
          `alerts (${a.status}${body?.error ? `: ${body.error}` : ""})`,
        );
      }
      if (!r.ok) {
        const body = await r.json().catch(() => ({}));
        failures.push(
          `rules (${r.status}${body?.error ? `: ${body.error}` : ""})`,
        );
      }
      if (failures.length > 0) {
        throw new Error(`Failed to load SIEM data — ${failures.join("; ")}`);
      }

      const [sData, aData, rData] = await Promise.all([
        s.json(),
        a.json(),
        r.json(),
      ]);
      setStats(sData);
      setAlerts(aData.alerts || []);
      setRules(rData.rules || []);

      if (baselineRes.ok) {
        setBaseline(await baselineRes.json());
      }

      const [actorsRes, trapsRes] = await Promise.allSettled([
        fetch(`${SCAN_API}/threat-actors`, { headers: authHeader() }),
        fetch(`${HONEYPOT_API}/traps`, { headers: authHeader() }),
      ]);

      if (actorsRes.status === "fulfilled" && actorsRes.value.ok) {
        const d = await actorsRes.value.json();
        setActors(d.actors || []);
        setSpikes(d.campaignSpikes || []);
      }

      if (trapsRes.status === "fulfilled" && trapsRes.value.ok) {
        setTraps(await trapsRes.value.json());
      }

      try {
        const crRes = await fetch(`${SIEM_API}/rules/custom`, {
          headers: authHeader(),
        });
        if (crRes.ok) setCustomRules((await crRes.json()).rules || []);
      } catch {}

      try {
        const snRes = await fetch(`${SIEM_API}/shift-notes`, {
          headers: authHeader(),
        });
        if (snRes.ok) setShiftNotes((await snRes.json()).notes || []);
      } catch {}

      setError(null);
    } catch (err: any) {
      // TypeError: Failed to fetch = server unreachable (backend down / wrong port)
      const msg =
        err?.message === "Failed to fetch"
          ? `Cannot reach backend at ${API_BASE} — ensure the server is running on port 5000`
          : err?.message || "Failed to load SIEM dashboard";
      setError(msg);
    } finally {
      setLoading(false);
    }
  }, [authHeader, statusFilter, severityFilter]);

  useSocket({
    threat_detected: (data: any) => {
      setLiveAlert(data);
      setLiveCount((c) => c + 1);
      fetchData();
      setTimeout(() => setLiveAlert(null), 8000);
    },
    siem_alert: () => {
      fetchData();
    },
    anomaly_detected: () => {
      fetchData();
      fetch(`${SIEM_API}/baseline`)
        .then((r) => r.json())
        .then(setBaseline)
        .catch(() => {});
    },
    ids_alert: (data: any) => {
      setLiveAlert({
        status: "phishing",
        riskScore: data.severity * 20,
        input: `IDS: ${data.type} from ${data.ip}`,
        dna: null,
        confidence: "high",
      });
      fetchData();
      setTimeout(() => setLiveAlert(null), 8000);
    },
    honeypot_triggered: (data: any) => {
      fetchData();
      setLiveAlert({
        status: "phishing",
        riskScore: 100,
        input: `🍯 HONEYPOT: "${data.trapLabel}" triggered by ${data.ip}`,
        dna: null,
        confidence: "high",
      });
      setTimeout(() => setLiveAlert(null), 10000);
    },
    alert_escalated: (data: any) => {
      fetchData();
      setLiveAlert({
        status: "phishing",
        riskScore: 100,
        input: `🚨 ESCALATED: ${data.title}`,
        dna: null,
        confidence: "high",
      });
      setTimeout(() => setLiveAlert(null), 12000);
    },
  });

  useEffect(() => {
    const t = setInterval(fetchData, 5 * 60 * 1000);
    return () => clearInterval(t);
  }, [fetchData]);

  const updateAlertStatus = async (alertId: string, status: string) => {
    // Slide-out animation
    setSlidingOut(alertId);
    await new Promise((r) => setTimeout(r, 380));

    // Optimistically remove from local state so no re-render glitch
    // while the fetch is in-flight
    setAlerts((prev) => prev.filter((a) => a.alertId !== alertId));
    setSlidingOut(null);
    setExpandedAlert(null);

    // Fire the PATCH in the background — fetchData will reconcile
    fetch(`${SIEM_API}/alerts/${alertId}`, {
      method: "PATCH",
      headers: authHeader(),
      body: JSON.stringify({ status }),
    }).then(() => fetchData());
  };

  const handleDeleteEvents = async () => {
    setDeleteModal((m) => ({ ...m, loading: true }));
    try {
      const res = await fetch(`${SIEM_API}/events`, {
        method: "DELETE",
        headers: authHeader(),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Delete failed");
      addToast("success", data.message || "All SIEM events deleted");
      setDeleteModal({ type: null, loading: false });
      fetchData();
    } catch (err: any) {
      addToast("error", err.message || "Failed to delete events");
      setDeleteModal((m) => ({ ...m, loading: false }));
    }
  };

  const handleDeleteAlerts = async () => {
    setDeleteModal((m) => ({ ...m, loading: true }));
    try {
      const res = await fetch(`${SIEM_API}/alerts`, {
        method: "DELETE",
        headers: authHeader(),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Delete failed");
      addToast("success", data.message || "All alerts deleted");
      setDeleteModal({ type: null, loading: false });
      fetchData();
    } catch (err: any) {
      addToast("error", err.message || "Failed to delete alerts");
      setDeleteModal((m) => ({ ...m, loading: false }));
    }
  };

  const fetchLogs = useCallback(async () => {
    setLogsLoading(true);
    try {
      const [logsRes, statsRes] = await Promise.all([
        fetch(`${LOGS_API}?limit=50`, { headers: authHeader() }),
        fetch(`${LOGS_API}/stats`, { headers: authHeader() }),
      ]);
      if (logsRes.ok) setLogEvents((await logsRes.json()).logs ?? []);
      if (statsRes.ok) setLogStats(await statsRes.json());
    } catch {
    } finally {
      setLogsLoading(false);
    }
  }, [authHeader]);

  const fetchIOCs = useCallback(async () => {
    setIocLoading(true);
    try {
      const params = new URLSearchParams({
        page: String(iocPage),
        limit: "50",
        ...(iocFilter.type ? { type: iocFilter.type } : {}),
        ...(iocFilter.severity ? { severity: String(iocFilter.severity) } : {}),
        status: iocFilter.status || "active",
      });
      const [statsRes, listRes] = await Promise.all([
        fetch(`${SIEM_API}/ioc/stats`, { headers: authHeader() }),
        fetch(`${SIEM_API}/ioc?${params}`, { headers: authHeader() }),
      ]);
      if (statsRes.ok) setIocStats(await statsRes.json());
      if (listRes.ok) {
        const d = await listRes.json();
        setIocs(d.iocs || []);
        setIocTotal(d.total || 0);
      }
    } catch {
      /* offline */
    } finally {
      setIocLoading(false);
    }
  }, [iocPage, iocFilter, authHeader]);

  useEffect(() => {
    fetchData();
    fetchLogs();
  }, [fetchData, fetchLogs]);

  useEffect(() => {
    if (activeTab === "alerts") fetchData();
  }, [statusFilter, severityFilter, activeTab, fetchData]);

  useEffect(() => {
    if (activeTab === "ioc") fetchIOCs();
  }, [activeTab, fetchIOCs]);

  const correlate = async () => {
    setCorrelating(true);
    try {
      await fetch(`${SIEM_API}/correlate`, { method: "POST" });
      await fetchData();
    } finally {
      setCorrelating(false);
    }
  };

  const runBaselineCheck = async () => {
    setRunningBaseline(true);
    try {
      await fetch(`${SIEM_API}/baseline/check`, { method: "POST" });
      await fetchData();
    } finally {
      setRunningBaseline(false);
    }
  };

  const exportCsv = () => {
    const headers = [
      "Alert ID",
      "Title",
      "Category",
      "Severity",
      "Status",
      "Risk Score",
      "First Seen",
      "MITRE Tactic",
    ];
    const rows = alerts.map((a) => [
      a.alertId,
      `"${(a.title || "").replace(/"/g, '""')}"`,
      a.category,
      a.severityLabel,
      a.status,
      String(a.riskScore),
      new Date(a.firstSeen).toLocaleString(),
      a.mitre?.tactic || "",
    ]);
    const csv = [headers, ...rows].map((r) => r.join(",")).join("\n");
    const blob = new Blob([csv], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `siem-alerts-${Date.now()}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const exportPdf = async () => {
    try {
      const params = new URLSearchParams({
        format: "pdf",
        ...(statusFilter ? { status: statusFilter } : {}),
        ...(severityFilter > 0 ? { severity: String(severityFilter) } : {}),
      });
      const res = await fetch(`${SIEM_API}/alerts/export?${params}`, {
        headers: authHeader(),
      });
      if (!res.ok) throw new Error("Failed to generate PDF report");
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `siem-alerts-report-${Date.now()}.pdf`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      addToast("error", "Failed to export PDF report");
    }
  };

  if (error && !loading) {
    return (
      <div
        className="min-h-full flex items-center justify-center px-6"
        style={{ background: "var(--bg-base)" }}
      >
        <div className="text-center max-w-sm">
          <XCircle
            className="size-12 mx-auto mb-4"
            style={{ color: "#E1251B" }}
          />
          <h2
            className="text-xl font-bold mb-2"
            style={{
              fontFamily: "'Syne',sans-serif",
              color: "var(--text-primary)",
            }}
          >
            SentinelCore Offline
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
            style={{ fontFamily: "'Syne',sans-serif", fontWeight: 700 }}
          >
            <RefreshCw className="size-4" /> Retry Connection
          </button>
        </div>
      </div>
    );
  }

  return (
    <div
      className="min-h-full px-6 py-8"
      style={{ background: "var(--bg-base)" }}
    >
      <div className="max-w-7xl mx-auto space-y-5">
        <div className="flex flex-wrap items-center gap-3">
          <div className="tag-green inline-flex">
            <Terminal className="size-3" /> SENTINELCORE SIEM
          </div>
          <h1
            className="text-3xl font-bold"
            style={{
              color: "var(--text-primary)",
              fontFamily: "'Syne', sans-serif",
            }}
          >
            Security Operations Dashboard
          </h1>
          <button
            onClick={fetchData}
            className="ml-auto btn-ghost flex items-center gap-2 px-3 py-2 text-sm"
            style={{ fontFamily: "'DM Sans', sans-serif" }}
          >
            <RefreshCw className="size-4" /> Refresh
          </button>
        </div>

        <AnimatePresence>
          {liveAlert && (
            <motion.div
              initial={{ opacity: 0, y: -20, scale: 0.97 }}
              animate={{ opacity: 1, y: 0, scale: 1 }}
              exit={{ opacity: 0, y: -20, scale: 0.97 }}
              transition={{ duration: 0.3 }}
              className="p-4 rounded-xl flex items-start gap-4 cursor-pointer"
              style={{
                background:
                  liveAlert.status === "phishing"
                    ? "rgba(255,68,68,0.1)"
                    : "rgba(245,166,35,0.1)",
                border: `2px solid ${liveAlert.status === "phishing" ? "#E1251B" : "#f5a623"}`,
                boxShadow: `0 0 30px ${liveAlert.status === "phishing" ? "rgba(255,68,68,0.2)" : "rgba(245,166,35,0.15)"}`,
              }}
              onClick={() => setLiveAlert(null)}
            >
              <span className="text-xl">
                {liveAlert.status === "phishing" ? "🚨" : "⚠️"}
              </span>
              <div className="flex-1 min-w-0">
                <div className="flex flex-wrap items-center gap-2">
                  <span
                    className="font-bold text-sm"
                    style={{
                      color:
                        liveAlert.status === "phishing" ? "#E1251B" : "#f5a623",
                      fontFamily: "'Syne', sans-serif",
                    }}
                  >
                    LIVE — {liveAlert.status.toUpperCase()} DETECTED
                  </span>
                  <span
                    className="text-xs px-2 py-0.5 rounded"
                    style={{
                      background: "rgba(0,0,0,0.3)",
                      color: "var(--text-muted)",
                      fontFamily: "'JetBrains Mono', monospace",
                    }}
                  >
                    Score: {liveAlert.riskScore}/100 ·{" "}
                    {liveAlert.confidence?.toUpperCase() || "UNKNOWN"}
                  </span>
                  <span
                    className="text-xs ml-auto"
                    style={{
                      color: "var(--text-muted)",
                      fontFamily: "'JetBrains Mono', monospace",
                    }}
                  >
                    click to dismiss
                  </span>
                </div>
                <p
                  className="text-xs truncate mt-1"
                  style={{
                    color: "var(--text-secondary)",
                    fontFamily: "'JetBrains Mono', monospace",
                  }}
                >
                  {liveAlert.input}
                </p>
                {liveAlert.dna?.fingerprint && (
                  <p
                    className="text-xs mt-1"
                    style={{
                      color: "#a78bfa",
                      fontFamily: "'JetBrains Mono', monospace",
                    }}
                  >
                    🧬 DNA #{liveAlert.dna.fingerprint} ·{" "}
                    {liveAlert.dna.technique?.replace(/_/g, " ")}
                  </p>
                )}
              </div>
              <div
                className="flex-shrink-0 text-xs font-bold px-2 py-1 rounded"
                style={{
                  background: "rgba(0,0,0,0.3)",
                  color: "var(--accent-green)",
                  fontFamily: "'JetBrains Mono', monospace",
                }}
              >
                #{liveCount}
              </div>
            </motion.div>
          )}
        </AnimatePresence>

        {stats && (
          <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 xl:grid-cols-7 gap-3 mb-6">
            {[
              {
                label: "Total Events",
                value: stats.overview.totalEvents,
                color: "var(--accent-green)",
                icon: Database,
                deletable: "events" as const,
              },
              {
                label: "Total Alerts",
                value: stats.overview.totalAlerts,
                color: "var(--accent-cyan)",
                icon: Activity,
                deletable: "alerts" as const,
              },
              {
                label: "Open Alerts",
                value: stats.overview.openAlerts,
                color: "#f5a623",
                icon: AlertTriangle,
                deletable: null,
              },
              {
                label: "Critical",
                value: stats.overview.criticalAlerts,
                color: "#E1251B",
                icon: XCircle,
                deletable: null,
              },
              {
                label: "Events 24h",
                value: stats.overview.events24h,
                color: "var(--accent-green)",
                icon: TrendingUp,
                deletable: null,
              },
              {
                label: "Alerts 24h",
                value: stats.overview.alerts24h,
                color: "#f97316",
                icon: Zap,
                deletable: null,
              },
              {
                label: "Attack Chains",
                value: stats.overview.correlatedAlerts,
                color: "#a78bfa",
                icon: LinkIcon,
                deletable: null,
              },
            ].map((card, i) => (
              <motion.div
                key={card.label}
                initial={{ opacity: 0, y: 16 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: i * 0.05 }}
                className="card p-4 text-center relative group"
                style={{ background: "var(--bg-card)" }}
              >
                <card.icon
                  className="size-4 mx-auto mb-2"
                  style={{ color: card.color }}
                />
                <div
                  className="text-2xl font-bold"
                  style={{
                    color: card.color,
                    fontFamily: "'Syne', sans-serif",
                  }}
                >
                  {loading ? "—" : card.value}
                </div>
                <div
                  className="text-xs mt-0.5 uppercase tracking-widest"
                  style={{
                    color: "var(--text-muted)",
                    fontFamily: "'JetBrains Mono', monospace",
                  }}
                >
                  {card.label}
                </div>
                {/* Delete button — only on Total Events and Total Alerts */}
                {card.deletable && (
                  <button
                    onClick={() =>
                      setDeleteModal({ type: card.deletable, loading: false })
                    }
                    title={`Delete all ${card.deletable}`}
                    className="absolute top-2 right-2 opacity-0 group-hover:opacity-100 transition-all p-1 rounded-lg"
                    style={{
                      color: "#E1251B",
                      background: "rgba(255,68,68,0.08)",
                      border: "1px solid rgba(255,68,68,0.2)",
                    }}
                  >
                    <Trash2 className="size-3" />
                  </button>
                )}
              </motion.div>
            ))}
          </div>
        )}

        {/* ── Delete Confirmation Modal ── */}
        <AnimatePresence>
          {deleteModal.type && (
            <>
              {/* Backdrop */}
              <motion.div
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
                className="fixed inset-0 z-50"
                style={{
                  background: "rgba(5,8,15,0.80)",
                  backdropFilter: "blur(6px)",
                }}
                onClick={() =>
                  !deleteModal.loading &&
                  setDeleteModal({ type: null, loading: false })
                }
              />
              {/* Modal */}
              <motion.div
                initial={{ opacity: 0, scale: 0.95, y: -20 }}
                animate={{ opacity: 1, scale: 1, y: 0 }}
                exit={{ opacity: 0, scale: 0.95, y: -20 }}
                transition={{ duration: 0.18, ease: [0.4, 0, 0.2, 1] }}
                className="fixed top-1/4 left-1/2 -translate-x-1/2 z-50 w-full max-w-md px-4"
              >
                <div
                  className="rounded-2xl overflow-hidden"
                  style={{
                    background: "var(--bg-elevated)",
                    border: "2px solid rgba(255,68,68,0.35)",
                    boxShadow:
                      "0 25px 80px rgba(0,0,0,0.7), 0 0 0 1px rgba(255,68,68,0.1)",
                  }}
                >
                  {/* Modal header */}
                  <div
                    className="px-6 py-4 flex items-center gap-3"
                    style={{
                      background: "rgba(255,68,68,0.08)",
                      borderBottom: "1px solid rgba(255,68,68,0.2)",
                    }}
                  >
                    <div
                      className="w-10 h-10 rounded-xl flex items-center justify-center flex-shrink-0"
                      style={{
                        background: "rgba(255,68,68,0.12)",
                        border: "1px solid rgba(255,68,68,0.3)",
                      }}
                    >
                      <TriangleAlert
                        className="size-5"
                        style={{ color: "#E1251B" }}
                      />
                    </div>
                    <div>
                      <h3
                        className="text-base font-bold"
                        style={{
                          color: "#E1251B",
                          fontFamily: "'Syne', sans-serif",
                        }}
                      >
                        Permanent Delete —{" "}
                        {deleteModal.type === "events"
                          ? "All Events"
                          : "All Alerts"}
                      </h3>
                      <p
                        className="text-xs mt-0.5"
                        style={{
                          color: "var(--text-muted)",
                          fontFamily: "'JetBrains Mono', monospace",
                        }}
                      >
                        This action cannot be undone
                      </p>
                    </div>
                  </div>

                  {/* Warning body */}
                  <div className="px-6 py-5">
                    <div
                      className="rounded-xl p-4 mb-4"
                      style={{
                        background: "rgba(255,68,68,0.06)",
                        border: "1px solid rgba(255,68,68,0.15)",
                      }}
                    >
                      <div className="flex items-start gap-3">
                        <span className="text-xl flex-shrink-0">⚠️</span>
                        <div className="space-y-1.5">
                          <p
                            className="text-sm font-semibold"
                            style={{
                              color: "#E1251B",
                              fontFamily: "'Syne', sans-serif",
                            }}
                          >
                            You are about to permanently delete{" "}
                            {deleteModal.type === "events"
                              ? `all ${stats?.overview.totalEvents?.toLocaleString() || 0} SIEM events`
                              : `all ${stats?.overview.totalAlerts?.toLocaleString() || 0} alerts`}
                            .
                          </p>
                          <p
                            className="text-xs leading-relaxed"
                            style={{ color: "var(--text-secondary)" }}
                          >
                            {deleteModal.type === "events"
                              ? "This will erase all SIEM event logs including IDS detections, scan events, honeypot triggers, and correlation data. Active alerts will also be removed."
                              : "This will erase all generated alerts including open, resolved, and escalated alerts. SIEM events will not be affected."}
                          </p>
                          <p
                            className="text-xs font-bold"
                            style={{
                              color: "#E1251B",
                              fontFamily: "'JetBrains Mono', monospace",
                            }}
                          >
                            ⚠ This is permanent and cannot be recovered.
                          </p>
                        </div>
                      </div>
                    </div>

                    {/* Count display */}
                    <div
                      className="flex items-center gap-3 px-4 py-3 rounded-xl mb-5"
                      style={{
                        background: "var(--bg-card)",
                        border: "1px solid var(--bg-border)",
                      }}
                    >
                      <Trash2
                        className="size-4 flex-shrink-0"
                        style={{ color: "#E1251B" }}
                      />
                      <div>
                        <p
                          className="text-xs"
                          style={{
                            color: "var(--text-muted)",
                            fontFamily: "'JetBrains Mono', monospace",
                          }}
                        >
                          Records to be deleted:
                        </p>
                        <p
                          className="text-sm font-bold mt-0.5"
                          style={{
                            color: "#E1251B",
                            fontFamily: "'Syne', sans-serif",
                          }}
                        >
                          {deleteModal.type === "events"
                            ? `${stats?.overview.totalEvents?.toLocaleString() || 0} events`
                            : `${stats?.overview.totalAlerts?.toLocaleString() || 0} alerts`}
                        </p>
                      </div>
                    </div>

                    {/* Action buttons */}
                    <div className="flex gap-3">
                      <button
                        onClick={() =>
                          !deleteModal.loading &&
                          setDeleteModal({ type: null, loading: false })
                        }
                        disabled={deleteModal.loading}
                        className="flex-1 py-3 rounded-xl text-sm font-semibold transition-all"
                        style={{
                          background: "var(--bg-card)",
                          border: "1px solid var(--bg-border)",
                          color: "var(--text-secondary)",
                          fontFamily: "'DM Sans', sans-serif",
                        }}
                      >
                        Cancel
                      </button>
                      <button
                        onClick={
                          deleteModal.type === "events"
                            ? handleDeleteEvents
                            : handleDeleteAlerts
                        }
                        disabled={deleteModal.loading}
                        className="flex-1 py-3 rounded-xl text-sm font-bold transition-all flex items-center justify-center gap-2"
                        style={{
                          background: deleteModal.loading
                            ? "rgba(255,68,68,0.3)"
                            : "rgba(255,68,68,0.12)",
                          border: "2px solid rgba(255,68,68,0.5)",
                          color: "#E1251B",
                          fontFamily: "'Syne', sans-serif",
                        }}
                      >
                        {deleteModal.loading ? (
                          <>
                            <div
                              className="w-4 h-4 border-2 rounded-full animate-spin"
                              style={{
                                borderColor: "#E1251B",
                                borderTopColor: "transparent",
                              }}
                            />
                            Deleting...
                          </>
                        ) : (
                          <>
                            <Trash2 className="size-4" />
                            Yes, Delete Permanently
                          </>
                        )}
                      </button>
                    </div>
                  </div>
                </div>
              </motion.div>
            </>
          )}
        </AnimatePresence>

        {/* ── Toast notifications ── */}
        <div className="fixed bottom-6 right-6 z-[60] flex flex-col gap-2 pointer-events-none">
          <AnimatePresence>
            {toasts.map((t) => (
              <motion.div
                key={t.id}
                initial={{ opacity: 0, y: 12, scale: 0.95 }}
                animate={{ opacity: 1, y: 0, scale: 1 }}
                exit={{ opacity: 0, y: 12, scale: 0.95 }}
                className="px-4 py-3 rounded-xl text-sm font-semibold pointer-events-auto"
                style={{
                  background:
                    t.type === "success"
                      ? "rgba(0,255,136,0.12)"
                      : "rgba(255,68,68,0.12)",
                  border:
                    t.type === "success"
                      ? "1px solid rgba(0,255,136,0.3)"
                      : "1px solid rgba(255,68,68,0.3)",
                  color:
                    t.type === "success" ? "var(--accent-green)" : "#E1251B",
                  fontFamily: "'Syne', sans-serif",
                  boxShadow: "0 8px 32px rgba(0,0,0,0.4)",
                }}
              >
                {t.type === "success" ? "✓ " : "✗ "}
                {t.msg}
              </motion.div>
            ))}
          </AnimatePresence>
        </div>

        <div
          className="rounded-xl p-2 flex flex-wrap gap-1 overflow-x-auto"
          style={{
            background: "var(--bg-card)",
            border: "1px solid var(--bg-border)",
            scrollbarWidth: "none",
            WebkitOverflowScrolling: "touch",
            maxWidth: "100%",
          }}
        >
          {(
            [
              "alerts",
              "rules",
              "topology",
              "baseline",
              "behavior",
              "honeypot",
              "custom-rules",
              "shift",
              "logs",
            ] as const
          ).map((tab) => {
            const pillBg =
              tab === "honeypot" || tab === "custom-rules"
                ? "rgba(245,166,35,0.12)"
                : tab === "behavior" || tab === "shift"
                  ? "rgba(0,212,255,0.08)"
                  : "rgba(0,255,136,0.08)";
            return (
              <button
                key={tab}
                onClick={() => setActiveTab(tab)}
                className="relative px-4 py-2 rounded-lg text-sm font-medium transition-all flex-shrink-0 whitespace-nowrap"
                style={{
                  fontFamily: "'DM Sans', sans-serif",
                  color:
                    activeTab === tab
                      ? "var(--accent)"
                      : "var(--text-secondary)",
                  background:
                    activeTab === tab ? "var(--accent-subtle)" : "transparent",
                  border:
                    activeTab === tab
                      ? "1px solid var(--accent-border)"
                      : "1px solid transparent",
                  fontWeight: activeTab === tab ? 700 : 400,
                }}
              >
                {activeTab === tab && (
                  <motion.div
                    layoutId="siem-tab-pill"
                    className="absolute inset-0 rounded-lg"
                    style={{ background: pillBg }}
                    transition={{ type: "spring", bounce: 0.2, duration: 0.35 }}
                  />
                )}
                <span className="relative z-10">
                  {tab === "alerts" && "Alerts"}
                  {tab === "rules" && "Rules"}
                  {tab === "topology" && "Trends"}
                  {tab === "baseline" && "Baseline"}
                  {tab === "behavior" && "Threat Actors"}
                  {tab === "honeypot" && "🍯 Honeypot"}
                  {tab === "custom-rules" && "Custom Rules"}
                  {tab === "shift" && "Shift Notes"}
                  {tab === "logs" && "📋 Logs"}
                </span>
              </button>
            );
          })}

          {/* ── IOC tab button — distinct red style ── */}
          <button
            onClick={() => setActiveTab("ioc")}
            className="relative px-3 md:px-5 py-2 rounded-lg text-sm font-medium transition-all flex-shrink-0 whitespace-nowrap flex items-center gap-1.5"
            style={{
              fontFamily: "var(--font-sans)",
              color: activeTab === "ioc" ? "#080c14" : "var(--color-danger)",
              background:
                activeTab === "ioc"
                  ? "var(--color-danger)"
                  : "rgba(225,37,27,0.08)",
              border:
                activeTab === "ioc" ? "none" : "1px solid rgba(225,37,27,0.2)",
              fontWeight: activeTab === "ioc" ? 700 : 400,
            }}
          >
            🔴 IOC
            {iocStats?.active > 0 && (
              <span
                className="text-[9px] px-1.5 py-0.5 rounded-full font-bold"
                style={{
                  background: "rgba(225,37,27,0.25)",
                  color: activeTab === "ioc" ? "#080c14" : "#E1251B",
                }}
              >
                {iocStats.active}
              </span>
            )}
          </button>
        </div>

        {activeTab === "alerts" && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            className="space-y-3"
          >
            {/* ── Filter bar ─────────────────────────────────────────── */}
            <div className="flex flex-wrap items-center gap-2">
              {/* Status pills */}
              <div
                className="flex items-center gap-1 p-1 rounded-xl"
                style={{
                  background: "var(--bg-elevated)",
                  border: "1px solid var(--bg-border)",
                }}
              >
                {(
                  [
                    { value: "open", label: "Open", color: "#f87171" },
                    {
                      value: "investigating",
                      label: "Investigating",
                      color: "#fbbf24",
                    },
                    { value: "resolved", label: "Resolved", color: "#34d399" },
                    {
                      value: "false_positive",
                      label: "False +",
                      color: "#64748b",
                    },
                  ] as const
                ).map(({ value, label, color }) => {
                  const active = statusFilter === value;
                  const count = alerts.filter((a) => a.status === value).length;
                  return (
                    <button
                      key={value}
                      onClick={() => setStatusFilter(value)}
                      className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-all"
                      style={{
                        background: active ? `${color}12` : "transparent",
                        color: active ? color : "var(--text-muted)",
                        border: active
                          ? `1px solid ${color}30`
                          : "1px solid transparent",
                        fontFamily: "var(--font-mono)",
                      }}
                    >
                      {label}
                      {count > 0 && (
                        <span
                          className="text-[9px] px-1.5 py-0.5 rounded-full font-bold"
                          style={{
                            background: active
                              ? `${color}20`
                              : "var(--bg-border)",
                            color: active ? color : "var(--text-muted)",
                          }}
                        >
                          {count}
                        </span>
                      )}
                    </button>
                  );
                })}
              </div>

              {/* Severity filter */}
              <select
                value={severityFilter}
                onChange={(e) => setSeverityFilter(Number(e.target.value))}
                className="text-xs px-2.5 py-1.5 rounded-xl"
                style={{
                  background: "var(--bg-elevated)",
                  border: "1px solid var(--bg-border)",
                  color: "var(--text-secondary)",
                  fontFamily: "var(--font-mono)",
                  outline: "none",
                }}
              >
                <option value={0}>All severities</option>
                <option value={5}>Critical (5)</option>
                <option value={4}>High (4)</option>
                <option value={3}>Medium (3)</option>
                <option value={2}>Low (2)</option>
              </select>

              {/* Correlate */}
              <button
                onClick={correlate}
                disabled={correlating}
                className="btn-ghost flex items-center gap-2 px-3.5 py-1.5 text-sm"
              >
                <LinkIcon className="size-3.5" />
                {correlating ? "Correlating..." : "Correlate"}
              </button>

              {/* Export buttons */}
              <div className="ml-auto flex gap-1.5">
                <button
                  onClick={exportCsv}
                  className="btn-ghost px-3 py-1.5 text-xs"
                  style={{
                    color: "var(--accent)",
                    fontFamily: "var(--font-mono)",
                  }}
                >
                  ↓ CSV
                </button>
                <button
                  onClick={exportPdf}
                  className="btn-ghost px-3 py-1.5 text-xs"
                  style={{
                    color: "var(--color-danger)",
                    fontFamily: "var(--font-mono)",
                  }}
                >
                  ↓ PDF
                </button>
              </div>
            </div>

            {/* Active filter indicator */}
            {(statusFilter !== "open" || severityFilter > 0) && (
              <div
                className="flex items-center gap-2 px-3 py-2 rounded-xl text-xs"
                style={{
                  background: "var(--accent-subtle)",
                  border: "1px solid var(--accent-border)",
                  fontFamily: "var(--font-mono)",
                }}
              >
                <Filter className="size-3" style={{ color: "var(--accent)" }} />
                <span style={{ color: "var(--text-secondary)" }}>
                  {statusFilter !== "open" && (
                    <strong style={{ color: "var(--accent)" }}>
                      {statusFilter.replace("_", " ")}
                    </strong>
                  )}
                  {severityFilter > 0 && (
                    <strong style={{ color: "var(--accent)" }}>
                      {statusFilter !== "open" ? " · " : ""}SEV {severityFilter}
                      +
                    </strong>
                  )}
                </span>
                <button
                  onClick={() => {
                    setStatusFilter("open");
                    setSeverityFilter(0);
                  }}
                  className="ml-auto text-xs"
                  style={{
                    color: "var(--text-muted)",
                    background: "none",
                    border: "none",
                    cursor: "pointer",
                  }}
                >
                  Clear
                </button>
              </div>
            )}

            {/* Empty state */}
            {alerts.filter(
              (a) =>
                a.status === statusFilter &&
                (severityFilter === 0 || a.severity >= severityFilter),
            ).length === 0 ? (
              <div className="card p-10 text-center">
                <CheckCircle
                  className="size-10 mx-auto mb-3"
                  style={{ color: "var(--safe)", opacity: 0.5 }}
                />
                <p
                  className="text-sm font-semibold"
                  style={{ color: "var(--safe)" }}
                >
                  No {statusFilter.replace("_", " ")} alerts
                </p>
                <p
                  className="text-xs mt-1"
                  style={{ color: "var(--text-muted)" }}
                >
                  SIEM is quiet for this filter.
                </p>
              </div>
            ) : (
              // ── Alert list ──────────────────────────────────────────
              <AnimatePresence initial={false}>
                {alerts
                  .filter(
                    (a) =>
                      a.status === statusFilter &&
                      (severityFilter === 0 || a.severity >= severityFilter),
                  )
                  .map((alert) => {
                    const sev = SEV[alert.severity] || SEV[3];
                    const open = expandedAlert === alert.alertId;
                    const sliding = slidingOut === alert.alertId;
                    const target = getAlertTarget(alert);
                    const itype = getInputTypeLabel(alert);

                    const statusColor =
                      alert.status === "resolved"
                        ? "#34d399"
                        : alert.status === "investigating"
                          ? "#fbbf24"
                          : alert.status === "false_positive"
                            ? "#64748b"
                            : "#f87171";

                    const SCORE_COLOR =
                      alert.riskScore >= 70
                        ? "#f87171"
                        : alert.riskScore >= 40
                          ? "#fbbf24"
                          : "#34d399";

                    return (
                      <motion.div
                        key={alert.alertId}
                        layout
                        initial={{ opacity: 0, x: -12 }}
                        animate={{ opacity: 1, x: 0 }}
                        exit={{ opacity: 0, x: 48, scale: 0.97 }}
                        transition={{ duration: 0.28, ease: [0.4, 0, 0.2, 1] }}
                        className="overflow-hidden rounded-2xl"
                        style={{
                          background: "var(--bg-card)",
                          border: `1px solid ${sev.border}`,
                        }}
                      >
                        {/* ── Collapsed row ────────────────────────────── */}
                        <button
                          onClick={() =>
                            setExpandedAlert(open ? null : alert.alertId)
                          }
                          className="w-full text-left flex items-stretch"
                          style={{ minHeight: 64 }}
                        >
                          {/* Severity block — color + glowing circle + rotated label */}
                          <div
                            className="flex-shrink-0 flex flex-col items-center justify-center rounded-l-2xl py-4"
                            style={{
                              background: `${sev.color}14`,
                              borderRight: `2px solid ${sev.color}`,
                              minWidth: 52,
                              alignSelf: "stretch",
                              gap: 6,
                            }}
                          >
                            {/* Glowing circle */}
                            <div
                              className="rounded-full flex-shrink-0"
                              style={{
                                width: 18,
                                height: 18,
                                background: sev.color,
                                boxShadow: `0 0 10px ${sev.color}60, 0 0 3px ${sev.color}`,
                              }}
                            />
                            {/* Severity label — rotated vertical */}
                            <span
                              style={{
                                color: sev.color,
                                fontFamily: "var(--font-mono)",
                                fontSize: 8,
                                fontWeight: 800,
                                letterSpacing: "0.15em",
                                writingMode: "vertical-rl" as const,
                                transform: "rotate(180deg)",
                                textTransform: "uppercase" as const,
                                lineHeight: 1,
                                userSelect: "none" as const,
                                opacity: 0.85,
                              }}
                            >
                              {sev.label}
                            </span>
                          </div>
                          <div className="flex-1 flex items-center gap-3 px-4 py-3.5">
                            {/* Main content */}
                            <div className="flex-1 min-w-0">
                              {/* Row 1: title + badges */}
                              <div className="flex items-center gap-2 flex-wrap mb-1">
                                <span
                                  className="text-sm font-semibold"
                                  style={{ color: "var(--text-primary)" }}
                                >
                                  {alert.title}
                                </span>
                                {/* Severity badge */}
                                <span
                                  className="text-[9px] font-bold px-1.5 py-0.5 rounded tracking-widest"
                                  style={{
                                    color: sev.color,
                                    background: sev.bg,
                                    border: `1px solid ${sev.border}`,
                                    fontFamily: "var(--font-mono)",
                                  }}
                                >
                                  {sev.label}
                                </span>
                                {/* Status badge */}
                                <span
                                  className="text-[9px] font-semibold px-1.5 py-0.5 rounded capitalize"
                                  style={{
                                    color: statusColor,
                                    background: `${statusColor}10`,
                                    border: `1px solid ${statusColor}25`,
                                    fontFamily: "var(--font-mono)",
                                  }}
                                >
                                  {alert.status.replace("_", " ")}
                                </span>
                                {/* Correlation chain */}
                                {alert.isCorrelated && (
                                  <span
                                    className="text-[9px] px-1.5 py-0.5 rounded font-bold"
                                    style={{
                                      color: "#a78bfa",
                                      background: "rgba(167,139,250,0.08)",
                                      border: "1px solid rgba(167,139,250,0.2)",
                                      fontFamily: "var(--font-mono)",
                                    }}
                                  >
                                    🔗 CHAIN
                                  </span>
                                )}
                                {/* SLA near-breach */}
                                {alert.slaDeadline &&
                                  new Date(alert.slaDeadline).getTime() -
                                    Date.now() <
                                    3600000 && (
                                    <span
                                      className="text-[9px] px-1.5 py-0.5 rounded font-bold"
                                      style={{
                                        color: "#f87171",
                                        background: "rgba(248,113,113,0.08)",
                                        border:
                                          "1px solid rgba(248,113,113,0.2)",
                                        fontFamily: "var(--font-mono)",
                                      }}
                                    >
                                      ⏱ SLA
                                    </span>
                                  )}
                                {(alert as any).escalated && (
                                  <span
                                    className="text-[9px] px-1.5 py-0.5 rounded font-bold animate-pulse"
                                    style={{
                                      color: "#f87171",
                                      background: "rgba(248,113,113,0.1)",
                                      border: "1px solid rgba(248,113,113,0.3)",
                                      fontFamily: "var(--font-mono)",
                                    }}
                                  >
                                    🚨 ESCALATED
                                  </span>
                                )}
                                {/* Forensic ID chip — copyable, always visible in collapsed row */}
                                <span
                                  className="text-[10px] font-bold px-2 py-0.5 rounded select-all cursor-copy"
                                  style={{
                                    color: "var(--accent)",
                                    background: "var(--accent-subtle)",
                                    border: "1px solid var(--accent-border)",
                                    fontFamily: "var(--font-mono)",
                                  }}
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    navigator.clipboard.writeText(
                                      alert.alertId,
                                    );
                                  }}
                                  title="Click to copy Alert ID"
                                >
                                  {alert.alertId}
                                </span>
                              </div>

                              {/* Row 2: target + MITRE — the actually useful intel line */}
                              <div className="flex items-center gap-2 flex-wrap">
                                {itype && (
                                  <span
                                    className="text-[9px] font-bold px-1.5 py-0.5 rounded flex-shrink-0"
                                    style={{
                                      fontFamily: "var(--font-mono)",
                                      color:
                                        itype === "URL"
                                          ? "var(--accent)"
                                          : itype === "Email"
                                            ? "#a78bfa"
                                            : "#34d399",
                                      background:
                                        itype === "URL"
                                          ? "rgba(59,130,246,0.08)"
                                          : itype === "Email"
                                            ? "rgba(167,139,250,0.08)"
                                            : "rgba(52,211,153,0.08)",
                                      border: `1px solid ${
                                        itype === "URL"
                                          ? "rgba(59,130,246,0.2)"
                                          : itype === "Email"
                                            ? "rgba(167,139,250,0.2)"
                                            : "rgba(52,211,153,0.2)"
                                      }`,
                                    }}
                                  >
                                    {itype}
                                  </span>
                                )}
                                <span
                                  className="text-xs truncate max-w-xs md:max-w-sm"
                                  style={{
                                    color: "var(--text-muted)",
                                    fontFamily: "var(--font-mono)",
                                  }}
                                  title={target}
                                >
                                  {target}
                                </span>
                                {alert.mitre?.technique && (
                                  <span
                                    className="text-[9px] hidden md:inline-block truncate max-w-[180px]"
                                    style={{
                                      color: "#a78bfa",
                                      fontFamily: "var(--font-mono)",
                                    }}
                                  >
                                    · {alert.mitre.technique.split(" - ")[0]}
                                  </span>
                                )}
                              </div>
                            </div>

                            {/* Right: risk score + time — clean column */}
                            <div className="flex-shrink-0 text-right ml-2">
                              <div
                                className="text-base font-black"
                                style={{
                                  color: SCORE_COLOR,
                                  lineHeight: 1,
                                  fontFamily: "var(--font-display)",
                                }}
                              >
                                {alert.riskScore}
                              </div>
                              <div
                                className="text-[9px]"
                                style={{
                                  color: "var(--text-muted)",
                                  fontFamily: "var(--font-mono)",
                                }}
                              >
                                /100
                              </div>
                              <div
                                className="text-[9px] mt-1"
                                style={{
                                  color: "var(--text-muted)",
                                  fontFamily: "var(--font-mono)",
                                }}
                              >
                                {new Date(alert.firstSeen).toLocaleDateString()}
                              </div>
                            </div>

                            {/* Chevron */}
                            {open ? (
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
                        </button>

                        {/* ── Expanded detail ──────────────────────────── */}
                        {open && (
                          <motion.div
                            initial={{ opacity: 0, height: 0 }}
                            animate={{ opacity: 1, height: "auto" }}
                            exit={{ opacity: 0, height: 0 }}
                            transition={{
                              duration: 0.22,
                              ease: [0.4, 0, 0.2, 1],
                            }}
                            className="overflow-hidden"
                          >
                            <div
                              className="border-t"
                              style={{ borderColor: "var(--bg-border)" }}
                            >
                              {/* Description */}
                              <div className="px-5 pt-4 pb-3">
                                <p
                                  className="text-xs leading-relaxed"
                                  style={{ color: "var(--text-secondary)" }}
                                >
                                  {alert.description}
                                </p>
                                <div
                                  className="flex items-center gap-3 mt-2 text-[10px]"
                                  style={{
                                    color: "var(--text-muted)",
                                    fontFamily: "var(--font-mono)",
                                  }}
                                >
                                  <span
                                    className="text-[10px] font-bold px-2 py-0.5 rounded select-all cursor-copy"
                                    style={{
                                      color: "var(--accent)",
                                      background: "var(--accent-subtle)",
                                      border: "1px solid var(--accent-border)",
                                      fontFamily: "var(--font-mono)",
                                    }}
                                    onClick={(e) => {
                                      e.stopPropagation();
                                      navigator.clipboard.writeText(
                                        alert.alertId,
                                      );
                                    }}
                                    title="Click to copy Alert ID"
                                  >
                                    {alert.alertId}
                                  </span>
                                  <span>·</span>
                                  <span>Rule: {alert.ruleId}</span>
                                  <span>·</span>
                                  <span>
                                    {new Date(alert.firstSeen).toLocaleString()}
                                  </span>
                                  {alert.eventCount > 1 && (
                                    <>
                                      <span>·</span>
                                      <span>{alert.eventCount} events</span>
                                    </>
                                  )}
                                </div>
                              </div>

                              {/* Scanned target — full value, selectable */}
                              <div
                                className="mx-5 mb-4 px-4 py-3 rounded-xl"
                                style={{
                                  background: "var(--bg-elevated)",
                                  border: "1px solid var(--bg-border)",
                                }}
                              >
                                <div className="label-caps mb-1.5">
                                  Scanned Target
                                </div>
                                <div className="flex items-center gap-2 flex-wrap">
                                  {itype && (
                                    <span
                                      className="text-[9px] font-bold px-1.5 py-0.5 rounded flex-shrink-0"
                                      style={{
                                        fontFamily: "var(--font-mono)",
                                        color:
                                          itype === "URL"
                                            ? "var(--accent)"
                                            : itype === "Email"
                                              ? "#a78bfa"
                                              : "#34d399",
                                        background:
                                          itype === "URL"
                                            ? "rgba(59,130,246,0.08)"
                                            : itype === "Email"
                                              ? "rgba(167,139,250,0.08)"
                                              : "rgba(52,211,153,0.08)",
                                        border: `1px solid ${
                                          itype === "URL"
                                            ? "rgba(59,130,246,0.2)"
                                            : itype === "Email"
                                              ? "rgba(167,139,250,0.2)"
                                              : "rgba(52,211,153,0.2)"
                                        }`,
                                      }}
                                    >
                                      {itype}
                                    </span>
                                  )}
                                  <code
                                    className="text-xs break-all select-all"
                                    style={{
                                      color: "var(--text-primary)",
                                      fontFamily: "var(--font-mono)",
                                    }}
                                  >
                                    {target}
                                  </code>
                                </div>
                                {alert.riskScore > 0 && (
                                  <div className="mt-2 flex items-center gap-2">
                                    <div
                                      className="flex-1 h-1 rounded-full overflow-hidden"
                                      style={{ background: "var(--bg-border)" }}
                                    >
                                      <div
                                        className="h-full rounded-full"
                                        style={{
                                          width: `${alert.riskScore}%`,
                                          background: SCORE_COLOR,
                                        }}
                                      />
                                    </div>
                                    <span
                                      className="text-[9px] font-bold flex-shrink-0"
                                      style={{
                                        color: SCORE_COLOR,
                                        fontFamily: "var(--font-mono)",
                                      }}
                                    >
                                      {alert.riskScore}/100
                                    </span>
                                  </div>
                                )}
                              </div>

                              {/* ── Triage actions ─────────────────────────── */}
                              <div className="mx-5 mb-4">
                                <div className="label-caps mb-2">Triage</div>
                                <div className="flex flex-wrap gap-2">
                                  {(
                                    [
                                      {
                                        value: "investigating",
                                        label: "Investigate",
                                        color: "#fbbf24",
                                      },
                                      {
                                        value: "resolved",
                                        label: "Resolve",
                                        color: "#34d399",
                                      },
                                      {
                                        value: "false_positive",
                                        label: "False +",
                                        color: "#64748b",
                                      },
                                      {
                                        value: "open",
                                        label: "Reopen",
                                        color: "#f87171",
                                      },
                                    ] as const
                                  )
                                    .filter((s) => s.value !== alert.status)
                                    .map((s) => (
                                      <button
                                        key={s.value}
                                        onClick={() =>
                                          updateAlertStatus(
                                            alert.alertId,
                                            s.value,
                                          )
                                        }
                                        disabled={sliding}
                                        className="text-xs px-3.5 py-1.5 rounded-lg font-semibold transition-all"
                                        style={{
                                          color: s.color,
                                          background: `${s.color}10`,
                                          border: `1px solid ${s.color}30`,
                                          opacity: sliding ? 0.5 : 1,
                                          fontFamily: "var(--font-mono)",
                                        }}
                                      >
                                        {s.label}
                                      </button>
                                    ))}
                                </div>
                              </div>

                              {/* ── Evidence Reference ────────────────────── */}
                              <div className="mx-5 mb-4">
                                <div className="label-caps mb-2">
                                  Evidence Reference
                                </div>
                                <div
                                  className="flex items-center gap-3 px-4 py-3 rounded-xl"
                                  style={{
                                    background: "var(--bg-elevated)",
                                    border: "1px solid var(--bg-border)",
                                  }}
                                >
                                  <div className="flex-1">
                                    <div
                                      className="text-xs font-bold"
                                      style={{
                                        color: "var(--accent)",
                                        fontFamily: "var(--font-mono)",
                                      }}
                                    >
                                      {alert.alertId}
                                    </div>
                                    <div
                                      className="text-[10px] mt-0.5"
                                      style={{ color: "var(--text-muted)" }}
                                    >
                                      Reference this ID in shift notes, incident
                                      reports, and legal submissions
                                    </div>
                                  </div>
                                  <div className="flex gap-2 flex-shrink-0">
                                    <button
                                      onClick={() =>
                                        navigator.clipboard.writeText(
                                          alert.alertId,
                                        )
                                      }
                                      className="text-[10px] px-2.5 py-1.5 rounded-lg"
                                      style={{
                                        color: "var(--accent)",
                                        background: "var(--accent-subtle)",
                                        border:
                                          "1px solid var(--accent-border)",
                                        fontFamily: "var(--font-mono)",
                                      }}
                                    >
                                      Copy ID
                                    </button>
                                    <button
                                      onClick={async () => {
                                        const r = await fetch(
                                          `${SIEM_API}/alerts/${alert.alertId}/custody-report`,
                                          { headers: authHeader() },
                                        );
                                        if (!r.ok) return;
                                        const data = await r.json();
                                        const blob = new Blob([data.report], {
                                          type: "text/plain",
                                        });
                                        const a = document.createElement("a");
                                        a.href = URL.createObjectURL(blob);
                                        a.download = `COC-${alert.alertId}.txt`;
                                        a.click();
                                      }}
                                      className="text-[10px] px-2.5 py-1.5 rounded-lg"
                                      style={{
                                        color: "#34d399",
                                        background: "rgba(52,211,153,0.08)",
                                        border:
                                          "1px solid rgba(52,211,153,0.2)",
                                        fontFamily: "var(--font-mono)",
                                      }}
                                    >
                                      ↓ Custody Report
                                    </button>
                                  </div>
                                </div>
                              </div>

                              {/* ── Assign + SLA row ────────────────────────── */}
                              <div className="mx-5 mb-4 flex items-center gap-3 flex-wrap">
                                <div className="flex-1 min-w-48">
                                  <input
                                    type="text"
                                    placeholder="Assign to analyst (Enter to save)"
                                    className="w-full px-3 py-2 rounded-xl text-xs"
                                    style={{
                                      background: "var(--bg-elevated)",
                                      border: "1px solid var(--bg-border)",
                                      color: "var(--text-primary)",
                                      outline: "none",
                                      fontFamily: "var(--font-mono)",
                                    }}
                                    onKeyDown={async (e) => {
                                      if (
                                        e.key === "Enter" &&
                                        (
                                          e.target as HTMLInputElement
                                        ).value.trim()
                                      ) {
                                        await fetch(
                                          `${SIEM_API}/alerts/${alert.alertId}/assign`,
                                          {
                                            method: "PATCH",
                                            headers: authHeader(),
                                            body: JSON.stringify({
                                              assignee: (
                                                e.target as HTMLInputElement
                                              ).value.trim(),
                                            }),
                                          },
                                        );
                                        fetchData();
                                        (e.target as HTMLInputElement).value =
                                          "";
                                      }
                                    }}
                                  />
                                </div>
                                {alert.assignee && (
                                  <span
                                    className="text-xs px-2.5 py-1.5 rounded-xl flex-shrink-0"
                                    style={{
                                      color: "var(--accent)",
                                      background: "var(--accent-subtle)",
                                      border: "1px solid var(--accent-border)",
                                      fontFamily: "var(--font-mono)",
                                    }}
                                  >
                                    → {alert.assignee}
                                  </span>
                                )}
                                {alert.slaDeadline && (
                                  <SLATimer deadline={alert.slaDeadline} />
                                )}
                              </div>

                              {/* ── MITRE ──────────────────────────────────── */}
                              {alert.mitre?.technique && (
                                <div className="mx-5 mb-4">
                                  <div className="label-caps mb-1.5">
                                    MITRE ATT&amp;CK
                                  </div>
                                  <div className="flex flex-wrap gap-1.5">
                                    {alert.mitre.tactic && (
                                      <span
                                        className="text-[10px] px-2.5 py-1 rounded-lg"
                                        style={{
                                          color: "#a78bfa",
                                          background: "rgba(167,139,250,0.08)",
                                          border:
                                            "1px solid rgba(167,139,250,0.2)",
                                          fontFamily: "var(--font-mono)",
                                        }}
                                      >
                                        {alert.mitre.tactic.split(" - ")[0]}
                                      </span>
                                    )}
                                    <span
                                      className="text-[10px] px-2.5 py-1 rounded-lg"
                                      style={{
                                        color: "var(--text-secondary)",
                                        background: "var(--bg-elevated)",
                                        border: "1px solid var(--bg-border)",
                                        fontFamily: "var(--font-mono)",
                                      }}
                                    >
                                      {alert.mitre.technique}
                                    </span>
                                  </div>
                                </div>
                              )}

                              {/* ── Tags ────────────────────────────────────── */}
                              {alert.tags?.length > 0 && (
                                <div className="mx-5 mb-4 flex flex-wrap gap-1.5">
                                  {alert.tags.map((tag) => (
                                    <span
                                      key={tag}
                                      className="text-[9px] px-2 py-0.5 rounded"
                                      style={{
                                        color: "var(--text-muted)",
                                        background: "var(--bg-elevated)",
                                        border: "1px solid var(--bg-border)",
                                        fontFamily: "var(--font-mono)",
                                      }}
                                    >
                                      #{tag}
                                    </span>
                                  ))}
                                </div>
                              )}

                              {/* ── Sigma + Splunk detection rules ─────────── */}
                              {((alert.sigmaRules?.length ?? 0) > 0 ||
                                (alert.splunkRules?.length ?? 0) > 0) && (
                                <div className="mx-5 mb-4">
                                  <div className="label-caps mb-2">
                                    Detection Rules
                                  </div>
                                  <div className="grid md:grid-cols-2 gap-3">
                                    {/* Sigma */}
                                    {(alert.sigmaRules?.length ?? 0) > 0 && (
                                      <div
                                        className="rounded-xl overflow-hidden"
                                        style={{
                                          border:
                                            "1px solid rgba(234,179,8,0.2)",
                                          background: "rgba(234,179,8,0.03)",
                                        }}
                                      >
                                        <div
                                          className="px-3 py-2 border-b flex items-center gap-2"
                                          style={{
                                            borderColor: "rgba(234,179,8,0.12)",
                                          }}
                                        >
                                          <span
                                            className="text-[10px] font-bold"
                                            style={{
                                              color: "#eab308",
                                              fontFamily: "var(--font-mono)",
                                            }}
                                          >
                                            Σ Sigma ({alert.sigmaRules!.length})
                                          </span>
                                        </div>
                                        <div className="p-2 space-y-1">
                                          {alert.sigmaRules!.map((rule, i) => (
                                            <div
                                              key={i}
                                              className="flex items-center gap-2 px-1"
                                            >
                                              <a
                                                href={rule.rule_link}
                                                target="_blank"
                                                rel="noreferrer"
                                                className="text-[10px] flex-1 truncate hover:underline"
                                                style={{
                                                  color:
                                                    "var(--text-secondary)",
                                                  fontFamily:
                                                    "var(--font-mono)",
                                                }}
                                              >
                                                {rule.rule_name}
                                              </a>
                                              <span
                                                className="text-[9px] flex-shrink-0"
                                                style={{
                                                  color: "var(--text-muted)",
                                                }}
                                              >
                                                {rule.platform}
                                              </span>
                                              <a
                                                href={rule.rule_link}
                                                target="_blank"
                                                rel="noreferrer"
                                                className="text-[9px] px-1.5 py-0.5 rounded flex-shrink-0"
                                                style={{
                                                  color: "#eab308",
                                                  background:
                                                    "rgba(234,179,8,0.08)",
                                                  border:
                                                    "1px solid rgba(234,179,8,0.2)",
                                                }}
                                              >
                                                ↗ yml
                                              </a>
                                            </div>
                                          ))}
                                        </div>
                                      </div>
                                    )}

                                    {/* Splunk ESCU */}
                                    {(alert.splunkRules?.length ?? 0) > 0 && (
                                      <div
                                        className="rounded-xl overflow-hidden"
                                        style={{
                                          border:
                                            "1px solid rgba(56,189,248,0.2)",
                                          background: "rgba(56,189,248,0.03)",
                                        }}
                                      >
                                        <div
                                          className="px-3 py-2 border-b flex items-center gap-2"
                                          style={{
                                            borderColor:
                                              "rgba(56,189,248,0.12)",
                                          }}
                                        >
                                          <span
                                            className="text-[10px] font-bold"
                                            style={{
                                              color: "#38bdf8",
                                              fontFamily: "var(--font-mono)",
                                            }}
                                          >
                                            ⊞ Splunk ESCU (
                                            {alert.splunkRules!.length})
                                          </span>
                                        </div>
                                        <div className="p-2 space-y-1">
                                          {alert.splunkRules!.map((rule, i) => (
                                            <div
                                              key={i}
                                              className="flex items-center gap-2 px-1"
                                            >
                                              <a
                                                href={rule.rule_link}
                                                target="_blank"
                                                rel="noreferrer"
                                                className="text-[10px] flex-1 truncate hover:underline"
                                                style={{
                                                  color:
                                                    "var(--text-secondary)",
                                                  fontFamily:
                                                    "var(--font-mono)",
                                                }}
                                              >
                                                {rule.rule_name}
                                              </a>
                                              <span
                                                className="text-[9px] flex-shrink-0"
                                                style={{
                                                  color: "var(--text-muted)",
                                                }}
                                              >
                                                {rule.platform}
                                              </span>
                                              <a
                                                href={rule.rule_link}
                                                target="_blank"
                                                rel="noreferrer"
                                                className="text-[9px] px-1.5 py-0.5 rounded flex-shrink-0"
                                                style={{
                                                  color: "#38bdf8",
                                                  background:
                                                    "rgba(56,189,248,0.08)",
                                                  border:
                                                    "1px solid rgba(56,189,248,0.2)",
                                                }}
                                              >
                                                ↗ ESCU
                                              </a>
                                            </div>
                                          ))}
                                        </div>
                                      </div>
                                    )}
                                  </div>
                                </div>
                              )}

                              {/* ── Comments ────────────────────────────────── */}
                              <div className="mx-5 mb-4">
                                <button
                                  onClick={() =>
                                    setShowComments(
                                      showComments === alert.alertId
                                        ? null
                                        : alert.alertId,
                                    )
                                  }
                                  className="flex items-center gap-1.5 text-xs mb-2"
                                  style={{
                                    color: "var(--text-muted)",
                                    background: "none",
                                    border: "none",
                                    cursor: "pointer",
                                  }}
                                >
                                  <span>
                                    {showComments === alert.alertId ? "▲" : "▼"}
                                  </span>
                                  Comments ({alert.comments?.length || 0})
                                </button>

                                {showComments === alert.alertId && (
                                  <div className="space-y-2">
                                    {(alert.comments || []).map((c, i) => (
                                      <div
                                        key={i}
                                        className="px-3 py-2.5 rounded-xl"
                                        style={{
                                          background: "var(--bg-elevated)",
                                          border: "1px solid var(--bg-border)",
                                        }}
                                      >
                                        <div className="flex items-center gap-2 mb-1">
                                          <span
                                            className="text-xs font-semibold"
                                            style={{
                                              color: "var(--accent)",
                                              fontFamily: "var(--font-mono)",
                                            }}
                                          >
                                            {c.author}
                                          </span>
                                          <span
                                            className="text-[10px]"
                                            style={{
                                              color: "var(--text-muted)",
                                              fontFamily: "var(--font-mono)",
                                            }}
                                          >
                                            {new Date(
                                              c.timestamp,
                                            ).toLocaleString()}
                                          </span>
                                        </div>
                                        <p
                                          className="text-xs"
                                          style={{
                                            color: "var(--text-secondary)",
                                          }}
                                        >
                                          {c.text}
                                        </p>
                                      </div>
                                    ))}

                                    <div className="flex gap-2 mt-2">
                                      <input
                                        type="text"
                                        placeholder="Add comment..."
                                        value={commentText[alert.alertId] || ""}
                                        onChange={(e) =>
                                          setCommentText((prev) => ({
                                            ...prev,
                                            [alert.alertId]: e.target.value,
                                          }))
                                        }
                                        className="flex-1 px-3 py-2 rounded-xl text-xs"
                                        style={{
                                          background: "var(--bg-elevated)",
                                          border: "1px solid var(--bg-border)",
                                          color: "var(--text-primary)",
                                          outline: "none",
                                          fontFamily: "var(--font-mono)",
                                        }}
                                      />
                                      <button
                                        onClick={async () => {
                                          const text =
                                            commentText[alert.alertId]?.trim();
                                          if (!text) return;
                                          await fetch(
                                            `${SIEM_API}/alerts/${alert.alertId}/comment`,
                                            {
                                              method: "POST",
                                              headers: authHeader(),
                                              body: JSON.stringify({ text }),
                                            },
                                          );
                                          setCommentText((prev) => ({
                                            ...prev,
                                            [alert.alertId]: "",
                                          }));
                                          fetchData();
                                        }}
                                        className="btn-primary text-xs px-3.5 py-2"
                                      >
                                        Post
                                      </button>
                                    </div>
                                  </div>
                                )}
                              </div>
                            </div>
                          </motion.div>
                        )}
                      </motion.div>
                    );
                  })}
              </AnimatePresence>
            )}
          </motion.div>
        )}

        {activeTab === "rules" && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            className="rounded-xl overflow-x-auto"
            style={{
              background: "var(--bg-card)",
              border: "1px solid var(--bg-border)",
            }}
          >
            <table className="min-w-full text-sm">
              <thead>
                <tr style={{ background: "var(--bg-elevated)" }}>
                  {[
                    "Rule ID",
                    "Name",
                    "Category",
                    "Severity",
                    "MITRE Tactic",
                    "CVE / CWE",
                  ].map((h) => (
                    <th
                      key={h}
                      className="text-left px-4 py-3 text-xs"
                      style={{
                        color: "var(--text-muted)",
                        fontFamily: "'JetBrains Mono', monospace",
                      }}
                    >
                      {h}
                    </th>
                  ))}
                  <th
                    className="text-left px-4 py-3 text-xs hidden xl:table-cell"
                    style={{
                      color: "var(--text-muted)",
                      fontFamily: "'JetBrains Mono', monospace",
                    }}
                  >
                    <span style={{ color: "#eab308" }}>Σ</span> Sigma
                  </th>
                  <th
                    className="text-left px-4 py-3 text-xs hidden xl:table-cell"
                    style={{
                      color: "var(--text-muted)",
                      fontFamily: "'JetBrains Mono', monospace",
                    }}
                  >
                    <span style={{ color: "#38bdf8" }}>⊞</span> Splunk
                  </th>
                </tr>
              </thead>
              <tbody>
                {rules.map((rule) => (
                  <tr
                    key={rule.id}
                    className="border-t"
                    style={{ borderColor: "var(--bg-border)" }}
                  >
                    <td
                      className="px-4 py-3"
                      style={{
                        color: "var(--accent-cyan)",
                        fontFamily: "'JetBrains Mono', monospace",
                      }}
                    >
                      {rule.id}
                    </td>
                    <td
                      className="px-4 py-3"
                      style={{
                        color: "var(--text-primary)",
                        fontFamily: "'Syne', sans-serif",
                      }}
                    >
                      {rule.name}
                    </td>
                    <td
                      className="px-4 py-3"
                      style={{ color: "var(--text-secondary)" }}
                    >
                      {rule.category}
                    </td>
                    <td
                      className="px-4 py-3"
                      style={{ color: SEV[rule.severity]?.color || "#f5a623" }}
                    >
                      {rule.severityLabel || rule.severity}
                    </td>
                    <td
                      className="px-4 py-3"
                      style={{
                        color: "var(--text-muted)",
                        fontFamily: "'JetBrains Mono', monospace",
                      }}
                    >
                      {rule.mitre?.tactic?.split(" - ")[0] || "—"}
                    </td>
                    <td
                      className="px-4 py-3"
                      style={{
                        color: "var(--text-muted)",
                        fontFamily: "'JetBrains Mono', monospace",
                      }}
                    >
                      {rule.cve ? rule.cve.split(" ")[0] : "—"}
                    </td>
                    <td className="hidden xl:table-cell px-4 py-3">
                      {(rule as any).sigmaCount > 0 ? (
                        <span
                          className="text-xs font-bold px-2 py-0.5 rounded"
                          style={{
                            color: "#eab308",
                            background: "rgba(234,179,8,0.08)",
                            border: "1px solid rgba(234,179,8,0.2)",
                            fontFamily: "'JetBrains Mono', monospace",
                          }}
                        >
                          {(rule as any).sigmaCount} rules
                        </span>
                      ) : (
                        <span
                          className="text-xs"
                          style={{
                            color: "var(--text-muted)",
                            fontFamily: "'JetBrains Mono', monospace",
                          }}
                        >
                          —
                        </span>
                      )}
                    </td>
                    <td className="hidden xl:table-cell px-4 py-3">
                      {(rule as any).splunkCount > 0 ? (
                        <span
                          className="text-xs font-bold px-2 py-0.5 rounded"
                          style={{
                            color: "#38bdf8",
                            background: "rgba(56,189,248,0.08)",
                            border: "1px solid rgba(56,189,248,0.2)",
                            fontFamily: "'JetBrains Mono', monospace",
                          }}
                        >
                          {(rule as any).splunkCount} rules
                        </span>
                      ) : (
                        <span
                          className="text-xs"
                          style={{
                            color: "var(--text-muted)",
                            fontFamily: "'JetBrains Mono', monospace",
                          }}
                        >
                          —
                        </span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </motion.div>
        )}

        {activeTab === "topology" && stats && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            className="grid md:grid-cols-2 gap-4"
          >
            {/* Alert Trend */}
            <div
              className="card p-5"
              style={{
                background: "var(--bg-card)",
                border: "1px solid var(--bg-border)",
              }}
            >
              <div className="flex items-center gap-2 mb-3">
                <TrendingUp
                  className="size-4"
                  style={{ color: "var(--accent-green)" }}
                />
                <span
                  className="text-sm font-semibold"
                  style={{
                    color: "var(--text-primary)",
                    fontFamily: "'Syne', sans-serif",
                  }}
                >
                  Alert Trend (7d)
                </span>
              </div>
              {(stats.alertTrend || []).length === 0 ? (
                <div className="py-8 text-center">
                  <TrendingUp
                    className="size-8 mx-auto mb-2"
                    style={{ color: "var(--text-muted)", opacity: 0.4 }}
                  />
                  <p
                    className="text-xs"
                    style={{
                      color: "var(--text-muted)",
                      fontFamily: "'JetBrains Mono', monospace",
                    }}
                  >
                    No alert data yet — alerts appear here once SIEM rules fire
                  </p>
                </div>
              ) : (
                <TrendBars data={stats.alertTrend} />
              )}
            </div>

            {/* Top Targets */}
            <div
              className="card p-5"
              style={{
                background: "var(--bg-card)",
                border: "1px solid var(--bg-border)",
              }}
            >
              <div className="flex items-center gap-2 mb-3">
                <Globe className="size-4" style={{ color: "#a78bfa" }} />
                <span
                  className="text-sm font-semibold"
                  style={{
                    color: "var(--text-primary)",
                    fontFamily: "'Syne', sans-serif",
                  }}
                >
                  Top Targets
                </span>
              </div>
              {(stats.topTargets || []).length === 0 ? (
                <div className="py-8 text-center">
                  <Globe
                    className="size-8 mx-auto mb-2"
                    style={{ color: "var(--text-muted)", opacity: 0.4 }}
                  />
                  <p
                    className="text-xs"
                    style={{
                      color: "var(--text-muted)",
                      fontFamily: "'JetBrains Mono', monospace",
                    }}
                  >
                    No target data yet — domains are tracked once events are
                    ingested
                  </p>
                </div>
              ) : (
                <div className="space-y-2">
                  {stats.topTargets.map((t) => (
                    <div
                      key={t.domain}
                      className="flex items-center justify-between text-xs rounded px-3 py-2"
                      style={{
                        background: "var(--bg-elevated)",
                        border: "1px solid var(--bg-border)",
                      }}
                    >
                      <span
                        style={{
                          color: "var(--text-secondary)",
                          fontFamily: "'JetBrains Mono', monospace",
                        }}
                      >
                        {t.domain}
                      </span>
                      <span
                        style={{
                          color: "var(--accent-green)",
                          fontFamily: "'JetBrains Mono', monospace",
                        }}
                      >
                        {t.count}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* MITRE coverage — shown when available */}
            {(stats.mitreTactics || []).length > 0 && (
              <div
                className="card p-5 md:col-span-2"
                style={{
                  background: "var(--bg-card)",
                  border: "1px solid var(--bg-border)",
                }}
              >
                <div className="flex items-center gap-2 mb-4">
                  <Shield className="size-4" style={{ color: "#E1251B" }} />
                  <span
                    className="text-sm font-semibold"
                    style={{
                      color: "var(--text-primary)",
                      fontFamily: "'Syne', sans-serif",
                    }}
                  >
                    MITRE ATT&amp;CK Coverage
                  </span>
                </div>
                <div className="flex flex-wrap gap-2">
                  {stats.mitreTactics.map((m) => (
                    <div
                      key={m.tactic}
                      className="flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs"
                      style={{
                        background: "rgba(225,37,27,0.07)",
                        border: "1px solid rgba(225,37,27,0.18)",
                      }}
                    >
                      <span
                        style={{
                          color: "#E1251B",
                          fontFamily: "'JetBrains Mono', monospace",
                        }}
                      >
                        {m.tactic}
                      </span>
                      <span
                        className="font-bold px-1.5 py-0.5 rounded"
                        style={{
                          background: "rgba(225,37,27,0.15)",
                          color: "#E1251B",
                          fontFamily: "'JetBrains Mono', monospace",
                        }}
                      >
                        {m.count}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </motion.div>
        )}

        {activeTab === "baseline" && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            className="space-y-4"
          >
            <div className="flex items-center justify-between">
              <p className="text-sm" style={{ color: "var(--text-secondary)" }}>
                Monitors scan behavior and fires alerts when patterns deviate
                from the 7-day baseline.
              </p>
              <button
                onClick={runBaselineCheck}
                disabled={runningBaseline}
                className="btn-ghost flex items-center gap-2 px-4 py-2 text-sm"
              >
                <Brain className="size-4" />{" "}
                {runningBaseline ? "Running..." : "Run Check"}
              </button>
            </div>

            {!baseline || baseline.baseline == null ? (
              <div
                className="card p-8 text-center"
                style={{
                  background: "var(--bg-card)",
                  border: "1px solid var(--bg-border)",
                }}
              >
                <Brain
                  className="size-10 mx-auto mb-3"
                  style={{ color: "var(--text-muted)" }}
                />
                <p
                  className="text-sm"
                  style={{
                    color: "var(--text-muted)",
                    fontFamily: "'JetBrains Mono', monospace",
                  }}
                >
                  Insufficient data — run more scans to build a baseline
                </p>
              </div>
            ) : (
              <>
                <div
                  className="card p-5"
                  style={{
                    background: "var(--bg-card)",
                    border: "1px solid var(--bg-border)",
                  }}
                >
                  <div className="flex items-center gap-2 mb-4">
                    <Activity
                      className="size-4"
                      style={{ color: "var(--accent-cyan)" }}
                    />
                    <span
                      className="text-sm font-semibold"
                      style={{
                        color: "var(--text-primary)",
                        fontFamily: "'Syne', sans-serif",
                      }}
                    >
                      Current Hour
                    </span>
                    <span
                      className="ml-auto text-xs px-2 py-0.5 rounded"
                      style={{
                        color: baseline.healthy
                          ? "var(--accent-green)"
                          : "#E1251B",
                        background: baseline.healthy
                          ? "rgba(0,255,136,0.08)"
                          : "rgba(255,68,68,0.08)",
                        border: `1px solid ${baseline.healthy ? "rgba(0,255,136,0.2)" : "rgba(255,68,68,0.2)"}`,
                        fontFamily: "'JetBrains Mono', monospace",
                      }}
                    >
                      {baseline.healthy ? "NORMAL" : "ANOMALY"}
                    </span>
                  </div>
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                    {[
                      {
                        label: "Scans",
                        val: baseline.current?.total,
                        color: "var(--accent-green)",
                      },
                      {
                        label: "Phishing",
                        val: baseline.current?.phishing,
                        color: "#E1251B",
                      },
                      {
                        label: "Suspicious",
                        val: baseline.current?.suspicious,
                        color: "#f5a623",
                      },
                      {
                        label: "Phishing Rate",
                        val: `${baseline.current?.phishingRate}%`,
                        color: "#f97316",
                      },
                    ].map(({ label, val, color }) => (
                      <div key={label}>
                        <span
                          className="text-xs"
                          style={{ color: "var(--text-muted)" }}
                        >
                          {label}
                        </span>
                        <div
                          className="text-sm font-bold"
                          style={{
                            color,
                            fontFamily: "'JetBrains Mono', monospace",
                          }}
                        >
                          {val ?? "—"}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                <div
                  className="card p-5"
                  style={{
                    background: "var(--bg-card)",
                    border: "1px solid var(--bg-border)",
                  }}
                >
                  <div className="flex items-center gap-2 mb-4">
                    <TrendingUp
                      className="size-4"
                      style={{ color: "#a78bfa" }}
                    />
                    <span
                      className="text-sm font-semibold"
                      style={{
                        color: "var(--text-primary)",
                        fontFamily: "'Syne', sans-serif",
                      }}
                    >
                      7-Day Baseline
                    </span>
                    <span
                      className="ml-auto text-xs"
                      style={{
                        color: "var(--text-muted)",
                        fontFamily: "'JetBrains Mono', monospace",
                      }}
                    >
                      {baseline.baseline.sampleHours} hours sampled
                    </span>
                  </div>
                  <div className="grid grid-cols-2 gap-4">
                    {[
                      {
                        label: "Avg Scans/Hour",
                        val: baseline.baseline.avgScansPerHour?.toFixed(1),
                        color: "var(--accent-green)",
                      },
                      {
                        label: "Avg Phishing Rate",
                        val: `${baseline.baseline.avgPhishingRate?.toFixed(1)}%`,
                        color: "#E1251B",
                      },
                    ].map(({ label, val, color }) => (
                      <div key={label}>
                        <span
                          className="text-xs"
                          style={{ color: "var(--text-muted)" }}
                        >
                          {label}
                        </span>
                        <div
                          className="text-sm font-bold"
                          style={{
                            color,
                            fontFamily: "'JetBrains Mono', monospace",
                          }}
                        >
                          {val ?? "—"}
                        </div>
                      </div>
                    ))}
                  </div>
                  <div
                    className="mt-4 pt-4 border-t"
                    style={{ borderColor: "var(--bg-border)" }}
                  >
                    <p
                      className="text-xs"
                      style={{
                        color: "var(--text-muted)",
                        fontFamily: "'JetBrains Mono', monospace",
                      }}
                    >
                      Anomaly fires when current hour is{" "}
                      <span style={{ color: "#f5a623" }}>
                        40%+ above baseline.
                      </span>{" "}
                      Checks run every 15 minutes.
                    </p>
                  </div>
                </div>
              </>
            )}
          </motion.div>
        )}

        {activeTab === "behavior" && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            className="space-y-4"
          >
            {spikes.length > 0 && (
              <div
                className="card p-5"
                style={{
                  background: "var(--bg-card)",
                  border: "1px solid var(--bg-border)",
                }}
              >
                <span
                  className="text-xs font-bold uppercase tracking-wider"
                  style={{
                    color: "#E1251B",
                    fontFamily: "'JetBrains Mono', monospace",
                  }}
                >
                  🔥 Active Brand Campaigns (last 2h)
                </span>
                <div className="grid md:grid-cols-2 gap-3 mt-3">
                  {spikes.map((s) => (
                    <div
                      key={s.brand}
                      className="rounded-xl p-4"
                      style={{
                        background: "rgba(255,68,68,0.06)",
                        border: "1px solid rgba(255,68,68,0.2)",
                      }}
                    >
                      <div
                        className="text-lg font-bold capitalize mb-1"
                        style={{
                          color: "#E1251B",
                          fontFamily: "'Syne', sans-serif",
                        }}
                      >
                        {s.brand}
                      </div>
                      <div
                        className="text-xs"
                        style={{
                          color: "var(--text-muted)",
                          fontFamily: "'JetBrains Mono', monospace",
                        }}
                      >
                        {s.count} detections · {s.uniqueIPs} IPs
                        {s.isCampaign && (
                          <span
                            className="ml-2 px-1.5 py-0.5 rounded text-xs font-bold"
                            style={{
                              color: "#E1251B",
                              background: "rgba(255,68,68,0.12)",
                            }}
                          >
                            CAMPAIGN
                          </span>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            <div
              className="card overflow-hidden"
              style={{
                background: "var(--bg-card)",
                border: "1px solid var(--bg-border)",
              }}
            >
              <div
                className="px-5 py-3 border-b"
                style={{
                  borderColor: "var(--bg-border)",
                  background: "rgba(0,0,0,0.3)",
                }}
              >
                <span
                  className="text-xs"
                  style={{
                    color: "var(--text-muted)",
                    fontFamily: "'JetBrains Mono', monospace",
                  }}
                >
                  threat_actors.log — {actors.length} active IPs (last 24h)
                </span>
              </div>

              {actors.length === 0 ? (
                <div className="p-8 text-center space-y-2">
                  <Shield
                    className="size-10 mx-auto"
                    style={{ color: "var(--text-muted)", opacity: 0.35 }}
                  />
                  <p
                    className="text-sm font-semibold"
                    style={{
                      color: "var(--text-muted)",
                      fontFamily: "'JetBrains Mono', monospace",
                    }}
                  >
                    No threat actors detected in the last 24 hours
                  </p>
                  <p
                    className="text-xs"
                    style={{
                      color: "var(--text-muted)",
                      fontFamily: "'JetBrains Mono', monospace",
                      opacity: 0.7,
                    }}
                  >
                    Threat actors appear here when the same IP submits phishing
                    URLs. Run phishing scans to populate this view.
                  </p>
                </div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="min-w-full">
                    <thead>
                      <tr style={{ background: "var(--bg-elevated)" }}>
                        {[
                          "IP Address",
                          "Threat Level",
                          "Phishing",
                          "Avg Score",
                          "Targeted Brands",
                          "Last Seen",
                        ].map((h) => (
                          <th
                            key={h}
                            className="text-left px-4 py-3 text-xs"
                            style={{
                              color: "var(--text-muted)",
                              fontFamily: "'JetBrains Mono', monospace",
                            }}
                          >
                            {h}
                          </th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {actors.map((a, i) => {
                        const lvlColor =
                          a.threatLevel === "critical"
                            ? "#E1251B"
                            : a.threatLevel === "high"
                              ? "#f97316"
                              : "#f5a623";
                        return (
                          <motion.tr
                            key={a.ip}
                            initial={{ opacity: 0, y: 4 }}
                            animate={{ opacity: 1, y: 0 }}
                            transition={{ delay: i * 0.05 }}
                            className="border-t"
                            style={{ borderColor: "var(--bg-border)" }}
                          >
                            <td
                              className="px-4 py-3 text-xs font-bold"
                              style={{
                                color: "var(--accent-cyan)",
                                fontFamily: "'JetBrains Mono', monospace",
                              }}
                            >
                              {a.ip}
                            </td>
                            <td className="px-4 py-3">
                              <span
                                className="text-xs font-bold px-2 py-0.5 rounded uppercase"
                                style={{
                                  color: lvlColor,
                                  background: `${lvlColor}12`,
                                  border: `1px solid ${lvlColor}30`,
                                  fontFamily: "'JetBrains Mono', monospace",
                                }}
                              >
                                {a.threatLevel}
                              </span>
                            </td>
                            <td
                              className="px-4 py-3 text-xs font-bold"
                              style={{
                                color: "#E1251B",
                                fontFamily: "'JetBrains Mono', monospace",
                              }}
                            >
                              {a.phishingCount}{" "}
                              <span
                                style={{
                                  color: "var(--text-muted)",
                                  fontWeight: 400,
                                }}
                              >
                                ({a.phishingRate}%)
                              </span>
                            </td>
                            <td
                              className="px-4 py-3 text-xs"
                              style={{
                                color: "var(--text-secondary)",
                                fontFamily: "'JetBrains Mono', monospace",
                              }}
                            >
                              {a.avgScore}/100
                            </td>
                            <td className="px-4 py-3">
                              <div className="flex flex-wrap gap-1">
                                {a.targetedBrands
                                  .filter(Boolean)
                                  .slice(0, 3)
                                  .map((b) => (
                                    <span
                                      key={b}
                                      className="text-xs px-1.5 py-0.5 rounded capitalize"
                                      style={{
                                        color: "#f5a623",
                                        background: "rgba(245,166,35,0.08)",
                                        border:
                                          "1px solid rgba(245,166,35,0.2)",
                                        fontFamily:
                                          "'JetBrains Mono', monospace",
                                      }}
                                    >
                                      {b}
                                    </span>
                                  ))}
                              </div>
                            </td>
                            <td
                              className="px-4 py-3 text-xs"
                              style={{
                                color: "var(--text-muted)",
                                fontFamily: "'JetBrains Mono', monospace",
                              }}
                            >
                              {new Date(a.lastSeen).toLocaleTimeString()}
                            </td>
                          </motion.tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </motion.div>
        )}

        {activeTab === "honeypot" && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            className="space-y-4"
          >
            <div
              className="card p-5"
              style={{
                background: "var(--bg-card)",
                border: "1px solid var(--bg-border)",
              }}
            >
              <span
                className="text-sm font-semibold"
                style={{
                  color: "var(--text-primary)",
                  fontFamily: "'Syne', sans-serif",
                }}
              >
                🍯 Generate Honeypot Trap
              </span>
              <p
                className="text-xs mb-4 mt-2"
                style={{ color: "var(--text-muted)" }}
              >
                Creates a fake sensitive URL. Any access = immediate CRITICAL
                alert.
              </p>
              <div className="flex flex-col md:flex-row gap-2">
                <input
                  type="text"
                  value={trapLabel}
                  onChange={(e) => setTrapLabel(e.target.value)}
                  placeholder="Label (optional) e.g. hr-payroll-2026"
                  className="input-terminal flex-1 px-4 py-2.5 rounded-xl text-xs"
                  style={{ fontFamily: "'JetBrains Mono', monospace" }}
                />
                <button
                  onClick={async () => {
                    try {
                      const res = await fetch(`${HONEYPOT_API}/generate`, {
                        method: "POST",
                        headers: authHeader(),
                        body: JSON.stringify({
                          label: trapLabel || undefined,
                        }),
                      });
                      const data = await res.json().catch(() => ({}));
                      if (!res.ok) {
                        addToast(
                          "error",
                          data.error || "Failed to generate honeypot trap",
                        );
                        return;
                      }
                      setNewTrap(data.url || "");
                      setTrapLabel("");
                      addToast("success", "Honeypot trap created");
                      fetchData();
                    } catch {
                      addToast("error", "Failed to generate honeypot trap");
                    }
                  }}
                  className="btn-primary px-5 py-2.5 text-sm"
                  style={{
                    fontFamily: "'Syne', sans-serif",
                    fontWeight: 700,
                    background: "#f5a623",
                    color: "#080b10",
                  }}
                >
                  Generate Trap
                </button>
              </div>

              {newTrap && (
                <div
                  className="mt-3 flex items-center gap-3 px-4 py-3 rounded-xl"
                  style={{
                    background: "rgba(245,166,35,0.08)",
                    border: "1px solid rgba(245,166,35,0.25)",
                  }}
                >
                  <span
                    className="text-xs flex-1 break-all"
                    style={{
                      color: "#f5a623",
                      fontFamily: "'JetBrains Mono', monospace",
                    }}
                  >
                    🍯 {newTrap}
                  </span>
                  <button
                    onClick={() => {
                      navigator.clipboard.writeText(newTrap);
                    }}
                    className="text-xs px-2 py-1 rounded"
                    style={{
                      color: "var(--accent-green)",
                      background: "rgba(0,255,136,0.08)",
                      border: "1px solid rgba(0,255,136,0.2)",
                      fontFamily: "'JetBrains Mono', monospace",
                    }}
                  >
                    Copy
                  </button>
                </div>
              )}
            </div>

            <div
              className="card overflow-hidden"
              style={{
                background: "var(--bg-card)",
                border: "1px solid var(--bg-border)",
              }}
            >
              <div
                className="px-5 py-3 border-b"
                style={{
                  borderColor: "var(--bg-border)",
                  background: "rgba(0,0,0,0.3)",
                }}
              >
                <span
                  className="text-xs"
                  style={{
                    color: "var(--text-muted)",
                    fontFamily: "'JetBrains Mono', monospace",
                  }}
                >
                  honeypot_traps.log — {traps.length} active traps
                </span>
              </div>

              {traps.length === 0 ? (
                <div className="p-6 text-center">
                  <p
                    className="text-sm"
                    style={{
                      color: "var(--text-muted)",
                      fontFamily: "'JetBrains Mono', monospace",
                    }}
                  >
                    No traps deployed yet
                  </p>
                </div>
              ) : (
                <div
                  className="divide-y"
                  style={{ borderColor: "rgba(30,39,54,0.5)" }}
                >
                  {traps.map((t) => (
                    <div
                      key={t.id}
                      className="px-5 py-4 flex items-center gap-3"
                    >
                      <div className="min-w-0 flex-1">
                        <p
                          className="text-sm font-semibold mb-0.5"
                          style={{
                            color: "var(--text-primary)",
                            fontFamily: "'Syne', sans-serif",
                          }}
                        >
                          🍯 {t.label}
                        </p>
                        <p
                          className="text-xs truncate"
                          style={{
                            color: "var(--accent-cyan)",
                            fontFamily: "'JetBrains Mono', monospace",
                          }}
                        >
                          {t.fullUrl}
                        </p>
                      </div>
                      <div className="text-center px-3">
                        <div
                          className="text-lg font-bold"
                          style={{
                            color: t.hits > 0 ? "#E1251B" : "var(--text-muted)",
                            fontFamily: "'Syne', sans-serif",
                          }}
                        >
                          {t.hits}
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
                      {t.hits > 0 && (
                        <span
                          className="text-xs px-2 py-1 rounded font-bold animate-pulse"
                          style={{
                            color: "#E1251B",
                            background: "rgba(255,68,68,0.1)",
                            border: "1px solid rgba(255,68,68,0.3)",
                            fontFamily: "'JetBrains Mono', monospace",
                          }}
                        >
                          ⚠ TRIGGERED
                        </span>
                      )}
                      <button
                        onClick={async () => {
                          try {
                            const res = await fetch(
                              `${HONEYPOT_API}/traps/${t.id}`,
                              { method: "DELETE", headers: authHeader() },
                            );
                            if (!res.ok) {
                              const data = await res.json().catch(() => ({}));
                              addToast(
                                "error",
                                data.error || "Failed to remove trap",
                              );
                              return;
                            }
                            fetchData();
                          } catch {
                            addToast("error", "Failed to remove trap");
                          }
                        }}
                        className="text-xs px-2 py-1 rounded transition-all"
                        style={{
                          color: "var(--text-muted)",
                          border: "1px solid var(--bg-border)",
                        }}
                        onMouseEnter={(e) => {
                          (e.currentTarget as HTMLButtonElement).style.color =
                            "#E1251B";
                        }}
                        onMouseLeave={(e) => {
                          (e.currentTarget as HTMLButtonElement).style.color =
                            "var(--text-muted)";
                        }}
                      >
                        Remove
                      </button>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </motion.div>
        )}

        {activeTab === "custom-rules" && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            className="space-y-4"
          >
            {/* Create new rule */}
            <div className="card p-5" style={{ background: "var(--bg-card)" }}>
              <div className="flex items-center justify-between mb-4">
                <span
                  className="text-sm font-semibold"
                  style={{
                    color: "var(--text-primary)",
                    fontFamily: "'Syne', sans-serif",
                  }}
                >
                  ⚡ Create Custom Detection Rule
                </span>
                <button
                  onClick={() => setShowCreate(!showCreate)}
                  className="btn-ghost text-xs px-3 py-1.5"
                  style={{ fontFamily: "'DM Sans', sans-serif" }}
                >
                  {showCreate ? "Cancel" : "+ New Rule"}
                </button>
              </div>

              {showCreate && (
                <div className="space-y-3">
                  <div className="grid md:grid-cols-3 gap-3">
                    <div>
                      <div
                        className="text-xs mb-1"
                        style={{
                          color: "var(--text-muted)",
                          fontFamily: "'JetBrains Mono', monospace",
                        }}
                      >
                        RULE NAME *
                      </div>
                      <input
                        value={newRuleName}
                        onChange={(e) => setNewRuleName(e.target.value)}
                        placeholder="e.g. High-risk banking phishing"
                        className="input-terminal w-full px-3 py-2 rounded-lg text-xs"
                      />
                    </div>
                    <div>
                      <div
                        className="text-xs mb-1"
                        style={{
                          color: "var(--text-muted)",
                          fontFamily: "'JetBrains Mono', monospace",
                        }}
                      >
                        SEVERITY
                      </div>
                      <select
                        value={newRuleSev}
                        onChange={(e) => setNewRuleSev(Number(e.target.value))}
                        className="input-terminal w-full px-3 py-2 rounded-lg text-xs"
                      >
                        <option value={5}>5 — CRITICAL</option>
                        <option value={4}>4 — HIGH</option>
                        <option value={3}>3 — MEDIUM</option>
                        <option value={2}>2 — LOW</option>
                        <option value={1}>1 — INFO</option>
                      </select>
                    </div>
                    <div>
                      <div
                        className="text-xs mb-1"
                        style={{
                          color: "var(--text-muted)",
                          fontFamily: "'JetBrains Mono', monospace",
                        }}
                      >
                        CATEGORY
                      </div>
                      <select
                        value={newRuleCat}
                        onChange={(e) => setNewRuleCat(e.target.value)}
                        className="input-terminal w-full px-3 py-2 rounded-lg text-xs"
                      >
                        <option value="phishing">Phishing</option>
                        <option value="anomaly">Anomaly</option>
                        <option value="network">Network</option>
                        <option value="brute_force">Brute Force</option>
                      </select>
                    </div>
                  </div>

                  <div className="grid md:grid-cols-3 gap-3">
                    <div>
                      <div
                        className="text-xs mb-1"
                        style={{
                          color: "var(--text-muted)",
                          fontFamily: "'JetBrains Mono', monospace",
                        }}
                      >
                        MIN RISK SCORE
                      </div>
                      <input
                        type="number"
                        min={0}
                        max={100}
                        value={newRuleScore}
                        onChange={(e) =>
                          setNewRuleScore(Number(e.target.value))
                        }
                        className="input-terminal w-full px-3 py-2 rounded-lg text-xs"
                      />
                    </div>
                    <div>
                      <div
                        className="text-xs mb-1"
                        style={{
                          color: "var(--text-muted)",
                          fontFamily: "'JetBrains Mono', monospace",
                        }}
                      >
                        STATUS MATCH
                      </div>
                      <select
                        value={newRuleStatus}
                        onChange={(e) => setNewRuleStatus(e.target.value)}
                        className="input-terminal w-full px-3 py-2 rounded-lg text-xs"
                      >
                        <option value="">Any</option>
                        <option value="phishing">Phishing</option>
                        <option value="suspicious">Suspicious</option>
                      </select>
                    </div>
                    <div>
                      <div
                        className="text-xs mb-1"
                        style={{
                          color: "var(--text-muted)",
                          fontFamily: "'JetBrains Mono', monospace",
                        }}
                      >
                        ISSUE KEYWORD
                      </div>
                      <input
                        value={newRuleIssue}
                        onChange={(e) => setNewRuleIssue(e.target.value)}
                        placeholder="e.g. paypal, otp, redirect"
                        className="input-terminal w-full px-3 py-2 rounded-lg text-xs"
                      />
                    </div>
                  </div>

                  <button
                    onClick={async () => {
                      if (!newRuleName.trim()) return;
                      await fetch(`${SIEM_API}/rules/custom`, {
                        method: "POST",
                        headers: {
                          "Content-Type": "application/json",
                          Authorization: `Bearer ${localStorage.getItem("pg_token")}`,
                        },
                        body: JSON.stringify({
                          name: newRuleName,
                          severity: newRuleSev,
                          category: newRuleCat,
                          conditions: {
                            riskScoreMin: newRuleScore || null,
                            statusMatch: newRuleStatus || null,
                            issueContains: newRuleIssue || null,
                          },
                        }),
                      });
                      setNewRuleName("");
                      setShowCreate(false);
                      fetchData();
                    }}
                    className="btn-primary px-5 py-2.5 text-sm"
                    style={{
                      fontFamily: "'Syne', sans-serif",
                      fontWeight: 700,
                      background: "#f5a623",
                      color: "#080b10",
                    }}
                  >
                    Create Rule
                  </button>
                </div>
              )}
            </div>

            {/* Custom rules list */}
            <div
              className="card overflow-hidden"
              style={{ background: "var(--bg-card)" }}
            >
              <div
                className="px-5 py-3 border-b"
                style={{
                  borderColor: "var(--bg-border)",
                  background: "rgba(0,0,0,0.3)",
                }}
              >
                <span
                  className="text-xs"
                  style={{
                    color: "var(--text-muted)",
                    fontFamily: "'JetBrains Mono', monospace",
                  }}
                >
                  custom_rules.json — {customRules.length} rules
                </span>
              </div>

              {customRules.length === 0 ? (
                <div className="py-10 text-center">
                  <p
                    className="text-sm"
                    style={{
                      color: "var(--text-muted)",
                      fontFamily: "'JetBrains Mono', monospace",
                    }}
                  >
                    No custom rules yet
                  </p>
                </div>
              ) : (
                <div
                  className="divide-y"
                  style={{ borderColor: "rgba(30,39,54,0.5)" }}
                >
                  {customRules.map((rule: any) => {
                    const sev =
                      SEV[rule.severity as keyof typeof SEV] || SEV[1];
                    return (
                      <div
                        key={rule._id}
                        className="px-5 py-4 flex items-center gap-4"
                      >
                        {/* Enabled toggle */}
                        <button
                          onClick={async () => {
                            await fetch(
                              `${SIEM_API}/rules/custom/${rule._id}`,
                              {
                                method: "PATCH",
                                headers: {
                                  "Content-Type": "application/json",
                                  Authorization: `Bearer ${localStorage.getItem("pg_token")}`,
                                },
                                body: JSON.stringify({
                                  enabled: !rule.enabled,
                                }),
                              },
                            );
                            fetchData();
                          }}
                          className="relative inline-flex h-5 w-9 items-center rounded-full transition-all flex-shrink-0"
                          style={{
                            background: rule.enabled
                              ? "var(--accent-green)"
                              : "var(--bg-border)",
                          }}
                        >
                          <span
                            className="inline-block h-3 w-3 rounded-full bg-white transition-transform"
                            style={{
                              transform: rule.enabled
                                ? "translateX(18px)"
                                : "translateX(2px)",
                            }}
                          />
                        </button>

                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 mb-1 flex-wrap">
                            <span
                              className="text-xs font-bold"
                              style={{
                                color: "var(--accent-cyan)",
                                fontFamily: "'JetBrains Mono', monospace",
                              }}
                            >
                              {rule.ruleId}
                            </span>
                            <span
                              className="text-sm font-semibold"
                              style={{
                                color: rule.enabled
                                  ? "var(--text-primary)"
                                  : "var(--text-muted)",
                                fontFamily: "'Syne', sans-serif",
                              }}
                            >
                              {rule.name}
                            </span>
                            <span
                              className="text-xs px-2 py-0.5 rounded font-bold"
                              style={{
                                color: sev.color,
                                background: sev.bg,
                                border: `1px solid ${sev.border}`,
                                fontFamily: "'JetBrains Mono', monospace",
                              }}
                            >
                              {sev.label}
                            </span>
                          </div>
                          <div
                            className="flex flex-wrap gap-2 text-xs"
                            style={{
                              fontFamily: "'JetBrains Mono', monospace",
                              color: "var(--text-muted)",
                            }}
                          >
                            {rule.conditions.riskScoreMin !== null && (
                              <span>
                                score ≥ {rule.conditions.riskScoreMin}
                              </span>
                            )}
                            {rule.conditions.statusMatch && (
                              <span>
                                status = {rule.conditions.statusMatch}
                              </span>
                            )}
                            {rule.conditions.issueContains && (
                              <span>
                                issue contains "{rule.conditions.issueContains}"
                              </span>
                            )}
                            <span>· {rule.triggerCount} triggers</span>
                            {rule.lastTriggered && (
                              <span>
                                · last{" "}
                                {new Date(
                                  rule.lastTriggered,
                                ).toLocaleTimeString()}
                              </span>
                            )}
                          </div>
                        </div>

                        <button
                          onClick={async () => {
                            if (!confirm("Delete this rule?")) return;
                            await fetch(
                              `${SIEM_API}/rules/custom/${rule._id}`,
                              {
                                method: "DELETE",
                                headers: {
                                  Authorization: `Bearer ${localStorage.getItem("pg_token")}`,
                                },
                              },
                            );
                            fetchData();
                          }}
                          className="p-2 rounded-lg flex-shrink-0 transition-all"
                          style={{
                            color: "var(--text-muted)",
                            border: "1px solid var(--bg-border)",
                          }}
                          onMouseEnter={(e) => {
                            (e.currentTarget as HTMLButtonElement).style.color =
                              "#E1251B";
                          }}
                          onMouseLeave={(e) => {
                            (e.currentTarget as HTMLButtonElement).style.color =
                              "var(--text-muted)";
                          }}
                        >
                          <XCircle className="size-4" />
                        </button>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          </motion.div>
        )}

        {activeTab === "shift" && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            className="space-y-4"
          >
            {/* New note composer */}
            <div className="card p-5" style={{ background: "var(--bg-card)" }}>
              <div className="flex items-center gap-2 mb-4">
                <span
                  className="text-sm font-semibold"
                  style={{
                    color: "var(--text-primary)",
                    fontFamily: "'Syne', sans-serif",
                  }}
                >
                  📋 Shift Handover Notes
                </span>
                <span
                  className="text-xs px-2 py-0.5 rounded ml-2"
                  style={{
                    color: "var(--text-muted)",
                    background: "var(--bg-elevated)",
                    border: "1px solid var(--bg-border)",
                    fontFamily: "'JetBrains Mono', monospace",
                  }}
                >
                  Auto-expire 24h · Pinned = permanent
                </span>
              </div>

              <textarea
                value={newNoteText}
                onChange={(e) => setNewNoteText(e.target.value)}
                placeholder={
                  "Write a handover note for the incoming analyst...\ne.g. — PHI-001 alert cluster is a known false positive from internal scanner\n— Campaign #A3F9 is ongoing, 12 detections in last 2 hours\n— Escalate any new credential harvest alerts immediately"
                }
                rows={4}
                className="input-terminal w-full px-4 py-3 rounded-xl text-xs mb-3"
                style={{
                  fontFamily: "'JetBrains Mono', monospace",
                  resize: "vertical",
                }}
              />

              <div className="mb-3">
                <input
                  type="text"
                  placeholder="Reference Alert/Log IDs (comma-separated: ALT-20240115-0923-A3F9, LOG-...)"
                  className="w-full px-3 py-2 rounded-xl text-[10px]"
                  style={{
                    background: "var(--bg-elevated)",
                    border: "1px solid var(--bg-border)",
                    color: "var(--text-primary)",
                    outline: "none",
                    fontFamily: "'JetBrains Mono', monospace",
                  }}
                  value={noteAlertRefs}
                  onChange={(e) => setNoteAlertRefs(e.target.value)}
                />
              </div>

              <div className="flex items-center gap-3 flex-wrap">
                <select
                  value={newNotePriority}
                  onChange={(e) => setNewNotePriority(e.target.value)}
                  className="input-terminal text-xs px-3 py-2 rounded-lg"
                  style={{ fontFamily: "'JetBrains Mono', monospace" }}
                >
                  <option value="normal">Normal</option>
                  <option value="high">High</option>
                  <option value="critical">Critical</option>
                </select>

                <label
                  className="flex items-center gap-2 text-xs cursor-pointer"
                  style={{ color: "var(--text-muted)" }}
                >
                  <input
                    type="checkbox"
                    checked={newNotePinned}
                    onChange={(e) => setNewNotePinned(e.target.checked)}
                  />
                  Pin (don't auto-expire)
                </label>

                <button
                  onClick={async () => {
                    if (!newNoteText.trim()) return;
                    const refs = noteAlertRefs
                      .split(",")
                      .map((s) => s.trim())
                      .filter(Boolean);
                    await fetch(`${SIEM_API}/shift-notes`, {
                      method: "POST",
                      headers: {
                        "Content-Type": "application/json",
                        Authorization: `Bearer ${localStorage.getItem("pg_token")}`,
                      },
                      body: JSON.stringify({
                        content: newNoteText,
                        priority: newNotePriority,
                        pinned: newNotePinned,
                        referencedAlertIds: refs.filter((s) =>
                          s.startsWith("ALT-"),
                        ),
                        referencedLogIds: refs.filter((s) =>
                          s.startsWith("LOG-"),
                        ),
                        signedBy:
                          JSON.parse(localStorage.getItem("pg_user") || "null")
                            ?.username || "analyst",
                        isHandover: newNotePinned,
                      }),
                    });
                    setNewNoteText("");
                    setNewNotePriority("normal");
                    setNewNotePinned(false);
                    setNoteAlertRefs("");
                    fetchData();
                  }}
                  disabled={!newNoteText.trim()}
                  className="btn-primary flex items-center gap-2 px-5 py-2.5 text-sm ml-auto"
                  style={{ fontFamily: "'Syne', sans-serif", fontWeight: 700 }}
                >
                  Post Note
                </button>
              </div>
            </div>

            {/* Notes list */}
            {shiftNotes.length === 0 ? (
              <div
                className="card py-10 text-center"
                style={{ background: "var(--bg-card)" }}
              >
                <p
                  className="text-sm"
                  style={{
                    color: "var(--text-muted)",
                    fontFamily: "'JetBrains Mono', monospace",
                  }}
                >
                  No shift notes yet
                </p>
              </div>
            ) : (
              <div className="space-y-3">
                {shiftNotes.map((note: any) => {
                  const priorityColor =
                    note.priority === "critical"
                      ? "#E1251B"
                      : note.priority === "high"
                        ? "#f97316"
                        : "var(--text-muted)";
                  return (
                    <motion.div
                      key={note._id}
                      initial={{ opacity: 0, y: 4 }}
                      animate={{ opacity: 1, y: 0 }}
                      className="card p-4"
                      style={{
                        background: "var(--bg-card)",
                        borderColor: note.pinned
                          ? "rgba(0,212,255,0.25)"
                          : note.priority === "critical"
                            ? "rgba(255,68,68,0.25)"
                            : note.priority === "high"
                              ? "rgba(249,115,22,0.25)"
                              : "var(--bg-border)",
                      }}
                    >
                      <div className="flex items-start gap-3">
                        <div className="flex-1">
                          <div className="flex items-center gap-2 mb-2 flex-wrap">
                            {/* Note ID — prominent and copyable */}
                            {note.noteId && (
                              <span
                                className="text-[9px] font-bold px-2 py-0.5 rounded select-all cursor-copy"
                                style={{
                                  color: "var(--accent)",
                                  background: "var(--accent-subtle)",
                                  border: "1px solid var(--accent-border)",
                                  fontFamily: "var(--font-mono)",
                                }}
                                onClick={() =>
                                  navigator.clipboard.writeText(note.noteId)
                                }
                                title="Click to copy Note ID"
                              >
                                {note.noteId}
                              </span>
                            )}
                            {note.pinned && (
                              <span
                                className="text-xs px-2 py-0.5 rounded font-bold"
                                style={{
                                  color: "var(--accent-cyan)",
                                  background: "rgba(0,212,255,0.08)",
                                  border: "1px solid rgba(0,212,255,0.2)",
                                  fontFamily: "'JetBrains Mono', monospace",
                                }}
                              >
                                📌 PINNED
                              </span>
                            )}
                            {note.priority !== "normal" && (
                              <span
                                className="text-xs px-2 py-0.5 rounded font-bold uppercase"
                                style={{
                                  color: priorityColor,
                                  background: `${priorityColor}12`,
                                  border: `1px solid ${priorityColor}30`,
                                  fontFamily: "'JetBrains Mono', monospace",
                                }}
                              >
                                {note.priority}
                              </span>
                            )}
                            {/* Referenced alert IDs */}
                            {(note.referencedAlertIds ?? []).map(
                              (id: string) => (
                                <span
                                  key={id}
                                  className="text-[9px] px-1.5 py-0.5 rounded"
                                  style={{
                                    color: "#f87171",
                                    background: "rgba(248,113,113,0.08)",
                                    border: "1px solid rgba(248,113,113,0.2)",
                                    fontFamily: "var(--font-mono)",
                                  }}
                                >
                                  → {id}
                                </span>
                              ),
                            )}
                            <span
                              className="text-xs"
                              style={{
                                color: "var(--text-muted)",
                                fontFamily: "'JetBrains Mono', monospace",
                              }}
                            >
                              {note.author} ·{" "}
                              {new Date(note.createdAt).toLocaleString()}
                            </span>
                            {!note.pinned && note.expiresAt && (
                              <span
                                className="text-xs"
                                style={{
                                  color: "var(--text-muted)",
                                  fontFamily: "'JetBrains Mono', monospace",
                                }}
                              >
                                · expires{" "}
                                {new Date(note.expiresAt).toLocaleTimeString()}
                              </span>
                            )}
                          </div>
                          <p
                            className="text-sm leading-relaxed whitespace-pre-wrap"
                            style={{ color: "var(--text-secondary)" }}
                          >
                            {note.content}
                          </p>
                        </div>

                        {/* Actions */}
                        <div className="flex flex-col gap-1.5 flex-shrink-0">
                          <button
                            onClick={async () => {
                              await fetch(
                                `${SIEM_API}/shift-notes/${note._id}`,
                                {
                                  method: "PATCH",
                                  headers: {
                                    "Content-Type": "application/json",
                                    Authorization: `Bearer ${localStorage.getItem("pg_token")}`,
                                  },
                                  body: JSON.stringify({
                                    pinned: !note.pinned,
                                  }),
                                },
                              );
                              fetchData();
                            }}
                            className="text-xs px-2 py-1 rounded"
                            style={{
                              color: note.pinned
                                ? "var(--accent-cyan)"
                                : "var(--text-muted)",
                              border: "1px solid var(--bg-border)",
                              fontFamily: "'JetBrains Mono', monospace",
                            }}
                          >
                            {note.pinned ? "Unpin" : "Pin"}
                          </button>
                          <button
                            onClick={async () => {
                              await fetch(
                                `${SIEM_API}/shift-notes/${note._id}`,
                                {
                                  method: "DELETE",
                                  headers: {
                                    Authorization: `Bearer ${localStorage.getItem("pg_token")}`,
                                  },
                                },
                              );
                              fetchData();
                            }}
                            className="text-xs px-2 py-1 rounded"
                            style={{
                              color: "var(--text-muted)",
                              border: "1px solid var(--bg-border)",
                            }}
                            onMouseEnter={(e) => {
                              (
                                e.currentTarget as HTMLButtonElement
                              ).style.color = "#E1251B";
                            }}
                            onMouseLeave={(e) => {
                              (
                                e.currentTarget as HTMLButtonElement
                              ).style.color = "var(--text-muted)";
                            }}
                          >
                            Delete
                          </button>
                        </div>
                      </div>
                    </motion.div>
                  );
                })}
              </div>
            )}
          </motion.div>
        )}

        {activeTab === "logs" && (
          <div className="space-y-3">
            {/* Mini stats row */}
            {logStats && (
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-4">
                {[
                  {
                    label: "Total (24h)",
                    value: logStats.logs24h,
                    color: "var(--color-info)",
                  },
                  {
                    label: "Brute Force",
                    value: logStats.bruteForceCount24h,
                    color: "#E1251B",
                  },
                  {
                    label: "DNS Alerts",
                    value: logStats.byType?.dns_malicious ?? 0,
                    color: "#fb923c",
                  },
                  {
                    label: "PowerShell",
                    value: logStats.byType?.powershell_execution ?? 0,
                    color: "#a78bfa",
                  },
                ].map((s) => (
                  <div key={s.label} className="card p-4">
                    <div
                      className="text-xl font-bold"
                      style={{ color: s.color, fontFamily: "var(--font-mono)" }}
                    >
                      {s.value ?? "—"}
                    </div>
                    <div
                      className="text-xs mt-0.5"
                      style={{ color: "var(--text-muted)" }}
                    >
                      {s.label}
                    </div>
                  </div>
                ))}
              </div>
            )}

            {/* Recent log events list */}
            {logsLoading ? (
              <div className="flex justify-center py-12">
                <div
                  className="w-6 h-6 border-2 rounded-full animate-spin"
                  style={{
                    borderColor: "var(--accent)",
                    borderTopColor: "transparent",
                  }}
                />
              </div>
            ) : logEvents.length === 0 ? (
              <div className="card p-10 text-center">
                <p className="text-sm" style={{ color: "var(--text-muted)" }}>
                  No log events yet. Run a collector script to start ingesting.
                </p>
                <p
                  className="text-xs mt-1"
                  style={{ color: "var(--text-muted)" }}
                >
                  See: collectors/collect-failed-logins.ps1
                </p>
              </div>
            ) : (
              <div className="space-y-1.5">
                {logEvents.map((log: any) => {
                  const SEV_COLOR: Record<number, string> = {
                    5: "#E1251B",
                    4: "#fb923c",
                    3: "#fbbf24",
                    2: "#34d399",
                    1: "#64748b",
                  };
                  const sevCol = SEV_COLOR[log.severity as number] || "#94a3b8";
                  return (
                    <div
                      key={log._id}
                      className="card px-4 py-3 flex items-center gap-3"
                      style={{ background: "var(--bg-card)" }}
                    >
                      <div
                        className="w-2 h-2 rounded-full flex-shrink-0"
                        style={{
                          background: sevCol,
                          boxShadow: `0 0 6px ${sevCol}60`,
                        }}
                      />
                      <div className="flex-1 min-w-0">
                        <p
                          className="text-xs truncate"
                          style={{ color: "var(--text-primary)" }}
                        >
                          {log.description}
                        </p>
                        <p
                          className="text-[10px] mt-0.5"
                          style={{
                            color: "var(--text-muted)",
                            fontFamily: "var(--font-mono)",
                          }}
                        >
                          {String(log.logType).replace(/_/g, " ")} ·{" "}
                          {log.sourceHost} ·{" "}
                          {new Date(log.createdAt).toLocaleString()}
                        </p>
                      </div>
                      <span
                        className="text-[10px] px-2 py-0.5 rounded flex-shrink-0"
                        style={{
                          color: sevCol,
                          background: `${sevCol}10`,
                          border: `1px solid ${sevCol}20`,
                          fontFamily: "var(--font-mono)",
                        }}
                      >
                        SEV-{log.severity}
                      </span>
                      <span
                        className="text-[9px] px-2 py-0.5 rounded select-all cursor-copy flex-shrink-0"
                        style={{
                          color: "var(--text-muted)",
                          background: "var(--bg-elevated)",
                          border: "1px solid var(--bg-border)",
                          fontFamily: "var(--font-mono)",
                        }}
                        onClick={() =>
                          navigator.clipboard.writeText(log.logId || log._id)
                        }
                        title="Click to copy Log ID"
                      >
                        {log.logId || log._id}
                      </span>
                    </div>
                  );
                })}

                {/* Link to full Logs page */}
                <div className="text-center pt-2">
                  <Link
                    to="/logs"
                    className="text-xs"
                    style={{
                      color: "var(--accent)",
                      fontFamily: "var(--font-mono)",
                    }}
                  >
                    View all logs →
                  </Link>
                </div>
              </div>
            )}
          </div>
        )}

        {/* ══════════════════ IOC TAB PANEL ══════════════════ */}
        {activeTab === "ioc" &&
          (() => {
            const _user = JSON.parse(localStorage.getItem("pg_user") || "null");
            const canWrite = ["admin", "analyst"].includes(_user?.role);
            const canDelete = _user?.role === "admin";
            return (
              <motion.div
                initial={{ opacity: 0, y: 8 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.2 }}
              >
                {/* Stats strip */}
                {iocStats && (
                  <div className="grid grid-cols-2 md:grid-cols-5 gap-3 mb-5">
                    {[
                      {
                        label: "Total IOCs",
                        value: iocStats.total ?? 0,
                        color: "var(--text-secondary)",
                      },
                      {
                        label: "Active",
                        value: iocStats.active ?? 0,
                        color: "var(--color-danger)",
                      },
                      {
                        label: "New (7d)",
                        value: iocStats.new7d ?? 0,
                        color: "#fbbf24",
                      },
                      {
                        label: "Critical",
                        value: iocStats.bySeverity?.[5] ?? 0,
                        color: "#ff0d00ff",
                      },
                      {
                        label: "High",
                        value: iocStats.bySeverity?.[4] ?? 0,
                        color: "#fb923c",
                      },
                    ].map((s) => (
                      <div
                        key={s.label}
                        className="card p-4"
                        style={{ background: "var(--bg-card)" }}
                      >
                        <div
                          className="text-2xl font-bold font-display"
                          style={{ color: s.color }}
                        >
                          {s.value}
                        </div>
                        <div className="label-caps mt-0.5">{s.label}</div>
                      </div>
                    ))}
                  </div>
                )}

                {/* Type breakdown pills */}
                {iocStats?.byType &&
                  Object.keys(iocStats.byType).length > 0 && (
                    <div
                      className="card p-4 mb-4"
                      style={{ background: "var(--bg-card)" }}
                    >
                      <div className="label-caps mb-3">Filter by IOC Type</div>
                      <div className="flex flex-wrap gap-2">
                        <button
                          onClick={() =>
                            setIocFilter((f) => ({ ...f, type: "" }))
                          }
                          className="px-3 py-1.5 rounded-lg text-xs transition-all"
                          style={{
                            background:
                              iocFilter.type === ""
                                ? "rgba(225,37,27,0.12)"
                                : "var(--bg-elevated)",
                            border:
                              iocFilter.type === ""
                                ? "1px solid rgba(225,37,27,0.35)"
                                : "1px solid var(--bg-border)",
                            color:
                              iocFilter.type === ""
                                ? "#E1251B"
                                : "var(--text-muted)",
                            fontFamily: "var(--font-mono)",
                          }}
                        >
                          ALL
                        </button>
                        {Object.entries(iocStats.byType).map(
                          ([type, count]: [string, any]) => (
                            <button
                              key={type}
                              onClick={() =>
                                setIocFilter((f) => ({
                                  ...f,
                                  type: f.type === type ? "" : type,
                                }))
                              }
                              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs transition-all"
                              style={{
                                background:
                                  iocFilter.type === type
                                    ? "rgba(225,37,27,0.12)"
                                    : "var(--bg-elevated)",
                                border:
                                  iocFilter.type === type
                                    ? "1px solid rgba(225,37,27,0.35)"
                                    : "1px solid var(--bg-border)",
                                color:
                                  iocFilter.type === type
                                    ? "#E1251B"
                                    : "var(--text-secondary)",
                                fontFamily: "var(--font-mono)",
                              }}
                            >
                              {type.replace(/_/g, " ").toUpperCase()}
                              <span
                                className="font-bold"
                                style={{ color: "var(--accent)" }}
                              >
                                {count}
                              </span>
                            </button>
                          ),
                        )}
                      </div>
                    </div>
                  )}

                {/* Filter bar */}
                <div className="flex items-center gap-3 mb-4 flex-wrap">
                  <Filter
                    className="size-4"
                    style={{ color: "var(--text-muted)" }}
                  />
                  {["active", "false_positive"].map((s) => (
                    <button
                      key={s}
                      onClick={() => setIocFilter((f) => ({ ...f, status: s }))}
                      className="px-3 py-1.5 rounded-lg text-xs capitalize transition-all"
                      style={{
                        background:
                          iocFilter.status === s
                            ? "var(--accent-subtle)"
                            : "transparent",
                        border:
                          iocFilter.status === s
                            ? "1px solid var(--accent-border)"
                            : "1px solid var(--bg-border)",
                        color:
                          iocFilter.status === s
                            ? "var(--accent)"
                            : "var(--text-muted)",
                      }}
                    >
                      {s.replace(/_/g, " ")}
                    </button>
                  ))}
                  <select
                    value={iocFilter.severity}
                    onChange={(e) =>
                      setIocFilter((f) => ({
                        ...f,
                        severity: Number(e.target.value),
                      }))
                    }
                    className="text-xs px-2.5 py-1.5 rounded-lg"
                    style={{
                      background: "var(--bg-elevated)",
                      border: "1px solid var(--bg-border)",
                      color: "var(--text-secondary)",
                      fontFamily: "var(--font-mono)",
                    }}
                  >
                    <option value={0}>All severities</option>
                    <option value={5}>Critical (5)</option>
                    <option value={4}>High (4)</option>
                    <option value={3}>Medium (3)</option>
                    <option value={2}>Low (2)</option>
                  </select>
                  <span
                    className="text-xs ml-auto"
                    style={{
                      color: "var(--text-muted)",
                      fontFamily: "var(--font-mono)",
                    }}
                  >
                    {iocTotal} indicators
                  </span>
                  <button
                    onClick={fetchIOCs}
                    disabled={iocLoading}
                    className="btn-ghost flex items-center gap-1.5 px-3 py-1.5 text-xs"
                  >
                    <RefreshCw
                      className={`size-3.5 ${iocLoading ? "animate-spin" : ""}`}
                    />
                    Refresh
                  </button>
                </div>

                {/* IOC list card */}
                <div
                  className="card overflow-hidden"
                  style={{ background: "var(--bg-card)" }}
                >
                  {/* Terminal chrome bar */}
                  <div
                    className="flex items-center gap-2 px-5 py-2.5 border-b"
                    style={{
                      borderColor: "var(--bg-border)",
                      background: "rgba(0,0,0,0.3)",
                    }}
                  >
                    <div className="flex gap-1.5">
                      <div
                        className="w-2.5 h-2.5 rounded-full"
                        style={{ background: "#ff5f57" }}
                      />
                      <div
                        className="w-2.5 h-2.5 rounded-full"
                        style={{ background: "#febc2e" }}
                      />
                      <div
                        className="w-2.5 h-2.5 rounded-full"
                        style={{ background: "#28c840" }}
                      />
                    </div>
                    <span
                      className="text-xs ml-2"
                      style={{
                        color: "var(--text-muted)",
                        fontFamily: "var(--font-mono)",
                      }}
                    >
                      ioc.db — {iocFilter.status} · {iocTotal} records
                    </span>
                  </div>

                  {/* Loading */}
                  {iocLoading && (
                    <div className="py-16 flex flex-col items-center gap-3">
                      <div
                        className="w-7 h-7 border-2 rounded-full animate-spin"
                        style={{
                          borderColor: "var(--color-danger)",
                          borderTopColor: "transparent",
                        }}
                      />
                      <span
                        className="text-xs"
                        style={{
                          color: "var(--text-muted)",
                          fontFamily: "var(--font-mono)",
                        }}
                      >
                        Loading indicators...
                      </span>
                    </div>
                  )}

                  {/* Empty state */}
                  {!iocLoading && iocs.length === 0 && (
                    <div className="py-16 flex flex-col items-center gap-3">
                      <div
                        className="text-4xl opacity-30"
                        style={{ filter: "grayscale(1)" }}
                      >
                        🔴
                      </div>
                      <p
                        className="text-sm font-medium"
                        style={{ color: "var(--text-secondary)" }}
                      >
                        No IOCs yet
                      </p>
                      <p
                        className="text-xs text-center max-w-xs"
                        style={{ color: "var(--text-muted)" }}
                      >
                        Run phishing or suspicious URL scans — indicators are
                        extracted and stored automatically on every detection.
                      </p>
                    </div>
                  )}

                  {/* IOC rows */}
                  {!iocLoading && iocs.length > 0 && (
                    <div
                      className="divide-y"
                      style={{ borderColor: "var(--bg-border)" }}
                    >
                      {iocs.map((ioc: any) => {
                        const sevColor =
                          ioc.severity === 5
                            ? "#E1251B"
                            : ioc.severity === 4
                              ? "#fb923c"
                              : ioc.severity === 3
                                ? "#fbbf24"
                                : ioc.severity === 2
                                  ? "#60a5fa"
                                  : "var(--text-muted)";
                        const typeColor =
                          ioc.type === "url"
                            ? "var(--color-info)"
                            : ioc.type === "domain"
                              ? "#a78bfa"
                              : ioc.type === "ip"
                                ? "#fb923c"
                                : ioc.type === "email_sender"
                                  ? "#fbbf24"
                                  : ioc.type === "file_hash"
                                    ? "#E1251B"
                                    : ioc.type === "keyword"
                                      ? "#34d399"
                                      : ioc.type === "phone"
                                        ? "#60a5fa"
                                        : ioc.type === "upi_id"
                                          ? "#fbbf24"
                                          : "var(--text-muted)";
                        const typeIcon =
                          ioc.type === "url"
                            ? "🔗"
                            : ioc.type === "domain"
                              ? "🌐"
                              : ioc.type === "ip"
                                ? "📡"
                                : ioc.type === "email_sender"
                                  ? "📧"
                                  : ioc.type === "file_hash"
                                    ? "🗂"
                                    : ioc.type === "keyword"
                                      ? "💬"
                                      : ioc.type === "phone"
                                        ? "📞"
                                        : ioc.type === "upi_id"
                                          ? "💰"
                                          : "●";
                        return (
                          <div
                            key={ioc._id}
                            className="px-5 py-3.5 flex items-start gap-3 hover:bg-white/[0.02] transition-colors"
                          >
                            <div
                              className="flex-shrink-0 w-2 h-2 rounded-full mt-2"
                              style={{
                                background: sevColor,
                                boxShadow: `0 0 6px ${sevColor}60`,
                              }}
                            />
                            <span
                              className="text-[9px] px-1.5 py-0.5 rounded font-bold flex-shrink-0 mt-1"
                              style={{
                                color: typeColor,
                                background: `${typeColor}18`,
                                border: `1px solid ${typeColor}30`,
                                fontFamily: "var(--font-mono)",
                              }}
                            >
                              {typeIcon}{" "}
                              {ioc.type.replace(/_/g, " ").toUpperCase()}
                            </span>
                            <div className="flex-1 min-w-0">
                              <div className="flex items-center gap-2 flex-wrap">
                                <code
                                  className="text-xs font-semibold truncate max-w-[280px] md:max-w-md"
                                  style={{
                                    color: "var(--text-primary)",
                                    fontFamily: "var(--font-mono)",
                                  }}
                                >
                                  {ioc.value}
                                </code>
                                <button
                                  onClick={() =>
                                    navigator.clipboard.writeText(ioc.value)
                                  }
                                  className="text-[9px] px-1.5 py-0.5 rounded flex-shrink-0 transition-all"
                                  style={{
                                    color: "var(--text-muted)",
                                    border: "1px solid var(--bg-border)",
                                  }}
                                  title="Copy to clipboard"
                                >
                                  Copy
                                </button>
                              </div>
                              {ioc.type === "keyword" && ioc.rawSnippet && (
                                <div
                                  className="mt-1 text-[9px] px-2 py-1 rounded"
                                  style={{
                                    background: "var(--bg-elevated)",
                                    color: "var(--text-muted)",
                                    fontFamily: "var(--font-mono)",
                                    fontStyle: "italic",
                                    border: "1px solid var(--bg-border)",
                                  }}
                                >
                                  "…{ioc.rawSnippet}…"
                                </div>
                              )}
                              {ioc.type === "keyword" &&
                                ioc.keywordCategory && (
                                  <span
                                    className="inline-block mt-1 text-[9px] px-1.5 py-0.5 rounded capitalize"
                                    style={{
                                      color: "#34d399",
                                      background: "rgba(52,211,153,0.08)",
                                      border: "1px solid rgba(52,211,153,0.2)",
                                      fontFamily: "var(--font-mono)",
                                    }}
                                  >
                                    {ioc.keywordCategory} ·{" "}
                                    {ioc.keywordLanguage}
                                  </span>
                                )}
                              <div className="flex items-center gap-2 mt-1 flex-wrap">
                                {ioc.brand && (
                                  <span
                                    className="text-[9px]"
                                    style={{
                                      color: "#fbbf24",
                                      fontFamily: "var(--font-mono)",
                                    }}
                                  >
                                    🎯 {ioc.brand}
                                  </span>
                                )}
                                {ioc.mitreId && (
                                  <span
                                    className="text-[9px] px-1.5 py-0.5 rounded"
                                    style={{
                                      color: "#a78bfa",
                                      background: "rgba(167,139,250,0.08)",
                                      border: "1px solid rgba(167,139,250,0.2)",
                                      fontFamily: "var(--font-mono)",
                                    }}
                                  >
                                    {ioc.mitreId}
                                  </span>
                                )}
                                {(ioc.attackTypes || [])
                                  .slice(0, 3)
                                  .map((a: string) => (
                                    <span
                                      key={a}
                                      className="text-[9px] px-1.5 py-0.5 rounded"
                                      style={{
                                        color: "var(--text-muted)",
                                        background: "var(--bg-elevated)",
                                        fontFamily: "var(--font-mono)",
                                      }}
                                    >
                                      {a}
                                    </span>
                                  ))}
                                <span
                                  className="text-[9px] ml-auto"
                                  style={{
                                    color: "var(--text-muted)",
                                    fontFamily: "var(--font-mono)",
                                  }}
                                >
                                  first:{" "}
                                  {new Date(ioc.firstSeen).toLocaleDateString()}{" "}
                                  · last:{" "}
                                  {new Date(ioc.lastSeen).toLocaleDateString()}
                                </span>
                              </div>
                            </div>
                            <div className="flex-shrink-0 text-center min-w-[36px]">
                              <div
                                className="text-sm font-bold"
                                style={{
                                  color: sevColor,
                                  fontFamily: "var(--font-mono)",
                                }}
                              >
                                {ioc.hitCount}×
                              </div>
                              <div
                                className="text-[9px]"
                                style={{ color: "var(--text-muted)" }}
                              >
                                seen
                              </div>
                            </div>
                            <div className="flex-shrink-0">
                              <span
                                className="text-[9px] px-2 py-1 rounded font-bold"
                                style={{
                                  color: sevColor,
                                  background: `${sevColor}12`,
                                  border: `1px solid ${sevColor}25`,
                                  fontFamily: "var(--font-mono)",
                                }}
                              >
                                SEV-{ioc.severity}
                              </span>
                            </div>
                            <div className="flex-shrink-0 text-center min-w-[36px] hidden md:block">
                              <div
                                className="text-xs"
                                style={{
                                  color: "var(--text-muted)",
                                  fontFamily: "var(--font-mono)",
                                }}
                              >
                                {ioc.confidence}%
                              </div>
                              <div
                                className="text-[9px]"
                                style={{ color: "var(--text-muted)" }}
                              >
                                conf
                              </div>
                            </div>
                            {canWrite && ioc.status === "active" && (
                              <button
                                onClick={async () => {
                                  try {
                                    const res = await fetch(
                                      `${SIEM_API}/ioc/${ioc._id}/false-positive`,
                                      {
                                        method: "PATCH",
                                        headers: authHeader(),
                                      },
                                    );
                                    if (res.ok) fetchIOCs();
                                  } catch {
                                    /* offline */
                                  }
                                }}
                                className="flex-shrink-0 text-[9px] px-2 py-1 rounded transition-all"
                                style={{
                                  color: "var(--text-muted)",
                                  border: "1px solid var(--bg-border)",
                                }}
                                title="Mark as false positive"
                              >
                                FP
                              </button>
                            )}
                            {canDelete && (
                              <button
                                onClick={async () => {
                                  if (
                                    !window.confirm(
                                      `Permanently delete IOC: ${ioc.value}?`,
                                    )
                                  )
                                    return;
                                  try {
                                    const res = await fetch(
                                      `${SIEM_API}/ioc/${ioc._id}`,
                                      {
                                        method: "DELETE",
                                        headers: authHeader(),
                                      },
                                    );
                                    if (res.ok) fetchIOCs();
                                  } catch {
                                    /* offline */
                                  }
                                }}
                                className="flex-shrink-0 text-[9px] px-2 py-1 rounded transition-all"
                                style={{
                                  color: "#E1251B",
                                  border: "1px solid rgba(225,37,27,0.2)",
                                }}
                                title="Delete IOC permanently"
                              >
                                Del
                              </button>
                            )}
                          </div>
                        );
                      })}
                    </div>
                  )}

                  {/* Pagination */}
                  {iocTotal > 50 && (
                    <div
                      className="px-5 py-3 border-t flex items-center justify-between"
                      style={{ borderColor: "var(--bg-border)" }}
                    >
                      <button
                        onClick={() => setIocPage((p) => Math.max(1, p - 1))}
                        disabled={iocPage === 1}
                        className="text-xs btn-ghost px-3 py-1.5 disabled:opacity-40"
                      >
                        ← Prev
                      </button>
                      <span
                        className="text-xs"
                        style={{
                          color: "var(--text-muted)",
                          fontFamily: "var(--font-mono)",
                        }}
                      >
                        Page {iocPage} of {Math.ceil(iocTotal / 50)} ·{" "}
                        {iocTotal} total
                      </span>
                      <button
                        onClick={() => setIocPage((p) => p + 1)}
                        disabled={iocPage >= Math.ceil(iocTotal / 50)}
                        className="text-xs btn-ghost px-3 py-1.5 disabled:opacity-40"
                      >
                        Next →
                      </button>
                    </div>
                  )}
                </div>
              </motion.div>
            );
          })()}
        {/* ══════════════════ END IOC TAB ══════════════════════ */}
      </div>
    </div>
  );
}
