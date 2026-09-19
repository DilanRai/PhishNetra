// FILE: src/pages/Logs.tsx — CREATE NEW
// Blue Team Log Analysis dashboard — Splunk-style for individual use
// Shows all log types: failed logins, brute force, DNS, PowerShell, USB

import { useState, useEffect, useCallback } from "react";
import { motion, AnimatePresence } from "motion/react";
import {
  FileSearch,
  ShieldAlert,
  Activity,
  RefreshCw,
  AlertTriangle,
  ChevronDown,
  ChevronUp,
  Filter,
  Terminal,
  Usb,
  Globe,
  Lock,
  Wifi,
  Trash2,
  CheckCircle,
  Clock,
  Eye,
  XCircle,
  Download,
} from "lucide-react";
import { API_BASE } from "../config";
// ── Types ──
interface LogEvent {
  _id: string;
  logType: string;
  sourceHost: string;
  sourceIp: string | null;
  sourceUser: string | null;
  severity: number;
  eventId: string | null;
  description: string;
  rawData: Record<string, any>;
  attackTypes: string[];
  mitre: { tactic: string; technique: string } | null;
  status: "new" | "investigating" | "resolved" | "false_positive";
  createdAt: string;
}
interface LogStats {
  totalLogs: number;
  logs24h: number;
  bruteForceCount24h: number;
  byType: Record<string, number>;
  bySeverity: Record<string, number>;
  recentLogs: LogEvent[];
}

// ── Constants ──
const API = `${API_BASE}/api`;
const SEV_COLOR: Record<number, string> = {
  5: "#f87171",
  4: "#fb923c",
  3: "#fbbf24",
  2: "#34d399",
  1: "#64748b",
};
const SEV_LABEL: Record<number, string> = {
  5: "Critical",
  4: "High",
  3: "Medium",
  2: "Low",
  1: "Info",
};
const TYPE_META: Record<string, { icon: any; label: string; color: string }> = {
  failed_login: { icon: Lock, label: "Failed Login", color: "#fbbf24" },
  multiple_login_attempts: {
    icon: ShieldAlert,
    label: "Brute Force",
    color: "#f87171",
  },
  powershell_execution: {
    icon: Terminal,
    label: "PowerShell",
    color: "#a78bfa",
  },
  suspicious_process: {
    icon: Activity,
    label: "Suspicious Process",
    color: "#fb923c",
  },
  usb_activity: { icon: Usb, label: "USB Activity", color: "#60a5fa" },
  dns_malicious: { icon: Globe, label: "Malicious DNS", color: "#f87171" },
  browser_alert: { icon: Wifi, label: "Browser Alert", color: "var(--accent)" },
};
const STATUS_META: Record<string, { color: string; label: string }> = {
  new: { color: "#f87171", label: "New" },
  investigating: { color: "#fbbf24", label: "Investigating" },
  resolved: { color: "#34d399", label: "Resolved" },
  false_positive: { color: "#64748b", label: "False Positive" },
};

function authHeader(): Record<string, string> {
  const token = localStorage.getItem("pg_token");
  return token ? { Authorization: `Bearer ${token}` } : {};
}

function severityBar(sev: number) {
  const filled = sev;
  return (
    <div className="flex items-center gap-0.5">
      {[1, 2, 3, 4, 5].map((i) => (
        <div
          key={i}
          className="w-1.5 h-3 rounded-sm"
          style={{
            background: i <= filled ? SEV_COLOR[sev] : "var(--bg-border)",
          }}
        />
      ))}
    </div>
  );
}

export default function Logs() {
  const [stats, setStats] = useState<LogStats | null>(null);
  const [logs, setLogs] = useState<LogEvent[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [filterType, setFilterType] = useState("");
  const [filterSev, setFilterSev] = useState("");
  const [filterStatus, setFilterStatus] = useState("");
  const [page, setPage] = useState(1);
  const [updating, setUpdating] = useState<string | null>(null);
  const [clearModal, setClearModal] = useState(false);

  const fetchStats = useCallback(async () => {
    try {
      const r = await fetch(`${API}/logs/stats`, { headers: authHeader() });
      if (r.ok) setStats(await r.json());
    } catch {}
  }, []);

  const fetchLogs = useCallback(
    async (pg = 1) => {
      setRefreshing(true);
      try {
        const params = new URLSearchParams({ page: String(pg), limit: "50" });
        if (filterType) params.set("logType", filterType);
        if (filterSev) params.set("severity", filterSev);
        if (filterStatus) params.set("status", filterStatus);
        const r = await fetch(`${API}/logs?${params}`, {
          headers: authHeader(),
        });
        if (r.ok) {
          const data = await r.json();
          setLogs(data.logs || []);
          setTotal(data.total || 0);
          setPage(pg);
        }
      } catch {
      } finally {
        setRefreshing(false);
        setLoading(false);
      }
    },
    [filterType, filterSev, filterStatus],
  );

  useEffect(() => {
    fetchStats();
    fetchLogs(1);
  }, [fetchStats, fetchLogs]);

  const updateStatus = async (id: string, status: string) => {
    setUpdating(id);
    try {
      const r = await fetch(`${API}/logs/${id}/status`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json", ...authHeader() },
        body: JSON.stringify({ status }),
      });
      if (r.ok) {
        setLogs((prev) =>
          prev.map((l) => (l._id === id ? { ...l, status: status as any } : l)),
        );
        fetchStats();
      }
    } catch {
    } finally {
      setUpdating(null);
    }
  };

  const trustDevice = async (id: string) => {
    setUpdating(id);
    try {
      const r = await fetch(`${API}/logs/${id}/trust-device`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json", ...authHeader() },
      });
      if (r.ok) {
        setLogs((prev) =>
          prev.map((l) =>
            l._id === id ? { ...l, status: "resolved" as any } : l,
          ),
        );
        fetchStats();
      }
    } catch {
    } finally {
      setUpdating(null);
    }
  };

  const clearAllLogs = async () => {
    try {
      await fetch(`${API}/logs`, { method: "DELETE", headers: authHeader() });
      setClearModal(false);
      fetchStats();
      fetchLogs(1);
    } catch {}
  };

  const exportCSV = () => {
    const headers = [
      "Time",
      "Type",
      "User",
      "Host",
      "IP",
      "Severity",
      "Description",
      "Status",
    ];
    const rows = logs.map((l) => [
      new Date(l.createdAt).toLocaleString(),
      l.logType,
      l.sourceUser || "",
      l.sourceHost,
      l.sourceIp || "",
      `SEV-${l.severity}`,
      `"${l.description.replace(/"/g, '""')}"`,
      l.status,
    ]);
    const csv = [headers, ...rows].map((r) => r.join(",")).join("\n");
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([csv], { type: "text/csv" }));
    a.download = `phishnetra-logs-${Date.now()}.csv`;
    a.click();
  };

  const STAT_CARDS = [
    {
      label: "Total Logs",
      value: stats?.totalLogs ?? "—",
      color: "var(--accent)",
    },
    {
      label: "Last 24h",
      value: stats?.logs24h ?? "—",
      color: "var(--color-info)",
    },
    {
      label: "Brute Force (24h)",
      value: stats?.bruteForceCount24h ?? "—",
      color: "#f87171",
    },
    {
      label: "Failed Logins",
      value: stats?.byType?.failed_login ?? 0,
      color: "#fbbf24",
    },
    {
      label: "DNS Alerts",
      value: stats?.byType?.dns_malicious ?? 0,
      color: "#fb923c",
    },
    {
      label: "PowerShell Alerts",
      value: stats?.byType?.powershell_execution ?? 0,
      color: "#a78bfa",
    },
  ];

  return (
    <div className="min-h-full" style={{ background: "var(--bg-base)" }}>
      {/* ── Header ── */}
      <div
        className="border-b"
        style={{
          borderColor: "var(--bg-border)",
          background: "var(--bg-elevated)",
        }}
      >
        <div className="max-w-7xl mx-auto px-6 py-5 flex items-center justify-between gap-4 flex-wrap">
          <div className="flex items-center gap-3">
            <div
              className="w-9 h-9 rounded-xl flex items-center justify-center"
              style={{
                background: "rgba(96,165,250,0.1)",
                border: "1px solid rgba(96,165,250,0.2)",
              }}
            >
              <FileSearch
                className="size-5"
                style={{ color: "var(--color-info)" }}
              />
            </div>
            <div>
              <h1
                className="text-lg font-bold"
                style={{
                  color: "var(--text-primary)",
                  letterSpacing: "-0.02em",
                }}
              >
                Log Analysis
              </h1>
              <p
                className="text-xs"
                style={{
                  color: "var(--text-muted)",
                  fontFamily: "var(--font-mono)",
                }}
              >
                {total} events · Phase 1–3 endpoint monitoring
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2 flex-wrap">
            <button
              onClick={exportCSV}
              className="btn-ghost flex items-center gap-1.5 px-3.5 py-2 text-sm"
            >
              <Download className="size-3.5" /> Export CSV
            </button>
            <button
              onClick={() => setClearModal(true)}
              className="btn-ghost flex items-center gap-1.5 px-3.5 py-2 text-sm"
              style={{
                color: "var(--color-danger)",
                borderColor: "rgba(248,113,113,0.25)",
              }}
            >
              <Trash2 className="size-3.5" /> Clear All
            </button>
            <button
              onClick={() => {
                fetchStats();
                fetchLogs(1);
              }}
              className="btn-primary flex items-center gap-1.5 px-3.5 py-2 text-sm"
            >
              <RefreshCw
                className={`size-3.5 ${refreshing ? "animate-spin" : ""}`}
              />{" "}
              Refresh
            </button>
          </div>
        </div>
      </div>

      <div className="max-w-7xl mx-auto px-6 py-6 space-y-6">
        {/* ── Stat Cards ── */}
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
          {STAT_CARDS.map((card, i) => (
            <motion.div
              key={card.label}
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: i * 0.05 }}
              className="card p-4 stat-card"
            >
              <div
                className="text-2xl font-bold mb-1"
                style={{ color: card.color, fontFamily: "var(--font-mono)" }}
              >
                {card.value}
              </div>
              <div className="text-xs" style={{ color: "var(--text-muted)" }}>
                {card.label}
              </div>
            </motion.div>
          ))}
        </div>

        {/* ── Log Type Breakdown ── */}
        {stats && (
          <div className="card p-5" style={{ background: "var(--bg-card)" }}>
            <div className="label-caps mb-4">Event Distribution</div>
            <div className="flex flex-wrap gap-3">
              {Object.entries(TYPE_META).map(([type, meta]) => {
                const count = stats.byType?.[type] || 0;
                const Icon = meta.icon;
                return (
                  <button
                    key={type}
                    onClick={() =>
                      setFilterType(filterType === type ? "" : type)
                    }
                    className="flex items-center gap-2 px-3 py-2 rounded-xl text-xs transition-all"
                    style={{
                      background:
                        filterType === type
                          ? `${meta.color}10`
                          : "var(--bg-elevated)",
                      border: `1px solid ${filterType === type ? meta.color + "35" : "var(--bg-border)"}`,
                      color:
                        filterType === type ? meta.color : "var(--text-muted)",
                    }}
                  >
                    <Icon className="size-3.5" style={{ color: meta.color }} />
                    {meta.label}
                    <span
                      className="font-bold"
                      style={{
                        color: meta.color,
                        fontFamily: "var(--font-mono)",
                      }}
                    >
                      {count}
                    </span>
                  </button>
                );
              })}
            </div>
          </div>
        )}

        {/* ── Filters ── */}
        <div className="flex items-center gap-2 flex-wrap">
          <Filter
            className="size-3.5 flex-shrink-0"
            style={{ color: "var(--text-muted)" }}
          />

          <select
            value={filterType}
            onChange={(e) => {
              setFilterType(e.target.value);
              fetchLogs(1);
            }}
            className="px-3 py-1.5 rounded-lg text-xs"
            style={{
              background: "var(--bg-elevated)",
              border: "1px solid var(--bg-border)",
              color: "var(--text-secondary)",
              fontFamily: "var(--font-mono)",
            }}
          >
            <option value="">All Types</option>
            {Object.entries(TYPE_META).map(([k, v]) => (
              <option key={k} value={k}>
                {v.label}
              </option>
            ))}
          </select>

          <select
            value={filterSev}
            onChange={(e) => {
              setFilterSev(e.target.value);
              fetchLogs(1);
            }}
            className="px-3 py-1.5 rounded-lg text-xs"
            style={{
              background: "var(--bg-elevated)",
              border: "1px solid var(--bg-border)",
              color: "var(--text-secondary)",
              fontFamily: "var(--font-mono)",
            }}
          >
            <option value="">All Severity</option>
            {[5, 4, 3, 2, 1].map((s) => (
              <option key={s} value={s}>
                SEV-{s} {SEV_LABEL[s]}
              </option>
            ))}
          </select>

          <select
            value={filterStatus}
            onChange={(e) => {
              setFilterStatus(e.target.value);
              fetchLogs(1);
            }}
            className="px-3 py-1.5 rounded-lg text-xs"
            style={{
              background: "var(--bg-elevated)",
              border: "1px solid var(--bg-border)",
              color: "var(--text-secondary)",
              fontFamily: "var(--font-mono)",
            }}
          >
            <option value="">All Status</option>
            {Object.entries(STATUS_META).map(([k, v]) => (
              <option key={k} value={k}>
                {v.label}
              </option>
            ))}
          </select>

          {(filterType || filterSev || filterStatus) && (
            <button
              onClick={() => {
                setFilterType("");
                setFilterSev("");
                setFilterStatus("");
                fetchLogs(1);
              }}
              className="text-xs px-2 py-1 rounded-lg"
              style={{
                color: "var(--color-danger)",
                border: "1px solid rgba(248,113,113,0.25)",
              }}
            >
              Clear filters
            </button>
          )}

          <span
            className="ml-auto text-xs"
            style={{
              color: "var(--text-muted)",
              fontFamily: "var(--font-mono)",
            }}
          >
            {total} results
          </span>
        </div>

        {/* ── Log Table ── */}
        {loading ? (
          <div className="flex items-center justify-center py-20">
            <div
              className="w-8 h-8 border-2 rounded-full animate-spin"
              style={{
                borderColor: "var(--accent)",
                borderTopColor: "transparent",
              }}
            />
          </div>
        ) : logs.length === 0 ? (
          <div
            className="card p-12 text-center"
            style={{ background: "var(--bg-card)" }}
          >
            <FileSearch
              className="size-10 mx-auto mb-3"
              style={{ color: "var(--text-dim)" }}
            />
            <p
              className="text-sm font-medium mb-1"
              style={{ color: "var(--text-secondary)" }}
            >
              No log events yet
            </p>
            <p className="text-xs" style={{ color: "var(--text-muted)" }}>
              Run a collector script to start ingesting events from your
              machine.
            </p>
          </div>
        ) : (
          <div className="space-y-1.5">
            <AnimatePresence>
              {logs.map((log, i) => {
                const meta = TYPE_META[log.logType] || {
                  icon: Activity,
                  label: log.logType,
                  color: "var(--text-muted)",
                };
                const Icon = meta.icon;
                const isOpen = expanded === log._id;
                const sevCol = SEV_COLOR[log.severity] || "#94a3b8";
                const statMeta = STATUS_META[log.status] || STATUS_META.new;

                return (
                  <motion.div
                    key={log._id}
                    initial={{ opacity: 0, y: 4 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: Math.min(i * 0.02, 0.3) }}
                    className="card overflow-hidden"
                    style={{
                      background: "var(--bg-card)",
                      borderColor: isOpen ? `${sevCol}30` : "var(--bg-border)",
                    }}
                  >
                    {/* ── Row ── */}
                    <div
                      className="flex items-center gap-3 px-4 py-3 cursor-pointer"
                      onClick={() => setExpanded(isOpen ? null : log._id)}
                    >
                      {/* Severity bar */}
                      <div className="flex-shrink-0">
                        {severityBar(log.severity)}
                      </div>

                      {/* Type icon */}
                      <div
                        className="w-7 h-7 rounded-lg flex items-center justify-center flex-shrink-0"
                        style={{
                          background: `${meta.color}10`,
                          border: `1px solid ${meta.color}22`,
                        }}
                      >
                        <Icon
                          className="size-3.5"
                          style={{ color: meta.color }}
                        />
                      </div>

                      {/* Main info */}
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 flex-wrap mb-0.5">
                          <span
                            className="text-xs font-semibold"
                            style={{
                              color: meta.color,
                              fontFamily: "var(--font-mono)",
                            }}
                          >
                            {meta.label}
                          </span>
                          {log.attackTypes.map((at) => (
                            <span
                              key={at}
                              className="text-[9px] px-1.5 py-0.5 rounded"
                              style={{
                                color: sevCol,
                                background: `${sevCol}10`,
                                border: `1px solid ${sevCol}20`,
                                fontFamily: "var(--font-mono)",
                              }}
                            >
                              {at.replace(/_/g, " ")}
                            </span>
                          ))}
                        </div>
                        <p
                          className="text-xs truncate"
                          style={{ color: "var(--text-secondary)" }}
                        >
                          {log.description}
                        </p>
                      </div>

                      {/* Meta */}
                      <div className="flex items-center gap-3 flex-shrink-0">
                        {log.sourceUser && (
                          <span
                            className="text-xs hidden md:block"
                            style={{
                              color: "var(--text-muted)",
                              fontFamily: "var(--font-mono)",
                            }}
                          >
                            {log.sourceUser}
                          </span>
                        )}
                        <span
                          className="text-xs px-2 py-0.5 rounded"
                          style={{
                            color: statMeta.color,
                            background: `${statMeta.color}10`,
                            border: `1px solid ${statMeta.color}20`,
                            fontFamily: "var(--font-mono)",
                          }}
                        >
                          {statMeta.label}
                        </span>
                        <span
                          className="text-xs hidden lg:block"
                          style={{
                            color: "var(--text-dim)",
                            fontFamily: "var(--font-mono)",
                          }}
                        >
                          {new Date(log.createdAt).toLocaleTimeString()}
                        </span>
                        {isOpen ? (
                          <ChevronUp
                            className="size-4"
                            style={{ color: "var(--text-dim)" }}
                          />
                        ) : (
                          <ChevronDown
                            className="size-4"
                            style={{ color: "var(--text-dim)" }}
                          />
                        )}
                      </div>
                    </div>

                    {/* ── Expanded Detail ── */}
                    <AnimatePresence>
                      {isOpen && (
                        <motion.div
                          initial={{ height: 0, opacity: 0 }}
                          animate={{ height: "auto", opacity: 1 }}
                          exit={{ height: 0, opacity: 0 }}
                          transition={{
                            duration: 0.22,
                            ease: [0.23, 1, 0.32, 1],
                          }}
                          className="overflow-hidden"
                        >
                          <div
                            className="px-5 pb-5 pt-1 border-t"
                            style={{ borderColor: "var(--bg-border)" }}
                          >
                            <div className="grid md:grid-cols-2 gap-5 mt-4">
                              {/* Left — event details */}
                              <div className="space-y-3">
                                <div>
                                  <div className="label-caps mb-2">
                                    Event Details
                                  </div>
                                  <div className="space-y-1.5">
                                    {[
                                      ["Event ID", log.eventId || "—"],
                                      ["Host", log.sourceHost],
                                      ["Source IP", log.sourceIp || "—"],
                                      ["User", log.sourceUser || "—"],
                                      [
                                        "Severity",
                                        `SEV-${log.severity} ${SEV_LABEL[log.severity]}`,
                                      ],
                                      [
                                        "Time",
                                        new Date(
                                          log.createdAt,
                                        ).toLocaleString(),
                                      ],
                                    ].map(([k, v]) => (
                                      <div
                                        key={k}
                                        className="flex items-start gap-2"
                                      >
                                        <span
                                          className="text-xs flex-shrink-0 w-20"
                                          style={{
                                            color: "var(--text-muted)",
                                            fontFamily: "var(--font-mono)",
                                          }}
                                        >
                                          {k}
                                        </span>
                                        <span
                                          className="text-xs break-all"
                                          style={{
                                            color: "var(--text-primary)",
                                            fontFamily: "var(--font-mono)",
                                          }}
                                        >
                                          {v}
                                        </span>
                                      </div>
                                    ))}
                                  </div>
                                </div>

                                {/* Raw data */}
                                {Object.keys(log.rawData).length > 0 && (
                                  <div>
                                    <div className="label-caps mb-2">
                                      Raw Data
                                    </div>
                                    <pre
                                      className="text-[10px] p-3 rounded-xl overflow-x-auto"
                                      style={{
                                        background: "var(--bg-base)",
                                        color: "var(--text-secondary)",
                                        fontFamily: "var(--font-mono)",
                                        border: "1px solid var(--bg-border)",
                                      }}
                                    >
                                      {JSON.stringify(log.rawData, null, 2)}
                                    </pre>
                                  </div>
                                )}
                              </div>

                              {/* Right — MITRE + actions */}
                              <div className="space-y-3">
                                {log.mitre && (
                                  <div>
                                    <div className="label-caps mb-2">
                                      MITRE ATT&CK
                                    </div>
                                    <div
                                      className="rounded-xl p-3 space-y-1"
                                      style={{
                                        background: "rgba(167,139,250,0.07)",
                                        border:
                                          "1px solid rgba(167,139,250,0.2)",
                                      }}
                                    >
                                      <p
                                        className="text-xs font-semibold"
                                        style={{
                                          color: "#a78bfa",
                                          fontFamily: "var(--font-mono)",
                                        }}
                                      >
                                        {log.mitre.technique}
                                      </p>
                                      <p
                                        className="text-xs"
                                        style={{
                                          color: "var(--text-muted)",
                                          fontFamily: "var(--font-mono)",
                                        }}
                                      >
                                        {log.mitre.tactic}
                                      </p>
                                    </div>
                                  </div>
                                )}

                                <div>
                                  <div className="label-caps mb-2">
                                    Update Status
                                  </div>
                                  <div className="grid grid-cols-2 gap-1.5">
                                    {Object.entries(STATUS_META).map(
                                      ([key, sm]) => (
                                        <button
                                          key={key}
                                          onClick={() =>
                                            updateStatus(log._id, key)
                                          }
                                          disabled={
                                            updating === log._id ||
                                            log.status === key
                                          }
                                          className="py-2 rounded-xl text-xs font-medium transition-all flex items-center justify-center gap-1.5"
                                          style={{
                                            background:
                                              log.status === key
                                                ? `${sm.color}12`
                                                : "var(--bg-elevated)",
                                            border: `1px solid ${log.status === key ? sm.color + "35" : "var(--bg-border)"}`,
                                            color:
                                              log.status === key
                                                ? sm.color
                                                : "var(--text-muted)",
                                            opacity:
                                              updating === log._id ? 0.6 : 1,
                                          }}
                                        >
                                          {log.status === key && (
                                            <CheckCircle className="size-3" />
                                          )}
                                          {sm.label}
                                        </button>
                                      ),
                                    )}
                                  </div>
                                  {/* Trust Device button — USB logs only */}
                                  {log.logType === "usb_activity" && (
                                    <button
                                      onClick={() => trustDevice(log._id)}
                                      disabled={updating === log._id}
                                      className="mt-2 w-full py-2 rounded-xl text-xs font-medium flex items-center justify-center gap-1.5 transition-all"
                                      style={{
                                        background: "rgba(96,165,250,0.08)",
                                        border:
                                          "1px solid rgba(96,165,250,0.3)",
                                        color: "var(--color-info)",
                                        opacity: updating === log._id ? 0.6 : 1,
                                      }}
                                    >
                                      <CheckCircle className="size-3" />
                                      Trust This Device
                                    </button>
                                  )}
                                </div>
                              </div>
                            </div>
                          </div>
                        </motion.div>
                      )}
                    </AnimatePresence>
                  </motion.div>
                );
              })}
            </AnimatePresence>

            {/* Pagination */}
            {total > 50 && (
              <div className="flex items-center justify-center gap-3 pt-4">
                <button
                  onClick={() => fetchLogs(page - 1)}
                  disabled={page <= 1}
                  className="btn-ghost px-4 py-2 text-sm disabled:opacity-40"
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
                  Page {page} of {Math.ceil(total / 50)}
                </span>
                <button
                  onClick={() => fetchLogs(page + 1)}
                  disabled={page >= Math.ceil(total / 50)}
                  className="btn-ghost px-4 py-2 text-sm disabled:opacity-40"
                >
                  Next →
                </button>
              </div>
            )}
          </div>
        )}
      </div>

      {/* ── Clear All Modal ── */}
      <AnimatePresence>
        {clearModal && (
          <>
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="fixed inset-0 z-50"
              style={{
                background: "rgba(5,8,15,0.8)",
                backdropFilter: "blur(6px)",
              }}
              onClick={() => setClearModal(false)}
            />
            <motion.div
              initial={{ opacity: 0, scale: 0.96 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.96 }}
              className="fixed top-1/4 left-1/2 -translate-x-1/2 z-50 w-full max-w-sm px-4"
            >
              <div
                className="card p-6 text-center"
                style={{ borderColor: "rgba(248,113,113,0.3)" }}
              >
                <Trash2
                  className="size-8 mx-auto mb-3"
                  style={{ color: "var(--color-danger)" }}
                />
                <h3
                  className="text-base font-bold mb-2"
                  style={{ color: "var(--text-primary)" }}
                >
                  Clear All Log Events?
                </h3>
                <p
                  className="text-xs mb-5"
                  style={{ color: "var(--text-muted)" }}
                >
                  This permanently deletes all {total} log events. The 30-day
                  TTL auto-expire also removes them automatically.
                </p>
                <div className="flex gap-3">
                  <button
                    onClick={() => setClearModal(false)}
                    className="btn-ghost flex-1 py-2.5 text-sm"
                  >
                    Cancel
                  </button>
                  <button
                    onClick={clearAllLogs}
                    className="flex-1 py-2.5 rounded-xl text-sm font-bold"
                    style={{
                      background: "rgba(248,113,113,0.1)",
                      border: "2px solid rgba(248,113,113,0.35)",
                      color: "var(--color-danger)",
                    }}
                  >
                    Clear All
                  </button>
                </div>
              </div>
            </motion.div>
          </>
        )}
      </AnimatePresence>
    </div>
  );
}
