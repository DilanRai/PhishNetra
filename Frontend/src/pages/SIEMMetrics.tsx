// FILE: src/pages/SIEMMetrics.tsx
// KPI dashboard + baseline only

import { useCallback, useEffect, useState } from "react";
import { motion } from "motion/react";
import {
  TrendingUp,
  Clock,
  Shield,
  Zap,
  CheckCircle,
  RefreshCw,
  AlertTriangle,
  Activity,
  Globe,
} from "lucide-react";
import { API_BASE } from "../config";

interface KPI {
  mttd: number;
  mttr: number;
  fpRate: number;
  totalAlerts30d: number;
  resolved30d: number;
  resolutionRate: number;
  severityDist: Record<string, number>;
  weeklyTrend: {
    _id: string;
    total: number;
    critical: number;
    resolved: number;
  }[];
  topTechniques: { ruleId: string; ruleName: string; count: number }[];
}

interface BaselineData {
  baseline: any;
  current: any;
  healthy: boolean;
}

const SEV_LABELS: Record<string, string> = {
  "5": "CRITICAL",
  "4": "HIGH",
  "3": "MEDIUM",
  "2": "LOW",
  "1": "INFO",
};

const SEV_COLORS: Record<string, string> = {
  "5": "#ff4444",
  "4": "#f97316",
  "3": "#f5a623",
  "2": "#00d4ff",
  "1": "#8b95a8",
};

const formatMinutes = (m: number) => {
  if (m === 0) return "N/A";
  if (m < 60) return `${m}m`;
  if (m < 1440) return `${Math.floor(m / 60)}h ${m % 60}m`;
  return `${Math.floor(m / 1440)}d ${Math.floor((m % 1440) / 60)}h`;
};

export default function SIEMMetrics() {
  const [kpi, setKpi] = useState<KPI | null>(null);
  const [baseline, setBaseline] = useState<BaselineData | null>(null);
  const [loading, setLoading] = useState(true);
  const [baselineLoad, setBaselineLoad] = useState(false);
  const [lastRefresh, setLastRefresh] = useState(new Date());
  const [activeTab, setActiveTab] = useState<"kpi" | "baseline">("kpi");
  const [correlating, setCorrelating] = useState(false);
  const [correlateRes, setCorrelateRes] = useState<any | null>(null);
  const [checkingAnomaly, setCheckingAnomaly] = useState(false);
  const [anomalyCheck, setAnomalyCheck] = useState<any | null>(null);
  const [testEvent, setTestEvent] = useState(
    `{
  "category": "phishing",
  "riskScore": 85,
  "rawData": {
    "issues": ["Brand spoofing detected"]
  }
}`,
  );
  const [testResult, setTestResult] = useState<any | null>(null);
  const [testing, setTesting] = useState(false);

  const fetchKPI = useCallback(async () => {
    setLoading(true);
    try {
      const res = await fetch(`${API_BASE}/api/siem/kpi`);
      if (res.ok) {
        setKpi(await res.json());
        setLastRefresh(new Date());
      }
    } catch {
      /* offline */
    } finally {
      setLoading(false);
    }
  }, []);

  const fetchBaseline = useCallback(async () => {
    setBaselineLoad(true);
    try {
      const res = await fetch(`${API_BASE}/api/siem/baseline`);
      if (res.ok) setBaseline(await res.json());
    } catch {
      /* offline */
    } finally {
      setBaselineLoad(false);
    }
  }, []);

  const handleTestRule = async () => {
    setTesting(true);
    setTestResult(null);
    try {
      const res = await fetch(`${API_BASE}/api/siem/rules/test`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ event: JSON.parse(testEvent) }),
      });
      setTestResult(
        res.ok
          ? await res.json()
          : { error: `Rule test failed (${res.status})` },
      );
    } catch (err: any) {
      setTestResult({ error: err.message || "Rule test failed" });
    } finally {
      setTesting(false);
    }
  };

  const runCorrelation = async () => {
    setCorrelating(true);
    setCorrelateRes(null);
    try {
      const res = await fetch(`${API_BASE}/api/siem/correlate`, {
        method: "POST",
      });
      setCorrelateRes(
        res.ok
          ? await res.json()
          : { error: `Correlation failed (${res.status})` },
      );
    } catch (err: any) {
      setCorrelateRes({ error: err.message || "Correlation failed" });
    } finally {
      setCorrelating(false);
    }
  };

  const runAnomalyCheck = async () => {
    setCheckingAnomaly(true);
    setAnomalyCheck(null);
    try {
      const res = await fetch(`${API_BASE}/api/siem/baseline/check`, {
        method: "POST",
      });
      setAnomalyCheck(
        res.ok ? await res.json() : { error: `Check failed (${res.status})` },
      );
    } catch (err: any) {
      setAnomalyCheck({ error: err.message || "Check failed" });
    } finally {
      setCheckingAnomaly(false);
    }
  };

  useEffect(() => {
    fetchKPI();
    fetchBaseline();
  }, [fetchKPI, fetchBaseline]);

  const totalSeverity = kpi
    ? Object.values(kpi.severityDist).reduce((a, b) => a + b, 0) || 1
    : 1;

  return (
    <div
      className="min-h-full py-10 px-6"
      style={{ background: "var(--bg-base)" }}
    >
      <div className="max-w-6xl mx-auto">
        <motion.div
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          className="flex items-start justify-between mb-8 flex-wrap gap-4"
        >
          <div>
            <div className="tag-green inline-flex mb-4">
              <TrendingUp className="size-3" /> SIEM METRICS
            </div>
            <h1
              className="text-4xl font-bold mb-1"
              style={{
                fontFamily: "'Syne', sans-serif",
                color: "var(--text-primary)",
              }}
            >
              KPI Dashboard
            </h1>
            <p
              className="text-sm"
              style={{
                color: "var(--text-muted)",
                fontFamily: "var(--font-mono)",
              }}
            >
              30-day rolling metrics · {lastRefresh.toLocaleTimeString()}
            </p>
          </div>
          <button
            onClick={fetchKPI}
            disabled={loading}
            className="btn-ghost flex items-center gap-2 px-3.5 py-2 text-sm"
          >
            <RefreshCw className={`size-4 ${loading ? "animate-spin" : ""}`} />{" "}
            Refresh
          </button>
        </motion.div>

        <div className="flex flex-wrap gap-2 mb-6">
          {[
            { key: "kpi", label: "KPI & Rules", icon: TrendingUp },
            { key: "baseline", label: "Baseline & Correlate", icon: Activity },
          ].map(({ key, label, icon: Icon }) => (
            <button
              key={key}
              onClick={() => setActiveTab(key as "kpi" | "baseline")}
              className="flex items-center gap-2 px-4 py-2 rounded-xl text-sm font-medium transition-all"
              style={{
                background:
                  activeTab === key
                    ? "rgba(52,211,153,0.08)"
                    : "var(--bg-card)",
                border: `1px solid ${activeTab === key ? "rgba(52,211,153,0.3)" : "var(--bg-border)"}`,
                color:
                  activeTab === key ? "var(--accent)" : "var(--text-secondary)",
              }}
            >
              <Icon className="size-4" /> {label}
            </button>
          ))}
        </div>

        {activeTab === "kpi" && (
          <>
            {kpi ? (
              <>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
                  {[
                    {
                      icon: Clock,
                      label: "MTTD",
                      value: formatMinutes(kpi.mttd),
                      sub: "Mean Time to Detect",
                      color: "var(--accent-cyan)",
                    },
                    {
                      icon: Zap,
                      label: "MTTR",
                      value: formatMinutes(kpi.mttr),
                      sub: "Mean Time to Respond",
                      color: "#a78bfa",
                    },
                    {
                      icon: Shield,
                      label: "False Positive Rate",
                      value: `${kpi.fpRate}%`,
                      sub: "Last 30 days",
                      color: kpi.fpRate > 20 ? "#ff4444" : "#34d399",
                    },
                    {
                      icon: CheckCircle,
                      label: "Resolution Rate",
                      value: `${kpi.resolutionRate}%`,
                      sub: `${kpi.resolved30d}/${kpi.totalAlerts30d}`,
                      color: "var(--accent)",
                    },
                  ].map((c, i) => (
                    <motion.div
                      key={c.label}
                      initial={{ opacity: 0, y: 16 }}
                      animate={{ opacity: 1, y: 0 }}
                      transition={{ delay: i * 0.07 }}
                      className="card p-5"
                      style={{ background: "var(--bg-card)" }}
                    >
                      <div className="flex items-center gap-2 mb-3">
                        <c.icon className="size-4" style={{ color: c.color }} />
                        <span
                          className="text-xs uppercase tracking-widest"
                          style={{
                            color: "var(--text-muted)",
                            fontFamily: "var(--font-mono)",
                          }}
                        >
                          {c.label}
                        </span>
                      </div>
                      <div
                        className="text-3xl font-bold mb-1"
                        style={{
                          color: c.color,
                          fontFamily: "'Syne', sans-serif",
                        }}
                      >
                        {c.value}
                      </div>
                      <div
                        className="text-xs"
                        style={{ color: "var(--text-muted)" }}
                      >
                        {c.sub}
                      </div>
                    </motion.div>
                  ))}
                </div>

                <div className="grid md:grid-cols-2 gap-4 mb-6">
                  <div
                    className="card p-5"
                    style={{ background: "var(--bg-card)" }}
                  >
                    <div className="flex items-center gap-2 mb-4">
                      <TrendingUp
                        className="size-4"
                        style={{ color: "var(--accent)" }}
                      />
                      <span
                        className="text-sm font-semibold"
                        style={{ color: "var(--text-primary)" }}
                      >
                        7-Day Alert Trend
                      </span>
                    </div>
                    <div className="flex items-end gap-2 h-20">
                      {kpi.weeklyTrend.map((d) => {
                        const max = Math.max(
                          ...kpi.weeklyTrend.map((x) => x.total),
                          1,
                        );
                        const h = Math.max((d.total / max) * 72, 2);
                        const ch = d.total > 0 ? (d.critical / d.total) * h : 0;
                        const rh = d.total > 0 ? (d.resolved / d.total) * h : 0;
                        return (
                          <div
                            key={d._id}
                            className="flex-1 flex flex-col items-center gap-1"
                          >
                            <div
                              className="w-full flex flex-col justify-end"
                              style={{ height: 72 }}
                            >
                              {ch > 0 && (
                                <div
                                  style={{
                                    height: ch,
                                    background: "#ff4444",
                                    borderRadius: "2px 2px 0 0",
                                  }}
                                />
                              )}
                              {rh > 0 && (
                                <div
                                  style={{
                                    height: rh,
                                    background: "#34d399",
                                    opacity: 0.4,
                                  }}
                                />
                              )}
                              {h - ch - rh > 0 && (
                                <div
                                  style={{
                                    height: h - ch - rh,
                                    background: "#f5a623",
                                    opacity: 0.3,
                                  }}
                                />
                              )}
                            </div>
                            <span
                              style={{
                                fontSize: 8,
                                color: "var(--text-muted)",
                                fontFamily: "var(--font-mono)",
                              }}
                            >
                              {d._id.slice(5)}
                            </span>
                          </div>
                        );
                      })}
                    </div>
                  </div>

                  <div
                    className="card p-5"
                    style={{ background: "var(--bg-card)" }}
                  >
                    <div className="flex items-center gap-2 mb-4">
                      <Shield
                        className="size-4"
                        style={{ color: "var(--accent)" }}
                      />
                      <span
                        className="text-sm font-semibold"
                        style={{ color: "var(--text-primary)" }}
                      >
                        Severity Distribution (7d)
                      </span>
                    </div>
                    <div className="space-y-2">
                      {[5, 4, 3, 2, 1].map((sev) => {
                        const count = kpi.severityDist[sev] || 0;
                        const pct = Math.round((count / totalSeverity) * 100);
                        const color = SEV_COLORS[String(sev)];
                        return (
                          <div key={sev}>
                            <div className="flex items-center justify-between mb-1">
                              <div className="flex items-center gap-2">
                                <div
                                  className="w-2 h-2 rounded-full"
                                  style={{ background: color }}
                                />
                                <span
                                  className="text-xs"
                                  style={{ color: "var(--text-secondary)" }}
                                >
                                  {SEV_LABELS[String(sev)]}
                                </span>
                              </div>
                              <span
                                className="text-xs font-bold"
                                style={{
                                  color,
                                  fontFamily: "var(--font-mono)",
                                }}
                              >
                                {count} ({pct}%)
                              </span>
                            </div>
                            <div
                              className="h-1.5 rounded-full"
                              style={{ background: "var(--bg-border)" }}
                            >
                              <motion.div
                                className="h-full rounded-full"
                                initial={{ width: 0 }}
                                animate={{ width: `${pct}%` }}
                                transition={{ duration: 1, ease: "easeOut" }}
                                style={{ background: color }}
                              />
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                </div>

                <div
                  className="card p-5 mb-6"
                  style={{ background: "var(--bg-card)" }}
                >
                  <div className="flex items-center gap-2 mb-4">
                    <Zap className="size-4" style={{ color: "#f5a623" }} />
                    <span
                      className="text-sm font-semibold"
                      style={{ color: "var(--text-primary)" }}
                    >
                      Top Triggered Rules (7d)
                    </span>
                  </div>
                  <div className="space-y-2">
                    {kpi.topTechniques.map((t, i) => {
                      const max = kpi.topTechniques[0]?.count || 1;
                      return (
                        <div key={t.ruleId} className="flex items-center gap-3">
                          <span
                            className="text-xs w-4 text-center"
                            style={{
                              color: "var(--text-muted)",
                              fontFamily: "var(--font-mono)",
                            }}
                          >
                            {i + 1}
                          </span>
                          <span
                            className="text-xs w-20 font-bold"
                            style={{
                              color: "var(--accent-cyan)",
                              fontFamily: "var(--font-mono)",
                            }}
                          >
                            {t.ruleId}
                          </span>
                          <span
                            className="text-xs flex-1 truncate"
                            style={{ color: "var(--text-secondary)" }}
                          >
                            {t.ruleName}
                          </span>
                          <div
                            className="w-24 h-1.5 rounded-full"
                            style={{ background: "var(--bg-border)" }}
                          >
                            <div
                              className="h-full rounded-full"
                              style={{
                                width: `${(t.count / max) * 100}%`,
                                background: "#f5a623",
                              }}
                            />
                          </div>
                          <span
                            className="text-xs font-bold w-6 text-right"
                            style={{
                              color: "#f5a623",
                              fontFamily: "var(--font-mono)",
                            }}
                          >
                            {t.count}
                          </span>
                        </div>
                      );
                    })}
                  </div>
                </div>

                <motion.div
                  initial={{ opacity: 0, y: 16 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: 0.4 }}
                  className="card overflow-hidden"
                  style={{ background: "var(--bg-card)" }}
                >
                  <div
                    className="flex items-center gap-2 px-5 py-3 border-b"
                    style={{
                      borderColor: "var(--bg-border)",
                      background: "rgba(0,0,0,0.4)",
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
                      className="text-xs ml-1"
                      style={{
                        color: "var(--text-muted)",
                        fontFamily: "var(--font-mono)",
                      }}
                    >
                      rule_sandbox.sh — test events against all detection rules
                    </span>
                  </div>
                  <div className="p-5">
                    <div className="grid md:grid-cols-2 gap-5">
                      <div>
                        <div className="label-caps mb-2">Test Event JSON</div>
                        <textarea
                          value={testEvent}
                          onChange={(e) => setTestEvent(e.target.value)}
                          rows={12}
                          className="input-terminal w-full px-4 py-3 rounded-xl text-xs"
                          style={{
                            fontFamily: "var(--font-mono)",
                            resize: "vertical",
                          }}
                        />
                        <button
                          onClick={handleTestRule}
                          disabled={testing}
                          className="btn-primary w-full flex items-center justify-center gap-2 py-3 text-sm mt-3"
                        >
                          <Activity className="size-4" />{" "}
                          {testing ? "Testing..." : "Run Against All Rules"}
                        </button>
                      </div>
                      <div>
                        <div className="label-caps mb-2">
                          Rule Match Results
                        </div>
                        {testResult ? (
                          <div className="space-y-2">
                            {testResult.error ? (
                              <div
                                className="px-4 py-3 rounded-xl text-xs"
                                style={{
                                  background: "rgba(255,68,68,0.08)",
                                  border: "1px solid rgba(255,68,68,0.2)",
                                  color: "#ff4444",
                                  fontFamily: "var(--font-mono)",
                                }}
                              >
                                ⚠ {testResult.error}
                              </div>
                            ) : (
                              <>
                                <div
                                  className="px-4 py-3 rounded-xl flex items-center justify-between"
                                  style={{
                                    background:
                                      testResult.fired > 0
                                        ? "rgba(245,166,35,0.08)"
                                        : "rgba(52,211,153,0.06)",
                                    border: `1px solid ${testResult.fired > 0 ? "rgba(245,166,35,0.25)" : "rgba(52,211,153,0.2)"}`,
                                  }}
                                >
                                  <span
                                    className="text-xs font-bold"
                                    style={{
                                      color:
                                        testResult.fired > 0
                                          ? "#f5a623"
                                          : "var(--accent)",
                                      fontFamily: "var(--font-mono)",
                                    }}
                                  >
                                    {testResult.fired > 0
                                      ? `⚡ ${testResult.fired} rule(s) fired`
                                      : "✓ No rules triggered"}
                                  </span>
                                  <span
                                    className="text-xs"
                                    style={{
                                      color: "var(--text-muted)",
                                      fontFamily: "var(--font-mono)",
                                    }}
                                  >
                                    {testResult.ruleIds?.join(", ")}
                                  </span>
                                </div>
                                {testResult.matches?.map(
                                  (m: any, i: number) => (
                                    <div
                                      key={i}
                                      className="rounded-xl p-4"
                                      style={{
                                        background: "var(--bg-elevated)",
                                        border: "1px solid var(--bg-border)",
                                      }}
                                    >
                                      <div className="flex items-center gap-2 mb-2">
                                        <span
                                          className="text-xs font-bold"
                                          style={{
                                            color: "var(--accent-cyan)",
                                            fontFamily: "var(--font-mono)",
                                          }}
                                        >
                                          {m.ruleId}
                                        </span>
                                        <span
                                          className="text-xs px-2 py-0.5 rounded font-bold"
                                          style={{
                                            color:
                                              m.severity >= 5
                                                ? "#ff4444"
                                                : m.severity >= 4
                                                  ? "#f97316"
                                                  : "#f5a623",
                                            background: "rgba(0,0,0,0.3)",
                                            fontFamily: "var(--font-mono)",
                                          }}
                                        >
                                          {m.severityLabel}
                                        </span>
                                      </div>
                                      <p
                                        className="text-xs mb-1"
                                        style={{ color: "var(--text-primary)" }}
                                      >
                                        {m.ruleName}
                                      </p>
                                      <p
                                        className="text-xs"
                                        style={{ color: "var(--text-muted)" }}
                                      >
                                        {m.description}
                                      </p>
                                      {m.mitre && (
                                        <p
                                          className="text-xs mt-2 px-2 py-1 rounded"
                                          style={{
                                            color: "#a78bfa",
                                            background: "rgba(124,58,237,0.08)",
                                            fontFamily: "var(--font-mono)",
                                          }}
                                        >
                                          {m.mitre.technique}
                                        </p>
                                      )}
                                    </div>
                                  ),
                                )}
                              </>
                            )}
                          </div>
                        ) : (
                          <div
                            className="h-full min-h-48 flex items-center justify-center rounded-xl"
                            style={{
                              background: "var(--bg-elevated)",
                              border: "1px dashed var(--bg-border)",
                            }}
                          >
                            <p
                              className="text-xs"
                              style={{
                                color: "var(--text-muted)",
                                fontFamily: "var(--font-mono)",
                              }}
                            >
                              Paste an event JSON and click Run
                            </p>
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                </motion.div>
              </>
            ) : null}
          </>
        )}

        {activeTab === "baseline" && (
          <div className="space-y-4">
            <div className="grid md:grid-cols-2 gap-4">
              <div
                className="card p-5"
                style={{ background: "var(--bg-card)" }}
              >
                <div className="flex items-center gap-2 mb-3">
                  <Activity
                    className="size-4"
                    style={{ color: "var(--accent)" }}
                  />
                  <span
                    className="text-sm font-semibold"
                    style={{ color: "var(--text-primary)" }}
                  >
                    Correlation Engine
                  </span>
                </div>
                <p
                  className="text-xs mb-4"
                  style={{ color: "var(--text-muted)" }}
                >
                  Manually trigger the attack-chain correlation engine. Runs
                  automatically every 5 minutes.
                </p>
                <button
                  onClick={runCorrelation}
                  disabled={correlating}
                  className="btn-primary w-full flex items-center justify-center gap-2 py-3 text-sm"
                >
                  <Zap
                    className={`size-4 ${correlating ? "animate-pulse" : ""}`}
                  />{" "}
                  {correlating ? "Correlating..." : "Run Correlation Now"}
                </button>
                {correlateRes && (
                  <div
                    className="mt-3 px-4 py-3 rounded-xl"
                    style={{
                      background:
                        correlateRes.chains > 0
                          ? "rgba(248,113,113,0.07)"
                          : "rgba(52,211,153,0.07)",
                      border: `1px solid ${correlateRes.chains > 0 ? "rgba(248,113,113,0.25)" : "rgba(52,211,153,0.2)"}`,
                    }}
                  >
                    <p
                      className="text-xs font-bold"
                      style={{
                        color: correlateRes.chains > 0 ? "#f87171" : "#34d399",
                        fontFamily: "var(--font-mono)",
                      }}
                    >
                      {correlateRes.chains > 0
                        ? `🔗 ${correlateRes.chains} attack chain(s) detected`
                        : "✓ No new attack chains found"}
                    </p>
                    {correlateRes.message && (
                      <p
                        className="text-xs mt-1"
                        style={{ color: "var(--text-muted)" }}
                      >
                        {correlateRes.message}
                      </p>
                    )}
                  </div>
                )}
              </div>

              <div
                className="card p-5"
                style={{ background: "var(--bg-card)" }}
              >
                <div className="flex items-center gap-2 mb-3">
                  <AlertTriangle
                    className="size-4"
                    style={{ color: "#fbbf24" }}
                  />
                  <span
                    className="text-sm font-semibold"
                    style={{ color: "var(--text-primary)" }}
                  >
                    Anomaly Detection
                  </span>
                </div>
                <p
                  className="text-xs mb-4"
                  style={{ color: "var(--text-muted)" }}
                >
                  Check current traffic patterns against the established 7-day
                  behavioral baseline.
                </p>
                <button
                  onClick={runAnomalyCheck}
                  disabled={checkingAnomaly}
                  className="btn-ghost w-full flex items-center justify-center gap-2 py-3 text-sm"
                  style={{
                    color: "#fbbf24",
                    borderColor: "rgba(251,191,36,0.3)",
                  }}
                >
                  <AlertTriangle
                    className={`size-4 ${checkingAnomaly ? "animate-pulse" : ""}`}
                  />{" "}
                  {checkingAnomaly ? "Checking..." : "Check Anomalies Now"}
                </button>
                {anomalyCheck && (
                  <div
                    className="mt-3 px-4 py-3 rounded-xl"
                    style={{
                      background:
                        anomalyCheck.anomalies > 0
                          ? "rgba(251,191,36,0.07)"
                          : "rgba(52,211,153,0.07)",
                      border: `1px solid ${anomalyCheck.anomalies > 0 ? "rgba(251,191,36,0.25)" : "rgba(52,211,153,0.2)"}`,
                    }}
                  >
                    <p
                      className="text-xs font-bold"
                      style={{
                        color:
                          anomalyCheck.anomalies > 0 ? "#fbbf24" : "#34d399",
                        fontFamily: "var(--font-mono)",
                      }}
                    >
                      {anomalyCheck.anomalies > 0
                        ? `⚠ ${anomalyCheck.anomalies} anomaly(s) detected`
                        : "✓ Traffic within normal baseline"}
                    </p>
                  </div>
                )}
              </div>
            </div>

            <div className="card p-5" style={{ background: "var(--bg-card)" }}>
              <div className="flex items-center justify-between mb-4">
                <div className="flex items-center gap-2">
                  <Globe
                    className="size-4"
                    style={{ color: "var(--color-info)" }}
                  />
                  <span
                    className="text-sm font-semibold"
                    style={{ color: "var(--text-primary)" }}
                  >
                    Current vs Baseline
                  </span>
                </div>
                <button
                  onClick={fetchBaseline}
                  disabled={baselineLoad}
                  className="btn-ghost flex items-center gap-2 px-3.5 py-2 text-sm"
                >
                  <RefreshCw
                    className={`size-4 ${baselineLoad ? "animate-spin" : ""}`}
                  />{" "}
                  Refresh
                </button>
              </div>
              {baselineLoad ? (
                <div className="py-6 text-center">
                  <div
                    className="w-6 h-6 border-2 rounded-full animate-spin mx-auto"
                    style={{
                      borderColor: "var(--accent)",
                      borderTopColor: "transparent",
                    }}
                  />
                </div>
              ) : baseline ? (
                <div className="space-y-4">
                  <div className="flex items-center gap-3">
                    <div
                      className={`w-3 h-3 rounded-full ${baseline.healthy ? "safe-pulse" : "threat-pulse"}`}
                      style={{
                        background: baseline.healthy ? "#34d399" : "#f87171",
                      }}
                    />
                    <span
                      className="text-sm font-semibold"
                      style={{
                        color: baseline.healthy ? "#34d399" : "#f87171",
                      }}
                    >
                      {baseline.healthy
                        ? "Traffic within normal baseline"
                        : "⚠ Anomalous traffic detected"}
                    </span>
                  </div>
                  {baseline.baseline && baseline.current && (
                    <div className="grid md:grid-cols-2 gap-4">
                      {[
                        {
                          label: "Current Scans/Hour",
                          current: baseline.current.total,
                          base: baseline.baseline.avgScansPerHour,
                        },
                        {
                          label: "Current Phishing Rate",
                          current: `${Math.round((baseline.current.phishingRate || 0) * 100)}%`,
                          base: `${Math.round((baseline.baseline.avgPhishingRate || 0) * 100)}%`,
                        },
                      ].map((item) => (
                        <div
                          key={item.label}
                          className="rounded-xl p-4"
                          style={{
                            background: "var(--bg-elevated)",
                            border: "1px solid var(--bg-border)",
                          }}
                        >
                          <div className="label-caps mb-2">{item.label}</div>
                          <div className="flex items-center gap-4">
                            <div>
                              <div
                                className="text-xs"
                                style={{
                                  color: "var(--text-muted)",
                                  fontFamily: "var(--font-mono)",
                                }}
                              >
                                Now
                              </div>
                              <div
                                className="text-lg font-bold"
                                style={{
                                  color: "var(--accent)",
                                  fontFamily: "'Syne', sans-serif",
                                }}
                              >
                                {item.current}
                              </div>
                            </div>
                            <div>
                              <div
                                className="text-xs"
                                style={{
                                  color: "var(--text-muted)",
                                  fontFamily: "var(--font-mono)",
                                }}
                              >
                                7d Avg
                              </div>
                              <div
                                className="text-lg font-bold"
                                style={{
                                  color: "var(--text-secondary)",
                                  fontFamily: "'Syne', sans-serif",
                                }}
                              >
                                {item.base}
                              </div>
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              ) : (
                <p className="text-xs" style={{ color: "var(--text-muted)" }}>
                  Could not load baseline data.
                </p>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
