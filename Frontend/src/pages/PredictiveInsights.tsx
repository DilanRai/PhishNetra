// FILE: src/pages/PredictiveInsights.tsx

import { useEffect, useState, useCallback } from "react";
import { motion } from "motion/react";
import {
  TrendingUp,
  TrendingDown,
  Minus,
  Brain,
  Clock,
  Calendar,
  RefreshCw,
  AlertTriangle,
} from "lucide-react";
import { API_BASE } from "../config";

interface Insights {
  trend: "rising" | "falling" | "stable";
  trendSlope: number;
  r2: number;
  predictions: {
    hoursFromNow: number;
    label: string;
    predicted: number;
    confidence: number;
  }[];
  peakDay: { day: string; avgPhishing: number; rate: number };
  peakHour: { hour: number; label: string; avgPhishing: number };
  dowPattern: {
    day: string;
    avgTotal: number;
    avgPhishing: number;
    rate: number;
  }[];
  hourPattern: { hour: number; avgTotal: number; avgPhishing: number }[];
  spikeRisk: number;
  insight: string;
  dataPoints: number;
  insufficient?: boolean;
  reason?: string;
}

const TREND_ICON = {
  rising: TrendingUp,
  falling: TrendingDown,
  stable: Minus,
};
const TREND_COLOR = {
  rising: "#ff4444",
  falling: "#00ff88",
  stable: "#f5a623",
};

export default function PredictiveInsights() {
  const [insights, setInsights] = useState<Insights | null>(null);
  const [loading, setLoading] = useState(true);
  const [lastRefresh, setLastRefresh] = useState(new Date());
  const [forecast, setForecast] = useState<any | null>(null);

  const fetchInsights = useCallback(async () => {
    setLoading(true);
    try {
      const res = await fetch(`${API_BASE}/api/scan/predict`);
      if (res.ok) {
        setInsights(await res.json());
        setLastRefresh(new Date());
      }
    } catch {
      /* offline */
    } finally {
      setLoading(false);
    }
  }, []);

  const fetchForecast = useCallback(async () => {
    try {
      const res = await fetch(`${API_BASE}/api/scan/forecast`);
      if (res.ok) setForecast(await res.json());
    } catch {
      /* offline */
    }
  }, []);

  useEffect(() => {
    fetchInsights();
    fetchForecast();
  }, [fetchInsights, fetchForecast]);

  if (loading && !insights)
    return (
      <div
        className="min-h-full flex items-center justify-center"
        style={{ background: "var(--bg-base)" }}
      >
        <div className="text-center">
          <div
            className="w-10 h-10 border-2 rounded-full mx-auto mb-4 animate-spin"
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
            Running regression analysis...
          </p>
        </div>
      </div>
    );

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
          className="flex items-start justify-between mb-10 flex-wrap gap-4"
        >
          <div>
            <div className="tag-green inline-flex mb-4">
              <Brain className="size-3" /> PREDICTIVE ANALYSIS
            </div>
            <h1
              className="text-4xl font-bold mb-1"
              style={{
                fontFamily: "'Syne', sans-serif",
                color: "var(--text-primary)",
              }}
            >
              Threat Forecasting
            </h1>
            <p
              className="text-sm"
              style={{
                color: "var(--text-muted)",
                fontFamily: "'JetBrains Mono', monospace",
              }}
            >
              Linear regression on {insights?.dataPoints || 0} hourly data
              points · {lastRefresh.toLocaleTimeString()}
            </p>
          </div>
          <button
            onClick={fetchInsights}
            disabled={loading}
            className="btn-ghost flex items-center gap-2 px-4 py-2.5 text-sm"
          >
            <RefreshCw className={`size-4 ${loading ? "animate-spin" : ""}`} />{" "}
            Refresh
          </button>
        </motion.div>

        {/* Insufficient data */}
        {insights?.insufficient && (
          <div
            className="card p-8 text-center"
            style={{ background: "var(--bg-card)" }}
          >
            <Brain
              className="size-10 mx-auto mb-3"
              style={{ color: "var(--text-muted)" }}
            />
            <p
              className="text-sm font-semibold mb-2"
              style={{
                color: "var(--text-secondary)",
                fontFamily: "'Syne', sans-serif",
              }}
            >
              Not enough data yet
            </p>
            <p className="text-xs" style={{ color: "var(--text-muted)" }}>
              {insights.reason}
            </p>
          </div>
        )}

        {insights && !insights.insufficient && (
          <>
            {/* AI Insight banner */}
            {insights.insight && (
              <motion.div
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                className="mb-6 p-4 rounded-xl flex items-start gap-3"
                style={{
                  background: "rgba(124,58,237,0.07)",
                  border: "1px solid rgba(124,58,237,0.2)",
                }}
              >
                <span className="text-xl flex-shrink-0">🧠</span>
                <p
                  className="text-sm leading-relaxed"
                  style={{ color: "var(--text-secondary)" }}
                >
                  {insights.insight}
                </p>
              </motion.div>
            )}

            {/* Spike risk alert */}
            {insights.spikeRisk > 40 && (
              <motion.div
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                className="mb-6 p-4 rounded-xl flex items-center gap-3"
                style={{
                  background: "rgba(255,68,68,0.08)",
                  border: "2px solid rgba(255,68,68,0.3)",
                }}
              >
                <AlertTriangle
                  className="size-5 flex-shrink-0"
                  style={{ color: "#ff4444" }}
                />
                <div>
                  <p
                    className="text-sm font-bold"
                    style={{
                      color: "#ff4444",
                      fontFamily: "'Syne', sans-serif",
                    }}
                  >
                    Active Spike Detected — {insights.spikeRisk}% above baseline
                  </p>
                  <p
                    className="text-xs mt-0.5"
                    style={{ color: "var(--text-muted)" }}
                  >
                    Current hour phishing rate is significantly elevated
                  </p>
                </div>
              </motion.div>
            )}

            {/* Trend + Stats row */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
              {(() => {
                const TrendIcon = TREND_ICON[insights.trend];
                const trendColor = TREND_COLOR[insights.trend];
                return [
                  {
                    icon: TrendIcon,
                    label: "Trend",
                    value: insights.trend.toUpperCase(),
                    color: trendColor,
                  },
                  {
                    icon: Brain,
                    label: "Model Fit (R²)",
                    value: `${insights.r2}%`,
                    color: "#a78bfa",
                  },
                  {
                    icon: Calendar,
                    label: "Peak Day",
                    value: insights.peakDay.day,
                    color: "var(--accent-cyan)",
                  },
                  {
                    icon: Clock,
                    label: "Peak Hour",
                    value: insights.peakHour.label,
                    color: "#f5a623",
                  },
                ].map((c, i) => (
                  <motion.div
                    key={c.label}
                    initial={{ opacity: 0, y: 12 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: i * 0.07 }}
                    className="card p-5 text-center"
                    style={{ background: "var(--bg-card)" }}
                  >
                    <c.icon
                      className="size-5 mx-auto mb-2"
                      style={{ color: c.color }}
                    />
                    <div
                      className="text-xl font-bold"
                      style={{
                        color: c.color,
                        fontFamily: "'Syne', sans-serif",
                      }}
                    >
                      {c.value}
                    </div>
                    <div
                      className="text-xs mt-0.5 uppercase tracking-widest"
                      style={{
                        color: "var(--text-muted)",
                        fontFamily: "'JetBrains Mono', monospace",
                      }}
                    >
                      {c.label}
                    </div>
                  </motion.div>
                ));
              })()}
            </div>

            {/* Next 6 hours prediction */}
            <motion.div
              initial={{ opacity: 0, y: 12 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.3 }}
              className="card p-5 mb-6"
              style={{ background: "var(--bg-card)" }}
            >
              <div className="flex items-center gap-2 mb-5">
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
                  Phishing Forecast — Next 6 Hours
                </span>
                <span
                  className="ml-auto text-xs"
                  style={{
                    color: "var(--text-muted)",
                    fontFamily: "'JetBrains Mono', monospace",
                  }}
                >
                  R² = {insights.r2}% confidence
                </span>
              </div>
              <div className="grid grid-cols-6 gap-2">
                {insights.predictions.map((p, i) => {
                  const maxPred = Math.max(
                    ...insights.predictions.map((x) => x.predicted),
                    1,
                  );
                  const h = Math.max((p.predicted / maxPred) * 80, 4);
                  const color =
                    p.predicted >= 5
                      ? "#ff4444"
                      : p.predicted >= 2
                        ? "#f5a623"
                        : "#00ff88";
                  return (
                    <div key={i} className="flex flex-col items-center gap-2">
                      <div
                        className="text-xs font-bold"
                        style={{
                          color,
                          fontFamily: "'JetBrains Mono', monospace",
                        }}
                      >
                        {p.predicted}
                      </div>
                      <div
                        className="w-full flex flex-col justify-end"
                        style={{ height: 80 }}
                      >
                        <motion.div
                          className="w-full rounded-t-lg"
                          initial={{ height: 0 }}
                          animate={{ height: h }}
                          transition={{
                            duration: 0.8,
                            delay: i * 0.1,
                            ease: "easeOut",
                          }}
                          style={{
                            background: color,
                            opacity: 0.7,
                            boxShadow: `0 0 8px ${color}50`,
                          }}
                        />
                      </div>
                      <div className="text-center">
                        <div
                          className="text-xs"
                          style={{
                            color: "var(--text-secondary)",
                            fontFamily: "'JetBrains Mono', monospace",
                            fontSize: 9,
                          }}
                        >
                          {p.label}
                        </div>
                        <div
                          className="text-xs"
                          style={{ color: "var(--text-muted)", fontSize: 8 }}
                        >
                          +{p.hoursFromNow}h
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
              <p
                className="text-xs mt-4"
                style={{
                  color: "var(--text-muted)",
                  fontFamily: "'JetBrains Mono', monospace",
                }}
              >
                ↑ Predicted phishing detections per hour (linear regression
                model)
              </p>
            </motion.div>

            {/* Day of week heatmap */}
            <div className="grid md:grid-cols-2 gap-4">
              <motion.div
                initial={{ opacity: 0, y: 12 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.4 }}
                className="card p-5"
                style={{ background: "var(--bg-card)" }}
              >
                <div className="flex items-center gap-2 mb-4">
                  <Calendar
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
                    Day-of-Week Pattern
                  </span>
                </div>
                <div className="space-y-2">
                  {insights.dowPattern.map((d) => {
                    const maxRate = Math.max(
                      ...insights.dowPattern.map((x) => x.rate),
                      1,
                    );
                    const color =
                      d.rate >= 50
                        ? "#ff4444"
                        : d.rate >= 25
                          ? "#f5a623"
                          : "#00ff88";
                    const isToday =
                      new Date().toLocaleDateString("en-US", {
                        weekday: "long",
                      }) === d.day;
                    return (
                      <div key={d.day} className="flex items-center gap-3">
                        <span
                          className="text-xs w-24 flex-shrink-0"
                          style={{
                            color: isToday
                              ? "var(--accent-cyan)"
                              : "var(--text-secondary)",
                            fontFamily: "'JetBrains Mono', monospace",
                            fontWeight: isToday ? 700 : 400,
                          }}
                        >
                          {d.day.substring(0, 3)} {isToday ? "←" : ""}
                        </span>
                        <div
                          className="flex-1 h-2 rounded-full"
                          style={{ background: "var(--bg-border)" }}
                        >
                          <div
                            className="h-full rounded-full transition-all duration-1000"
                            style={{
                              width: `${(d.rate / maxRate) * 100}%`,
                              background: color,
                            }}
                          />
                        </div>
                        <span
                          className="text-xs w-10 text-right"
                          style={{
                            color,
                            fontFamily: "'JetBrains Mono', monospace",
                          }}
                        >
                          {d.rate}%
                        </span>
                      </div>
                    );
                  })}
                </div>
              </motion.div>

              {/* Hour-of-day bars */}
              <motion.div
                initial={{ opacity: 0, y: 12 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.45 }}
                className="card p-5"
                style={{ background: "var(--bg-card)" }}
              >
                <div className="flex items-center gap-2 mb-4">
                  <Clock className="size-4" style={{ color: "#f5a623" }} />
                  <span
                    className="text-sm font-semibold"
                    style={{
                      color: "var(--text-primary)",
                      fontFamily: "'Syne', sans-serif",
                    }}
                  >
                    Hour-of-Day Pattern (6am–11pm)
                  </span>
                </div>
                <div className="flex items-end gap-1 h-20">
                  {insights.hourPattern.map((h) => {
                    const max = Math.max(
                      ...insights.hourPattern.map((x) => x.avgPhishing),
                      1,
                    );
                    const ht = Math.max((h.avgPhishing / max) * 64, 2);
                    const isNow = new Date().getHours() === h.hour;
                    const color = isNow
                      ? "var(--accent-cyan)"
                      : h.avgPhishing >= max * 0.7
                        ? "#ff4444"
                        : "#f5a623";
                    return (
                      <div
                        key={h.hour}
                        className="flex-1 flex flex-col items-center gap-1"
                        title={`${h.hour}:00 — avg ${h.avgPhishing} phishing/hr`}
                      >
                        <div
                          className="w-full flex flex-col justify-end"
                          style={{ height: 64 }}
                        >
                          <div
                            style={{
                              height: ht,
                              background: color,
                              borderRadius: "2px 2px 0 0",
                              opacity: isNow ? 1 : 0.6,
                              boxShadow: isNow ? `0 0 8px ${color}` : "none",
                            }}
                          />
                        </div>
                        <span
                          style={{
                            fontSize: 7,
                            color: isNow
                              ? "var(--accent-cyan)"
                              : "var(--text-muted)",
                            fontFamily: "'JetBrains Mono', monospace",
                          }}
                        >
                          {h.hour}
                        </span>
                      </div>
                    );
                  })}
                </div>
                <p
                  className="text-xs mt-2"
                  style={{
                    color: "var(--text-muted)",
                    fontFamily: "'JetBrains Mono', monospace",
                  }}
                >
                  Cyan bar = current hour
                </p>
              </motion.div>
            </div>
          </>
        )}

        {/* ── CAMPAIGN FORECAST (/api/scan/forecast) ── */}
        {forecast && !forecast.error && (
          <motion.div
            initial={{ opacity: 0, y: 12 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.5 }}
            className="card p-5 mt-4"
            style={{
              background:
                "var(--bg-base)".replace("base", "card") || "var(--bg-card)",
            }}
          >
            <div className="flex items-center gap-2 mb-4">
              <Calendar className="size-4" style={{ color: "#a78bfa" }} />
              <span
                className="text-sm font-semibold"
                style={{
                  color: "var(--text-primary)",
                  fontFamily: "'Syne', sans-serif",
                }}
              >
                Campaign Forecast
              </span>
              {forecast.spikeRisk > 40 && (
                <span
                  className="text-[10px] px-2 py-0.5 rounded font-bold ml-auto"
                  style={{
                    color: "#ff4444",
                    background: "rgba(255,68,68,0.08)",
                    border: "1px solid rgba(255,68,68,0.25)",
                    fontFamily: "'JetBrains Mono', monospace",
                  }}
                >
                  ⚠ SPIKE RISK {forecast.spikeRisk}%
                </span>
              )}
            </div>

            {forecast.insight && (
              <div
                className="mb-4 p-3 rounded-xl"
                style={{
                  background: "rgba(124,58,237,0.07)",
                  border: "1px solid rgba(124,58,237,0.2)",
                }}
              >
                <p
                  className="text-xs leading-relaxed"
                  style={{ color: "var(--text-secondary)" }}
                >
                  🧠 {forecast.insight}
                </p>
              </div>
            )}

            <div className="grid grid-cols-2 md:grid-cols-3 gap-3 mb-4">
              {[
                {
                  label: "Trend",
                  value: forecast.trend?.toUpperCase() ?? "—",
                  color:
                    forecast.trend === "rising"
                      ? "#ff4444"
                      : forecast.trend === "falling"
                        ? "#34d399"
                        : "#f5a623",
                },
                {
                  label: "Model Fit R²",
                  value: forecast.r2 != null ? `${forecast.r2}%` : "—",
                  color: "#a78bfa",
                },
                {
                  label: "Peak Day",
                  value: forecast.peakDay?.day ?? "—",
                  color: "var(--accent-cyan)",
                },
                {
                  label: "Peak Hour",
                  value: forecast.peakHour?.label ?? "—",
                  color: "#f5a623",
                },
                {
                  label: "Active Campaigns",
                  value:
                    forecast.activeCampaigns ??
                    forecast.topCampaigns?.length ??
                    "—",
                  color: "#fb923c",
                },
                {
                  label: "Data Points",
                  value: forecast.dataPoints ?? "—",
                  color: "var(--text-muted)",
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
                    className="text-xs mb-1"
                    style={{
                      color: "var(--text-muted)",
                      fontFamily: "'JetBrains Mono', monospace",
                    }}
                  >
                    {c.label}
                  </div>
                  <div
                    className="text-sm font-bold"
                    style={{ color: c.color, fontFamily: "'Syne', sans-serif" }}
                  >
                    {String(c.value)}
                  </div>
                </div>
              ))}
            </div>

            {/* Next 6h predictions */}
            {forecast.predictions && forecast.predictions.length > 0 && (
              <div>
                <div className="label-caps mb-2">6-Hour Phishing Forecast</div>
                <div className="flex items-end gap-2 h-14">
                  {forecast.predictions.slice(0, 6).map((p: any, i: number) => {
                    const max = Math.max(
                      ...forecast.predictions.map((x: any) => x.predicted),
                      1,
                    );
                    const h = Math.max((p.predicted / max) * 48, 2);
                    const col =
                      p.predicted >= 5
                        ? "#f87171"
                        : p.predicted >= 2
                          ? "#fbbf24"
                          : "#34d399";
                    return (
                      <div
                        key={i}
                        className="flex-1 flex flex-col items-center gap-1"
                      >
                        <div
                          className="text-[9px] font-bold"
                          style={{
                            color: col,
                            fontFamily: "'JetBrains Mono', monospace",
                          }}
                        >
                          {p.predicted}
                        </div>
                        <div
                          style={{
                            height: h,
                            width: "100%",
                            background: col,
                            borderRadius: "2px 2px 0 0",
                            opacity: 0.7,
                          }}
                        />
                        <div
                          className="text-[8px] text-center"
                          style={{
                            color: "var(--text-muted)",
                            fontFamily: "'JetBrains Mono', monospace",
                          }}
                        >
                          {p.label || `+${p.hoursFromNow}h`}
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            )}

            {/* Top active campaigns */}
            {forecast.topCampaigns && forecast.topCampaigns.length > 0 && (
              <div
                className="mt-4 pt-4 border-t"
                style={{ borderColor: "var(--bg-border)" }}
              >
                <div className="label-caps mb-2">Top Active Campaigns</div>
                <div className="space-y-1.5">
                  {forecast.topCampaigns
                    .slice(0, 5)
                    .map((c: any, i: number) => (
                      <div
                        key={i}
                        className="flex items-center gap-3 px-3 py-2 rounded-lg"
                        style={{
                          background: "var(--bg-elevated)",
                          border: "1px solid var(--bg-border)",
                        }}
                      >
                        <span
                          className="text-xs font-bold"
                          style={{
                            color: "#a78bfa",
                            fontFamily: "'JetBrains Mono', monospace",
                          }}
                        >
                          #{c.fingerprint?.slice(0, 8)}
                        </span>
                        <div
                          className="flex-1 h-1.5 rounded-full"
                          style={{ background: "var(--bg-border)" }}
                        >
                          <div
                            className="h-full rounded-full"
                            style={{
                              width: `${Math.min((c.count / (forecast.topCampaigns[0]?.count || 1)) * 100, 100)}%`,
                              background: "#a78bfa",
                            }}
                          />
                        </div>
                        <span
                          className="text-xs font-bold"
                          style={{
                            color: "#a78bfa",
                            fontFamily: "'JetBrains Mono', monospace",
                          }}
                        >
                          {c.count}
                        </span>
                      </div>
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
