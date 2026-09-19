// FILE: src/pages/AdversaryIntel.tsx
// Adversary Fingerprinting — SOC war room actor board

import { useEffect, useState, useCallback } from "react";
import { motion, AnimatePresence } from "motion/react";
import {
  Shield,
  RefreshCw,
  ChevronDown,
  ChevronUp,
  Activity,
  Clock,
  Globe,
  Terminal,
  TrendingUp,
  AlertTriangle,
  Target,
  Cpu,
} from "lucide-react";
import { API_BASE } from "../config";
import { useSocket } from "../hooks/useSocket";

interface ActorProfile {
  actorId: string;
  ip: string;
  threatClass: string;
  riskLevel: string;
  persistenceScore: number;
  totalScans: number;
  phishingCount: number;
  phishingRate: number;
  firstSeen: string;
  lastSeen: string;
  ttps: {
    primaryTechnique: string;
    allTechniques: { technique: string; count: number }[];
    targetedBrands: { brand: string; count: number }[];
    topBrandPairs: string[];
    campaigns: { fingerprint: string; count: number }[];
    attackVectors: { type: string; count: number }[];
    isBEC: boolean;
    isMultiPlatform: boolean;
  };
  schedule: {
    operatingHours: string;
    peakDay: string;
    activeDays: string[];
    hourDistribution: number[];
  } | null;
  infrastructure: {
    uniqueIPs: number;
    geoDistribution: { ip: string; country: string; city: string | null }[];
    preferredTLD: string;
    tldBreakdown: Record<string, number>;
    uniqueDomains: number;
    knownInfrastructure: { ip: string; provider: string }[];
  };
  domainRotation: {
    uniqueDomains: number;
    rotationEvery: string;
    recentDomains: string[];
  } | null;
  campaignHistory: {
    month: string;
    count: number;
    fingerprints: number;
    brands: string[];
  }[];
  nextCampaignPrediction: {
    expectedDate: string;
    daysFromNow: number;
    predictedTarget: string;
    predictedTechnique: string;
    confidence: number;
    operatingWindow: string;
    note: string;
  } | null;
}

const RISK_CFG: Record<string, { color: string; bg: string; border: string }> =
  {
    critical: {
      color: "#ff4444",
      bg: "rgba(255,68,68,0.08)",
      border: "rgba(255,68,68,0.3)",
    },
    high: {
      color: "#f97316",
      bg: "rgba(249,115,22,0.08)",
      border: "rgba(249,115,22,0.3)",
    },
    medium: {
      color: "#f5a623",
      bg: "rgba(245,166,35,0.08)",
      border: "rgba(245,166,35,0.3)",
    },
    low: {
      color: "#00ff88",
      bg: "rgba(0,255,136,0.06)",
      border: "rgba(0,255,136,0.2)",
    },
  };

function timeAgo(iso: string) {
  const diff = Date.now() - new Date(iso).getTime();
  const m = Math.floor(diff / 60000),
    h = Math.floor(m / 60),
    d = Math.floor(h / 24);
  if (d > 0) return `${d}d ago`;
  if (h > 0) return `${h}h ago`;
  if (m > 0) return `${m}m ago`;
  return "just now";
}

function HourHeatmap({ dist }: { dist: number[] }) {
  const max = Math.max(...dist, 1);
  return (
    <div className="flex items-end gap-0.5 h-8">
      {dist.map((v, h) => {
        const ht = Math.max((v / max) * 28, 1);
        const isNow = new Date().getHours() === h;
        const color =
          v >= max * 0.7
            ? "#ff4444"
            : v >= max * 0.4
              ? "#f5a623"
              : "var(--bg-border)";
        return (
          <div
            key={h}
            title={`${h}:00 — ${v} scans`}
            className="flex-1 rounded-t-sm"
            style={{
              height: ht,
              background: isNow ? "var(--accent-cyan)" : color,
            }}
          />
        );
      })}
    </div>
  );
}

export default function AdversaryIntel() {
  const [profiles, setProfiles] = useState<ActorProfile[]>([]);
  const [loading, setLoading] = useState(true);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [lastRefresh, setLastRefresh] = useState(new Date());

  const fetchProfiles = useCallback(async () => {
    setLoading(true);
    try {
      const res = await fetch(`${API_BASE}/api/scan/adversaries`);
      if (res.ok) {
        const data = await res.json();
        // Backend sends { actors, campaignSpikes } — not { profiles }
        setProfiles(data.actors || data.profiles || []);
        setLastRefresh(new Date());
      }
    } catch {
      /* offline */
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchProfiles();
  }, [fetchProfiles]);
  useSocket({ threat_detected: () => fetchProfiles() });

  const critCount = profiles.filter((p) => p.riskLevel === "critical").length;
  const highCount = profiles.filter((p) => p.riskLevel === "high").length;

  return (
    <div
      className="min-h-full py-10 px-6"
      style={{ background: "var(--bg-base)" }}
    >
      <div className="max-w-5xl mx-auto">
        {/* ── HEADER ── */}
        <motion.div
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          className="flex items-start justify-between mb-10 flex-wrap gap-4"
        >
          <div>
            <div className="tag-green inline-flex mb-4">
              <Shield className="size-3" /> ADVERSARY INTEL
            </div>
            <h1
              className="text-4xl font-bold mb-1"
              style={{
                fontFamily: "'Syne', sans-serif",
                color: "var(--text-primary)",
              }}
            >
              Threat Actor Intelligence
            </h1>
            <p
              className="text-sm flex items-center gap-3"
              style={{
                color: "var(--text-muted)",
                fontFamily: "'JetBrains Mono', monospace",
              }}
            >
              <Clock className="size-3" />
              {lastRefresh.toLocaleTimeString()} ·
              <span
                style={{
                  color: critCount > 0 ? "#ff4444" : "var(--text-muted)",
                }}
              >
                {critCount} critical actor{critCount !== 1 ? "s" : ""}
              </span>
            </p>
          </div>
          <button
            onClick={fetchProfiles}
            disabled={loading}
            className="btn-ghost flex items-center gap-2 px-4 py-2.5 text-sm"
          >
            <RefreshCw className={`size-4 ${loading ? "animate-spin" : ""}`} />
            Refresh
          </button>
        </motion.div>

        {/* ── SUMMARY CARDS ── */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
          {[
            {
              label: "Total Actors",
              value: profiles.length,
              color: "var(--accent-green)",
            },
            { label: "Critical", value: critCount, color: "#ff4444" },
            { label: "High Threat", value: highCount, color: "#f97316" },
            {
              label: "Active (24h)",
              value: profiles.filter(
                (p) => Date.now() - new Date(p.lastSeen).getTime() < 86400000,
              ).length,
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

        {/* ── ACTOR PROFILES ── */}
        {loading && profiles.length === 0 ? (
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
              Building adversary profiles...
            </p>
          </div>
        ) : profiles.length === 0 ? (
          <div
            className="card py-16 text-center"
            style={{ background: "var(--bg-card)" }}
          >
            <Shield
              className="size-10 mx-auto mb-3"
              style={{ color: "var(--text-muted)" }}
            />
            <p
              className="text-sm font-semibold mb-1"
              style={{
                color: "var(--text-secondary)",
                fontFamily: "'Syne', sans-serif",
              }}
            >
              No actor profiles yet
            </p>
            <p className="text-xs" style={{ color: "var(--text-muted)" }}>
              Need 3+ phishing scans from the same IP to generate an adversary
              profile
            </p>
          </div>
        ) : (
          <div className="space-y-4">
            {profiles.map((actor, i) => {
              const cfg = RISK_CFG[actor.riskLevel] || RISK_CFG.low;
              const isExpanded = expanded === actor.actorId;

              return (
                <motion.div
                  key={actor.actorId}
                  initial={{ opacity: 0, y: 8 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: i * 0.05 }}
                  className="card overflow-hidden"
                  style={{
                    background: "var(--bg-card)",
                    borderColor: cfg.border,
                    boxShadow: `0 0 30px ${cfg.color}06`,
                  }}
                >
                  {/* ── Actor header ── */}
                  <div
                    className="px-5 py-4 cursor-pointer"
                    onClick={() =>
                      setExpanded(isExpanded ? null : actor.actorId)
                    }
                  >
                    <div className="flex items-center gap-4 flex-wrap">
                      {/* Actor ID badge */}
                      <div className="flex-shrink-0">
                        <div
                          className="px-3 py-2 rounded-xl"
                          style={{
                            background: cfg.bg,
                            border: `1px solid ${cfg.border}`,
                          }}
                        >
                          <div
                            className="text-xs uppercase tracking-wider mb-0.5"
                            style={{
                              color: cfg.color,
                              fontFamily: "'JetBrains Mono', monospace",
                            }}
                          >
                            {actor.actorId}
                          </div>
                          <div
                            className="text-xs"
                            style={{
                              color: "var(--text-muted)",
                              fontFamily: "'JetBrains Mono', monospace",
                            }}
                          >
                            {actor.ip}
                          </div>
                        </div>
                      </div>

                      {/* Classification */}
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 mb-1 flex-wrap">
                          <span
                            className="text-sm font-bold"
                            style={{
                              color: cfg.color,
                              fontFamily: "'Syne', sans-serif",
                            }}
                          >
                            {actor.threatClass}
                          </span>
                          <span
                            className="text-xs px-2 py-0.5 rounded font-bold uppercase"
                            style={{
                              color: cfg.color,
                              background: cfg.bg,
                              border: `1px solid ${cfg.border}`,
                              fontFamily: "'JetBrains Mono', monospace",
                            }}
                          >
                            {actor.riskLevel}
                          </span>
                          {actor.ttps.isBEC && (
                            <span
                              className="text-xs px-2 py-0.5 rounded"
                              style={{
                                color: "#f97316",
                                background: "rgba(249,115,22,0.08)",
                                border: "1px solid rgba(249,115,22,0.2)",
                                fontFamily: "'JetBrains Mono', monospace",
                              }}
                            >
                              BEC
                            </span>
                          )}
                          {actor.ttps.isMultiPlatform && (
                            <span
                              className="text-xs px-2 py-0.5 rounded"
                              style={{
                                color: "var(--accent-cyan)",
                                background: "rgba(0,212,255,0.06)",
                                border: "1px solid rgba(0,212,255,0.2)",
                                fontFamily: "'JetBrains Mono', monospace",
                              }}
                            >
                              MULTI-BRAND
                            </span>
                          )}
                        </div>
                        <div
                          className="flex flex-wrap items-center gap-3 text-xs"
                          style={{
                            fontFamily: "'JetBrains Mono', monospace",
                            color: "var(--text-muted)",
                          }}
                        >
                          <span className="flex items-center gap-1">
                            <Activity className="size-3" />
                            {actor.phishingCount} phishing ({actor.phishingRate}
                            %)
                          </span>
                          <span className="flex items-center gap-1">
                            <Globe className="size-3" />
                            {actor.infrastructure.uniqueDomains} domains
                          </span>
                          {actor.schedule && (
                            <span className="flex items-center gap-1">
                              <Clock className="size-3" />
                              {actor.schedule.peakDay} ·{" "}
                              {actor.schedule.operatingHours}
                            </span>
                          )}
                          <span>
                            First: {timeAgo(actor.firstSeen)} · Last:{" "}
                            {timeAgo(actor.lastSeen)}
                          </span>
                        </div>
                      </div>

                      {/* Persistence score ring */}
                      <div className="flex-shrink-0 flex items-center gap-3">
                        <div className="text-center">
                          <div
                            className="text-2xl font-black"
                            style={{
                              color: cfg.color,
                              fontFamily: "'Syne', sans-serif",
                            }}
                          >
                            {actor.persistenceScore}
                          </div>
                          <div
                            className="text-xs"
                            style={{
                              color: "var(--text-muted)",
                              fontFamily: "'JetBrains Mono', monospace",
                            }}
                          >
                            score
                          </div>
                        </div>
                        {isExpanded ? (
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
                  </div>

                  {/* ── EXPANDED PROFILE ── */}
                  <AnimatePresence>
                    {isExpanded && (
                      <motion.div
                        initial={{ opacity: 0, height: 0 }}
                        animate={{ opacity: 1, height: "auto" }}
                        exit={{ opacity: 0, height: 0 }}
                        className="border-t"
                        style={{ borderColor: "var(--bg-border)" }}
                      >
                        <div className="p-5 grid md:grid-cols-2 gap-5">
                          {/* ── TTPs ── */}
                          <div className="space-y-4">
                            <div
                              className="text-xs font-bold uppercase tracking-widest"
                              style={{
                                color: cfg.color,
                                fontFamily: "'JetBrains Mono', monospace",
                              }}
                            >
                              Tactics · Techniques · Procedures
                            </div>

                            {/* Primary technique */}
                            <div
                              className="rounded-xl p-3"
                              style={{
                                background: cfg.bg,
                                border: `1px solid ${cfg.border}`,
                              }}
                            >
                              <div
                                className="text-xs mb-1"
                                style={{
                                  color: "var(--text-muted)",
                                  fontFamily: "'JetBrains Mono', monospace",
                                }}
                              >
                                PRIMARY TECHNIQUE
                              </div>
                              <div
                                className="text-sm font-bold capitalize"
                                style={{
                                  color: cfg.color,
                                  fontFamily: "'Syne', sans-serif",
                                }}
                              >
                                {actor.ttps.primaryTechnique.replace(/_/g, " ")}
                              </div>
                            </div>

                            {/* Targeted brands */}
                            {actor.ttps.targetedBrands.length > 0 && (
                              <div>
                                <div
                                  className="text-xs mb-2 uppercase tracking-widest"
                                  style={{
                                    color: "var(--text-muted)",
                                    fontFamily: "'JetBrains Mono', monospace",
                                  }}
                                >
                                  Known Targets (
                                  {actor.ttps.targetedBrands.length} brands)
                                </div>
                                <div className="space-y-1.5">
                                  {actor.ttps.targetedBrands
                                    .slice(0, 5)
                                    .map(({ brand, count }) => {
                                      const maxCount =
                                        actor.ttps.targetedBrands[0].count;
                                      return (
                                        <div
                                          key={brand}
                                          className="flex items-center gap-3"
                                        >
                                          <span
                                            className="text-xs w-20 capitalize truncate"
                                            style={{
                                              color: "var(--text-secondary)",
                                              fontFamily:
                                                "'JetBrains Mono', monospace",
                                            }}
                                          >
                                            {brand}
                                          </span>
                                          <div
                                            className="flex-1 h-1.5 rounded-full"
                                            style={{
                                              background: "var(--bg-border)",
                                            }}
                                          >
                                            <div
                                              className="h-full rounded-full"
                                              style={{
                                                width: `${(count / maxCount) * 100}%`,
                                                background: cfg.color,
                                              }}
                                            />
                                          </div>
                                          <span
                                            className="text-xs w-8 text-right"
                                            style={{
                                              color: cfg.color,
                                              fontFamily:
                                                "'JetBrains Mono', monospace",
                                            }}
                                          >
                                            {count}
                                          </span>
                                        </div>
                                      );
                                    })}
                                </div>
                              </div>
                            )}

                            {/* Attack vectors */}
                            {actor.ttps.attackVectors.length > 0 && (
                              <div>
                                <div
                                  className="text-xs mb-2 uppercase tracking-widest"
                                  style={{
                                    color: "var(--text-muted)",
                                    fontFamily: "'JetBrains Mono', monospace",
                                  }}
                                >
                                  Attack Vectors
                                </div>
                                <div className="flex flex-wrap gap-1.5">
                                  {actor.ttps.attackVectors.map(
                                    ({ type, count }) => (
                                      <span
                                        key={type}
                                        className="text-xs px-2 py-0.5 rounded capitalize"
                                        style={{
                                          color: "var(--accent-cyan)",
                                          background: "rgba(0,212,255,0.06)",
                                          border:
                                            "1px solid rgba(0,212,255,0.15)",
                                          fontFamily:
                                            "'JetBrains Mono', monospace",
                                        }}
                                      >
                                        {type.replace(/_/g, " ")} ×{count}
                                      </span>
                                    ),
                                  )}
                                </div>
                              </div>
                            )}
                          </div>

                          {/* ── Infrastructure + Schedule ── */}
                          <div className="space-y-4">
                            <div
                              className="text-xs font-bold uppercase tracking-widest"
                              style={{
                                color: cfg.color,
                                fontFamily: "'JetBrains Mono', monospace",
                              }}
                            >
                              Infrastructure · Behavioral Schedule
                            </div>

                            {/* Known infrastructure */}
                            <div
                              className="rounded-xl p-3"
                              style={{
                                background: "var(--bg-elevated)",
                                border: "1px solid var(--bg-border)",
                              }}
                            >
                              <div className="grid grid-cols-2 gap-3 mb-3">
                                {[
                                  {
                                    label: "Unique IPs",
                                    value: actor.infrastructure.uniqueIPs,
                                  },
                                  {
                                    label: "Domains",
                                    value: actor.infrastructure.uniqueDomains,
                                  },
                                  {
                                    label: "Preferred TLD",
                                    value:
                                      actor.infrastructure.preferredTLD || "—",
                                  },
                                  {
                                    label: "Campaigns",
                                    value: actor.ttps.campaigns.length,
                                  },
                                ].map(({ label, value }) => (
                                  <div key={label}>
                                    <div
                                      className="text-xs"
                                      style={{
                                        color: "var(--text-muted)",
                                        fontFamily:
                                          "'JetBrains Mono', monospace",
                                      }}
                                    >
                                      {label}
                                    </div>
                                    <div
                                      className="text-sm font-bold"
                                      style={{
                                        color: "var(--text-primary)",
                                        fontFamily: "'Syne', sans-serif",
                                      }}
                                    >
                                      {value}
                                    </div>
                                  </div>
                                ))}
                              </div>
                              {actor.infrastructure.knownInfrastructure.length >
                                0 && (
                                <div
                                  className="pt-2 border-t"
                                  style={{ borderColor: "var(--bg-border)" }}
                                >
                                  {actor.infrastructure.knownInfrastructure.map(
                                    (inf) => (
                                      <div
                                        key={inf.ip}
                                        className="text-xs"
                                        style={{
                                          color: "#f97316",
                                          fontFamily:
                                            "'JetBrains Mono', monospace",
                                        }}
                                      >
                                        ⚠ {inf.provider}
                                      </div>
                                    ),
                                  )}
                                </div>
                              )}
                            </div>

                            {/* Operating schedule heatmap */}
                            {actor.schedule && (
                              <div>
                                <div
                                  className="text-xs mb-2 uppercase tracking-widest"
                                  style={{
                                    color: "var(--text-muted)",
                                    fontFamily: "'JetBrains Mono', monospace",
                                  }}
                                >
                                  Hourly Activity (UTC) — Peak:{" "}
                                  {actor.schedule.peakDay}
                                </div>
                                <HourHeatmap
                                  dist={actor.schedule.hourDistribution}
                                />
                                <div
                                  className="flex justify-between text-xs mt-1"
                                  style={{
                                    color: "var(--text-muted)",
                                    fontFamily: "'JetBrains Mono', monospace",
                                  }}
                                >
                                  <span>00:00</span>
                                  <span>
                                    Active: {actor.schedule.operatingHours}
                                  </span>
                                  <span>23:00</span>
                                </div>
                              </div>
                            )}

                            {/* Domain rotation */}
                            {actor.domainRotation && (
                              <div
                                className="rounded-xl p-3"
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
                                  DOMAIN ROTATION SPEED
                                </div>
                                <div
                                  className="text-sm font-bold"
                                  style={{
                                    color: "#f97316",
                                    fontFamily: "'Syne', sans-serif",
                                  }}
                                >
                                  {actor.domainRotation.rotationEvery} per
                                  domain
                                </div>
                                <div
                                  className="text-xs mt-1"
                                  style={{
                                    color: "var(--text-muted)",
                                    fontFamily: "'JetBrains Mono', monospace",
                                  }}
                                >
                                  {actor.domainRotation.uniqueDomains} domains
                                  used
                                </div>
                              </div>
                            )}
                          </div>
                        </div>

                        {/* ── Campaign History ── */}
                        {actor.campaignHistory.length > 0 && (
                          <div className="px-5 pb-5">
                            <div
                              className="text-xs mb-3 uppercase tracking-widest"
                              style={{
                                color: "var(--text-muted)",
                                fontFamily: "'JetBrains Mono', monospace",
                              }}
                            >
                              Campaign History
                            </div>
                            <div className="space-y-2">
                              {actor.campaignHistory.map((c, ci) => (
                                <div
                                  key={c.month}
                                  className="flex items-center gap-4 py-2 border-b"
                                  style={{ borderColor: "rgba(30,39,54,0.5)" }}
                                >
                                  <span
                                    className="text-xs w-24 flex-shrink-0"
                                    style={{
                                      color: "var(--text-muted)",
                                      fontFamily: "'JetBrains Mono', monospace",
                                    }}
                                  >
                                    Campaign {ci + 1}
                                  </span>
                                  <span
                                    className="text-xs"
                                    style={{
                                      color: "var(--text-secondary)",
                                      fontFamily: "'JetBrains Mono', monospace",
                                    }}
                                  >
                                    {c.month}
                                  </span>
                                  <span
                                    className="text-xs font-bold"
                                    style={{
                                      color: cfg.color,
                                      fontFamily: "'JetBrains Mono', monospace",
                                    }}
                                  >
                                    {c.count} detections
                                  </span>
                                  {c.brands.length > 0 && (
                                    <span
                                      className="text-xs capitalize"
                                      style={{ color: "var(--text-muted)" }}
                                    >
                                      → {c.brands.join(", ")}
                                    </span>
                                  )}
                                  {ci === actor.campaignHistory.length - 1 && (
                                    <span
                                      className="text-xs px-2 py-0.5 rounded font-bold safe-pulse"
                                      style={{
                                        color: "#ff4444",
                                        background: "rgba(255,68,68,0.1)",
                                        border: "1px solid rgba(255,68,68,0.3)",
                                        fontFamily:
                                          "'JetBrains Mono', monospace",
                                      }}
                                    >
                                      ACTIVE
                                    </span>
                                  )}
                                </div>
                              ))}
                            </div>
                          </div>
                        )}

                        {/* ── Next Campaign Prediction ── */}
                        {actor.nextCampaignPrediction && (
                          <div
                            className="mx-5 mb-5 rounded-xl p-4"
                            style={{
                              background: "rgba(124,58,237,0.07)",
                              border: "1px solid rgba(124,58,237,0.25)",
                            }}
                          >
                            <div className="flex items-center gap-2 mb-3">
                              <Target
                                className="size-4"
                                style={{ color: "#a78bfa" }}
                              />
                              <span
                                className="text-sm font-bold"
                                style={{
                                  color: "#a78bfa",
                                  fontFamily: "'Syne', sans-serif",
                                }}
                              >
                                Next Campaign Prediction
                              </span>
                              <span
                                className="ml-auto text-xs px-2 py-0.5 rounded"
                                style={{
                                  color: "#a78bfa",
                                  background: "rgba(124,58,237,0.1)",
                                  fontFamily: "'JetBrains Mono', monospace",
                                }}
                              >
                                {actor.nextCampaignPrediction.confidence}%
                                confidence
                              </span>
                            </div>
                            <div className="grid md:grid-cols-3 gap-3">
                              {[
                                {
                                  label: "Expected",
                                  value:
                                    actor.nextCampaignPrediction.expectedDate,
                                  color: "#a78bfa",
                                },
                                {
                                  label: "Target",
                                  value:
                                    actor.nextCampaignPrediction
                                      .predictedTarget,
                                  color: "#ff4444",
                                },
                                {
                                  label: "Window",
                                  value:
                                    actor.nextCampaignPrediction
                                      .operatingWindow,
                                  color: "var(--accent-cyan)",
                                },
                              ].map(({ label, value, color }) => (
                                <div key={label}>
                                  <div
                                    className="text-xs mb-0.5"
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
                            <p
                              className="text-xs mt-3"
                              style={{
                                color: "var(--text-muted)",
                                fontFamily: "'JetBrains Mono', monospace",
                              }}
                            >
                              {actor.nextCampaignPrediction.note}
                            </p>
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
      </div>
    </div>
  );
}
