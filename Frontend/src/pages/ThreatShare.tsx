// FILE: src/pages/ThreatShare.tsx
// Cross-Organization Threat Sharing Dashboard — STIX 2.1

import { useEffect, useState, useCallback } from "react";
import { motion } from "motion/react";
import {
  Globe,
  RefreshCw,
  Download,
  Shield,
  Activity,
  Clock,
  CheckCircle,
  Share2,
  Plus,
} from "lucide-react";
import { API_BASE } from "../config";

interface FeedStats {
  total: number;
  last24h: number;
  last7d: number;
  highConf: number;
  topTechniques: { technique: string; count: number }[];
  topBrands: { brand: string; count: number }[];
  feedHealth: string;
  privacy: string;
  stixVersion: string;
  generatedAt: string;
}

interface FeedItem {
  indicatorHash: string;
  type: string;
  confidence: number;
  severity: number;
  technique: string | null;
  brand: string | null;
  reportCount: number;
  firstSeen: string;
  lastSeen: string;
}

const SEV_COLOR = (s: number) =>
  s >= 5 ? "#ff4444" : s >= 4 ? "#f97316" : s >= 3 ? "#f5a623" : "#00ff88";

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

export default function ThreatShare() {
  const [stats, setStats] = useState<FeedStats | null>(null);
  const [feed, setFeed] = useState<FeedItem[]>([]);
  const [checkVal, setCheckVal] = useState("");
  const [checkRes, setCheckRes] = useState<any | null>(null);
  const [checking, setChecking] = useState(false);
  const [contributeVal, setContributeVal] = useState("");
  const [contributeRes, setContributeRes] = useState<any | null>(null);
  const [contributing, setContributing] = useState(false);
  const [loading, setLoading] = useState(true);
  const [lastRefresh, setLastRefresh] = useState(new Date());

  const fetchData = useCallback(async () => {
    setLoading(true);
    try {
      const [statsRes, feedRes] = await Promise.all([
        fetch(`${API_BASE}/api/threatshare/stats`),
        fetch(`${API_BASE}/api/threatshare/feed?limit=50&severity=3`),
      ]);
      if (statsRes.ok) setStats(await statsRes.json());
      if (feedRes.ok) {
        const bundle = await feedRes.json();
        // Extract PhishNetra extension data from STIX bundle
        const items = (bundle.objects || []).map((obj: any) => ({
          indicatorHash: obj.extensions?.["x-phishnetra-v1"]?.indicator_hash,
          type: "url",
          confidence: obj.confidence,
          severity: obj.extensions?.["x-phishnetra-v1"]?.severity || 3,
          technique: obj.extensions?.["x-phishnetra-v1"]?.technique,
          brand: obj.extensions?.["x-phishnetra-v1"]?.brand,
          reportCount: obj.extensions?.["x-phishnetra-v1"]?.report_count || 1,
          firstSeen: obj.created,
          lastSeen: obj.modified,
        }));
        setFeed(items);
        setLastRefresh(new Date());
      }
    } catch {
      /* offline */
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  const handleCheck = async () => {
    if (!checkVal.trim()) return;
    setChecking(true);
    setCheckRes(null);
    try {
      const res = await fetch(`${API_BASE}/api/threatshare/check`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ value: checkVal }),
      });
      setCheckRes(await res.json());
    } catch {
      setCheckRes({ found: false, error: "Check failed" });
    } finally {
      setChecking(false);
    }
  };

  const handleContribute = async () => {
    if (!contributeVal.trim()) return;
    setContributing(true);
    setContributeRes(null);
    try {
      const res = await fetch(`${API_BASE}/api/threatshare/contribute`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          indicator: contributeVal.trim(),
          type: "url",
          confidence: 75,
        }),
      });
      const data = await res.json();
      setContributeRes(data);
      if (res.ok) {
        setContributeVal("");
        fetchData();
      }
    } catch {
      setContributeRes({ error: "Contribution failed" });
    } finally {
      setContributing(false);
    }
  };

  const handleExportSTIX = () => {
    window.open(`${API_BASE}/api/threatshare/export/stix`, "_blank");
  };

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
              <Globe className="size-3" /> THREAT SHARING
            </div>
            <h1
              className="text-4xl font-bold mb-1"
              style={{
                fontFamily: "'Syne', sans-serif",
                color: "var(--text-primary)",
              }}
            >
              Community Threat Feed
            </h1>
            <p
              className="text-sm"
              style={{
                color: "var(--text-muted)",
                fontFamily: "'JetBrains Mono', monospace",
              }}
            >
              STIX 2.1 · SHA-256 hashed indicators ·{" "}
              {lastRefresh.toLocaleTimeString()}
            </p>
            <p
              className="text-xs mt-1 px-3 py-1.5 rounded-lg inline-flex items-center gap-2"
              style={{
                color: "#00ff88",
                background: "rgba(0,255,136,0.06)",
                border: "1px solid rgba(0,255,136,0.15)",
                fontFamily: "'JetBrains Mono', monospace",
              }}
            >
              <CheckCircle className="size-3" />
              Privacy: Original URLs never stored or shared — SHA-256 hashes
              only
            </p>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={handleExportSTIX}
              className="btn-ghost flex items-center gap-2 px-4 py-2.5 text-sm"
              style={{
                color: "var(--accent-cyan)",
                borderColor: "rgba(0,212,255,0.3)",
              }}
            >
              <Download className="size-4" /> Export STIX
            </button>
            <button
              onClick={fetchData}
              disabled={loading}
              className="btn-ghost flex items-center gap-2 px-4 py-2.5 text-sm"
            >
              <RefreshCw
                className={`size-4 ${loading ? "animate-spin" : ""}`}
              />{" "}
              Refresh
            </button>
          </div>
        </motion.div>

        {/* Stats cards */}
        {stats && (
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
            {[
              {
                label: "Total Indicators",
                value: stats.total,
                color: "var(--accent-green)",
              },
              {
                label: "Last 24h",
                value: stats.last24h,
                color: "var(--accent-cyan)",
              },
              { label: "Last 7d", value: stats.last7d, color: "#a78bfa" },
              {
                label: "High Confidence",
                value: stats.highConf,
                color: "#f97316",
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
        )}

        <div className="grid md:grid-cols-2 gap-4 mb-6">
          {/* Top techniques */}
          {stats?.topTechniques && stats.topTechniques.length > 0 && (
            <div className="card p-5" style={{ background: "var(--bg-card)" }}>
              <div className="flex items-center gap-2 mb-4">
                <Activity
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
                  Top Techniques
                </span>
              </div>
              <div className="space-y-2">
                {stats.topTechniques.map((t) => {
                  const max = stats.topTechniques[0].count;
                  return (
                    <div key={t.technique} className="flex items-center gap-3">
                      <span
                        className="text-xs w-32 truncate capitalize"
                        style={{
                          color: "var(--text-secondary)",
                          fontFamily: "'JetBrains Mono', monospace",
                        }}
                      >
                        {t.technique?.replace(/_/g, " ")}
                      </span>
                      <div
                        className="flex-1 h-1.5 rounded-full"
                        style={{ background: "var(--bg-border)" }}
                      >
                        <div
                          className="h-full rounded-full"
                          style={{
                            width: `${(t.count / max) * 100}%`,
                            background: "var(--accent-green)",
                          }}
                        />
                      </div>
                      <span
                        className="text-xs w-8 text-right font-bold"
                        style={{
                          color: "var(--accent-green)",
                          fontFamily: "'JetBrains Mono', monospace",
                        }}
                      >
                        {t.count}
                      </span>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* Quick check */}
          <div className="card p-5" style={{ background: "var(--bg-card)" }}>
            <div className="flex items-center gap-2 mb-4">
              <Shield
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
                Community Check
              </span>
            </div>
            <p className="text-xs mb-3" style={{ color: "var(--text-muted)" }}>
              Check if a URL is already confirmed in the community threat
              database.
            </p>
            <div className="flex gap-2 mb-3">
              <input
                type="text"
                value={checkVal}
                onChange={(e) => setCheckVal(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && handleCheck()}
                placeholder="Enter URL to check..."
                className="input-terminal flex-1 px-3 py-2 rounded-lg text-xs"
                style={{ fontFamily: "'JetBrains Mono', monospace" }}
              />
              <button
                onClick={handleCheck}
                disabled={checking || !checkVal.trim()}
                className="btn-primary px-4 py-2 text-xs"
                style={{ fontFamily: "'Syne', sans-serif", fontWeight: 700 }}
              >
                {checking ? "..." : "Check"}
              </button>
            </div>
            {checkRes && (
              <div
                className="px-3 py-2.5 rounded-lg"
                style={{
                  background: checkRes.found
                    ? "rgba(255,68,68,0.08)"
                    : "rgba(0,255,136,0.06)",
                  border: `1px solid ${checkRes.found ? "rgba(255,68,68,0.25)" : "rgba(0,255,136,0.2)"}`,
                }}
              >
                {checkRes.found ? (
                  <div>
                    <p
                      className="text-xs font-bold mb-1"
                      style={{
                        color: "#ff4444",
                        fontFamily: "'JetBrains Mono', monospace",
                      }}
                    >
                      ✗ COMMUNITY CONFIRMED PHISHING
                    </p>
                    <div className="grid grid-cols-2 gap-1">
                      {[
                        {
                          label: "Confidence",
                          value: `${checkRes.confidence}%`,
                        },
                        { label: "Reports", value: checkRes.reportCount },
                        {
                          label: "Technique",
                          value: checkRes.technique?.replace(/_/g, " ") || "—",
                        },
                        {
                          label: "First Seen",
                          value: timeAgo(checkRes.firstSeen),
                        },
                      ].map(({ label, value }) => (
                        <div key={label}>
                          <span
                            className="text-xs"
                            style={{
                              color: "var(--text-muted)",
                              fontFamily: "'JetBrains Mono', monospace",
                            }}
                          >
                            {label}:{" "}
                          </span>
                          <span
                            className="text-xs font-bold"
                            style={{
                              color: "#ff4444",
                              fontFamily: "'JetBrains Mono', monospace",
                            }}
                          >
                            {value}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                ) : (
                  <p
                    className="text-xs"
                    style={{
                      color: "#00ff88",
                      fontFamily: "'JetBrains Mono', monospace",
                    }}
                  >
                    ✓ Not found in community database
                  </p>
                )}
              </div>
            )}
          </div>
        </div>

        {/* Contribute Indicator */}
        <motion.div
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.28 }}
          className="card p-5"
          style={{ background: "var(--bg-card)" }}
        >
          <div className="flex items-center gap-2 mb-4">
            <Plus className="size-4" style={{ color: "var(--accent)" }} />
            <span
              className="text-sm font-semibold"
              style={{
                color: "var(--text-primary)",
                fontFamily: "'Syne', sans-serif",
              }}
            >
              Contribute Indicator
            </span>
          </div>
          <p className="text-xs mb-3" style={{ color: "var(--text-muted)" }}>
            Share a confirmed phishing URL with the community. SHA-256 hashed —
            original URL never stored or transmitted.
          </p>
          <div className="flex gap-2 mb-3">
            <input
              type="text"
              value={contributeVal}
              onChange={(e) => setContributeVal(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && handleContribute()}
              placeholder="Enter confirmed phishing URL..."
              className="input-terminal flex-1 px-3 py-2 rounded-lg text-xs"
              style={{ fontFamily: "'JetBrains Mono', monospace" }}
            />
            <button
              onClick={handleContribute}
              disabled={contributing || !contributeVal.trim()}
              className="btn-primary px-4 py-2 text-xs"
              style={{ fontFamily: "'Syne', sans-serif", fontWeight: 700 }}
            >
              {contributing ? "..." : "Contribute"}
            </button>
          </div>
          {contributeRes && (
            <div
              className="px-3 py-2.5 rounded-lg"
              style={{
                background: contributeRes.error
                  ? "rgba(248,113,113,0.08)"
                  : "rgba(52,211,153,0.07)",
                border: `1px solid ${contributeRes.error ? "rgba(248,113,113,0.25)" : "rgba(52,211,153,0.2)"}`,
              }}
            >
              {contributeRes.error ? (
                <p
                  className="text-xs"
                  style={{
                    color: "#f87171",
                    fontFamily: "'JetBrains Mono', monospace",
                  }}
                >
                  ⚠ {contributeRes.error}
                </p>
              ) : (
                <div>
                  <p
                    className="text-xs font-bold mb-1"
                    style={{
                      color: "#34d399",
                      fontFamily: "'JetBrains Mono', monospace",
                    }}
                  >
                    ✓{" "}
                    {contributeRes.status === "updated"
                      ? "Indicator confidence boosted"
                      : "Indicator contributed"}
                  </p>
                  <p
                    className="text-xs"
                    style={{
                      color: "var(--text-muted)",
                      fontFamily: "'JetBrains Mono', monospace",
                    }}
                  >
                    {contributeRes.message} · Hash: {contributeRes.hash}
                  </p>
                </div>
              )}
            </div>
          )}
        </motion.div>

        {/* Live feed table */}
        <motion.div
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3 }}
          className="card overflow-hidden"
          style={{ background: "var(--bg-card)" }}
        >
          {/* Terminal bar */}
          <div
            className="flex items-center gap-2 px-5 py-3 border-b"
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
              className="text-xs ml-1"
              style={{
                color: "var(--text-muted)",
                fontFamily: "'JetBrains Mono', monospace",
              }}
            >
              stix_feed.json — {feed.length} indicators · SHA-256 hashed · STIX
              2.1
            </span>
            <div className="ml-auto flex items-center gap-1.5">
              <div
                className="w-1.5 h-1.5 rounded-full safe-pulse"
                style={{ background: "var(--accent-green)" }}
              />
              <span
                className="text-xs"
                style={{
                  color: "var(--accent-green)",
                  fontFamily: "'JetBrains Mono', monospace",
                }}
              >
                live
              </span>
            </div>
          </div>

          {feed.length === 0 ? (
            <div className="py-12 text-center">
              <Globe
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
                No community indicators yet — scan phishing URLs to populate the
                feed
              </p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full data-table">
                <thead>
                  <tr>
                    <th className="text-left">Indicator Hash</th>
                    <th className="text-left">Technique</th>
                    <th className="text-left">Brand</th>
                    <th className="text-left">Severity</th>
                    <th className="text-left">Confidence</th>
                    <th className="text-left hidden md:table-cell">Reports</th>
                    <th className="text-left hidden md:table-cell">
                      First Seen
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {feed.map((item, i) => (
                    <motion.tr
                      key={i}
                      initial={{ opacity: 0, y: 3 }}
                      animate={{ opacity: 1, y: 0 }}
                      transition={{ delay: Math.min(i * 0.02, 0.5) }}
                    >
                      <td>
                        <code
                          className="text-xs"
                          style={{
                            color: "var(--accent-cyan)",
                            fontFamily: "'JetBrains Mono', monospace",
                          }}
                        >
                          {item.indicatorHash?.slice(0, 16)}...
                        </code>
                      </td>
                      <td>
                        <span
                          className="text-xs capitalize"
                          style={{
                            color: "var(--text-secondary)",
                            fontFamily: "'JetBrains Mono', monospace",
                          }}
                        >
                          {item.technique?.replace(/_/g, " ") || "—"}
                        </span>
                      </td>
                      <td>
                        <span
                          className="text-xs capitalize"
                          style={{
                            color: item.brand ? "#f97316" : "var(--text-muted)",
                            fontFamily: "'JetBrains Mono', monospace",
                          }}
                        >
                          {item.brand || "—"}
                        </span>
                      </td>
                      <td>
                        <span
                          className="text-xs font-bold"
                          style={{
                            color: SEV_COLOR(item.severity),
                            fontFamily: "'JetBrains Mono', monospace",
                          }}
                        >
                          {item.severity}/5
                        </span>
                      </td>
                      <td>
                        <div className="flex items-center gap-2">
                          <div
                            className="w-12 h-1.5 rounded-full"
                            style={{ background: "var(--bg-border)" }}
                          >
                            <div
                              className="h-full rounded-full"
                              style={{
                                width: `${item.confidence}%`,
                                background: SEV_COLOR(item.severity),
                              }}
                            />
                          </div>
                          <span
                            className="text-xs"
                            style={{
                              color: SEV_COLOR(item.severity),
                              fontFamily: "'JetBrains Mono', monospace",
                            }}
                          >
                            {item.confidence}%
                          </span>
                        </div>
                      </td>
                      <td className="hidden md:table-cell">
                        <span
                          className="text-xs font-bold"
                          style={{
                            color:
                              item.reportCount > 1
                                ? "#f5a623"
                                : "var(--text-muted)",
                            fontFamily: "'JetBrains Mono', monospace",
                          }}
                        >
                          {item.reportCount}
                        </span>
                      </td>
                      <td className="hidden md:table-cell">
                        <span
                          className="text-xs"
                          style={{
                            color: "var(--text-muted)",
                            fontFamily: "'JetBrains Mono', monospace",
                          }}
                        >
                          {timeAgo(item.firstSeen)}
                        </span>
                      </td>
                    </motion.tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </motion.div>
      </div>
    </div>
  );
}
