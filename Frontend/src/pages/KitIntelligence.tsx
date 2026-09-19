// FILE: src/pages/KitIntelligence.tsx
// Phishing Kit DNA Fingerprinting — SOC Intelligence Dashboard

import { useEffect, useState, useCallback } from "react";
import { motion, AnimatePresence } from "motion/react";
import {
  Fingerprint,
  RefreshCw,
  Shield,
  ChevronDown,
  ChevronUp,
  Activity,
  Clock,
  Target,
  AlertTriangle,
  Database,
} from "lucide-react";
import { API_BASE } from "../config";

interface KitStat {
  kitId: string;
  kitName: string;
  version: string;
  targetBrands: string[];
  sophistication: string;
  description: string;
  confidence: number;
  detections: number;
  firstSeen: string;
  lastSeen: string;
  sampleInputs: string[];
  matchedSignals: string[];
}

interface KitSignature {
  kitId: string;
  kitName: string;
  version: string;
  targetBrands: string[];
  sophistication: string;
  description: string;
}

const SOPH_CFG: Record<
  string,
  { color: string; bg: string; border: string; label: string }
> = {
  expert: {
    color: "#ff4444",
    bg: "rgba(255,68,68,0.08)",
    border: "rgba(255,68,68,0.3)",
    label: "EXPERT",
  },
  high: {
    color: "#f97316",
    bg: "rgba(249,115,22,0.08)",
    border: "rgba(249,115,22,0.3)",
    label: "HIGH",
  },
  medium: {
    color: "#f5a623",
    bg: "rgba(245,166,35,0.07)",
    border: "rgba(245,166,35,0.25)",
    label: "MEDIUM",
  },
  low: {
    color: "#00ff88",
    bg: "rgba(0,255,136,0.06)",
    border: "rgba(0,255,136,0.2)",
    label: "LOW",
  },
};

const MITRE_LABEL: Record<string, string> = {
  expert: "T1557 — Adversary-in-the-Middle",
  high: "T1566.002 — Spearphishing Link",
  medium: "T1566.002 — Spearphishing Link",
  low: "T1566 — Phishing",
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

function isActive(lastSeen: string) {
  return Date.now() - new Date(lastSeen).getTime() < 24 * 60 * 60 * 1000;
}

// ── Active kit cards ──────────────────────────────────────────────
function ActiveKitCard({
  kit,
  expanded,
  onToggle,
}: {
  kit: KitStat;
  expanded: boolean;
  onToggle: () => void;
}) {
  const cfg = SOPH_CFG[kit.sophistication] || SOPH_CFG.low;
  const active = isActive(kit.lastSeen);

  return (
    <motion.div
      className="card overflow-hidden"
      style={{
        background: "var(--bg-card)",
        borderColor: cfg.border,
        boxShadow: `0 0 20px ${cfg.color}06`,
      }}
    >
      {/* Header row */}
      <div
        className="px-5 py-4 cursor-pointer flex items-center gap-4 flex-wrap"
        onClick={onToggle}
      >
        {/* Status + kit ID */}
        <div className="flex flex-col items-center gap-1 flex-shrink-0">
          <div
            className={`w-2.5 h-2.5 rounded-full ${active ? "threat-pulse" : ""}`}
            style={{ background: active ? cfg.color : "var(--bg-border)" }}
          />
          <span
            style={{
              fontSize: 8,
              color: active ? cfg.color : "var(--text-muted)",
              fontFamily: "'JetBrains Mono', monospace",
            }}
          >
            {active ? "LIVE" : "COLD"}
          </span>
        </div>

        {/* Kit badge */}
        <div
          className="px-3 py-2 rounded-xl flex-shrink-0"
          style={{ background: cfg.bg, border: `1px solid ${cfg.border}` }}
        >
          <div
            className="text-xs font-bold"
            style={{
              color: cfg.color,
              fontFamily: "'JetBrains Mono', monospace",
            }}
          >
            {kit.kitId}
          </div>
          <div
            className="text-xs mt-0.5"
            style={{
              color: "var(--text-muted)",
              fontFamily: "'JetBrains Mono', monospace",
            }}
          >
            {kit.version}
          </div>
        </div>

        {/* Name + meta */}
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1 flex-wrap">
            <span
              className="text-sm font-bold"
              style={{
                color: "var(--text-primary)",
                fontFamily: "'Syne', sans-serif",
              }}
            >
              {kit.kitName}
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
              {cfg.label}
            </span>
          </div>
          <div
            className="flex flex-wrap items-center gap-3 text-xs"
            style={{
              fontFamily: "'JetBrains Mono', monospace",
              color: "var(--text-muted)",
            }}
          >
            <span className="flex items-center gap-1">
              <Activity className="size-3" /> {kit.detections} detections
            </span>
            <span className="flex items-center gap-1">
              <Clock className="size-3" /> Last: {timeAgo(kit.lastSeen)}
            </span>
            <span className="flex items-center gap-1">
              <Target className="size-3" />
              {kit.targetBrands.slice(0, 3).join(", ")}
              {kit.targetBrands.length > 3
                ? ` +${kit.targetBrands.length - 3}`
                : ""}
            </span>
          </div>
        </div>

        {/* Detection count */}
        <div className="flex items-center gap-3 flex-shrink-0">
          <div className="text-center">
            <div
              className="text-2xl font-black"
              style={{ color: cfg.color, fontFamily: "'Syne', sans-serif" }}
            >
              {kit.detections}
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
          {expanded ? (
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
        {expanded && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: "auto" }}
            exit={{ opacity: 0, height: 0 }}
            className="border-t"
            style={{ borderColor: "var(--bg-border)" }}
          >
            <div className="p-5 grid md:grid-cols-2 gap-5">
              {/* Left: Description + MITRE */}
              <div className="space-y-3">
                <div
                  className="text-xs uppercase tracking-widest"
                  style={{
                    color: cfg.color,
                    fontFamily: "'JetBrains Mono', monospace",
                  }}
                >
                  Kit Intelligence
                </div>
                <p
                  className="text-sm leading-relaxed"
                  style={{ color: "var(--text-secondary)" }}
                >
                  {kit.description}
                </p>
                <div
                  className="rounded-xl p-3"
                  style={{
                    background: "rgba(124,58,237,0.07)",
                    border: "1px solid rgba(124,58,237,0.18)",
                  }}
                >
                  <div
                    className="text-xs mb-1"
                    style={{
                      color: "var(--text-muted)",
                      fontFamily: "'JetBrains Mono', monospace",
                    }}
                  >
                    MITRE ATT&CK
                  </div>
                  <div
                    className="text-xs font-bold"
                    style={{
                      color: "#a78bfa",
                      fontFamily: "'JetBrains Mono', monospace",
                    }}
                  >
                    {MITRE_LABEL[kit.sophistication] || MITRE_LABEL.low}
                  </div>
                </div>

                {/* Matched signals */}
                {kit.matchedSignals?.length > 0 && (
                  <div>
                    <div
                      className="text-xs mb-2 uppercase tracking-widest"
                      style={{
                        color: "var(--text-muted)",
                        fontFamily: "'JetBrains Mono', monospace",
                      }}
                    >
                      Matched Signal Types
                    </div>
                    <div className="flex flex-wrap gap-1.5">
                      {[...new Set(kit.matchedSignals)].map((sig) => (
                        <span
                          key={sig}
                          className="text-xs px-2 py-0.5 rounded"
                          style={{
                            color: "var(--accent-cyan)",
                            background: "rgba(0,212,255,0.06)",
                            border: "1px solid rgba(0,212,255,0.15)",
                            fontFamily: "'JetBrains Mono', monospace",
                          }}
                        >
                          {sig.replace(/_/g, " ")}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </div>

              {/* Right: Stats + sample URLs */}
              <div className="space-y-3">
                <div
                  className="text-xs uppercase tracking-widest"
                  style={{
                    color: cfg.color,
                    fontFamily: "'JetBrains Mono', monospace",
                  }}
                >
                  Detection Stats
                </div>

                {/* Stats grid */}
                <div className="grid grid-cols-2 gap-2">
                  {[
                    { label: "Confidence", value: `${kit.confidence}%` },
                    { label: "First Seen", value: timeAgo(kit.firstSeen) },
                    { label: "Last Seen", value: timeAgo(kit.lastSeen) },
                    { label: "Detections", value: kit.detections },
                  ].map(({ label, value }) => (
                    <div
                      key={label}
                      className="rounded-lg p-2.5"
                      style={{
                        background: "var(--bg-elevated)",
                        border: "1px solid var(--bg-border)",
                      }}
                    >
                      <div
                        className="text-xs"
                        style={{
                          color: "var(--text-muted)",
                          fontFamily: "'JetBrains Mono', monospace",
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

                {/* Target brands */}
                <div>
                  <div
                    className="text-xs mb-2 uppercase tracking-widest"
                    style={{
                      color: "var(--text-muted)",
                      fontFamily: "'JetBrains Mono', monospace",
                    }}
                  >
                    Known Target Brands
                  </div>
                  <div className="flex flex-wrap gap-1.5">
                    {kit.targetBrands.map((b) => (
                      <span
                        key={b}
                        className="text-xs px-2 py-0.5 rounded capitalize"
                        style={{
                          color: "#f97316",
                          background: "rgba(249,115,22,0.08)",
                          border: "1px solid rgba(249,115,22,0.2)",
                          fontFamily: "'JetBrains Mono', monospace",
                        }}
                      >
                        {b}
                      </span>
                    ))}
                  </div>
                </div>

                {/* Sample detection patterns (domain only — not full URL) */}
                {kit.sampleInputs?.length > 0 && (
                  <div>
                    <div
                      className="text-xs mb-2 uppercase tracking-widest"
                      style={{
                        color: "var(--text-muted)",
                        fontFamily: "'JetBrains Mono', monospace",
                      }}
                    >
                      Sample Detection Patterns
                    </div>
                    <div className="space-y-1">
                      {kit.sampleInputs.map((s, si) => {
                        // Only show domain part for privacy / safety
                        let display = s;
                        try {
                          const u = new URL(
                            s.startsWith("http") ? s : `https://${s}`,
                          );
                          display = u.hostname;
                        } catch {}
                        return (
                          <div
                            key={si}
                            className="text-xs px-2 py-1 rounded"
                            style={{
                              color: "var(--accent-cyan)",
                              background: "rgba(0,212,255,0.04)",
                              border: "1px solid rgba(0,212,255,0.1)",
                              fontFamily: "'JetBrains Mono', monospace",
                            }}
                          >
                            {display}
                          </div>
                        );
                      })}
                    </div>
                  </div>
                )}
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
}

// ── Signature DB row ─────────────────────────────────────────────
function SignatureRow({ sig }: { sig: KitSignature }) {
  const cfg = SOPH_CFG[sig.sophistication] || SOPH_CFG.low;
  return (
    <div
      className="px-5 py-3 flex items-center gap-4 border-b"
      style={{ borderColor: "rgba(30,39,54,0.5)" }}
    >
      <span
        className="text-xs w-36 flex-shrink-0"
        style={{ color: cfg.color, fontFamily: "'JetBrains Mono', monospace" }}
      >
        {sig.kitId}
      </span>
      <span
        className="text-sm font-medium flex-1"
        style={{ color: "var(--text-primary)" }}
      >
        {sig.kitName}
        <span
          className="ml-2 text-xs"
          style={{
            color: "var(--text-muted)",
            fontFamily: "'JetBrains Mono', monospace",
          }}
        >
          {sig.version}
        </span>
      </span>
      <span
        className="text-xs px-2 py-0.5 rounded font-bold uppercase flex-shrink-0"
        style={{
          color: cfg.color,
          background: cfg.bg,
          border: `1px solid ${cfg.border}`,
          fontFamily: "'JetBrains Mono', monospace",
        }}
      >
        {cfg.label}
      </span>
      <div className="flex flex-wrap gap-1 max-w-48 justify-end flex-shrink-0">
        {sig.targetBrands.slice(0, 3).map((b) => (
          <span
            key={b}
            className="text-xs capitalize"
            style={{
              color: "var(--text-muted)",
              fontFamily: "'JetBrains Mono', monospace",
            }}
          >
            {b}
          </span>
        ))}
        {sig.targetBrands.length > 3 && (
          <span
            className="text-xs"
            style={{
              color: "var(--text-muted)",
              fontFamily: "'JetBrains Mono', monospace",
            }}
          >
            +{sig.targetBrands.length - 3}
          </span>
        )}
      </div>
    </div>
  );
}

// ── Main Page ────────────────────────────────────────────────────
export default function KitIntelligence() {
  const [activeTab, setActiveTab] = useState<"active" | "database">("active");
  const [kits, setKits] = useState<KitStat[]>([]);
  const [signatures, setSignatures] = useState<KitSignature[]>([]);
  const [loading, setLoading] = useState(true);
  const [sigLoading, setSigLoading] = useState(false);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [filterSoph, setFilterSoph] = useState<string>("all");
  const [lastRefresh, setLastRefresh] = useState(new Date());
  const [kitPage, setKitPage] = useState(1);
  const [kitTotal, setKitTotal] = useState(0);
  const [kitPages, setKitPages] = useState(1);
  const [analyzeUrl, setAnalyzeUrl] = useState("");
  const [analyzeResult, setAnalyzeResult] = useState<any | null>(null);
  const [analyzing, setAnalyzing] = useState(false);

  const fetchKits = useCallback(async () => {
    setLoading(true);
    try {
      const res = await fetch(`${API_BASE}/api/scan/kits`);
      if (res.ok) {
        const data = await res.json();
        setKits(data.kits || []);
        setLastRefresh(new Date());
      }
    } catch {
      /* offline */
    } finally {
      setLoading(false);
    }
  }, []);

  const fetchSignatures = useCallback(async () => {
    if (signatures.length > 0) return; // already loaded
    setSigLoading(true);
    try {
      const res = await fetch(`${API_BASE}/api/scan/kits/signatures`);
      if (res.ok) {
        const data = await res.json();
        setSignatures(data.signatures || []);
      }
    } catch {
      /* offline */
    } finally {
      setSigLoading(false);
    }
  }, [signatures.length]);

  // Paginated kits (for large datasets)
  const fetchKitsPaged = useCallback(async (page = 1) => {
    try {
      const res = await fetch(
        `${API_BASE}/api/scan/kits/paged?page=${page}&limit=20&days=30`,
      );
      if (res.ok) {
        const data = await res.json();
        if (data.kits?.length > 0) {
          setKits(data.kits);
          setKitPage(data.page || 1);
          setKitTotal(data.total || 0);
          setKitPages(data.pages || 1);
          setLastRefresh(new Date());
        }
      }
    } catch {
      /* offline — fall back to /kits */
    }
  }, []);

  // Kit URL analyzer
  const analyzeKitUrl = async () => {
    if (!analyzeUrl.trim()) return;
    setAnalyzing(true);
    setAnalyzeResult(null);
    try {
      const res = await fetch(`${API_BASE}/api/scan/kits/analyze`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${localStorage.getItem("pg_token")}`,
        },
        body: JSON.stringify({ url: analyzeUrl.trim() }),
      });
      if (res.ok) setAnalyzeResult(await res.json());
      else setAnalyzeResult({ error: "Analysis failed" });
    } catch {
      setAnalyzeResult({ error: "Network error" });
    } finally {
      setAnalyzing(false);
    }
  };

  useEffect(() => {
    fetchKits();
    fetchKitsPaged(1);
  }, [fetchKits, fetchKitsPaged]);

  useEffect(() => {
    if (activeTab === "database") fetchSignatures();
  }, [activeTab, fetchSignatures]);

  const filtered =
    filterSoph === "all"
      ? kits
      : kits.filter((k) => k.sophistication === filterSoph);

  const expertCount = kits.filter((k) => k.sophistication === "expert").length;
  const highCount = kits.filter((k) => k.sophistication === "high").length;
  const activeCount = kits.filter((k) => isActive(k.lastSeen)).length;
  const totalHits = kits.reduce((s, k) => s + k.detections, 0);

  return (
    <div
      className="min-h-full py-10 px-6"
      style={{ background: "var(--bg-base)" }}
    >
      <div className="max-w-5xl mx-auto">
        {/* ── Header ── */}
        <motion.div
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          className="flex items-start justify-between mb-10 flex-wrap gap-4"
        >
          <div>
            <div className="tag-green inline-flex mb-4">
              <Fingerprint className="size-3" /> KIT INTELLIGENCE
            </div>
            <h1
              className="text-4xl font-bold mb-1"
              style={{
                fontFamily: "'Syne', sans-serif",
                color: "var(--text-primary)",
              }}
            >
              Phishing Kit DNA
            </h1>
            <p
              className="text-sm"
              style={{
                color: "var(--text-muted)",
                fontFamily: "'JetBrains Mono', monospace",
              }}
            >
              Passive kit identification · {signatures.length || "15"}{" "}
              signatures · {lastRefresh.toLocaleTimeString()}
            </p>
          </div>
          <button
            onClick={fetchKits}
            disabled={loading}
            className="btn-ghost flex items-center gap-2 px-4 py-2.5 text-sm"
          >
            <RefreshCw className={`size-4 ${loading ? "animate-spin" : ""}`} />
            Refresh
          </button>
        </motion.div>

        {/* ── Summary cards ── */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
          {[
            {
              label: "Kits Detected",
              value: kits.length,
              color: "var(--accent-green)",
            },
            { label: "Expert (AiTM)", value: expertCount, color: "#ff4444" },
            { label: "Active (24h)", value: activeCount, color: "#f5a623" },
            {
              label: "Total Hit",
              value: totalHits,
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

        {/* ── Tab selector ── */}
        <div className="flex items-center gap-2 mb-6">
          {[
            { key: "active", label: "Active Detections", icon: AlertTriangle },
            { key: "database", label: "Signature Database", icon: Database },
          ].map(({ key, label, icon: Icon }) => (
            <button
              key={key}
              onClick={() => setActiveTab(key as "active" | "database")}
              className="flex items-center gap-2 px-5 py-2.5 rounded-xl text-sm font-medium transition-all"
              style={{
                fontFamily: "'DM Sans', sans-serif",
                background:
                  activeTab === key ? "rgba(0,255,136,0.08)" : "var(--bg-card)",
                border: `1px solid ${activeTab === key ? "rgba(0,255,136,0.3)" : "var(--bg-border)"}`,
                color:
                  activeTab === key
                    ? "var(--accent-green)"
                    : "var(--text-secondary)",
                fontWeight: activeTab === key ? 700 : 400,
              }}
            >
              <Icon className="size-4" /> {label}
            </button>
          ))}
        </div>

        {/* ── Active Detections tab ── */}
        {activeTab === "active" && (
          <>
            {/* Sophistication filter */}
            <div className="flex items-center gap-2 mb-4 flex-wrap">
              {["all", "expert", "high", "medium", "low"].map((f) => {
                const cfg = SOPH_CFG[f];
                return (
                  <button
                    key={f}
                    onClick={() => setFilterSoph(f)}
                    className="text-xs px-3 py-1.5 rounded-lg transition-all capitalize"
                    style={{
                      fontFamily: "'JetBrains Mono', monospace",
                      background:
                        filterSoph === f
                          ? cfg?.color || "var(--accent-green)"
                          : "var(--bg-card)",
                      color: filterSoph === f ? "#080b10" : "var(--text-muted)",
                      border: `1px solid ${filterSoph === f ? cfg?.color || "var(--accent-green)" : "var(--bg-border)"}`,
                      fontWeight: filterSoph === f ? 700 : 400,
                    }}
                  >
                    {f === "all" ? "All Sophistication" : cfg?.label}
                  </button>
                );
              })}
            </div>

            {loading && kits.length === 0 ? (
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
                  Analyzing kit signatures...
                </p>
              </div>
            ) : filtered.length === 0 ? (
              <div
                className="card py-16 text-center"
                style={{ background: "var(--bg-card)" }}
              >
                <Fingerprint
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
                  No kit detections yet
                </p>
                <p className="text-xs" style={{ color: "var(--text-muted)" }}>
                  Scan phishing URLs to build a kit detection database
                </p>
              </div>
            ) : (
              <div className="space-y-3">
                {filtered.map((kit, i) => (
                  <motion.div
                    key={kit.kitId}
                    initial={{ opacity: 0, y: 8 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: i * 0.04 }}
                  >
                    <ActiveKitCard
                      kit={kit}
                      expanded={expanded === kit.kitId}
                      onToggle={() =>
                        setExpanded(expanded === kit.kitId ? null : kit.kitId)
                      }
                    />
                  </motion.div>
                ))}
              </div>
            )}

            {/* Pagination */}
            {kitPages > 1 && (
              <div className="flex items-center justify-center gap-3 mt-4">
                <button
                  onClick={() => {
                    const p = Math.max(1, kitPage - 1);
                    setKitPage(p);
                    fetchKitsPaged(p);
                  }}
                  disabled={kitPage <= 1}
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
                  Page {kitPage} of {kitPages} · {kitTotal} total kits
                </span>
                <button
                  onClick={() => {
                    const p = Math.min(kitPages, kitPage + 1);
                    setKitPage(p);
                    fetchKitsPaged(p);
                  }}
                  disabled={kitPage >= kitPages}
                  className="btn-ghost px-4 py-2 text-sm disabled:opacity-40"
                >
                  Next →
                </button>
              </div>
            )}

            {/* Kit URL Analyzer */}
            <div
              className="card p-5 mt-4"
              style={{ background: "var(--bg-card)" }}
            >
              <div className="flex items-center gap-2 mb-3">
                <Target
                  className="size-4"
                  style={{ color: "var(--accent-cyan)" }}
                />
                <span
                  className="text-sm font-semibold"
                  style={{ color: "var(--text-primary)" }}
                >
                  Kit URL Analyzer
                </span>
                <span
                  className="text-xs ml-2"
                  style={{ color: "var(--text-muted)" }}
                >
                  Analyze any URL against 15 kit signatures
                </span>
              </div>
              <div className="flex gap-2 mb-3">
                <input
                  value={analyzeUrl}
                  onChange={(e) => setAnalyzeUrl(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && analyzeKitUrl()}
                  placeholder="https://suspicious-site.tk/login"
                  className="input-terminal flex-1 px-3 py-2 rounded-lg text-xs"
                  style={{ fontFamily: "var(--font-mono)" }}
                />
                <button
                  onClick={analyzeKitUrl}
                  disabled={analyzing || !analyzeUrl.trim()}
                  className="btn-primary px-4 py-2 text-xs"
                >
                  {analyzing ? "..." : "Analyze"}
                </button>
              </div>
              {analyzeResult && (
                <div
                  className="rounded-xl p-4"
                  style={{
                    background: analyzeResult.error
                      ? "rgba(248,113,113,0.07)"
                      : "var(--bg-elevated)",
                    border: `1px solid ${analyzeResult.error ? "rgba(248,113,113,0.25)" : "var(--bg-border)"}`,
                  }}
                >
                  {analyzeResult.error ? (
                    <p
                      className="text-xs"
                      style={{
                        color: "#f87171",
                        fontFamily: "var(--font-mono)",
                      }}
                    >
                      ⚠ {analyzeResult.error}
                    </p>
                  ) : analyzeResult.total === 0 ? (
                    <p
                      className="text-xs"
                      style={{
                        color: "#34d399",
                        fontFamily: "var(--font-mono)",
                      }}
                    >
                      ✓ No kit signatures matched — URL appears clean of known
                      kit infrastructure
                    </p>
                  ) : (
                    <div>
                      <p
                        className="text-xs font-bold mb-2"
                        style={{
                          color:
                            SOPH_CFG[analyzeResult.topMatch?.sophistication]
                              ?.color || "#f87171",
                          fontFamily: "var(--font-mono)",
                        }}
                      >
                        {analyzeResult.total} kit match
                        {analyzeResult.total !== 1 ? "es" : ""} · Top:{" "}
                        {analyzeResult.topMatch?.kitName}
                      </p>
                      {analyzeResult.topMatch?.riskSignals?.length > 0 && (
                        <div className="flex flex-wrap gap-1.5">
                          {analyzeResult.topMatch.riskSignals.map(
                            (sig: string, i: number) => (
                              <span
                                key={i}
                                className="text-[10px] px-2 py-0.5 rounded"
                                style={{
                                  color: "var(--accent-cyan)",
                                  background: "rgba(0,212,255,0.06)",
                                  border: "1px solid rgba(0,212,255,0.15)",
                                  fontFamily: "var(--font-mono)",
                                }}
                              >
                                {sig}
                              </span>
                            ),
                          )}
                        </div>
                      )}
                    </div>
                  )}
                </div>
              )}
            </div>
          </>
        )}

        {/* ── Signature Database tab ── */}
        {activeTab === "database" && (
          <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
            <div
              className="card overflow-hidden"
              style={{ background: "var(--bg-card)" }}
            >
              {/* DB header */}
              <div
                className="flex items-center justify-between px-5 py-3 border-b"
                style={{
                  borderColor: "var(--bg-border)",
                  background: "rgba(0,0,0,0.3)",
                }}
              >
                <div className="flex items-center gap-2">
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
                    kit_signatures.db — {signatures.length} entries
                  </span>
                </div>
                <div
                  className="flex items-center gap-3 text-xs"
                  style={{
                    color: "var(--text-muted)",
                    fontFamily: "'JetBrains Mono', monospace",
                  }}
                >
                  <span style={{ color: "#ff4444" }}>
                    {
                      signatures.filter((s) => s.sophistication === "expert")
                        .length
                    }{" "}
                    expert
                  </span>
                  <span style={{ color: "#f97316" }}>
                    {
                      signatures.filter((s) => s.sophistication === "high")
                        .length
                    }{" "}
                    high
                  </span>
                  <span style={{ color: "#f5a623" }}>
                    {
                      signatures.filter((s) => s.sophistication === "medium")
                        .length
                    }{" "}
                    medium
                  </span>
                </div>
              </div>

              {/* Column headers */}
              <div
                className="px-5 py-2 flex items-center gap-4 border-b"
                style={{
                  borderColor: "var(--bg-border)",
                  background: "rgba(0,0,0,0.2)",
                }}
              >
                {["KIT ID", "KIT NAME", "SOPHISTICATION", "TARGETS"].map(
                  (col) => (
                    <span
                      key={col}
                      className="text-xs uppercase tracking-widest flex-1"
                      style={{
                        color: "var(--text-muted)",
                        fontFamily: "'JetBrains Mono', monospace",
                      }}
                    >
                      {col}
                    </span>
                  ),
                )}
              </div>

              {sigLoading ? (
                <div className="py-10 text-center">
                  <div
                    className="w-6 h-6 border-2 rounded-full animate-spin mx-auto"
                    style={{
                      borderColor: "var(--accent-green)",
                      borderTopColor: "transparent",
                    }}
                  />
                </div>
              ) : (
                <div
                  className="divide-y"
                  style={{ borderColor: "rgba(30,39,54,0.3)" }}
                >
                  {signatures.map((sig, i) => (
                    <motion.div
                      key={sig.kitId}
                      initial={{ opacity: 0 }}
                      animate={{ opacity: 1 }}
                      transition={{ delay: i * 0.02 }}
                    >
                      <SignatureRow sig={sig} />
                    </motion.div>
                  ))}
                </div>
              )}

              {/* DB footer */}
              <div
                className="px-5 py-3 border-t flex items-center justify-between"
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
                  Sources: CISA, Microsoft MSTIC, Google TAG, Proofpoint,
                  Group-IB, Mandiant, INTERPOL
                </span>
                <span
                  className="text-xs px-2 py-0.5 rounded"
                  style={{
                    color: "var(--accent-green)",
                    background: "rgba(0,255,136,0.06)",
                    border: "1px solid rgba(0,255,136,0.15)",
                    fontFamily: "'JetBrains Mono', monospace",
                  }}
                >
                  Passive analysis only
                </span>
              </div>
            </div>
          </motion.div>
        )}
      </div>
    </div>
  );
}
