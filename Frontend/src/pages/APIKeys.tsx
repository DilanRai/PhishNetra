// FILE: src/pages/APIKeys.tsx

import { useState, useEffect, useCallback } from "react";
import { motion, AnimatePresence } from "motion/react";
import {
  Key,
  Plus,
  Trash2,
  Copy,
  CheckCircle,
  Shield,
  Terminal,
  Clock,
  Activity,
  TrendingUp,
  AlertTriangle,
  Eye,
  Users,
} from "lucide-react";
import { API_BASE } from "../config";

interface ApiKey {
  _id: string;
  key: string;
  name: string;
  rateLimit: number;
  usageCount: number;
  lastUsed: string | null;
  active: boolean;
  createdAt: string;
}

interface IntelClient {
  name: string;
  username: string;
  trustScore: number;
  trustLevel: string;
  totalScans: number;
  phishingRate: number;
  isUnderAttack: boolean;
  isReconClient: boolean;
  scanBursts: number;
  lastUsed: string | null;
  firstScan: string | null;
  anomalies: string[];
}

interface IntelStats {
  totalClients: number;
  trustedClients: number;
  suspiciousClients: number;
  underAttack: number;
  reconClients: number;
  totalApiScans: number;
}

export default function APIKeys() {
  const [keys, setKeys] = useState<ApiKey[]>([]);
  const [loading, setLoading] = useState(true);
  const [creating, setCreating] = useState(false);
  const [newName, setNewName] = useState("");
  const [rateLimit, setRateLimit] = useState(100);
  const [newKey, setNewKey] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<"keys" | "intelligence">("keys");
  const [intel, setIntel] = useState<{
    stats: IntelStats;
    clients: IntelClient[];
  } | null>(null);
  const [intelLoad, setIntelLoad] = useState(false);

  const authHeader = () => ({
    "Content-Type": "application/json",
    Authorization: `Bearer ${localStorage.getItem("pg_token")}`,
  });

  const fetchKeys = useCallback(async () => {
    try {
      const res = await fetch(`${API_BASE}/api/keys`, {
        headers: authHeader(),
      });
      if (res.ok) setKeys(await res.json());
    } catch {
      /* offline */
    } finally {
      setLoading(false);
    }
  }, []);

  const fetchIntel = useCallback(async () => {
    setIntelLoad(true);
    try {
      const res = await fetch(`${API_BASE}/api/keys/intelligence`, {
        headers: authHeader(),
      });
      if (res.ok) setIntel(await res.json());
    } catch {
      /* offline */
    } finally {
      setIntelLoad(false);
    }
  }, []);

  useEffect(() => {
    fetchKeys();
  }, [fetchKeys]);

  useEffect(() => {
    if (activeTab === "intelligence" && !intel) fetchIntel();
  }, [activeTab, intel, fetchIntel]);

  const handleCreate = async () => {
    if (!newName.trim()) return;
    setError(null);
    try {
      const res = await fetch(`${API_BASE}/api/keys`, {
        method: "POST",
        headers: authHeader(),
        body: JSON.stringify({ name: newName.trim(), rateLimit }),
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data.error);
        return;
      }
      setNewKey(data.key); // Show full key once
      setNewName("");
      setRateLimit(100);
      setCreating(false);
      fetchKeys();
    } catch {
      setError("Failed to create key");
    }
  };

  const handleRevoke = async (keyId: string) => {
    if (!confirm("Revoke this API key? This cannot be undone.")) return;
    try {
      await fetch(`${API_BASE}/api/keys/${keyId}`, {
        method: "DELETE",
        headers: authHeader(),
      });
      fetchKeys();
    } catch {
      /* offline */
    }
  };

  const handlePermanentDelete = async (keyId: string) => {
    if (!confirm("Permanently delete this API key? It cannot be recovered."))
      return;
    try {
      await fetch(`${API_BASE}/api/keys/${keyId}/permanent`, {
        method: "DELETE",
        headers: authHeader(),
      });
      fetchKeys();
    } catch {
      /* offline */
    }
  };

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div
      className="min-h-full py-10 px-6"
      style={{ background: "var(--bg-base)" }}
    >
      <div className="max-w-4xl mx-auto">
        {/* Header */}
        <motion.div
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          className="mb-10"
        >
          <div className="tag-green inline-flex mb-4">
            <Key className="size-3" /> API KEYS
          </div>
          <h1
            className="text-4xl font-bold mb-2"
            style={{
              fontFamily: "'Syne', sans-serif",
              color: "var(--text-primary)",
            }}
          >
            API Key Management
          </h1>
          <p className="text-sm" style={{ color: "var(--text-secondary)" }}>
            Create API keys to integrate PhishGuard into your own tools and
            pipelines.
          </p>
        </motion.div>
        {/* Tab selector */}
        <div className="flex gap-2 mb-6">
          {(
            [
              { key: "keys", label: "API Keys", icon: Key },
              {
                key: "intelligence",
                label: "API Intelligence",
                icon: TrendingUp,
              },
            ] as const
          ).map(({ key, label, icon: Icon }) => (
            <button
              key={key}
              onClick={() => setActiveTab(key)}
              className="flex items-center gap-2 px-5 py-2.5 rounded-xl text-sm font-medium transition-all"
              style={{
                background:
                  activeTab === key ? "rgba(0,255,136,0.08)" : "var(--bg-card)",
                border: `1px solid ${activeTab === key ? "rgba(0,255,136,0.3)" : "var(--bg-border)"}`,
                color:
                  activeTab === key ? "var(--accent)" : "var(--text-secondary)",
              }}
            >
              <Icon className="size-4" /> {label}
            </button>
          ))}
        </div>
        {/* Keys tab */}
        {activeTab === "keys" && (
          <>
            {/* New key banner — shown once after creation */}
            <AnimatePresence>
              {newKey && (
                <motion.div
                  initial={{ opacity: 0, y: -10 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0 }}
                  className="mb-6 p-5 rounded-2xl"
                  style={{
                    background: "rgba(0,255,136,0.06)",
                    border: "2px solid rgba(0,255,136,0.3)",
                  }}
                >
                  <div className="flex items-center gap-2 mb-3">
                    <CheckCircle
                      className="size-5"
                      style={{ color: "var(--accent-green)" }}
                    />
                    <p
                      className="text-sm font-bold"
                      style={{
                        color: "var(--accent-green)",
                        fontFamily: "'Syne', sans-serif",
                      }}
                    >
                      API Key Created — Save it now, it won't be shown again
                    </p>
                  </div>
                  <div
                    className="flex items-center gap-3 p-3 rounded-xl"
                    style={{
                      background: "var(--bg-elevated)",
                      border: "1px solid var(--bg-border)",
                    }}
                  >
                    <code
                      className="text-sm flex-1 break-all"
                      style={{
                        color: "var(--accent-cyan)",
                        fontFamily: "'JetBrains Mono', monospace",
                      }}
                    >
                      {newKey}
                    </code>
                    <button
                      onClick={() => handleCopy(newKey)}
                      className="btn-ghost flex items-center gap-1.5 px-3 py-1.5 text-xs flex-shrink-0"
                      style={{
                        color: copied
                          ? "var(--accent-green)"
                          : "var(--text-secondary)",
                      }}
                    >
                      {copied ? (
                        <CheckCircle className="size-3.5" />
                      ) : (
                        <Copy className="size-3.5" />
                      )}
                      {copied ? "Copied!" : "Copy"}
                    </button>
                  </div>
                  <p
                    className="text-xs mt-3"
                    style={{
                      color: "var(--text-muted)",
                      fontFamily: "'JetBrains Mono', monospace",
                    }}
                  >
                    Usage:{" "}
                    <code style={{ color: "var(--accent-cyan)" }}>
                      curl -X POST http://localhost:5000/api/scan -H "X-API-Key:{" "}
                      {newKey}" -H "Content-Type: application/json" -d
                      '&#123;"input":"https://example.com"&#125;'
                    </code>
                  </p>
                  <button
                    onClick={() => setNewKey(null)}
                    className="text-xs mt-2"
                    style={{ color: "var(--text-muted)" }}
                  >
                    Dismiss
                  </button>
                </motion.div>
              )}
            </AnimatePresence>

            {/* Create new key */}
            <motion.div
              initial={{ opacity: 0, y: 16 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.1 }}
              className="card p-5 mb-6"
              style={{ background: "var(--bg-card)" }}
            >
              <div className="flex items-center gap-2 mb-4">
                <Plus
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
                  Create New API Key
                </span>
              </div>

              {!creating ? (
                <button
                  onClick={() => setCreating(true)}
                  className="btn-ghost flex items-center gap-2 px-4 py-2.5 text-sm"
                  style={{ fontFamily: "'DM Sans', sans-serif" }}
                >
                  <Plus className="size-4" /> New Key
                </button>
              ) : (
                <div className="space-y-3">
                  {error && (
                    <p
                      className="text-xs px-3 py-2 rounded-lg"
                      style={{
                        color: "#ff4444",
                        background: "rgba(255,68,68,0.08)",
                        border: "1px solid rgba(255,68,68,0.2)",
                        fontFamily: "'JetBrains Mono', monospace",
                      }}
                    >
                      ⚠ {error}
                    </p>
                  )}
                  <div className="grid md:grid-cols-2 gap-3">
                    <div>
                      <div
                        className="text-xs mb-1.5"
                        style={{
                          color: "var(--text-muted)",
                          fontFamily: "'JetBrains Mono', monospace",
                        }}
                      >
                        KEY NAME
                      </div>
                      <input
                        type="text"
                        value={newName}
                        onChange={(e) => setNewName(e.target.value)}
                        onKeyDown={(e) => e.key === "Enter" && handleCreate()}
                        placeholder="e.g. CI Pipeline, Slack Bot..."
                        className="input-terminal w-full px-4 py-2.5 rounded-xl text-sm"
                      />
                    </div>
                    <div>
                      <div
                        className="text-xs mb-1.5"
                        style={{
                          color: "var(--text-muted)",
                          fontFamily: "'JetBrains Mono', monospace",
                        }}
                      >
                        RATE LIMIT (req/hour)
                      </div>
                      <input
                        type="number"
                        value={rateLimit}
                        min={1}
                        max={1000}
                        onChange={(e) => setRateLimit(Number(e.target.value))}
                        className="input-terminal w-full px-4 py-2.5 rounded-xl text-sm"
                      />
                    </div>
                  </div>
                  <div className="flex gap-2">
                    <button
                      onClick={handleCreate}
                      disabled={!newName.trim()}
                      className="btn-primary flex items-center gap-2 px-5 py-2.5 text-sm"
                      style={{
                        fontFamily: "'Syne', sans-serif",
                        fontWeight: 700,
                      }}
                    >
                      <Key className="size-4" /> Create Key
                    </button>
                    <button
                      onClick={() => {
                        setCreating(false);
                        setError(null);
                      }}
                      className="btn-ghost px-5 py-2.5 text-sm"
                      style={{ fontFamily: "'DM Sans', sans-serif" }}
                    >
                      Cancel
                    </button>
                  </div>
                </div>
              )}
            </motion.div>

            {/* Keys list */}
            <motion.div
              initial={{ opacity: 0, y: 16 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.2 }}
              className="card overflow-hidden"
              style={{ background: "var(--bg-card)" }}
            >
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
                    api_keys.log — {keys.length}/5 keys
                  </span>
                </div>
              </div>

              {loading ? (
                <div className="py-10 text-center">
                  <div
                    className="w-6 h-6 border-2 rounded-full animate-spin mx-auto"
                    style={{
                      borderColor: "var(--accent-green)",
                      borderTopColor: "transparent",
                    }}
                  />
                </div>
              ) : keys.length === 0 ? (
                <div className="py-12 text-center">
                  <Key
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
                    No API keys yet
                  </p>
                </div>
              ) : (
                <div
                  className="divide-y"
                  style={{ borderColor: "rgba(30,39,54,0.5)" }}
                >
                  {keys.map((k, i) => (
                    <motion.div
                      key={k._id}
                      initial={{ opacity: 0, y: 4 }}
                      animate={{ opacity: 1, y: 0 }}
                      transition={{ delay: i * 0.05 }}
                      className="px-5 py-4 flex items-start gap-4"
                    >
                      {/* Status dot */}
                      <div
                        className="w-2 h-2 rounded-full mt-2 flex-shrink-0"
                        style={{
                          background: k.active
                            ? "var(--accent-green)"
                            : "#4a5568",
                          boxShadow: k.active
                            ? "0 0 6px rgba(0,255,136,0.5)"
                            : "none",
                        }}
                      />

                      {/* Key info */}
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-3 mb-1 flex-wrap">
                          <span
                            className="text-sm font-semibold"
                            style={{
                              color: "var(--text-primary)",
                              fontFamily: "'Syne', sans-serif",
                            }}
                          >
                            {k.name}
                          </span>
                          <code
                            className="text-xs px-2 py-0.5 rounded"
                            style={{
                              color: "var(--accent-cyan)",
                              background: "rgba(0,212,255,0.06)",
                              border: "1px solid rgba(0,212,255,0.15)",
                              fontFamily: "'JetBrains Mono', monospace",
                            }}
                          >
                            {k.key}
                          </code>
                        </div>
                        <div
                          className="flex flex-wrap items-center gap-4 text-xs"
                          style={{
                            fontFamily: "'JetBrains Mono', monospace",
                            color: "var(--text-muted)",
                          }}
                        >
                          <span className="flex items-center gap-1">
                            <Activity className="size-3" />
                            {k.usageCount.toLocaleString()} scans
                          </span>
                          <span className="flex items-center gap-1">
                            <Shield className="size-3" />
                            {k.rateLimit}/hr limit
                          </span>
                          <span className="flex items-center gap-1">
                            <Clock className="size-3" />
                            {k.lastUsed
                              ? `Last used ${new Date(k.lastUsed).toLocaleDateString()}`
                              : "Never used"}
                          </span>
                          <span>
                            Created {new Date(k.createdAt).toLocaleDateString()}
                          </span>
                        </div>
                      </div>

                      {/* Actions */}
                      <div className="flex items-center gap-1.5 flex-shrink-0">
                        <button
                          onClick={() => handleRevoke(k._id)}
                          className="p-2 rounded-lg transition-all"
                          style={{
                            color: "var(--text-muted)",
                            border: "1px solid var(--bg-border)",
                          }}
                          title="Revoke key (soft disable)"
                          onMouseEnter={(e) => {
                            (e.currentTarget as HTMLButtonElement).style.color =
                              "#f5a623";
                            (
                              e.currentTarget as HTMLButtonElement
                            ).style.borderColor = "rgba(245,166,35,0.3)";
                          }}
                          onMouseLeave={(e) => {
                            (e.currentTarget as HTMLButtonElement).style.color =
                              "var(--text-muted)";
                            (
                              e.currentTarget as HTMLButtonElement
                            ).style.borderColor = "var(--bg-border)";
                          }}
                        >
                          <Eye className="size-4" style={{ opacity: 0.7 }} />
                        </button>
                        <button
                          onClick={() => handlePermanentDelete(k._id)}
                          className="p-2 rounded-lg transition-all"
                          style={{
                            color: "var(--text-muted)",
                            border: "1px solid var(--bg-border)",
                          }}
                          title="Permanently delete key"
                          onMouseEnter={(e) => {
                            (e.currentTarget as HTMLButtonElement).style.color =
                              "#ff4444";
                            (
                              e.currentTarget as HTMLButtonElement
                            ).style.borderColor = "rgba(255,68,68,0.3)";
                          }}
                          onMouseLeave={(e) => {
                            (e.currentTarget as HTMLButtonElement).style.color =
                              "var(--text-muted)";
                            (
                              e.currentTarget as HTMLButtonElement
                            ).style.borderColor = "var(--bg-border)";
                          }}
                        >
                          <Trash2 className="size-4" />
                        </button>
                      </div>
                    </motion.div>
                  ))}
                </div>
              )}
            </motion.div>

            {/* Usage docs */}
            <motion.div
              initial={{ opacity: 0, y: 12 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.3 }}
              className="mt-6 card p-5"
              style={{ background: "var(--bg-card)" }}
            >
              <div className="flex items-center gap-2 mb-4">
                <Terminal
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
                  API Usage
                </span>
              </div>
              <div className="space-y-3">
                {[
                  {
                    label: "Scan a URL",
                    code: `curl -X POST http://localhost:5000/api/scan \\
  -H "X-API-Key: pgk_your_key_here" \\
  -H "Content-Type: application/json" \\
  -d '{"input": "https://suspicious-domain.tk"}'`,
                  },
                  {
                    label: "Bulk scan",
                    code: `curl -X POST http://localhost:5000/api/bulk/scan \\
  -H "X-API-Key: pgk_your_key_here" \\
  -H "Content-Type: application/json" \\
  -d '{"inputs": ["https://url1.com", "https://url2.tk"]}'`,
                  },
                ].map(({ label, code }) => (
                  <div key={label}>
                    <div
                      className="text-xs mb-1.5"
                      style={{
                        color: "var(--text-muted)",
                        fontFamily: "'JetBrains Mono', monospace",
                        letterSpacing: "0.1em",
                      }}
                    >
                      {label.toUpperCase()}
                    </div>
                    <pre
                      className="text-xs p-3 rounded-xl overflow-x-auto"
                      style={{
                        background: "var(--bg-elevated)",
                        border: "1px solid var(--bg-border)",
                        color: "var(--accent-cyan)",
                        fontFamily: "'JetBrains Mono', monospace",
                        lineHeight: 1.6,
                      }}
                    >
                      {code}
                    </pre>
                  </div>
                ))}
              </div>
            </motion.div>
          </>
        )}{" "}
        {/* end keys tab */}
        {/* Intelligence tab */}
        {activeTab === "intelligence" && (
          <motion.div
            initial={{ opacity: 0, y: 12 }}
            animate={{ opacity: 1, y: 0 }}
            className="space-y-4"
          >
            {intelLoad ? (
              <div className="flex items-center justify-center py-20">
                <div
                  className="w-8 h-8 border-2 rounded-full animate-spin"
                  style={{
                    borderColor: "var(--accent)",
                    borderTopColor: "transparent",
                  }}
                />
              </div>
            ) : !intel ? (
              <div
                className="card p-10 text-center"
                style={{ background: "var(--bg-card)" }}
              >
                <TrendingUp
                  className="size-10 mx-auto mb-3"
                  style={{ color: "var(--text-muted)" }}
                />
                <p className="text-sm" style={{ color: "var(--text-muted)" }}>
                  No intelligence data available yet
                </p>
              </div>
            ) : (
              <>
                {/* Summary stats */}
                <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
                  {[
                    {
                      label: "Total Clients",
                      value: intel.stats.totalClients,
                      color: "var(--accent)",
                    },
                    {
                      label: "Trusted",
                      value: intel.stats.trustedClients,
                      color: "#34d399",
                    },
                    {
                      label: "Suspicious",
                      value: intel.stats.suspiciousClients,
                      color: "#fbbf24",
                    },
                    {
                      label: "Under Attack",
                      value: intel.stats.underAttack,
                      color: "#f87171",
                    },
                    {
                      label: "Recon Clients",
                      value: intel.stats.reconClients,
                      color: "#fb923c",
                    },
                    {
                      label: "Total API Scans",
                      value: intel.stats.totalApiScans,
                      color: "var(--color-info)",
                    },
                  ].map((s) => (
                    <div
                      key={s.label}
                      className="card p-4 text-center"
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

                {/* Client table */}
                <div
                  className="card overflow-hidden"
                  style={{ background: "var(--bg-card)" }}
                >
                  <div
                    className="px-5 py-3 border-b flex items-center justify-between"
                    style={{
                      borderColor: "var(--bg-border)",
                      background: "rgba(0,0,0,0.3)",
                    }}
                  >
                    <div className="flex items-center gap-2">
                      <Users
                        className="size-3.5"
                        style={{ color: "var(--accent)" }}
                      />
                      <span
                        className="text-xs"
                        style={{
                          color: "var(--text-muted)",
                          fontFamily: "var(--font-mono)",
                        }}
                      >
                        api_intelligence.log — {intel.clients.length} clients
                      </span>
                    </div>
                    <button
                      onClick={fetchIntel}
                      className="text-xs px-3 py-1.5 rounded-lg btn-ghost"
                    >
                      Refresh
                    </button>
                  </div>
                  <div
                    className="divide-y"
                    style={{ borderColor: "rgba(30,39,54,0.5)" }}
                  >
                    {intel.clients.map((client, i) => {
                      const trustColor =
                        client.trustLevel === "trusted"
                          ? "#34d399"
                          : client.trustLevel === "suspicious"
                            ? "#fbbf24"
                            : client.trustLevel === "untrusted"
                              ? "#f87171"
                              : "var(--text-muted)";
                      return (
                        <div key={i} className="px-5 py-4">
                          <div className="flex items-center justify-between mb-2 flex-wrap gap-2">
                            <div className="flex items-center gap-2">
                              <span
                                className="text-sm font-semibold"
                                style={{ color: "var(--text-primary)" }}
                              >
                                {client.name}
                              </span>
                              <span
                                className="text-xs"
                                style={{
                                  color: "var(--text-muted)",
                                  fontFamily: "var(--font-mono)",
                                }}
                              >
                                ({client.username})
                              </span>
                              {client.isUnderAttack && (
                                <span
                                  className="text-[9px] px-1.5 py-0.5 rounded font-bold"
                                  style={{
                                    color: "#f87171",
                                    background: "rgba(248,113,113,0.1)",
                                    border: "1px solid rgba(248,113,113,0.3)",
                                    fontFamily: "var(--font-mono)",
                                  }}
                                >
                                  UNDER ATTACK
                                </span>
                              )}
                              {client.isReconClient && (
                                <span
                                  className="text-[9px] px-1.5 py-0.5 rounded font-bold"
                                  style={{
                                    color: "#fb923c",
                                    background: "rgba(251,146,60,0.1)",
                                    border: "1px solid rgba(251,146,60,0.3)",
                                    fontFamily: "var(--font-mono)",
                                  }}
                                >
                                  RECON
                                </span>
                              )}
                            </div>
                            <div
                              className="flex items-center gap-3 text-xs"
                              style={{ fontFamily: "var(--font-mono)" }}
                            >
                              <span
                                style={{ color: trustColor, fontWeight: 700 }}
                              >
                                {client.trustLevel.toUpperCase()}
                              </span>
                              <span style={{ color: "var(--accent)" }}>
                                Score: {client.trustScore}/100
                              </span>
                              <span style={{ color: "var(--text-muted)" }}>
                                {client.totalScans} scans
                              </span>
                              <span
                                style={{
                                  color:
                                    client.phishingRate > 50
                                      ? "#f87171"
                                      : "var(--text-muted)",
                                }}
                              >
                                {client.phishingRate}% phishing
                              </span>
                            </div>
                          </div>
                          {/* Trust bar */}
                          <div
                            className="h-1.5 rounded-full mb-2"
                            style={{ background: "var(--bg-border)" }}
                          >
                            <div
                              className="h-full rounded-full"
                              style={{
                                width: `${client.trustScore}%`,
                                background: trustColor,
                              }}
                            />
                          </div>
                          {/* Anomalies */}
                          {client.anomalies.length > 0 && (
                            <div className="flex flex-wrap gap-1.5 mt-1">
                              {client.anomalies.map((a, ai) => (
                                <span
                                  key={ai}
                                  className="text-[10px] px-2 py-0.5 rounded flex items-center gap-1"
                                  style={{
                                    color: "#fbbf24",
                                    background: "rgba(251,191,36,0.07)",
                                    border: "1px solid rgba(251,191,36,0.2)",
                                    fontFamily: "var(--font-mono)",
                                  }}
                                >
                                  <AlertTriangle className="size-2.5" /> {a}
                                </span>
                              ))}
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>
                </div>
              </>
            )}
          </motion.div>
        )}
      </div>
    </div>
  );
}
