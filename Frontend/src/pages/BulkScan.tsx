// FILE: src/pages/BulkScan.tsx

import { useState, useRef, useCallback } from "react";
import { motion, AnimatePresence } from "motion/react";
import {
  Upload,
  Download,
  Terminal,
  CheckCircle,
  XCircle,
  TriangleAlert as AlertTriangle,
  RefreshCw,
  FileText,
  Zap,
  Shield,
} from "lucide-react";
import { API_BASE } from "../config";

interface BulkResult {
  input: string;
  status: string;
  riskScore: number;
  confidence: string;
  inputType: string;
  issues: string[];
  attackTypes: string[];
  fingerprint: string | null;
  mlScore: number | null;
  skipped?: boolean;
}
interface BulkSummary {
  total: number;
  phishing: number;
  suspicious: number;
  safe: number;
  errors: number;
  skipped: number;
  threatRate: number;
}

const statusColor = (s: string) =>
  s === "phishing"
    ? "#ff4444"
    : s === "suspicious"
      ? "#f5a623"
      : s === "safe"
        ? "#00ff88"
        : "#8b95a8";
const statusBg = (s: string) =>
  s === "phishing"
    ? "rgba(255,68,68,0.08)"
    : s === "suspicious"
      ? "rgba(245,166,35,0.08)"
      : s === "safe"
        ? "rgba(0,255,136,0.06)"
        : "rgba(139,149,168,0.06)";
const statusBorder = (s: string) =>
  s === "phishing"
    ? "rgba(255,68,68,0.25)"
    : s === "suspicious"
      ? "rgba(245,166,35,0.25)"
      : s === "safe"
        ? "rgba(0,255,136,0.2)"
        : "rgba(139,149,168,0.2)";

export default function BulkScan() {
  const [inputs, setInputs] = useState("");
  const [loading, setLoading] = useState(false);
  const [progress, setProgress] = useState(0);
  const [results, setResults] = useState<BulkResult[]>([]);
  const [summary, setSummary] = useState<BulkSummary | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState<
    "all" | "phishing" | "suspicious" | "safe"
  >("all");
  const fileRef = useRef<HTMLInputElement>(null);

  // Parse CSV file
  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (ev) => {
      const text = ev.target?.result as string;
      // Extract first column from CSV, skip header
      const lines = text
        .split("\n")
        .slice(1)
        .map((l) => l.split(",")[0]?.replace(/["']/g, "").trim())
        .filter(Boolean);
      setInputs(lines.join("\n"));
    };
    reader.readAsText(file);
  };

  const handleScan = useCallback(async () => {
    const inputList = inputs
      .split("\n")
      .map((l) => l.trim())
      .filter(Boolean);
    if (inputList.length === 0) {
      setError("No inputs to scan");
      return;
    }
    if (inputList.length > 500) {
      setError("Max 500 inputs");
      return;
    }

    setLoading(true);
    setError(null);
    setResults([]);
    setSummary(null);
    setProgress(0);

    // Animate progress while scanning
    const interval = setInterval(() => {
      setProgress((p) => Math.min(p + 2, 90));
    }, 100);

    try {
      const res = await fetch(`${API_BASE}/api/bulk/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ inputs: inputList }),
      });
      if (!res.ok) throw new Error(`Server error ${res.status}`);
      const data = await res.json();
      clearInterval(interval);
      setProgress(100);
      setResults(data.results || []);
      setSummary(data.summary);
    } catch (err: any) {
      setError(err.message);
    } finally {
      clearInterval(interval);
      setLoading(false);
      setTimeout(() => setProgress(0), 1000);
    }
  }, [inputs]);

  const handleExportCSV = () => {
    const headers = [
      "Input",
      "Status",
      "Risk Score",
      "Confidence",
      "Type",
      "Top Issue",
      "Attack Type",
      "DNA Fingerprint",
      "ML Score",
    ];
    const rows = results.map((r) => [
      `"${r.input.replace(/"/g, '""')}"`,
      r.status,
      r.riskScore,
      r.confidence || "",
      r.inputType || "",
      `"${(r.issues?.[0] || "").replace(/"/g, '""')}"`,
      r.attackTypes?.[0] || "",
      r.fingerprint || "",
      r.mlScore ?? "",
    ]);
    const csv = [headers, ...rows].map((r) => r.join(",")).join("\n");
    const blob = new Blob([csv], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `phishguard-bulk-${Date.now()}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const filtered =
    filter === "all" ? results : results.filter((r) => r.status === filter);
  const inputCount = inputs.split("\n").filter((l) => l.trim()).length;

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
          className="mb-10"
        >
          <div className="tag-green inline-flex mb-4">
            <Zap className="size-3" /> BULK SCANNER
          </div>
          <h1
            className="text-4xl font-bold mb-2"
            style={{
              fontFamily: "'Syne', sans-serif",
              color: "var(--text-primary)",
            }}
          >
            Bulk URL Scanner
          </h1>
          <p className="text-sm" style={{ color: "var(--text-secondary)" }}>
            Scan up to 500 URLs, emails, or messages at once. Upload a CSV or
            paste directly.
          </p>
        </motion.div>

        {/* Input section */}
        <motion.div
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
          className="card p-5 mb-6"
          style={{ background: "var(--bg-card)" }}
        >
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-2">
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
                Input ({inputCount}/500)
              </span>
            </div>
            <div className="flex items-center gap-2">
              <input
                ref={fileRef}
                type="file"
                accept=".csv,.txt"
                className="hidden"
                onChange={handleFileUpload}
              />
              <button
                onClick={() => fileRef.current?.click()}
                className="btn-ghost flex items-center gap-2 px-3 py-2 text-xs"
                style={{ fontFamily: "'JetBrains Mono', monospace" }}
              >
                <Upload className="size-3.5" /> Upload CSV
              </button>
              {inputs && (
                <button
                  onClick={() => setInputs("")}
                  className="text-xs px-3 py-2 rounded-lg transition-all"
                  style={{
                    color: "var(--text-muted)",
                    border: "1px solid var(--bg-border)",
                  }}
                >
                  Clear
                </button>
              )}
            </div>
          </div>

          <textarea
            value={inputs}
            onChange={(e) => setInputs(e.target.value)}
            placeholder={
              "Paste URLs, emails, or messages — one per line:\n\nhttps://paypal-secure.tk/verify\nhttp://amaz0n-login.ml\nYour account has been suspended, click here...\n\nOr upload a CSV file (uses first column)"
            }
            rows={8}
            className="input-terminal w-full px-4 py-3 rounded-xl text-xs mb-4"
            style={{
              fontFamily: "'JetBrains Mono', monospace",
              resize: "vertical",
            }}
          />

          {error && (
            <p
              className="text-xs mb-3 px-3 py-2 rounded-lg"
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

          {/* Progress bar */}
          {(loading || progress > 0) && (
            <div className="mb-4">
              <div
                className="flex justify-between text-xs mb-1.5"
                style={{
                  color: "var(--text-muted)",
                  fontFamily: "'JetBrains Mono', monospace",
                }}
              >
                <span>
                  {loading ? `Scanning ${inputCount} inputs...` : "Complete"}
                </span>
                <span>{progress}%</span>
              </div>
              <div
                className="h-2 rounded-full overflow-hidden"
                style={{ background: "var(--bg-border)" }}
              >
                <motion.div
                  className="h-full rounded-full"
                  animate={{ width: `${progress}%` }}
                  style={{
                    background: `linear-gradient(90deg, var(--accent-green) 0%, var(--accent-cyan) 100%)`,
                    boxShadow: "0 0 8px rgba(0,255,136,0.5)",
                  }}
                />
              </div>
            </div>
          )}

          <button
            onClick={handleScan}
            disabled={loading || !inputs.trim()}
            className="btn-primary w-full flex items-center justify-center gap-2 py-3.5 text-sm"
            style={{ fontFamily: "'Syne', sans-serif", fontWeight: 700 }}
          >
            {loading ? (
              <>
                <div
                  className="w-4 h-4 border-2 rounded-full animate-spin"
                  style={{
                    borderColor: "#080b10",
                    borderTopColor: "transparent",
                  }}
                />
                Scanning {inputCount} inputs...
              </>
            ) : (
              <>
                <Zap className="size-4" /> Scan All ({inputCount})
              </>
            )}
          </button>
        </motion.div>

        {/* Summary cards */}
        <AnimatePresence>
          {summary && (
            <motion.div
              initial={{ opacity: 0, y: 12 }}
              animate={{ opacity: 1, y: 0 }}
              className="grid grid-cols-2 md:grid-cols-6 gap-3 mb-6"
            >
              {[
                {
                  label: "Total",
                  value: summary.total,
                  color: "var(--accent-green)",
                },
                {
                  label: "Phishing",
                  value: summary.phishing,
                  color: "#ff4444",
                },
                {
                  label: "Suspicious",
                  value: summary.suspicious,
                  color: "#f5a623",
                },
                { label: "Safe", value: summary.safe, color: "#00ff88" },
                { label: "Errors", value: summary.errors, color: "#8b95a8" },
                {
                  label: "Threat Rate",
                  value: `${summary.threatRate}%`,
                  color:
                    summary.threatRate > 50
                      ? "#ff4444"
                      : summary.threatRate > 20
                        ? "#f5a623"
                        : "#00ff88",
                },
              ].map((c) => (
                <div
                  key={c.label}
                  className="card p-3 text-center"
                  style={{ background: "var(--bg-card)" }}
                >
                  <div
                    className="text-xl font-bold"
                    style={{ color: c.color, fontFamily: "'Syne', sans-serif" }}
                  >
                    {c.value}
                  </div>
                  <div
                    className="text-xs"
                    style={{
                      color: "var(--text-muted)",
                      fontFamily: "'JetBrains Mono', monospace",
                    }}
                  >
                    {c.label}
                  </div>
                </div>
              ))}
            </motion.div>
          )}
        </AnimatePresence>

        {/* Results */}
        {results.length > 0 && (
          <motion.div
            initial={{ opacity: 0, y: 12 }}
            animate={{ opacity: 1, y: 0 }}
            className="card overflow-hidden"
            style={{ background: "var(--bg-card)" }}
          >
            {/* Table header */}
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
                  bulk_results.log — {filtered.length} records
                </span>
              </div>
              <div className="flex items-center gap-2">
                {/* Filter buttons */}
                {(["all", "phishing", "suspicious", "safe"] as const).map(
                  (f) => (
                    <button
                      key={f}
                      onClick={() => setFilter(f)}
                      className="text-xs px-2.5 py-1 rounded-lg transition-all"
                      style={{
                        fontFamily: "'JetBrains Mono', monospace",
                        background:
                          filter === f ? "var(--accent-green)" : "transparent",
                        color: filter === f ? "#080b10" : "var(--text-muted)",
                        border: `1px solid ${filter === f ? "var(--accent-green)" : "var(--bg-border)"}`,
                      }}
                    >
                      {f}
                    </button>
                  ),
                )}
                <button
                  onClick={handleExportCSV}
                  className="flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-lg ml-2"
                  style={{
                    color: "var(--accent-cyan)",
                    background: "rgba(0,212,255,0.06)",
                    border: "1px solid rgba(0,212,255,0.2)",
                    fontFamily: "'JetBrains Mono', monospace",
                  }}
                >
                  <Download className="size-3" /> CSV
                </button>
              </div>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full data-table">
                <thead>
                  <tr>
                    <th className="text-left">#</th>
                    <th className="text-left">Input</th>
                    <th className="text-left">Verdict</th>
                    <th className="text-left">Score</th>
                    <th className="text-left">Top Issue</th>
                    <th className="text-left hidden md:table-cell">DNA</th>
                  </tr>
                </thead>
                <tbody>
                  {filtered.map((r, i) => (
                    <motion.tr
                      key={i}
                      initial={{ opacity: 0, y: 3 }}
                      animate={{ opacity: 1, y: 0 }}
                      transition={{ delay: Math.min(i * 0.02, 0.5) }}
                    >
                      <td>
                        <span
                          className="text-xs"
                          style={{
                            color: "var(--text-muted)",
                            fontFamily: "'JetBrains Mono', monospace",
                          }}
                        >
                          {results.indexOf(r) + 1}
                        </span>
                      </td>
                      <td style={{ maxWidth: 220 }}>
                        <span
                          className="text-xs truncate block"
                          style={{
                            color: "var(--text-primary)",
                            fontFamily: "'JetBrains Mono', monospace",
                            fontSize: 11,
                          }}
                        >
                          {r.input}
                        </span>
                      </td>
                      <td>
                        {r.skipped ? (
                          <span
                            className="text-xs"
                            style={{ color: "var(--text-muted)" }}
                          >
                            SKIPPED
                          </span>
                        ) : (
                          <span
                            className="text-xs font-bold px-2 py-0.5 rounded"
                            style={{
                              color: statusColor(r.status),
                              background: statusBg(r.status),
                              border: `1px solid ${statusBorder(r.status)}`,
                              fontFamily: "'JetBrains Mono', monospace",
                            }}
                          >
                            {r.status?.toUpperCase()}
                          </span>
                        )}
                      </td>
                      <td>
                        <div className="flex items-center gap-2">
                          <div
                            className="w-14 h-1.5 rounded-full"
                            style={{ background: "var(--bg-border)" }}
                          >
                            <div
                              className="h-full rounded-full"
                              style={{
                                width: `${r.riskScore || 0}%`,
                                background: statusColor(r.status),
                              }}
                            />
                          </div>
                          <span
                            className="text-xs font-bold"
                            style={{
                              color: statusColor(r.status),
                              fontFamily: "'JetBrains Mono', monospace",
                            }}
                          >
                            {r.riskScore ?? "—"}
                          </span>
                        </div>
                      </td>
                      <td>
                        <span
                          className="text-xs"
                          style={{
                            color: "var(--text-muted)",
                            fontFamily: "'JetBrains Mono', monospace",
                            fontSize: 10,
                          }}
                        >
                          {r.issues?.[0]?.substring(0, 45) || "—"}
                        </span>
                      </td>
                      <td className="hidden md:table-cell">
                        {r.fingerprint && (
                          <span
                            className="text-xs px-2 py-0.5 rounded"
                            style={{
                              color: "#a78bfa",
                              background: "rgba(163,120,251,0.08)",
                              border: "1px solid rgba(163,120,251,0.2)",
                              fontFamily: "'JetBrains Mono', monospace",
                            }}
                          >
                            #{r.fingerprint}
                          </span>
                        )}
                      </td>
                    </motion.tr>
                  ))}
                </tbody>
              </table>
            </div>
          </motion.div>
        )}
      </div>
    </div>
  );
}
