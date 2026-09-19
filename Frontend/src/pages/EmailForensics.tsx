// FILE: src/pages/EmailForensics.tsx — CREATE NEW
// Complete Email Forensic Investigation Platform
// Brings together GAP 1 (IP Geo) + GAP 2 (Relay Chain) +
// GAP 3 (Domain Intel) + GAP 4 (IP Reputation) + GAP 5 (MX/SPF)
// into one analyst dashboard

import { useState, useRef, useCallback, useEffect } from "react";
import { motion, AnimatePresence } from "motion/react";
import {
  Mail,
  Search,
  Download,
  RefreshCw,
  AlertTriangle,
  CheckCircle,
  Shield,
  Globe,
  Activity,
  Copy,
  ChevronDown,
  ChevronUp,
  ExternalLink,
  FileText,
  MapPin,
  Cpu,
  Lock,
  Zap,
} from "lucide-react";
import { useRole } from "../hooks/useRole";
import { API_BASE } from "../config";

const authHeader = () => ({
  "Content-Type": "application/json",
  Authorization: `Bearer ${localStorage.getItem("pg_token")}`,
});

// ── Sample headers for quick testing ─────────────────────────
const SAMPLE_HEADERS = [
  {
    label: "Fake SBI Email (Phishing)",
    headers: `From: "SBI Bank Alert" <alert@sbi.co.in>
Reply-To: attacker@gmail.com
To: victim@example.com
Subject: Urgent: Your SBI account will be suspended
Date: Mon, 15 Jan 2024 03:23:11 +0000
Message-ID: <1705286591.12345@mail.attacker.ng>
Received: from mail.attacker.ng (mail.attacker.ng [41.190.3.155])
        by mx.example.com (Postfix) with ESMTP id ABC123
        for <victim@example.com>; Mon, 15 Jan 2024 03:23:11 +0000
Received: from localhost (localhost [127.0.0.1])
        by mail.attacker.ng with ESMTP id XYZ456
        Mon, 15 Jan 2024 03:23:10 +0000
X-Mailer: PHPMailer 6.1.8
Authentication-Results: mx.example.com; spf=fail smtp.mailfrom=sbi.co.in`,
  },
  {
    label: "Legitimate Google Email",
    headers: `From: "Google Security" <no-reply@accounts.google.com>
To: user@example.com
Subject: New sign-in to your Google Account
Date: Mon, 15 Jan 2024 10:15:33 +0530
Message-ID: <CAHZe1abc123@mail.gmail.com>
Received: from mail-sor-f41.google.com (mail-sor-f41.google.com [209.85.220.41])
        by mx.example.com (Postfix) with ESMTPS
        for <user@example.com>; Mon, 15 Jan 2024 10:15:33 +0530
Authentication-Results: mx.example.com;
        dkim=pass header.i=@accounts.google.com;
        spf=pass smtp.mailfrom=accounts.google.com;
        dmarc=pass policy=reject`,
  },
  {
    label: "BEC / CEO Fraud Email",
    headers: `From: "John Smith CEO" <ceo@company-corp.net>
Reply-To: urgent.wire@protonmail.com
To: accounts@victim.com
Subject: URGENT - Wire transfer required today
Date: Mon, 15 Jan 2024 14:33:00 -0500
Message-ID: <20240115143300.abcdef@protonmail.ch>
Received: from mail.protonmail.ch (mail.protonmail.ch [185.70.40.28])
        by mx.victim.com with ESMTPS
        Mon, 15 Jan 2024 14:33:00 -0500
X-Originating-IP: 185.70.40.28
Authentication-Results: spf=pass smtp.mailfrom=protonmail.com`,
  },
];

// ── Verdict colors ────────────────────────────────────────────
const VERDICT_STYLE = {
  phishing: {
    bg: "rgba(248,113,113,0.07)",
    border: "rgba(248,113,113,0.25)",
    text: "#f87171",
    label: "PHISHING",
  },
  suspicious: {
    bg: "rgba(251,191,36,0.07)",
    border: "rgba(251,191,36,0.25)",
    text: "#fbbf24",
    label: "SUSPICIOUS",
  },
  safe: {
    bg: "rgba(52,211,153,0.07)",
    border: "rgba(52,211,153,0.25)",
    text: "#34d399",
    label: "SAFE",
  },
};

const SPF_COLORS: Record<string, string> = {
  pass: "var(--safe)",
  fail: "#f87171",
  softfail: "#fbbf24",
  neutral: "var(--text-muted)",
  none: "#64748b",
  error: "#64748b",
};

export default function EmailForensics() {
  const { canWrite } = useRole();
  const [headers, setHeaders] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [activeTab, setActiveTab] = useState<
    "overview" | "relay" | "domain" | "ip" | "mx" | "raw" | "correlation"
  >("overview");
  const [showSamples, setShowSamples] = useState(false);
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  // Correlation state
  const [correlations, setCorrelations] = useState<any>(null);
  const [corrLoading, setCorrLoading] = useState(false);

  // Auto-fetch correlations when a scan result comes back with an emailScanId
  useEffect(() => {
    if (!result?.emailScanId) return;
    setCorrLoading(true);
    fetch(`${API_BASE}/api/email-clusters/${result.emailScanId}/related`, {
      headers: authHeader(),
    })
      .then((r) => (r.ok ? r.json() : null))
      .then((d) => {
        if (d) setCorrelations(d);
      })
      .catch(() => {})
      .finally(() => setCorrLoading(false));
  }, [result?.emailScanId]);

  const analyze = useCallback(async () => {
    if (!headers.trim() || headers.trim().length < 20) {
      setError(
        "Paste raw email headers (at least the From, Received, and Authentication-Results lines)",
      );
      return;
    }
    setLoading(true);
    setResult(null);
    setError(null);
    try {
      const res = await fetch(`${API_BASE}/api/scan/headers`, {
        method: "POST",
        headers: authHeader(),
        body: JSON.stringify({ headers: headers.trim() }),
      });
      if (!res.ok) {
        const d = await res.json().catch(() => ({}));
        throw new Error(d.error || `Analysis failed (${res.status})`);
      }
      const data = await res.json();
      setResult(data);
      setActiveTab("overview");
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, [headers]);

  const downloadReport = () => {
    if (!result) return;
    const lines = [
      "PHISHNETRA — EMAIL FORENSIC INVESTIGATION REPORT",
      `Generated: ${new Date().toLocaleString()}`,
      "═".repeat(60),
      "",
      `VERDICT:           ${(result.status || "unknown").toUpperCase()}`,
      `RISK SCORE:        ${result.riskScore}/100`,
      `CONFIDENCE:        ${result.confidence || "unknown"}`,
      "",
      "SENDER INFORMATION",
      `From Domain:       ${result.fromDomain || "—"}`,
      `Reply-To Domain:   ${result.replyToDomain || "—"}`,
      `Source IP:         ${result.sourceIP || "—"}`,
      "",
      "GEO INTELLIGENCE",
      `Location:          ${[result.sourceGeo?.city, result.sourceGeo?.region, result.sourceGeo?.country].filter(Boolean).join(", ") || "—"}`,
      `ISP:               ${result.sourceGeo?.isp || "—"}`,
      `Connection Type:   ${result.originType || "—"}`,
      `Attribution:       ${result.attributionConfidence ?? "—"}%`,
      "",
      "RELAY CHAIN",
      `Total Hops:        ${result.hops || 0}`,
      `Relay Anomalies:   ${result.relayAnomalies?.length || 0}`,
      ...(result.relayChain?.map(
        (h: any, i: number) =>
          `  Hop ${i + 1}: ${h.fromHost || h.fromIP || "unknown"} → ${h.byHost || "unknown"} (${h.protocol || "SMTP"})${h.delayFormatted ? " +" + h.delayFormatted : ""}`,
      ) || []),
      "",
      "DOMAIN INTELLIGENCE",
      `MX Records:        ${result.domainIntel?.hasMX ? result.domainIntel.mxRecords?.join(", ") : "None"}`,
      `MX Provider:       ${result.domainIntel?.mxProvider || "—"}`,
      `TLD Risk:          ${result.domainIntel?.tld} (${result.domainIntel?.tldRisk || 0}/100)`,
      `Brand Lookalike:   ${result.domainIntel?.lookalikeBrand || "None detected"}`,
      "",
      "MX / SPF VALIDATION",
      `Live SPF Result:   ${result.mxValidation?.spfLiveResult?.toUpperCase() || "—"}`,
      `MX Route Match:    ${result.mxValidation?.mxMismatch ? "MISMATCH" : "OK"}`,
      `Mail Platform:     ${result.mxValidation?.mxProvider || "—"}`,
      "",
      "IP REPUTATION",
      `Reputation Score:  ${result.ipReputation?.reputationScore ?? "—"}/100`,
      `Verdict:           ${result.ipReputation?.verdict?.toUpperCase() || "—"}`,
      `Threat Label:      ${result.ipReputation?.threatLabel || "—"}`,
      `DNSBL Hits:        ${result.ipReputation?.dnsblHits?.length || 0}`,
      ...(result.ipReputation?.dnsblHits?.map(
        (h: any) => `  • ${h.list}: ${h.meaning}`,
      ) || []),
      "",
      "DETECTION SIGNALS",
      ...(result.signals?.map((s: any) => `  [${s.label}] ${s.value}`) || []),
      "",
      "ISSUES DETECTED",
      ...(result.issues?.map(
        (issue: string, i: number) => `  ${i + 1}. ${issue}`,
      ) || []),
      "",
      "═".repeat(60),
      `MITRE ATT&CK: T1566 - Phishing | T1534 - Internal Spearphishing`,
      `Report generated by PhishNetra AI v6.0`,
    ];
    const blob = new Blob([lines.join("\n")], { type: "text/plain" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `PhishNetra-EmailForensics-${Date.now()}.txt`;
    a.click();
  };

  const vc = result
    ? VERDICT_STYLE[result.status as keyof typeof VERDICT_STYLE] ||
      VERDICT_STYLE.safe
    : null;

  const TABS = [
    { id: "overview", label: "Overview", icon: Shield },
    { id: "relay", label: "Relay Chain", icon: Activity },
    { id: "domain", label: "Domain Intel", icon: Globe },
    { id: "ip", label: "IP Reputation", icon: MapPin },
    { id: "mx", label: "MX / SPF", icon: Mail },
    { id: "raw", label: "Raw Issues", icon: FileText },
    { id: "correlation", label: "Correlations", icon: Zap },
  ] as const;

  return (
    <div
      className="min-h-full py-10 px-6"
      style={{ background: "var(--bg-base)" }}
    >
      <div className="max-w-6xl mx-auto">
        {/* Header */}
        <motion.div
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          className="mb-8"
        >
          <div className="tag-blue inline-flex mb-3">
            <Mail className="size-3" /> EMAIL FORENSICS
          </div>
          <h1
            className="font-display text-4xl mb-1.5"
            style={{ color: "var(--text-primary)" }}
          >
            Email Forensic Investigation
          </h1>
          <p style={{ color: "var(--text-muted)", fontSize: 14 }}>
            Deep header analysis · IP geolocation · Relay chain reconstruction ·
            Live SPF/MX validation · IP reputation · DNSBL checks
          </p>
        </motion.div>

        {/* Input panel */}
        <div className="card p-5 mb-6">
          <div className="flex items-center justify-between mb-3">
            <div
              className="text-sm font-semibold"
              style={{ color: "var(--text-primary)" }}
            >
              Paste Raw Email Headers
            </div>
            <div className="flex gap-2">
              <button
                onClick={() => setShowSamples((s) => !s)}
                className="text-xs btn-ghost px-3 py-1.5 flex items-center gap-1.5"
              >
                <FileText className="size-3.5" /> Sample Headers
              </button>
              {headers && (
                <button
                  onClick={() => {
                    setHeaders("");
                    setResult(null);
                    setError(null);
                  }}
                  className="text-xs btn-ghost px-3 py-1.5"
                >
                  Clear
                </button>
              )}
            </div>
          </div>

          {/* Sample header quick-load */}
          <AnimatePresence>
            {showSamples && (
              <motion.div
                initial={{ height: 0, opacity: 0 }}
                animate={{ height: "auto", opacity: 1 }}
                exit={{ height: 0, opacity: 0 }}
                className="overflow-hidden mb-3"
              >
                <div className="flex flex-wrap gap-2 pb-2">
                  {SAMPLE_HEADERS.map((s) => (
                    <button
                      key={s.label}
                      onClick={() => {
                        setHeaders(s.headers);
                        setShowSamples(false);
                      }}
                      className="text-xs px-3 py-1.5 rounded-lg transition-all"
                      style={{
                        background: "var(--bg-elevated)",
                        color: "var(--text-secondary)",
                        border: "1px solid var(--bg-border)",
                      }}
                    >
                      {s.label}
                    </button>
                  ))}
                </div>
              </motion.div>
            )}
          </AnimatePresence>

          <textarea
            ref={textareaRef}
            value={headers}
            onChange={(e) => setHeaders(e.target.value)}
            placeholder={`Paste full email headers here. You can find them in:
• Gmail → ⋮ → Show Original → copy the top section
• Outlook → File → Properties → copy "Internet headers"
• Thunderbird → View → Message Source → copy headers

Example:
From: "PayPal Security" <security@paypal-secure.tk>
Received: from mail.attacker.ng ([41.190.3.155])...
Authentication-Results: spf=fail...`}
            rows={8}
            className="w-full px-4 py-3 rounded-xl text-xs resize-y mb-3"
            style={{
              background: "var(--bg-elevated)",
              border: "1px solid var(--bg-border)",
              color: "var(--text-primary)",
              outline: "none",
              fontFamily: "var(--font-mono)",
              lineHeight: 1.6,
              minHeight: 180,
            }}
          />

          <div className="flex items-center justify-between">
            <span className="text-xs" style={{ color: "var(--text-muted)" }}>
              {headers.split("\n").filter((l) => l.trim()).length} header lines
            </span>
            <button
              onClick={analyze}
              disabled={loading || !headers.trim()}
              className="flex items-center gap-2 px-6 py-2.5 rounded-xl text-sm font-semibold transition-all"
              style={{
                background:
                  loading || !headers.trim()
                    ? "var(--bg-elevated)"
                    : "var(--accent)",
                color:
                  loading || !headers.trim() ? "var(--text-muted)" : "#fff",
              }}
            >
              {loading ? (
                <>
                  <RefreshCw className="size-4 animate-spin" /> Analyzing...
                </>
              ) : (
                <>
                  <Search className="size-4" /> Investigate
                </>
              )}
            </button>
          </div>
        </div>

        {/* Error */}
        {error && (
          <div
            className="flex items-center gap-2 px-4 py-2.5 rounded-xl mb-4"
            style={{
              background: "rgba(248,113,113,0.08)",
              border: "1px solid rgba(248,113,113,0.2)",
            }}
          >
            <AlertTriangle
              className="size-4 flex-shrink-0"
              style={{ color: "var(--color-danger)" }}
            />
            <span
              className="text-xs flex-1"
              style={{ color: "var(--color-danger)" }}
            >
              {error}
            </span>
            <button
              onClick={() => setError(null)}
              style={{
                background: "none",
                border: "none",
                cursor: "pointer",
                color: "var(--text-muted)",
              }}
            >
              ✕
            </button>
          </div>
        )}

        {/* Results */}
        <AnimatePresence>
          {result && vc && (
            <motion.div
              initial={{ opacity: 0, y: 16 }}
              animate={{ opacity: 1, y: 0 }}
            >
              {/* Verdict banner */}
              <div
                className="rounded-2xl overflow-hidden mb-4"
                style={{ background: vc.bg, border: `1px solid ${vc.border}` }}
              >
                <div className="px-6 py-5 flex items-center gap-4">
                  {result.status === "safe" ? (
                    <CheckCircle
                      className="size-10 flex-shrink-0"
                      style={{ color: vc.text }}
                    />
                  ) : (
                    <AlertTriangle
                      className="size-10 flex-shrink-0"
                      style={{ color: vc.text }}
                    />
                  )}
                  <div className="flex-1">
                    <div
                      className="text-2xl font-black"
                      style={{ color: vc.text }}
                    >
                      {vc.label}
                    </div>
                    <div
                      className="text-sm mt-0.5"
                      style={{ color: "var(--text-muted)" }}
                    >
                      From:{" "}
                      <span
                        style={{
                          color: "var(--text-primary)",
                          fontFamily: "var(--font-mono)",
                        }}
                      >
                        {result.fromDomain || "unknown"}
                      </span>
                      {result.replyToDomain &&
                        result.replyToDomain !== result.fromDomain && (
                          <>
                            {" "}
                            → Reply-To:{" "}
                            <span
                              style={{
                                color: "#f87171",
                                fontFamily: "var(--font-mono)",
                              }}
                            >
                              {result.replyToDomain}
                            </span>
                          </>
                        )}
                    </div>
                  </div>
                  <div className="text-right flex-shrink-0">
                    <div
                      className="text-4xl font-black"
                      style={{ color: vc.text }}
                    >
                      {result.riskScore}
                    </div>
                    <div
                      className="text-xs"
                      style={{
                        color: "var(--text-muted)",
                        fontFamily: "var(--font-mono)",
                      }}
                    >
                      /100 risk
                    </div>
                    <div
                      className="text-xs mt-1 capitalize"
                      style={{ color: "var(--text-muted)" }}
                    >
                      {result.confidence} confidence
                    </div>
                  </div>
                </div>

                {/* Signal badges */}
                {result.signals?.length > 0 && (
                  <div className="px-6 pb-4 flex flex-wrap gap-1.5">
                    {result.signals.map((s: any, i: number) => (
                      <span
                        key={i}
                        className="text-[10px] px-2 py-1 rounded font-bold"
                        style={{
                          color: s.color || "var(--accent)",
                          background: `${s.color || "var(--accent)"}15`,
                          border: `1px solid ${s.color || "var(--accent)"}30`,
                          fontFamily: "var(--font-mono)",
                          textTransform: "uppercase",
                        }}
                      >
                        {s.label}: {s.value}
                      </span>
                    ))}
                  </div>
                )}

                {/* Risk bar */}
                <div className="px-6 pb-4">
                  <div
                    className="rounded-full overflow-hidden"
                    style={{ height: 4, background: "rgba(255,255,255,0.06)" }}
                  >
                    <motion.div
                      initial={{ width: 0 }}
                      animate={{ width: `${result.riskScore}%` }}
                      transition={{ duration: 0.8, ease: [0.23, 1, 0.32, 1] }}
                      className="h-full rounded-full"
                      style={{
                        background: `linear-gradient(90deg, ${vc.text}80, ${vc.text})`,
                      }}
                    />
                  </div>
                </div>

                {/* Quick actions */}
                <div className="px-6 pb-4 flex gap-2">
                  <button
                    onClick={downloadReport}
                    className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs"
                    style={{
                      background: "rgba(255,255,255,0.07)",
                      color: "var(--text-secondary)",
                      border: "1px solid rgba(255,255,255,0.1)",
                    }}
                  >
                    <Download className="size-3.5" /> Download Report
                  </button>
                  <button
                    onClick={() => {
                      navigator.clipboard.writeText(
                        JSON.stringify(result, null, 2),
                      );
                      setCopied(true);
                      setTimeout(() => setCopied(false), 2000);
                    }}
                    className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs"
                    style={{
                      background: "rgba(255,255,255,0.07)",
                      color: "var(--text-secondary)",
                      border: "1px solid rgba(255,255,255,0.1)",
                    }}
                  >
                    <Copy className="size-3.5" />{" "}
                    {copied ? "Copied!" : "Copy JSON"}
                  </button>
                </div>
              </div>

              {/* Tabs */}
              <div
                className="flex gap-1 p-1 rounded-xl mb-4 overflow-x-auto"
                style={{
                  background: "var(--bg-elevated)",
                  border: "1px solid var(--bg-border)",
                }}
              >
                {TABS.map((tab) => {
                  const Icon = tab.icon;
                  return (
                    <button
                      key={tab.id}
                      onClick={() => setActiveTab(tab.id)}
                      className="flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-medium whitespace-nowrap transition-all flex-shrink-0"
                      style={{
                        background:
                          activeTab === tab.id
                            ? "var(--accent-subtle)"
                            : "transparent",
                        color:
                          activeTab === tab.id
                            ? "var(--accent)"
                            : "var(--text-muted)",
                        border:
                          activeTab === tab.id
                            ? "1px solid var(--accent-border)"
                            : "1px solid transparent",
                      }}
                    >
                      <Icon className="size-3.5" /> {tab.label}
                    </button>
                  );
                })}
              </div>

              {/* ── TAB: Overview ── */}
              {activeTab === "overview" && (
                <div className="space-y-3">
                  {/* Attribution confidence */}
                  <div className="card p-5">
                    <div className="label-caps mb-4">
                      Attribution Intelligence
                    </div>
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                      {[
                        {
                          label: "Source IP",
                          value: result.sourceIP || "Not found",
                          color: "var(--accent)",
                          mono: true,
                        },
                        {
                          label: "Origin Country",
                          value: result.sourceGeo?.country || "—",
                          color: "var(--text-primary)",
                        },
                        {
                          label: "Origin Type",
                          value: result.originType?.replace(/_/g, " ") || "—",
                          color: result.sourceGeo?.isTor
                            ? "#f87171"
                            : result.sourceGeo?.isVPN
                              ? "#fbbf24"
                              : "var(--safe)",
                        },
                        {
                          label: "Attribution",
                          value: `${result.attributionConfidence ?? 0}%`,
                          color:
                            (result.attributionConfidence || 0) >= 60
                              ? "var(--safe)"
                              : (result.attributionConfidence || 0) >= 30
                                ? "#fbbf24"
                                : "#f87171",
                        },
                      ].map((s) => (
                        <div
                          key={s.label}
                          className="px-4 py-3 rounded-xl"
                          style={{
                            background: "var(--bg-elevated)",
                            border: "1px solid var(--bg-border)",
                          }}
                        >
                          <div className="label-caps mb-1">{s.label}</div>
                          <div
                            className="text-sm font-bold"
                            style={{
                              color: s.color,
                              fontFamily: (s as any).mono
                                ? "var(--font-mono)"
                                : undefined,
                            }}
                          >
                            {s.value}
                          </div>
                        </div>
                      ))}
                    </div>

                    {/* Attribution confidence explanation */}
                    <div
                      className="mt-3 px-4 py-3 rounded-xl text-xs"
                      style={{
                        background: "var(--bg-base)",
                        border: "1px solid var(--bg-border)",
                      }}
                    >
                      <div
                        className="font-semibold mb-1"
                        style={{ color: "var(--text-secondary)" }}
                      >
                        Investigation Recommendation
                      </div>
                      <div style={{ color: "var(--text-muted)" }}>
                        {result.sourceGeo?.isTor
                          ? "Source is a TOR exit node — attacker is effectively untraceable. Focus on domain/campaign pattern matching rather than IP attribution."
                          : result.sourceGeo?.isVPN
                            ? "Source is a VPN provider. Submit a legal preservation request to the VPN provider with timestamp for subscriber records."
                            : result.sourceGeo?.isDatacenter
                              ? "Source is a datacenter IP. Submit a legal preservation request to the hosting provider for account/billing records."
                              : (result.attributionConfidence || 0) >= 60
                                ? "Residential IP with high geo-attribution confidence. ISP subscriber records can be obtained via legal process for this IP + timestamp."
                                : "Insufficient data for confident attribution. Expand analysis with campaign correlation."}
                      </div>
                    </div>
                  </div>

                  {/* Quick geo summary */}
                  {result.sourceGeo?.country && (
                    <div className="card p-5">
                      <div className="label-caps mb-3">Origin Geolocation</div>
                      <div className="grid grid-cols-2 md:grid-cols-3 gap-3 text-xs">
                        {[
                          {
                            label: "City / Region",
                            value:
                              [result.sourceGeo.city, result.sourceGeo.region]
                                .filter(Boolean)
                                .join(", ") || "—",
                          },
                          {
                            label: "Country",
                            value: result.sourceGeo.country || "—",
                          },
                          { label: "ISP", value: result.sourceGeo.isp || "—" },
                          { label: "ASN", value: result.sourceGeo.asn || "—" },
                          {
                            label: "Connection",
                            value: result.sourceGeo.isTor
                              ? "TOR Exit Node"
                              : result.sourceGeo.isVPN
                                ? "VPN"
                                : result.sourceGeo.isDatacenter
                                  ? "Datacenter"
                                  : result.sourceGeo.isMobile
                                    ? "Mobile"
                                    : "Residential",
                          },
                          {
                            label: "Abuse Risk",
                            value: result.sourceGeo.abuseRisk || "low",
                          },
                        ].map((s) => (
                          <div key={s.label}>
                            <div className="label-caps mb-0.5">{s.label}</div>
                            <div
                              style={{
                                color: "var(--text-secondary)",
                                fontFamily: "var(--font-mono)",
                              }}
                            >
                              {s.value}
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* ── Attribution Intelligence Panel (GAP 10) ── */}
                  {result?.attribution && (
                    <div className="card overflow-hidden">
                      {/* Actor type header */}
                      <div
                        className="px-5 py-4 flex items-center gap-4"
                        style={{
                          background: `${result.attribution.actorColor}08`,
                          borderBottom: "1px solid var(--bg-border)",
                        }}
                      >
                        <span className="text-3xl flex-shrink-0">
                          {result.attribution.actorIcon}
                        </span>
                        <div className="flex-1 min-w-0">
                          <div
                            className="font-bold text-base"
                            style={{ color: result.attribution.actorColor }}
                          >
                            {result.attribution.actorLabel}
                          </div>
                          <div
                            className="text-xs mt-0.5"
                            style={{ color: "var(--text-muted)" }}
                          >
                            {result.attribution.actorDesc}
                          </div>
                        </div>
                        <div className="text-right flex-shrink-0">
                          <div
                            className="text-3xl font-black"
                            style={{ color: result.attribution.actorColor }}
                          >
                            {result.attribution.confidence}%
                          </div>
                          <div
                            className="text-xs mt-0.5"
                            style={{ color: "var(--text-muted)" }}
                          >
                            attribution confidence
                          </div>
                        </div>
                      </div>

                      {/* Investigation tier badge */}
                      <div
                        className="px-5 py-3 flex items-center gap-3"
                        style={{
                          borderBottom: "1px solid var(--bg-border)",
                          background: "var(--bg-elevated)",
                        }}
                      >
                        <div
                          className="text-xs font-bold px-2.5 py-1 rounded-lg flex-shrink-0"
                          style={{
                            color: result.attribution.investigationColor,
                            background: `${result.attribution.investigationColor}15`,
                            border: `1px solid ${result.attribution.investigationColor}30`,
                            fontFamily: "var(--font-mono)",
                          }}
                        >
                          {result.attribution.investigationTier}
                        </div>
                        <div className="min-w-0">
                          <div
                            className="text-xs font-semibold"
                            style={{ color: "var(--text-primary)" }}
                          >
                            {result.attribution.investigationLabel}
                          </div>
                          <div
                            className="text-[10px] mt-0.5"
                            style={{ color: "var(--text-muted)" }}
                          >
                            {result.attribution.investigationDesc}
                          </div>
                        </div>
                      </div>

                      <div className="p-5 space-y-4">
                        {/* Confidence bar */}
                        <div>
                          <div className="flex justify-between mb-1.5 text-xs">
                            <span style={{ color: "var(--text-muted)" }}>
                              Attribution Confidence
                            </span>
                            <span
                              className="font-bold"
                              style={{ color: result.attribution.actorColor }}
                            >
                              {result.attribution.confidence}% —{" "}
                              {result.attribution.confidenceLabel}
                            </span>
                          </div>
                          <div
                            className="rounded-full overflow-hidden"
                            style={{
                              height: 6,
                              background: "var(--bg-elevated)",
                            }}
                          >
                            <div
                              className="h-full rounded-full transition-all duration-700"
                              style={{
                                width: `${result.attribution.confidence}%`,
                                background: `linear-gradient(90deg, ${result.attribution.actorColor}80, ${result.attribution.actorColor})`,
                              }}
                            />
                          </div>
                        </div>

                        {/* Signal breakdown — two columns */}
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                          {/* Positive signals */}
                          {result.attribution.signals.positive.length > 0 && (
                            <div>
                              <div
                                className="label-caps mb-2"
                                style={{ color: "var(--safe)" }}
                              >
                                ↑ Signals That Help Attribution (
                                {result.attribution.signals.positive.length})
                              </div>
                              <div className="space-y-1.5">
                                {result.attribution.signals.positive.map(
                                  (sig: any) => (
                                    <div
                                      key={sig.id}
                                      className="px-3 py-2 rounded-xl"
                                      style={{
                                        background: "rgba(52,211,153,0.05)",
                                        border:
                                          "1px solid rgba(52,211,153,0.15)",
                                      }}
                                    >
                                      <div className="flex items-center justify-between mb-0.5">
                                        <span
                                          className="text-xs font-semibold"
                                          style={{ color: "var(--safe)" }}
                                        >
                                          {sig.label}
                                        </span>
                                        <span
                                          className="text-[9px] font-bold"
                                          style={{
                                            color: "var(--safe)",
                                            fontFamily: "var(--font-mono)",
                                          }}
                                        >
                                          +{sig.weight}%
                                        </span>
                                      </div>
                                      <p
                                        className="text-[10px] leading-relaxed"
                                        style={{ color: "var(--text-muted)" }}
                                      >
                                        {sig.detail}
                                      </p>
                                    </div>
                                  ),
                                )}
                              </div>
                            </div>
                          )}

                          {/* Negative signals */}
                          {result.attribution.signals.negative.length > 0 && (
                            <div>
                              <div
                                className="label-caps mb-2"
                                style={{ color: "#f87171" }}
                              >
                                ↓ Signals That Hinder Attribution (
                                {result.attribution.signals.negative.length})
                              </div>
                              <div className="space-y-1.5">
                                {result.attribution.signals.negative.map(
                                  (sig: any) => (
                                    <div
                                      key={sig.id}
                                      className="px-3 py-2 rounded-xl"
                                      style={{
                                        background: "rgba(248,113,113,0.05)",
                                        border:
                                          "1px solid rgba(248,113,113,0.15)",
                                      }}
                                    >
                                      <div className="flex items-center justify-between mb-0.5">
                                        <span
                                          className="text-xs font-semibold"
                                          style={{ color: "#f87171" }}
                                        >
                                          {sig.label}
                                        </span>
                                        <span
                                          className="text-[9px] font-bold"
                                          style={{
                                            color: "#f87171",
                                            fontFamily: "var(--font-mono)",
                                          }}
                                        >
                                          {sig.weight}%
                                        </span>
                                      </div>
                                      <p
                                        className="text-[10px] leading-relaxed"
                                        style={{ color: "var(--text-muted)" }}
                                      >
                                        {sig.detail}
                                      </p>
                                    </div>
                                  ),
                                )}
                              </div>
                            </div>
                          )}
                        </div>

                        {/* Priority investigation actions */}
                        {result.attribution.priorityActions?.length > 0 && (
                          <div>
                            <div className="label-caps mb-2">
                              Priority Investigation Actions
                            </div>
                            <div className="space-y-2">
                              {result.attribution.priorityActions.map(
                                (action: any, i: number) => (
                                  <div
                                    key={i}
                                    className="px-4 py-3 rounded-xl"
                                    style={{
                                      background: "var(--bg-elevated)",
                                      border: "1px solid var(--bg-border)",
                                    }}
                                  >
                                    <div className="flex items-center gap-2 mb-1">
                                      <span
                                        className="text-[9px] font-bold px-1.5 py-0.5 rounded"
                                        style={{
                                          color: "var(--accent)",
                                          background: "var(--accent-subtle)",
                                          fontFamily: "var(--font-mono)",
                                        }}
                                      >
                                        ACTION {i + 1}
                                      </span>
                                      <span
                                        className="text-xs font-semibold"
                                        style={{ color: "var(--text-primary)" }}
                                      >
                                        {action.label}
                                      </span>
                                    </div>
                                    <p
                                      className="text-[10px] leading-relaxed"
                                      style={{ color: "var(--text-muted)" }}
                                    >
                                      {action.action}
                                    </p>
                                  </div>
                                ),
                              )}
                            </div>
                          </div>
                        )}

                        {/* Investigation IOCs */}
                        <div>
                          <div className="label-caps mb-2">
                            Investigation IOCs
                          </div>
                          <div className="grid grid-cols-2 md:grid-cols-3 gap-2">
                            {Object.entries(
                              result.attribution.investigationIOCs,
                            )
                              .filter(([, v]) => v)
                              .map(([k, v]) => (
                                <div
                                  key={k}
                                  className="px-3 py-2 rounded-lg"
                                  style={{
                                    background: "var(--bg-base)",
                                    border: "1px solid var(--bg-border)",
                                  }}
                                >
                                  <div
                                    className="text-[9px] uppercase tracking-wider mb-0.5"
                                    style={{
                                      color: "var(--text-muted)",
                                      fontFamily: "var(--font-mono)",
                                    }}
                                  >
                                    {k.replace(/([A-Z])/g, " $1").trim()}
                                  </div>
                                  <div
                                    className="text-[10px] font-medium truncate"
                                    style={{
                                      color: "var(--accent)",
                                      fontFamily: "var(--font-mono)",
                                    }}
                                  >
                                    {v as string}
                                  </div>
                                </div>
                              ))}
                          </div>
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* ── TAB: Relay Chain ── */}
              {activeTab === "relay" && (
                <div className="card overflow-hidden">
                  <div
                    className="px-5 py-3.5 border-b flex items-center justify-between"
                    style={{
                      borderColor: "var(--bg-border)",
                      background: "var(--bg-elevated)",
                    }}
                  >
                    <span
                      className="text-sm font-semibold"
                      style={{ color: "var(--text-primary)" }}
                    >
                      SMTP Relay Path — {result.hops || 0} hop
                      {result.hops !== 1 ? "s" : ""}
                    </span>
                    {result.relayAnomalies?.length > 0 && (
                      <span
                        className="text-xs px-2 py-0.5 rounded"
                        style={{
                          color: "#f87171",
                          background: "rgba(248,113,113,0.1)",
                          border: "1px solid rgba(248,113,113,0.2)",
                          fontFamily: "var(--font-mono)",
                        }}
                      >
                        {result.relayAnomalies.length} anomal
                        {result.relayAnomalies.length !== 1 ? "ies" : "y"}
                      </span>
                    )}
                  </div>

                  {!result.relayChain?.length ? (
                    <div className="p-8 text-center">
                      <Activity
                        className="size-10 mx-auto mb-2"
                        style={{ color: "var(--text-muted)" }}
                      />
                      <p
                        className="text-sm"
                        style={{ color: "var(--text-muted)" }}
                      >
                        No Received headers found — paste headers with Received:
                        lines for relay analysis
                      </p>
                    </div>
                  ) : (
                    <div className="p-5">
                      {/* Visual chain */}
                      <div className="flex items-start gap-0 overflow-x-auto pb-4 mb-5">
                        {result.relayChain.map((hop: any, i: number) => {
                          const hasAno = hop.anomalies?.length > 0;
                          const isFirst = i === 0;
                          const isLast = i === result.relayChain.length - 1;
                          const nodeColor = hasAno
                            ? "#f87171"
                            : isFirst
                              ? "#60a5fa"
                              : isLast
                                ? "#34d399"
                                : "var(--text-muted)";
                          return (
                            <div
                              key={i}
                              className="flex items-center flex-shrink-0"
                            >
                              <div
                                className="flex flex-col items-center text-center"
                                style={{ minWidth: 130, maxWidth: 140 }}
                              >
                                {/* Node */}
                                <div
                                  className="w-10 h-10 rounded-full flex items-center justify-center font-bold text-sm mb-2"
                                  style={{
                                    background: `${nodeColor}15`,
                                    border: `2px solid ${nodeColor}`,
                                    color: nodeColor,
                                  }}
                                >
                                  {i + 1}
                                </div>
                                {/* Label */}
                                <div
                                  className="text-[10px] font-semibold truncate w-full px-1"
                                  style={{
                                    color: nodeColor,
                                    fontFamily: "var(--font-mono)",
                                  }}
                                >
                                  {hop.fromHost?.length > 18
                                    ? hop.fromHost.substring(0, 16) + "…"
                                    : hop.fromHost || hop.fromIP || "unknown"}
                                </div>
                                {hop.fromIP && hop.fromIP !== hop.fromHost && (
                                  <div
                                    className="text-[9px] truncate w-full px-1"
                                    style={{
                                      color: "var(--text-muted)",
                                      fontFamily: "var(--font-mono)",
                                    }}
                                  >
                                    {hop.fromIP}
                                  </div>
                                )}
                                {hop.protocol && (
                                  <div
                                    className="text-[9px] px-1.5 py-0.5 rounded mt-1"
                                    style={{
                                      color: "var(--accent)",
                                      background: "var(--accent-subtle)",
                                      fontFamily: "var(--font-mono)",
                                    }}
                                  >
                                    {hop.protocol}
                                  </div>
                                )}
                                {hop.delayFormatted && i > 0 && (
                                  <div
                                    className="text-[9px] mt-1"
                                    style={{
                                      color:
                                        hop.delayMs < 0
                                          ? "#f87171"
                                          : hop.delayMs > 7200000
                                            ? "#fbbf24"
                                            : "var(--text-muted)",
                                    }}
                                  >
                                    +{hop.delayFormatted}
                                  </div>
                                )}
                                {hasAno && (
                                  <div
                                    className="text-[9px] mt-1"
                                    style={{
                                      color: "#f87171",
                                      fontWeight: 600,
                                    }}
                                  >
                                    ⚠ {hop.anomalies[0].label}
                                  </div>
                                )}
                                <div
                                  className="text-[9px] mt-1 truncate w-full px-1"
                                  style={{
                                    color: "var(--text-muted)",
                                    fontFamily: "var(--font-mono)",
                                  }}
                                >
                                  {isFirst
                                    ? "ORIGIN"
                                    : isLast
                                      ? "DESTINATION"
                                      : "RELAY"}
                                </div>
                              </div>
                              {i < result.relayChain.length - 1 && (
                                <div
                                  className="flex-shrink-0 mx-2 text-sm"
                                  style={{ color: "var(--text-muted)" }}
                                >
                                  →
                                </div>
                              )}
                            </div>
                          );
                        })}
                      </div>

                      {/* Hop details table */}
                      <div
                        className="divide-y"
                        style={{ borderColor: "var(--bg-border)" }}
                      >
                        {result.relayChain.map((hop: any, i: number) => (
                          <div key={i} className="py-3">
                            <div className="flex items-center gap-2 mb-1">
                              <span
                                className="text-[10px] font-bold px-2 py-0.5 rounded"
                                style={{
                                  color:
                                    i === 0
                                      ? "#60a5fa"
                                      : i === result.relayChain.length - 1
                                        ? "#34d399"
                                        : "var(--text-muted)",
                                  background: "var(--bg-elevated)",
                                  fontFamily: "var(--font-mono)",
                                }}
                              >
                                HOP {i + 1}
                              </span>
                              <span
                                className="text-xs font-medium"
                                style={{
                                  color: "var(--text-primary)",
                                  fontFamily: "var(--font-mono)",
                                }}
                              >
                                {hop.fromHost || hop.fromIP || "unknown"} →{" "}
                                {hop.byHost || "unknown"}
                              </span>
                              {hop.protocol && (
                                <span
                                  className="text-[9px] px-1.5 py-0.5 rounded"
                                  style={{
                                    color: "var(--accent)",
                                    background: "var(--accent-subtle)",
                                    fontFamily: "var(--font-mono)",
                                  }}
                                >
                                  {hop.protocol}
                                </span>
                              )}
                              {hop.delayFormatted && i > 0 && (
                                <span
                                  className="text-[9px] ml-auto"
                                  style={{
                                    color:
                                      hop.delayMs < 0
                                        ? "#f87171"
                                        : "var(--text-muted)",
                                    fontFamily: "var(--font-mono)",
                                  }}
                                >
                                  +{hop.delayFormatted}
                                </span>
                              )}
                            </div>
                            {hop.timestamp && (
                              <div
                                className="text-[10px]"
                                style={{
                                  color: "var(--text-muted)",
                                  fontFamily: "var(--font-mono)",
                                  paddingLeft: 4,
                                }}
                              >
                                {hop.timestamp}
                              </div>
                            )}
                            {hop.anomalies?.map((a: any, ai: number) => (
                              <div
                                key={ai}
                                className="mt-1.5 flex items-start gap-2 px-3 py-1.5 rounded-lg text-[10px]"
                                style={{
                                  background: "rgba(248,113,113,0.06)",
                                  border: "1px solid rgba(248,113,113,0.15)",
                                }}
                              >
                                <span style={{ color: "#f87171" }}>⚠</span>
                                <span style={{ color: "var(--text-muted)" }}>
                                  {a.detail}
                                </span>
                                <span
                                  className="ml-auto flex-shrink-0"
                                  style={{
                                    color: "#f87171",
                                    fontFamily: "var(--font-mono)",
                                  }}
                                >
                                  +{a.risk}
                                </span>
                              </div>
                            ))}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* ── TAB: Domain Intel ── */}
              {activeTab === "domain" && (
                <div className="card p-5 space-y-4">
                  {!result.domainIntel ? (
                    <div className="text-center py-8">
                      <Globe
                        className="size-10 mx-auto mb-2"
                        style={{ color: "var(--text-muted)" }}
                      />
                      <p
                        className="text-sm"
                        style={{ color: "var(--text-muted)" }}
                      >
                        Domain intelligence not available
                      </p>
                    </div>
                  ) : (
                    <>
                      <div className="label-caps mb-1">
                        Sender Domain:{" "}
                        <span
                          style={{
                            color: "var(--accent)",
                            fontFamily: "var(--font-mono)",
                          }}
                        >
                          {result.domainIntel.domain}
                        </span>
                      </div>
                      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                        {[
                          {
                            label: "MX Records",
                            value: result.domainIntel.hasMX
                              ? `${result.domainIntel.mxRecords?.length} found`
                              : "None",
                            color: result.domainIntel.hasMX
                              ? "var(--safe)"
                              : "#f87171",
                          },
                          {
                            label: "TLD",
                            value: `${result.domainIntel.tld} (${result.domainIntel.tldRisk || 0}/100)`,
                            color: result.domainIntel.isHighRiskTLD
                              ? "#fb923c"
                              : "var(--safe)",
                          },
                          {
                            label: "Free TLD",
                            value: result.domainIntel.isFreeTLD
                              ? "Yes (disposable)"
                              : "No",
                            color: result.domainIntel.isFreeTLD
                              ? "#f87171"
                              : "var(--safe)",
                          },
                          {
                            label: "Lookalike",
                            value: result.domainIntel.lookalikeBrand || "None",
                            color: result.domainIntel.lookalikeBrand
                              ? "#f87171"
                              : "var(--safe)",
                          },
                        ].map((s) => (
                          <div
                            key={s.label}
                            className="px-4 py-3 rounded-xl"
                            style={{
                              background: "var(--bg-elevated)",
                              border: "1px solid var(--bg-border)",
                            }}
                          >
                            <div className="label-caps mb-1">{s.label}</div>
                            <div
                              className="text-sm font-bold"
                              style={{ color: s.color }}
                            >
                              {s.value}
                            </div>
                          </div>
                        ))}
                      </div>
                      {result.domainIntel.mxRecords?.length > 0 && (
                        <div>
                          <div className="label-caps mb-2">MX Records</div>
                          {result.domainIntel.mxRecords.map((mx: string) => (
                            <div
                              key={mx}
                              className="text-xs px-3 py-1.5 rounded-lg mb-1"
                              style={{
                                background: "var(--bg-elevated)",
                                color: "var(--accent)",
                                fontFamily: "var(--font-mono)",
                              }}
                            >
                              {mx}
                            </div>
                          ))}
                        </div>
                      )}
                      {result.domainIntel.domainAnomalies?.length > 0 && (
                        <div>
                          <div className="label-caps mb-2">Anomalies</div>
                          <div className="space-y-1.5">
                            {result.domainIntel.domainAnomalies.map(
                              (a: any, i: number) => (
                                <div
                                  key={i}
                                  className="flex items-start gap-2 px-3 py-2 rounded-xl text-xs"
                                  style={{
                                    background: "rgba(251,146,60,0.05)",
                                    border: "1px solid rgba(251,146,60,0.15)",
                                  }}
                                >
                                  <span style={{ color: "#fb923c" }}>●</span>
                                  <div>
                                    <span
                                      className="font-semibold"
                                      style={{ color: "#fb923c" }}
                                    >
                                      {a.label}:{" "}
                                    </span>
                                    <span
                                      style={{ color: "var(--text-muted)" }}
                                    >
                                      {a.detail}
                                    </span>
                                  </div>
                                  <span
                                    className="ml-auto text-[9px] px-1.5 py-0.5 rounded flex-shrink-0"
                                    style={{
                                      color: "#fb923c",
                                      background: "rgba(251,146,60,0.1)",
                                      fontFamily: "var(--font-mono)",
                                    }}
                                  >
                                    +{a.risk}
                                  </span>
                                </div>
                              ),
                            )}
                          </div>
                        </div>
                      )}
                    </>
                  )}
                </div>
              )}

              {/* ── TAB: IP Reputation ── */}
              {activeTab === "ip" && (
                <div className="card p-5">
                  {!result.ipReputation ? (
                    <div className="text-center py-8">
                      <MapPin
                        className="size-10 mx-auto mb-2"
                        style={{ color: "var(--text-muted)" }}
                      />
                      <p
                        className="text-sm"
                        style={{ color: "var(--text-muted)" }}
                      >
                        IP reputation data not available
                      </p>
                    </div>
                  ) : (
                    <div className="space-y-4">
                      <div
                        className="flex items-center gap-4 px-5 py-4 rounded-xl"
                        style={{
                          background:
                            result.ipReputation.verdict === "malicious"
                              ? "rgba(248,113,113,0.08)"
                              : result.ipReputation.verdict === "suspicious"
                                ? "rgba(251,191,36,0.08)"
                                : "rgba(52,211,153,0.07)",
                          border: `1px solid ${
                            result.ipReputation.verdict === "malicious"
                              ? "rgba(248,113,113,0.25)"
                              : result.ipReputation.verdict === "suspicious"
                                ? "rgba(251,191,36,0.25)"
                                : "rgba(52,211,153,0.25)"
                          }`,
                        }}
                      >
                        <div
                          className="text-3xl font-black"
                          style={{
                            color:
                              result.ipReputation.verdict === "malicious"
                                ? "#f87171"
                                : result.ipReputation.verdict === "suspicious"
                                  ? "#fbbf24"
                                  : "var(--safe)",
                          }}
                        >
                          {result.ipReputation.reputationScore}/100
                        </div>
                        <div>
                          <div
                            className="font-bold text-sm"
                            style={{
                              color:
                                result.ipReputation.verdict === "malicious"
                                  ? "#f87171"
                                  : "var(--text-primary)",
                            }}
                          >
                            {result.ipReputation.threatLabel ||
                              result.ipReputation.verdict?.toUpperCase()}
                          </div>
                          <div
                            className="text-xs mt-0.5"
                            style={{ color: "var(--text-muted)" }}
                          >
                            IP: {result.ipReputation.ip}
                            {result.ipReputation.seenInScans > 1 &&
                              ` · Seen ${result.ipReputation.seenInScans}× in PhishNetra`}
                          </div>
                        </div>
                      </div>

                      {/* DNSBL hits */}
                      {result.ipReputation.dnsblHits?.length > 0 ? (
                        <div>
                          <div className="label-caps mb-2">
                            Blacklist Hits (
                            {result.ipReputation.dnsblHits.length})
                          </div>
                          <div className="space-y-1.5">
                            {result.ipReputation.dnsblHits.map(
                              (hit: any, i: number) => (
                                <div
                                  key={i}
                                  className="flex items-center gap-3 px-4 py-2.5 rounded-xl"
                                  style={{
                                    background: "var(--bg-elevated)",
                                    border: "1px solid var(--bg-border)",
                                  }}
                                >
                                  <span
                                    className="font-bold text-xs"
                                    style={{
                                      color:
                                        hit.score >= 70 ? "#f87171" : "#fbbf24",
                                      fontFamily: "var(--font-mono)",
                                      minWidth: 120,
                                    }}
                                  >
                                    {hit.list}
                                  </span>
                                  <span
                                    className="text-xs flex-1"
                                    style={{ color: "var(--text-secondary)" }}
                                  >
                                    {hit.meaning}
                                  </span>
                                  <span
                                    className="text-[9px] px-1.5 py-0.5 rounded"
                                    style={{
                                      color:
                                        hit.score >= 70 ? "#f87171" : "#fbbf24",
                                      background:
                                        hit.score >= 70
                                          ? "rgba(248,113,113,0.1)"
                                          : "rgba(251,191,36,0.1)",
                                      fontFamily: "var(--font-mono)",
                                    }}
                                  >
                                    score {hit.score}
                                  </span>
                                </div>
                              ),
                            )}
                          </div>
                        </div>
                      ) : (
                        <div
                          className="px-4 py-3 rounded-xl text-sm"
                          style={{
                            background: "rgba(52,211,153,0.07)",
                            border: "1px solid rgba(52,211,153,0.2)",
                            color: "var(--safe)",
                          }}
                        >
                          ✓ Not listed in any DNSBL — IP is not a known
                          spam/botnet source
                        </div>
                      )}

                      {/* Boolean flags */}
                      <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
                        {[
                          {
                            label: "TOR Exit Node",
                            value: result.ipReputation.isTorExitNode,
                          },
                          {
                            label: "Botnet Member",
                            value: result.ipReputation.isBotnet,
                          },
                          {
                            label: "Known Spam Src",
                            value: result.ipReputation.isKnownSpamSource,
                          },
                          {
                            label: "Open Relay",
                            value: result.ipReputation.isOpenRelay,
                          },
                          { label: "VPN", value: result.ipReputation.isVPN },
                          {
                            label: "Datacenter",
                            value: result.ipReputation.isDatacenter,
                          },
                          {
                            label: "Dynamic IP",
                            value: result.ipReputation.isDynamic,
                          },
                          {
                            label: "Repeat Offender",
                            value: (result.ipReputation.seenInScans || 0) > 3,
                          },
                        ].map((f) => (
                          <div
                            key={f.label}
                            className="flex items-center gap-2 px-3 py-2 rounded-lg"
                            style={{
                              background: "var(--bg-elevated)",
                              border: "1px solid var(--bg-border)",
                            }}
                          >
                            <div
                              className="w-2 h-2 rounded-full flex-shrink-0"
                              style={{
                                background: f.value ? "#f87171" : "var(--safe)",
                              }}
                            />
                            <span
                              className="text-[10px]"
                              style={{
                                color: f.value
                                  ? "#f87171"
                                  : "var(--text-muted)",
                              }}
                            >
                              {f.label}
                            </span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* ── TAB: MX / SPF ── */}
              {activeTab === "mx" && (
                <div className="card p-5">
                  {!result.mxValidation ? (
                    <div className="text-center py-8">
                      <Mail
                        className="size-10 mx-auto mb-2"
                        style={{ color: "var(--text-muted)" }}
                      />
                      <p
                        className="text-sm"
                        style={{ color: "var(--text-muted)" }}
                      >
                        MX/SPF validation data not available
                      </p>
                    </div>
                  ) : (
                    <div className="space-y-4">
                      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                        {[
                          {
                            label: "MX Records",
                            value: result.mxValidation.hasMX
                              ? `${result.mxValidation.mxRecords?.length} found`
                              : "None",
                            color: result.mxValidation.hasMX
                              ? "var(--safe)"
                              : "#f87171",
                          },
                          {
                            label: "Mail Platform",
                            value: result.mxValidation.mxProvider || "—",
                            color: "var(--text-primary)",
                          },
                          {
                            label: "Live SPF",
                            value: (
                              result.mxValidation.spfLiveResult || "—"
                            ).toUpperCase(),
                            color:
                              SPF_COLORS[result.mxValidation.spfLiveResult] ||
                              "var(--text-muted)",
                          },
                          {
                            label: "MX Route",
                            value: result.mxValidation.mxMismatch
                              ? "MISMATCH"
                              : "MATCH",
                            color: result.mxValidation.mxMismatch
                              ? "#f87171"
                              : "var(--safe)",
                          },
                        ].map((s) => (
                          <div
                            key={s.label}
                            className="px-4 py-3 rounded-xl"
                            style={{
                              background: "var(--bg-elevated)",
                              border: "1px solid var(--bg-border)",
                            }}
                          >
                            <div className="label-caps mb-1">{s.label}</div>
                            <div
                              className="text-sm font-bold"
                              style={{ color: s.color }}
                            >
                              {s.value}
                            </div>
                          </div>
                        ))}
                      </div>
                      {result.mxValidation.spfRecord && (
                        <div>
                          <div className="label-caps mb-2">
                            Published SPF Record
                          </div>
                          <div
                            className="px-4 py-3 rounded-xl text-[10px] overflow-x-auto"
                            style={{
                              background: "var(--bg-base)",
                              border: "1px solid var(--bg-border)",
                              color: "var(--accent)",
                              fontFamily: "var(--font-mono)",
                              whiteSpace: "nowrap",
                            }}
                          >
                            {result.mxValidation.spfRecord}
                          </div>
                        </div>
                      )}
                      {result.mxValidation.mxRecords?.length > 0 && (
                        <div>
                          <div className="label-caps mb-2">
                            Declared MX Servers
                          </div>
                          {result.mxValidation.mxRecords.map((mx: string) => (
                            <div
                              key={mx}
                              className="text-[10px] px-3 py-1.5 rounded-lg mb-1"
                              style={{
                                background: "var(--bg-elevated)",
                                color: "var(--safe)",
                                fontFamily: "var(--font-mono)",
                              }}
                            >
                              {mx}
                            </div>
                          ))}
                        </div>
                      )}
                      {result.mxValidation.anomalies?.length > 0 && (
                        <div>
                          <div className="label-caps mb-2">
                            Infrastructure Anomalies
                          </div>
                          <div className="space-y-1.5">
                            {result.mxValidation.anomalies.map(
                              (a: any, i: number) => (
                                <div
                                  key={i}
                                  className="flex items-start gap-2 px-3 py-2 rounded-xl text-xs"
                                  style={{
                                    background: "rgba(248,113,113,0.05)",
                                    border: "1px solid rgba(248,113,113,0.15)",
                                  }}
                                >
                                  <span style={{ color: "#f87171" }}>▸</span>
                                  <div>
                                    <span
                                      className="font-semibold"
                                      style={{ color: "#f87171" }}
                                    >
                                      {a.label}:{" "}
                                    </span>
                                    <span
                                      style={{ color: "var(--text-muted)" }}
                                    >
                                      {a.detail}
                                    </span>
                                  </div>
                                  <span
                                    className="ml-auto text-[9px] px-1.5 py-0.5 rounded flex-shrink-0"
                                    style={{
                                      color: "#f87171",
                                      background: "rgba(248,113,113,0.1)",
                                      fontFamily: "var(--font-mono)",
                                    }}
                                  >
                                    +{a.risk}
                                  </span>
                                </div>
                              ),
                            )}
                          </div>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              )}

              {/* ── TAB: Raw Issues ── */}
              {activeTab === "raw" && (
                <div className="card overflow-hidden">
                  <div
                    className="px-5 py-3.5 border-b"
                    style={{
                      borderColor: "var(--bg-border)",
                      background: "var(--bg-elevated)",
                    }}
                  >
                    <span
                      className="text-sm font-semibold"
                      style={{ color: "var(--text-primary)" }}
                    >
                      All Detection Signals — {result.issues?.length || 0}{" "}
                      issues
                    </span>
                  </div>
                  <div
                    className="divide-y"
                    style={{ borderColor: "var(--bg-border)" }}
                  >
                    {result.issues?.length === 0 ? (
                      <div className="p-8 text-center">
                        <CheckCircle
                          className="size-10 mx-auto mb-2"
                          style={{ color: "var(--safe)" }}
                        />
                        <p className="text-sm" style={{ color: "var(--safe)" }}>
                          No issues detected
                        </p>
                      </div>
                    ) : (
                      result.issues?.map((issue: string, i: number) => (
                        <div
                          key={i}
                          className="px-5 py-3 flex items-start gap-3 text-xs"
                        >
                          <span
                            className="flex-shrink-0 mt-0.5 font-bold"
                            style={{
                              color: vc?.text,
                              fontFamily: "var(--font-mono)",
                            }}
                          >
                            {String(i + 1).padStart(2, "0")}
                          </span>
                          <span style={{ color: "var(--text-secondary)" }}>
                            {issue}
                          </span>
                        </div>
                      ))
                    )}
                  </div>
                </div>
              )}

              {/* ── TAB: Correlation ── */}
              {activeTab === "correlation" && (
                <div className="card p-5">
                  <div className="label-caps mb-4">
                    Email Sender Correlation
                  </div>
                  {corrLoading ? (
                    <div className="flex items-center justify-center py-8">
                      <RefreshCw
                        className="size-5 animate-spin"
                        style={{ color: "var(--text-muted)" }}
                      />
                    </div>
                  ) : !correlations ? (
                    <div className="text-center py-8">
                      <Zap
                        className="size-10 mx-auto mb-2"
                        style={{ color: "var(--text-muted)" }}
                      />
                      <p
                        className="text-sm"
                        style={{ color: "var(--text-muted)" }}
                      >
                        Run more email header scans to see correlation patterns
                      </p>
                    </div>
                  ) : correlations.related?.length === 0 ? (
                    <div className="text-center py-8">
                      <CheckCircle
                        className="size-10 mx-auto mb-2"
                        style={{ color: "var(--safe)" }}
                      />
                      <p className="text-sm" style={{ color: "var(--safe)" }}>
                        No correlated scans found
                      </p>
                      <p
                        className="text-xs mt-1"
                        style={{ color: "var(--text-muted)" }}
                      >
                        This sender infrastructure hasn't been seen in previous
                        scans
                      </p>
                    </div>
                  ) : (
                    <div className="space-y-4">
                      {/* Shared infrastructure signals */}
                      {correlations.sharedSignals?.length > 0 && (
                        <div>
                          <div className="label-caps mb-2">
                            Shared Infrastructure Signals
                          </div>
                          <div className="space-y-2">
                            {correlations.sharedSignals.map(
                              (sig: any, i: number) => (
                                <div
                                  key={i}
                                  className="flex items-center gap-3 px-4 py-3 rounded-xl"
                                  style={{
                                    background: "rgba(248,113,113,0.06)",
                                    border: "1px solid rgba(248,113,113,0.2)",
                                  }}
                                >
                                  <AlertTriangle
                                    className="size-4 flex-shrink-0"
                                    style={{ color: "#f87171" }}
                                  />
                                  <div className="flex-1">
                                    <div
                                      className="text-xs font-semibold"
                                      style={{ color: "#f87171" }}
                                    >
                                      {sig.label}
                                    </div>
                                    <div
                                      className="text-[10px] mt-0.5"
                                      style={{
                                        color: "var(--text-muted)",
                                        fontFamily: "var(--font-mono)",
                                      }}
                                    >
                                      {sig.value}
                                    </div>
                                  </div>
                                  <div className="text-right flex-shrink-0">
                                    <div
                                      className="text-sm font-bold"
                                      style={{ color: "#f87171" }}
                                    >
                                      {sig.count}
                                    </div>
                                    <div
                                      className="text-[10px]"
                                      style={{ color: "var(--text-muted)" }}
                                    >
                                      other scans
                                    </div>
                                  </div>
                                </div>
                              ),
                            )}
                          </div>
                        </div>
                      )}

                      {/* Related scans list */}
                      <div>
                        <div className="label-caps mb-2">
                          Related Email Scans ({correlations.related?.length})
                        </div>
                        <div className="space-y-1.5">
                          {correlations.related?.map((scan: any) => {
                            const sc =
                              scan.status === "phishing"
                                ? "#f87171"
                                : scan.status === "suspicious"
                                  ? "#fbbf24"
                                  : "#34d399";
                            return (
                              <div
                                key={scan._id}
                                className="flex items-center gap-3 px-4 py-3 rounded-xl"
                                style={{
                                  background: "var(--bg-elevated)",
                                  border: "1px solid var(--bg-border)",
                                }}
                              >
                                <div
                                  className="w-2 h-2 rounded-full flex-shrink-0"
                                  style={{ background: sc }}
                                />
                                <div className="flex-1 min-w-0">
                                  <div
                                    className="text-xs font-medium truncate"
                                    style={{
                                      color: "var(--text-primary)",
                                      fontFamily: "var(--font-mono)",
                                    }}
                                  >
                                    {scan.fromDomain || "unknown domain"}
                                  </div>
                                  <div
                                    className="text-[10px] mt-0.5"
                                    style={{
                                      color: "var(--text-muted)",
                                      fontFamily: "var(--font-mono)",
                                    }}
                                  >
                                    {scan.sourceIP || "—"}
                                    {scan.originType &&
                                      ` · ${scan.originType.replace(/_/g, " ")}`}
                                    {scan.lookalikeBrand &&
                                      ` · targeting: ${scan.lookalikeBrand}`}
                                  </div>
                                </div>
                                <div className="text-right flex-shrink-0">
                                  <div
                                    className="text-xs font-bold"
                                    style={{ color: sc }}
                                  >
                                    {scan.riskScore}/100
                                  </div>
                                  <div
                                    className="text-[10px]"
                                    style={{
                                      color: "var(--text-muted)",
                                      fontFamily: "var(--font-mono)",
                                    }}
                                  >
                                    {new Date(
                                      scan.createdAt,
                                    ).toLocaleDateString()}
                                  </div>
                                </div>
                              </div>
                            );
                          })}
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              )}
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </div>
  );
}
