// FILE: src/pages/Onboarding.tsx
import { useState } from "react";
import { motion, AnimatePresence } from "motion/react";
import { useNavigate } from "react-router";
import {
  Shield, Key, Bell, Database, CheckCircle,
  ChevronRight, Terminal, FolderOpen, Mail,
} from "lucide-react";

const STEPS = [
  {
    id: "welcome",
    icon: Shield,
    color: "var(--accent)",
    bg: "var(--accent-subtle)",
    border: "var(--accent-border)",
    title: "Welcome to PhishNetra",
    desc: "Your SOC-grade phishing detection platform is ready. Let's configure the essentials in 4 quick steps.",
    action: null,
    actionLabel: null,
    extra: null,
  },
  {
    id: "apikey",
    icon: Key,
    color: "#a78bfa",
    bg: "rgba(167,139,250,0.08)",
    border: "rgba(167,139,250,0.2)",
    title: "Create Your First API Key",
    desc: "API keys let external tools — browser extensions, CI/CD pipelines, scripts — submit scans and receive threat verdicts.",
    action: "/keys",
    actionLabel: "Open API Keys →",
    extra: {
      type: "code",
      label: "Example API call",
      value: `POST /api/scan\nAuthorization: Bearer YOUR_KEY\n{ "input": "https://example.com" }`,
    },
  },
  {
    id: "datasets",
    icon: Database,
    color: "var(--color-info)",
    bg: "rgba(96,165,250,0.08)",
    border: "rgba(96,165,250,0.2)",
    title: "Add Phishing Datasets",
    desc: "Drop CSV files containing known phishing URLs into the datasets folder. The engine auto-detects schema and reloads every 10 minutes.",
    action: null,
    actionLabel: null,
    extra: {
      type: "path",
      label: "Dataset folder path",
      value: "backend/datasets/",
      note: "Accepts CSV with URL + label columns. Supports 5 schema formats — no config needed.",
    },
  },
  {
    id: "notifications",
    icon: Bell,
    color: "#fbbf24",
    bg: "rgba(251,191,36,0.08)",
    border: "rgba(251,191,36,0.2)",
    title: "Configure Threat Alerts",
    desc: "Get notified the moment a critical phishing campaign or SIEM alert fires — via email, Slack, or Discord webhook.",
    action: "/settings/notifications",
    actionLabel: "Open Notification Settings →",
    extra: {
      type: "channels",
      items: [
        { icon: "📧", label: "Email",   note: "SMTP configured via backend .env" },
        { icon: "💬", label: "Slack",   note: "Paste your Slack webhook URL"     },
        { icon: "🔔", label: "Discord", note: "Paste your Discord webhook URL"   },
      ],
    },
  },
  {
    id: "done",
    icon: CheckCircle,
    color: "var(--accent)",
    bg: "var(--accent-subtle)",
    border: "var(--accent-border)",
    title: "You're Fully Armed",
    desc: "PhishNetra is configured. Run your first scan, explore the SIEM dashboard, or deploy a honeypot trap.",
    action: null,
    actionLabel: null,
    extra: {
      type: "links",
      items: [
        { icon: Terminal,  label: "Scan a URL or message", path: "/scan"       },
        { icon: Shield,    label: "Open SIEM dashboard",   path: "/siem"       },
        { icon: FolderOpen,label: "Browse scan history",   path: "/history"    },
        { icon: Mail,      label: "Bulk scan emails",      path: "/bulk"       },
      ],
    },
  },
];

export default function Onboarding() {
  const navigate   = useNavigate();
  const [step, setStep] = useState(0);
  const current    = STEPS[step];
  const Icon       = current.icon;
  const isLast     = step === STEPS.length - 1;
  const isFirst    = step === 0;

  const finish = () => {
    localStorage.setItem("pg_onboarded", "true");
    navigate("/");
  };

  return (
    <div className="min-h-dvh flex items-center justify-center px-4 py-8"
         style={{ background: "var(--bg-base)" }}>

      {/* Background glow */}
      <div className="fixed inset-0 pointer-events-none">
        <div className="absolute top-1/4 left-1/2 -translate-x-1/2 w-96 h-96 rounded-full"
             style={{ background: "radial-gradient(circle, rgba(52,211,153,0.04), transparent 70%)", filter: "blur(80px)" }} />
      </div>

      <div className="w-full max-w-lg relative">

        {/* Progress bar */}
        <div className="flex items-center gap-2 mb-8 justify-center">
          {STEPS.map((s, i) => {
            const done    = i < step;
            const active  = i === step;
            return (
              <div key={s.id} className="flex items-center gap-2">
                <div className="rounded-full transition-all duration-400 flex items-center justify-center"
                     style={{
                       width:    active ? 28 : done ? 20 : 8,
                       height:   8,
                       background: done || active ? "var(--accent)" : "var(--bg-border)",
                       flexShrink: 0,
                     }}>
                  {done && (
                    <span style={{ fontSize: 6, color: "#080c14", fontWeight: 900 }}>✓</span>
                  )}
                </div>
                {i < STEPS.length - 1 && (
                  <div className="h-px w-6 rounded"
                       style={{ background: done ? "var(--accent)" : "var(--bg-border)" }} />
                )}
              </div>
            );
          })}
        </div>

        {/* Step counter */}
        <div className="text-center mb-4">
          <span className="text-xs"
                style={{ color: "var(--text-muted)", fontFamily: "var(--font-mono)" }}>
            {step + 1} / {STEPS.length}
          </span>
        </div>

        {/* Card */}
        <AnimatePresence mode="wait">
          <motion.div key={step}
            initial={{ opacity: 0, y: 16, scale: 0.98 }}
            animate={{ opacity: 1, y: 0,  scale: 1    }}
            exit={{    opacity: 0, y: -12, scale: 0.98 }}
            transition={{ duration: 0.28, ease: [0.23, 1, 0.32, 1] }}
            className="card p-8">

            {/* Icon */}
            <div className="w-16 h-16 rounded-2xl flex items-center justify-center mx-auto mb-6"
                 style={{ background: current.bg, border: `2px solid ${current.border}` }}>
              <Icon className="size-8" style={{ color: current.color }} />
            </div>

            {/* Title + desc */}
            <h2 className="font-display text-2xl mb-3 text-center"
                style={{ color: "var(--text-primary)" }}>
              {current.title}
            </h2>
            <p className="text-sm mb-6 leading-relaxed text-center"
               style={{ color: "var(--text-secondary)" }}>
              {current.desc}
            </p>

            {/* Extra content */}
            {current.extra && (
              <div className="mb-6">

                {/* Code block */}
                {current.extra.type === "code" && (
                  <div className="rounded-xl p-4"
                       style={{ background: "var(--bg-elevated)", border: "1px solid var(--bg-border)" }}>
                    <div className="label-caps mb-2">{current.extra.label}</div>
                    <pre className="text-xs whitespace-pre-wrap break-all"
                         style={{ color: "var(--accent)", fontFamily: "var(--font-mono)", lineHeight: 1.7 }}>
                      {current.extra.value}
                    </pre>
                  </div>
                )}

                {/* Folder path */}
                {current.extra.type === "path" && (
                  <div className="rounded-xl p-4"
                       style={{ background: "var(--bg-elevated)", border: "1px solid var(--bg-border)" }}>
                    <div className="label-caps mb-2">{current.extra.label}</div>
                    <div className="flex items-center gap-2 mb-2">
                      <FolderOpen className="size-4" style={{ color: "var(--color-info)", flexShrink: 0 }} />
                      <code className="text-sm"
                            style={{ color: "var(--color-info)", fontFamily: "var(--font-mono)" }}>
                        {current.extra.value}
                      </code>
                    </div>
                    {current.extra.note && (
                      <p className="text-xs mt-2"
                         style={{ color: "var(--text-muted)" }}>
                        {current.extra.note}
                      </p>
                    )}
                  </div>
                )}

                {/* Notification channels */}
                {current.extra.type === "channels" && (
                  <div className="space-y-2">
                    {current.extra.items?.map((ch: any) => (
                      <div key={ch.label}
                           className="flex items-center gap-3 px-4 py-3 rounded-xl"
                           style={{ background: "var(--bg-elevated)", border: "1px solid var(--bg-border)" }}>
                        <span className="text-lg">{ch.icon}</span>
                        <div>
                          <div className="text-sm font-semibold"
                               style={{ color: "var(--text-primary)" }}>{ch.label}</div>
                          <div className="text-xs"
                               style={{ color: "var(--text-muted)" }}>{ch.note}</div>
                        </div>
                      </div>
                    ))}
                  </div>
                )}

                {/* Quick links — done step */}
                {current.extra.type === "links" && (
                  <div className="grid grid-cols-2 gap-2">
                    {current.extra.items?.map((lnk: any) => {
                      const LIcon = lnk.icon;
                      return (
                        <button key={lnk.path}
                          onClick={() => { localStorage.setItem("pg_onboarded","true"); navigate(lnk.path); }}
                          className="flex items-center gap-2 px-4 py-3 rounded-xl text-left transition-all stat-card"
                          style={{ background: "var(--bg-elevated)", border: "1px solid var(--bg-border)" }}>
                          <LIcon className="size-4 flex-shrink-0" style={{ color: "var(--accent)" }} />
                          <span className="text-xs font-medium"
                                style={{ color: "var(--text-secondary)" }}>
                            {lnk.label}
                          </span>
                        </button>
                      );
                    })}
                  </div>
                )}
              </div>
            )}

            {/* Action button (opens a page) */}
            {current.action && (
              <button onClick={() => navigate(current.action!)}
                      className="btn-ghost w-full flex items-center justify-center gap-2 px-5 py-3 text-sm mb-3">
                {current.actionLabel}
              </button>
            )}

            {/* Primary CTA */}
            {!isLast ? (
              <button onClick={() => setStep(s => s + 1)}
                      className="btn-primary w-full flex items-center justify-center gap-2 px-5 py-3.5 text-sm">
                Continue <ChevronRight className="size-4" />
              </button>
            ) : (
              <button onClick={finish}
                      className="btn-primary w-full flex items-center justify-center gap-2 px-5 py-3.5 text-sm">
                <Terminal className="size-4" /> Go to Dashboard
              </button>
            )}

            {/* Back + Skip */}
            <div className="flex items-center justify-between mt-4">
              {!isFirst ? (
                <button onClick={() => setStep(s => s - 1)}
                        className="text-xs transition-colors"
                        style={{ color: "var(--text-muted)" }}>
                  ← Back
                </button>
              ) : <div />}
              {!isLast && (
                <button onClick={finish}
                        className="text-xs transition-colors"
                        style={{ color: "var(--text-muted)" }}>
                  Skip setup
                </button>
              )}
            </div>

          </motion.div>
        </AnimatePresence>
      </div>
    </div>
  );
}