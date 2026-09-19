// FILE: src/pages/NotificationSettings.tsx

import { useState, useEffect } from "react";
import { motion } from "motion/react";
import {
  Bell,
  Mail,
  MessageSquare,
  CheckCircle,
  Moon,
  Zap,
  RefreshCw,
} from "lucide-react";
import { API_BASE } from "../config";

const authHeader = () => ({
  "Content-Type": "application/json",
  Authorization: `Bearer ${localStorage.getItem("pg_token")}`,
});

export default function NotificationSettings() {
  const [prefs, setPrefs] = useState<any | null>(null);
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch(`${API_BASE}/api/auth/notification-prefs`, {
      headers: authHeader(),
    })
      .then((r) => (r.ok ? r.json() : null))
      .then((d) => {
        if (d) setPrefs(d);
      })
      .catch(() => {})
      .finally(() => setLoading(false));
  }, []);

  const save = async () => {
    if (!prefs) return;
    setSaving(true);
    try {
      const res = await fetch(`${API_BASE}/api/auth/notification-prefs`, {
        method: "PATCH",
        headers: authHeader(),
        body: JSON.stringify(prefs),
      });
      if (res.ok) {
        setSaved(true);
        setTimeout(() => setSaved(false), 2500);
      }
    } catch {
      /* offline */
    } finally {
      setSaving(false);
    }
  };

  const updateChannel = (ch: string, field: string, val: any) => {
    setPrefs((p: any) => ({
      ...p,
      channels: { ...p.channels, [ch]: { ...p.channels?.[ch], [field]: val } },
    }));
  };

  const SEV_LABELS: Record<number, string> = {
    1: "Info",
    2: "Low",
    3: "Medium",
    4: "High",
    5: "Critical",
  };
  const CHANNELS = [
    { key: "email", label: "Email", icon: Mail, color: "var(--accent-green)" },
    { key: "slack", label: "Slack", icon: MessageSquare, color: "#a78bfa" },
    { key: "discord", label: "Discord", icon: Zap, color: "#f97316" },
  ];

  if (loading)
    return (
      <div
        className="min-h-full flex items-center justify-center"
        style={{ background: "var(--bg-base)" }}
      >
        <div
          className="w-8 h-8 border-2 rounded-full animate-spin"
          style={{
            borderColor: "var(--accent-green)",
            borderTopColor: "transparent",
          }}
        />
      </div>
    );

  return (
    <div
      className="min-h-full py-10 px-6"
      style={{ background: "var(--bg-base)" }}
    >
      <div className="max-w-2xl mx-auto">
        <motion.div
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          className="mb-10"
        >
          <div className="tag-green inline-flex mb-4">
            <Bell className="size-3" /> NOTIFICATIONS
          </div>
          <h1
            className="text-4xl font-bold mb-2"
            style={{
              fontFamily: "'Syne', sans-serif",
              color: "var(--text-primary)",
            }}
          >
            Notification Preferences
          </h1>
          <p className="text-sm" style={{ color: "var(--text-secondary)" }}>
            Configure which alerts reach you and when.
          </p>
        </motion.div>

        {prefs && (
          <div className="space-y-4">
            {/* Channel toggles */}
            <div className="card p-5" style={{ background: "var(--bg-card)" }}>
              <div className="flex items-center gap-2 mb-5">
                <Bell
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
                  Alert Channels
                </span>
              </div>
              <div className="space-y-4">
                {CHANNELS.map(({ key, label, icon: Icon, color }) => (
                  <div
                    key={key}
                    className="flex items-center justify-between py-3 border-b"
                    style={{ borderColor: "var(--bg-border)" }}
                  >
                    <div className="flex items-center gap-3">
                      <div
                        className="w-8 h-8 rounded-lg flex items-center justify-center"
                        style={{
                          background: `${color}12`,
                          border: `1px solid ${color}30`,
                        }}
                      >
                        <Icon className="size-4" style={{ color }} />
                      </div>
                      <div>
                        <div
                          className="text-sm font-medium"
                          style={{ color: "var(--text-primary)" }}
                        >
                          {label}
                        </div>
                        <div
                          className="text-xs"
                          style={{ color: "var(--text-muted)" }}
                        >
                          Minimum severity:{" "}
                          {SEV_LABELS[prefs.channels?.[key]?.minSeverity || 4]}
                        </div>
                      </div>
                    </div>
                    <div className="flex items-center gap-4">
                      {/* Min severity selector */}
                      <select
                        value={prefs.channels?.[key]?.minSeverity || 4}
                        onChange={(e) =>
                          updateChannel(
                            key,
                            "minSeverity",
                            Number(e.target.value),
                          )
                        }
                        className="input-terminal text-xs px-2 py-1.5 rounded-lg"
                        style={{ fontFamily: "'JetBrains Mono', monospace" }}
                        disabled={!prefs.channels?.[key]?.enabled}
                      >
                        {[1, 2, 3, 4, 5].map((s) => (
                          <option key={s} value={s}>
                            {SEV_LABELS[s]}+
                          </option>
                        ))}
                      </select>
                      {/* Toggle */}
                      <button
                        onClick={() =>
                          updateChannel(
                            key,
                            "enabled",
                            !prefs.channels?.[key]?.enabled,
                          )
                        }
                        className="relative inline-flex h-6 w-11 items-center rounded-full transition-all"
                        style={{
                          background: prefs.channels?.[key]?.enabled
                            ? color
                            : "var(--bg-border)",
                        }}
                      >
                        <span
                          className="inline-block h-4 w-4 rounded-full bg-white transition-transform"
                          style={{
                            transform: prefs.channels?.[key]?.enabled
                              ? "translateX(24px)"
                              : "translateX(4px)",
                          }}
                        />
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Quiet hours */}
            <div className="card p-5" style={{ background: "var(--bg-card)" }}>
              <div className="flex items-center justify-between mb-4">
                <div className="flex items-center gap-2">
                  <Moon
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
                    Quiet Hours
                  </span>
                </div>
                <button
                  onClick={() =>
                    setPrefs((p: any) => ({
                      ...p,
                      quietHours: {
                        ...p.quietHours,
                        enabled: !p.quietHours?.enabled,
                      },
                    }))
                  }
                  className="relative inline-flex h-6 w-11 items-center rounded-full transition-all"
                  style={{
                    background: prefs.quietHours?.enabled
                      ? "var(--accent-cyan)"
                      : "var(--bg-border)",
                  }}
                >
                  <span
                    className="inline-block h-4 w-4 rounded-full bg-white transition-transform"
                    style={{
                      transform: prefs.quietHours?.enabled
                        ? "translateX(24px)"
                        : "translateX(4px)",
                    }}
                  />
                </button>
              </div>
              {prefs.quietHours?.enabled && (
                <div className="grid grid-cols-2 gap-3 mt-3">
                  {[
                    { label: "Start (No alerts from)", key: "start" },
                    { label: "End (Resume at)", key: "end" },
                  ].map(({ label, key }) => (
                    <div key={key}>
                      <div
                        className="text-xs mb-1.5"
                        style={{
                          color: "var(--text-muted)",
                          fontFamily: "'JetBrains Mono', monospace",
                        }}
                      >
                        {label}
                      </div>
                      <select
                        value={prefs.quietHours?.[key] || 0}
                        onChange={(e) =>
                          setPrefs((p: any) => ({
                            ...p,
                            quietHours: {
                              ...p.quietHours,
                              [key]: Number(e.target.value),
                            },
                          }))
                        }
                        className="input-terminal w-full px-3 py-2 rounded-lg text-sm"
                        style={{ fontFamily: "'JetBrains Mono', monospace" }}
                      >
                        {Array.from({ length: 24 }, (_, h) => (
                          <option key={h} value={h}>
                            {h.toString().padStart(2, "0")}:00
                          </option>
                        ))}
                      </select>
                    </div>
                  ))}
                </div>
              )}
              <p
                className="text-xs mt-3"
                style={{ color: "var(--text-muted)" }}
              >
                No alert notifications will fire during quiet hours.
              </p>
            </div>

            {/* Digest mode */}
            <div className="card p-5" style={{ background: "var(--bg-card)" }}>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <RefreshCw className="size-4" style={{ color: "#f5a623" }} />
                  <div>
                    <div
                      className="text-sm font-semibold"
                      style={{ color: "var(--text-primary)" }}
                    >
                      Digest Mode
                    </div>
                    <div
                      className="text-xs"
                      style={{ color: "var(--text-muted)" }}
                    >
                      {prefs.digestMode
                        ? "Batch alerts into hourly digest"
                        : "Instant — alert fires immediately"}
                    </div>
                  </div>
                </div>
                <button
                  onClick={() =>
                    setPrefs((p: any) => ({ ...p, digestMode: !p.digestMode }))
                  }
                  className="relative inline-flex h-6 w-11 items-center rounded-full transition-all"
                  style={{
                    background: prefs.digestMode
                      ? "#f5a623"
                      : "var(--bg-border)",
                  }}
                >
                  <span
                    className="inline-block h-4 w-4 rounded-full bg-white transition-transform"
                    style={{
                      transform: prefs.digestMode
                        ? "translateX(24px)"
                        : "translateX(4px)",
                    }}
                  />
                </button>
              </div>
            </div>

            {/* Save */}
            <button
              onClick={save}
              disabled={saving}
              className="btn-primary w-full flex items-center justify-center gap-2 py-3.5 text-sm"
              style={{ fontFamily: "'Syne', sans-serif", fontWeight: 700 }}
            >
              {saved ? (
                <>
                  <CheckCircle className="size-4" /> Saved!
                </>
              ) : saving ? (
                <>
                  <div
                    className="w-4 h-4 border-2 rounded-full animate-spin"
                    style={{
                      borderColor: "#080b10",
                      borderTopColor: "transparent",
                    }}
                  />{" "}
                  Saving...
                </>
              ) : (
                "Save Preferences"
              )}
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
