// FILE: src/pages/Login.tsx — PhishNetra v5 Redesign
// Logic unchanged — only visual design updated
// Design: Clean centered card, single accent, no hex-pattern

import { useState } from "react";
import { useNavigate } from "react-router";
import { motion, AnimatePresence } from "motion/react";
import { Shield, Terminal, Eye, EyeOff, Lock, User } from "lucide-react";
import { API_BASE } from "../config";

export default function Login() {
  const navigate = useNavigate();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [showPass, setShowPass] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [mode, setMode] = useState<"login" | "register">("login");
  const [role, setRole] = useState<"admin" | "analyst" | "viewer">("analyst");

  const handleSubmit = async () => {
    if (!username.trim() || !password.trim()) {
      setError("Username and password required");
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(`${API_BASE}/api/auth/${mode}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          username,
          password,
          ...(mode === "register" ? { role } : {}),
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data.error || "Authentication failed");
        return;
      }
      localStorage.setItem("pg_token", data.token);
      localStorage.setItem("pg_user", JSON.stringify(data.user));
      navigate("/");
    } catch {
      setError("Cannot connect to server. Is the backend running?");
    } finally {
      setLoading(false);
    }
  };

  const ROLE_CFG = {
    analyst: {
      label: "Analyst",
      desc: "Triage & Investigate",
      color: "#fbbf24",
    },
    admin: { label: "Admin", desc: "Full system access", color: "#f87171" },
    viewer: { label: "Viewer", desc: "Read only", color: "#34d399" },
  };

  return (
    <div
      className="min-h-dvh flex items-center justify-center px-6 hex-pattern circuit-pattern"
      style={{ background: "var(--bg-base)" }}
    >
      {/* Corner glows */}
      <div
        className="fixed top-0 right-0 w-96 h-96 pointer-events-none"
        style={{
          background:
            "radial-gradient(circle, rgba(124,58,237,0.06) 0%, transparent 70%)",
          filter: "blur(40px)",
        }}
      />
      <div
        className="fixed bottom-0 left-0 w-96 h-96 pointer-events-none"
        style={{
          background:
            "radial-gradient(circle, rgba(0,255,136,0.05) 0%, transparent 70%)",
          filter: "blur(40px)",
        }}
      />

      <motion.div
        initial={{ opacity: 0, y: 20, scale: 0.98 }}
        animate={{ opacity: 1, y: 0, scale: 1 }}
        transition={{ duration: 0.5, ease: [0.23, 1, 0.32, 1] }}
        className="w-full max-w-sm relative z-10"
      >
        {/* ── Logo ── */}
        <div className="text-center mb-8">
          <motion.div
            initial={{ scale: 0.8, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
            transition={{
              delay: 0.1,
              duration: 0.5,
              ease: [0.34, 1.56, 0.64, 1],
            }}
            className="inline-flex items-center justify-center w-16 h-16 rounded-2xl mb-4"
            style={{
              background: "var(--accent-subtle)",
              border: "1px solid var(--accent-border)",
            }}
          >
            <motion.div
              animate={{
                boxShadow: [
                  "0 0 0px rgba(0,255,136,0)",
                  "0 0 30px rgba(0,255,136,0.3)",
                  "0 0 0px rgba(0,255,136,0)",
                ],
              }}
              transition={{ duration: 3, repeat: Infinity, ease: "easeInOut" }}
              className="flex h-full w-full items-center justify-center rounded-2xl"
            >
              <Shield
                className="size-8"
                style={{ color: "var(--accent-green)" }}
              />
            </motion.div>
          </motion.div>
          <h1
            className="font-display text-2xl mb-1"
            style={{ color: "var(--text-primary)" }}
          >
            PhishNetra AI
          </h1>
          <p className="label-caps" style={{ letterSpacing: "0.18em" }}>
            Security Operations Platform
          </p>
        </div>

        {/* ── Card ── */}
        <div
          className="card-glass overflow-hidden"
          style={{
            background: "var(--bg-card)",
            border: "1px solid var(--bg-border)",
            boxShadow: "0 24px 80px rgba(0,0,0,0.5)",
          }}
        >
          {/* Tab bar */}
          <div
            className="flex border-b"
            style={{ borderColor: "var(--bg-border)" }}
          >
            {(["login", "register"] as const).map((m) => (
              <button
                key={m}
                onClick={() => {
                  setMode(m);
                  setError(null);
                }}
                className="flex-1 py-3 text-sm font-medium transition-colors relative"
                style={{
                  fontFamily: "var(--font-sans)",
                  color: mode === m ? "var(--accent)" : "var(--text-muted)",
                  background:
                    mode === m ? "var(--accent-subtle)" : "transparent",
                }}
              >
                {m === "login" ? "Sign In" : "Register"}
                {mode === m && (
                  <motion.div
                    layoutId="login-tab-indicator"
                    className="absolute bottom-0 left-0 right-0 h-0.5"
                    style={{ background: "var(--accent)" }}
                    transition={{ type: "spring", bounce: 0.2, duration: 0.3 }}
                  />
                )}
              </button>
            ))}
          </div>

          <div className="p-6 space-y-4">
            {/* Error */}
            <AnimatePresence>
              {error && (
                <motion.div
                  initial={{ opacity: 0, y: -4 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0 }}
                  className="px-4 py-3 rounded-xl text-xs flex items-start gap-2"
                  style={{
                    background: "rgba(248,113,113,0.08)",
                    border: "1px solid rgba(248,113,113,0.22)",
                    color: "var(--color-danger)",
                    fontFamily: "var(--font-mono)",
                  }}
                >
                  <span className="flex-shrink-0 mt-0.5">⚠</span>
                  {error}
                </motion.div>
              )}
            </AnimatePresence>

            {/* Username */}
            <div>
              <label className="label-caps block mb-1.5">Username</label>
              <div className="relative">
                <User
                  className="absolute left-3.5 top-1/2 -translate-y-1/2 size-4"
                  style={{ color: "var(--text-muted)" }}
                />
                <input
                  type="text"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && handleSubmit()}
                  placeholder="analyst"
                  className="input-terminal w-full pl-10 pr-4 py-3 text-sm"
                />
              </div>
            </div>

            {/* Password */}
            <div>
              <label className="label-caps block mb-1.5">Password</label>
              <div className="relative">
                <Lock
                  className="absolute left-3.5 top-1/2 -translate-y-1/2 size-4"
                  style={{ color: "var(--text-muted)" }}
                />
                <input
                  type={showPass ? "text" : "password"}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && handleSubmit()}
                  placeholder="••••••••"
                  className="input-terminal w-full pl-10 pr-11 py-3 text-sm"
                />
                <button
                  onClick={() => setShowPass(!showPass)}
                  className="absolute right-3.5 top-1/2 -translate-y-1/2 transition-colors"
                  style={{ color: "var(--text-muted)" }}
                  onMouseEnter={(e) =>
                    ((e.currentTarget as HTMLButtonElement).style.color =
                      "var(--text-secondary)")
                  }
                  onMouseLeave={(e) =>
                    ((e.currentTarget as HTMLButtonElement).style.color =
                      "var(--text-muted)")
                  }
                >
                  {showPass ? (
                    <EyeOff className="size-4" />
                  ) : (
                    <Eye className="size-4" />
                  )}
                </button>
              </div>
            </div>

            {/* Role selector (register only) */}
            <AnimatePresence>
              {mode === "register" && (
                <motion.div
                  initial={{ opacity: 0, height: 0 }}
                  animate={{ opacity: 1, height: "auto" }}
                  exit={{ opacity: 0, height: 0 }}
                >
                  <label className="label-caps block mb-2">Role</label>
                  <div className="grid grid-cols-3 gap-2">
                    {(["analyst", "admin", "viewer"] as const).map((r) => {
                      const cfg = ROLE_CFG[r];
                      const active = role === r;
                      return (
                        <button
                          key={r}
                          onClick={() => setRole(r)}
                          className="p-2.5 rounded-xl text-center transition-all"
                          style={{
                            background: active
                              ? `${cfg.color}10`
                              : "var(--bg-elevated)",
                            border: `1px solid ${active ? cfg.color + "30" : "var(--bg-border)"}`,
                          }}
                        >
                          <div
                            className="text-xs font-semibold mb-0.5"
                            style={{
                              color: active
                                ? cfg.color
                                : "var(--text-secondary)",
                            }}
                          >
                            {cfg.label}
                          </div>
                          <div
                            className="text-[9px]"
                            style={{
                              color: "var(--text-muted)",
                              fontFamily: "var(--font-mono)",
                            }}
                          >
                            {cfg.desc}
                          </div>
                        </button>
                      );
                    })}
                  </div>
                </motion.div>
              )}
            </AnimatePresence>

            {/* Submit */}
            <button
              onClick={handleSubmit}
              disabled={loading}
              className="btn-primary w-full flex items-center justify-center gap-2 py-3.5 text-sm mt-2"
            >
              {loading ? (
                <>
                  <div
                    className="w-4 h-4 border-2 rounded-full animate-spin"
                    style={{
                      borderColor: "#051a10",
                      borderTopColor: "transparent",
                    }}
                  />
                  Authenticating...
                </>
              ) : (
                <>
                  <Terminal className="size-4" />
                  {mode === "login" ? "Sign In" : "Create Account"}
                </>
              )}
            </button>
          </div>
        </div>

        {/* Footer */}
        <p
          className="text-center mt-5"
          style={{
            color: "var(--text-muted)",
            fontFamily: "var(--font-mono)",
            fontSize: 10,
            letterSpacing: "0.06em",
          }}
        >
          PhishNetra AI v6.0 · SentinelCore SIEM
        </p>
      </motion.div>
    </div>
  );
}
