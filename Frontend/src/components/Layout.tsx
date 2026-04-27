// FILE: src/components/Layout.tsx

import { useState } from "react";
import { Outlet, Link, useLocation } from "react-router";
import { motion, AnimatePresence } from "motion/react";
import {
  Shield, Menu, X, Terminal, Activity,
  LayoutDashboard, ShieldAlert,
} from "lucide-react";

export default function Layout() {
  const location = useLocation();
  const [mobileOpen, setMobileOpen] = useState(false);

  const navItems = [
    { path: "/",        label: "Home",      icon: null           },
    { path: "/scan",    label: "Scan",      icon: null           },
    { path: "/history", label: "History",   icon: null           },
    { path: "/about",   label: "About",     icon: null           },
    { path: "/admin",   label: "Dashboard", icon: LayoutDashboard },
    { path: "/siem",    label: "SIEM",      icon: ShieldAlert    },
  ];

  const isActive = (path: string) =>
    path === "/" ? location.pathname === "/" : location.pathname.startsWith(path);

  return (
    <div className="min-h-full flex flex-col" style={{ background: "var(--bg-base)" }}>

      {/* ── TOP STATUS BAR ── */}
      <div className="hidden md:flex items-center justify-between px-6 py-1.5 border-b"
           style={{ background: "rgba(0,255,136,0.04)", borderColor: "rgba(0,255,136,0.1)" }}>
        <div className="flex items-center gap-4">
          <span style={{ color: "var(--accent-green)", fontFamily: "'JetBrains Mono', monospace",
                         fontSize: 10, letterSpacing: "0.15em" }}>
            PHISHGUARD v3.0
          </span>
          <span style={{ color: "var(--text-muted)", fontSize: 10 }}>|</span>
          <div className="flex items-center gap-1.5">
            <div className="w-1.5 h-1.5 rounded-full safe-pulse" style={{ background: "var(--accent-green)" }} />
            <span style={{ color: "var(--text-muted)", fontSize: 10, fontFamily: "'JetBrains Mono', monospace" }}>
              ML + RULES HYBRID ENGINE ONLINE
            </span>
          </div>
        </div>
        <div className="flex items-center gap-4">
          <span style={{ color: "var(--text-muted)", fontSize: 10, fontFamily: "'JetBrains Mono', monospace" }}>
            SENTINELCORE SIEM ACTIVE
          </span>
        </div>
      </div>

      {/* ── NAVBAR ── */}
      <nav className="sticky top-0 z-50 border-b"
           style={{ background: "rgba(8,11,16,0.92)", borderColor: "var(--bg-border)",
                    backdropFilter: "blur(16px)" }}>
        <div className="max-w-7xl mx-auto px-6 h-16 flex items-center justify-between">

          {/* Logo */}
          <Link to="/" className="flex items-center gap-3 group">
            <div className="relative w-9 h-9 flex items-center justify-center rounded-lg"
                 style={{ background: "rgba(0,255,136,0.08)", border: "1px solid rgba(0,255,136,0.2)" }}>
              <Shield className="size-5" style={{ color: "var(--accent-green)" }} strokeWidth={2} />
              <div className="absolute inset-0 rounded-lg opacity-0 group-hover:opacity-100 transition-opacity duration-300"
                   style={{ boxShadow: "var(--glow-green)" }} />
            </div>
            <div className="flex flex-col leading-none">
              <span className="text-base tracking-tight"
                    style={{ color: "var(--text-primary)", fontFamily: "'Syne', sans-serif", fontWeight: 800 }}>
                PhishGuard
              </span>
              <span style={{ color: "var(--accent-green)", fontSize: 9,
                             fontFamily: "'JetBrains Mono', monospace", letterSpacing: "0.15em" }}>
                AI DETECTION
              </span>
            </div>
          </Link>

          {/* Desktop Nav */}
          <div className="hidden md:flex items-center gap-1">
            {navItems.map((item) => {
              const active = isActive(item.path);
              const Icon   = item.icon;
              // SIEM gets purple accent instead of green
              const isSiem  = item.path === "/siem";
              const activeColor  = isSiem ? "#a78bfa" : "var(--accent-green)";
              const activeBg     = isSiem ? "rgba(124,58,237,0.08)" : "rgba(0,255,136,0.06)";
              const activeBorder = isSiem ? "rgba(124,58,237,0.2)"  : "rgba(0,255,136,0.15)";

              return (
                <Link key={item.path} to={item.path}
                      className="relative px-4 py-2 text-sm font-medium transition-all duration-200 rounded-lg flex items-center gap-1.5"
                      style={{
                        fontFamily: "'DM Sans', sans-serif",
                        color:      active ? activeColor : "var(--text-secondary)",
                        background: active ? activeBg    : "transparent",
                      }}>
                  {active && (
                    <motion.div layoutId="nav-pill" className="absolute inset-0 rounded-lg"
                      style={{ background: activeBg, border: `1px solid ${activeBorder}` }} />
                  )}
                  {Icon && (
                    <Icon className="size-3.5 relative z-10"
                          style={{ color: active ? activeColor : "var(--text-muted)" }} />
                  )}
                  <span className="relative z-10">{item.label}</span>
                </Link>
              );
            })}
          </div>

          {/* Right: CTA + hamburger */}
          <div className="flex items-center gap-3">
            <Link to="/scan"
                  className="hidden md:flex items-center gap-2 px-4 py-2 text-sm font-bold rounded-lg transition-all duration-200"
                  style={{ background: "var(--accent-green)", color: "#080b10",
                           fontFamily: "'Syne', sans-serif", letterSpacing: "0.04em" }}
                  onMouseEnter={e => (e.currentTarget.style.boxShadow = "0 0 20px rgba(0,255,136,0.4)")}
                  onMouseLeave={e => (e.currentTarget.style.boxShadow = "none")}>
              <Terminal className="size-3.5" />
              Scan Now
            </Link>
            <button className="md:hidden p-2 rounded-lg transition-colors"
                    style={{ color: "var(--text-secondary)" }}
                    onClick={() => setMobileOpen(!mobileOpen)}>
              {mobileOpen ? <X className="size-5" /> : <Menu className="size-5" />}
            </button>
          </div>
        </div>

        {/* Mobile Menu */}
        <AnimatePresence>
          {mobileOpen && (
            <motion.div initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: "auto" }}
                        exit={{ opacity: 0, height: 0 }} transition={{ duration: 0.2 }}
                        className="md:hidden overflow-hidden border-t"
                        style={{ borderColor: "var(--bg-border)", background: "var(--bg-surface)" }}>
              <div className="px-6 py-4 flex flex-col gap-1">
                {navItems.map((item) => {
                  const active = isActive(item.path);
                  const Icon   = item.icon;
                  const isSiem = item.path === "/siem";
                  const activeColor = isSiem ? "#a78bfa" : "var(--accent-green)";
                  const activeBg    = isSiem ? "rgba(124,58,237,0.08)" : "rgba(0,255,136,0.06)";
                  return (
                    <Link key={item.path} to={item.path} onClick={() => setMobileOpen(false)}
                          className="px-4 py-3 rounded-lg text-sm font-medium transition-all flex items-center gap-2"
                          style={{
                            color:      active ? activeColor : "var(--text-secondary)",
                            background: active ? activeBg    : "transparent",
                          }}>
                      {Icon && <Icon className="size-4" style={{ color: active ? activeColor : "var(--text-muted)" }} />}
                      {item.label}
                    </Link>
                  );
                })}
                <Link to="/scan" onClick={() => setMobileOpen(false)}
                      className="mt-2 px-4 py-3 rounded-lg text-sm font-bold text-center flex items-center justify-center gap-2"
                      style={{ background: "var(--accent-green)", color: "#080b10",
                               fontFamily: "'Syne', sans-serif" }}>
                  <Terminal className="size-4" /> Scan Now
                </Link>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </nav>

      {/* PAGE CONTENT */}
      <main className="flex-1 relative z-10">
        <Outlet />
      </main>

      {/* FOOTER */}
      <footer className="border-t relative z-10"
              style={{ borderColor: "var(--bg-border)", background: "var(--bg-surface)" }}>
        <div className="max-w-7xl mx-auto px-6 py-8">
          <div className="flex flex-col md:flex-row items-center justify-between gap-6">
            <div className="flex items-center gap-3">
              <Shield className="size-5" style={{ color: "var(--accent-green)" }} />
              <span className="font-bold text-sm"
                    style={{ color: "var(--text-primary)", fontFamily: "'Syne', sans-serif" }}>
                PhishGuard
              </span>
              <span className="text-xs"
                    style={{ color: "var(--text-muted)", fontFamily: "'JetBrains Mono', monospace" }}>
                v3.0
              </span>
            </div>
            <div className="flex items-center gap-6">
              {navItems.map((item) => (
                <Link key={item.path} to={item.path}
                      className="text-xs transition-colors hover:text-white"
                      style={{ color: "var(--text-muted)" }}>
                  {item.label}
                </Link>
              ))}
            </div>
            <div className="flex items-center gap-2">
              <Activity className="size-3" style={{ color: "var(--accent-green)" }} />
              <span className="text-xs"
                    style={{ color: "var(--text-muted)", fontFamily: "'JetBrains Mono', monospace" }}>
                © 2026 PhishGuard · All rights reserved
              </span>
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
}