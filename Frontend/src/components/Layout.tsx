// FILE: src/components/Layout.tsx — PhishNetra v5 Redesign
// Changes: Removed top status bar, unified navbar, Geist font,
// spring active pill animation, streamlined dropdowns, clean footer

import { useState, useEffect, useRef } from "react";
import { Outlet, Link, useLocation } from "react-router";
import { motion, AnimatePresence } from "motion/react";
import {
  Shield,
  Menu,
  X,
  Terminal,
  Activity,
  LayoutDashboard,
  ShieldAlert,
  Globe,
  Radio,
  ChevronDown,
  Brain,
  Bell,
  Fingerprint,
  Share2,
  Key,
  Zap,
  TrendingUp,
  Database,
  MoreHorizontal,
  FileSearch,
  FileText,
  MessageSquare,
  Lock,
  Cpu,
  Mail,
  Sun,
  Moon,
} from "lucide-react";
import { useSocket, isSocketConnected } from "../hooks/useSocket";
import { useTheme } from "../hooks/useTheme";

const PRIMARY_NAV = [
  { path: "/", label: "Home" },
  { path: "/scan", label: "Scan", icon: Terminal },
  { path: "/history", label: "History" },
  { path: "/admin", label: "Dashboard", icon: LayoutDashboard },
  { path: "/siem", label: "SIEM", icon: ShieldAlert },
  { path: "/about", label: "About" },
];

const TOOLS_NAV = [
  {
    path: "/feed",
    label: "PhishFeed",
    icon: Radio,
    desc: "Live phishing threat feed",
    color: "#fb923c",
    bg: "rgba(251,146,60,0.07)",
    border: "rgba(251,146,60,0.18)",
  },
  {
    path: "/map",
    label: "Threat Map",
    icon: Globe,
    desc: "Real-time global attack map",
    color: "#f87171",
    bg: "rgba(248,113,113,0.07)",
    border: "rgba(248,113,113,0.18)",
  },
  {
    path: "/metrics",
    label: "KPIs",
    icon: TrendingUp,
    desc: "MTTD, MTTR, false positive rate",
    color: "#60a5fa",
    bg: "rgba(96,165,250,0.07)",
    border: "rgba(96,165,250,0.18)",
  },
  {
    path: "/bulk",
    label: "Bulk Scan",
    icon: Zap,
    desc: "Scan up to 500 URLs at once",
    color: "#34d399",
    bg: "rgba(52,211,153,0.07)",
    border: "rgba(52,211,153,0.16)",
  },
  {
    path: "/predict",
    label: "Forecasting",
    icon: TrendingUp,
    desc: "Predictive threat scoring and forecasting",
    color: "#a78bfa",
    bg: "rgba(167,139,250,0.07)",
    border: "rgba(167,139,250,0.18)",
  },
  {
    path: "/campaigns",
    label: "Campaigns",
    icon: Brain,
    desc: "Real-time phishing campaign tracker",
    color: "#a78bfa",
    bg: "rgba(167,139,250,0.07)",
    border: "rgba(167,139,250,0.18)",
  },
  {
    path: "/email-forensics",
    label: "Email Forensics",
    icon: Mail,
    desc: "Deep email header investigation",
    color: "#60a5fa",
    bg: "rgba(96,165,250,0.07)",
    border: "rgba(96,165,250,0.18)",
  },
];

const MORE_NAV = [
  {
    path: "/logs",
    label: "Logs",
    icon: FileSearch,
    desc: "System and scan logs",
    color: "#60a5fa",
    bg: "rgba(96,165,250,0.07)",
    border: "rgba(96,165,250,0.18)",
  },
  {
    path: "/adversaries",
    label: "Actor Intel",
    icon: Shield,
    desc: "Adversary fingerprinting and TTP profiling",
    color: "#f87171",
    bg: "rgba(248,113,113,0.07)",
    border: "rgba(248,113,113,0.18)",
  },
  {
    path: "/kits",
    label: "Kit Intel",
    icon: Fingerprint,
    desc: "Phishing kit DNA fingerprinting",
    color: "#fb923c",
    bg: "rgba(251,146,60,0.07)",
    border: "rgba(251,146,60,0.18)",
  },
  {
    path: "/threatshare",
    label: "Threat Share",
    icon: Share2,
    desc: "Community threat intel — STIX 2.1",
    color: "#60a5fa",
    bg: "rgba(96,165,250,0.07)",
    border: "rgba(96,165,250,0.18)",
  },
  {
    path: "/settings/notifications",
    label: "Alerts Config",
    icon: Bell,
    desc: "Email, Slack, Discord preferences",
    color: "#fbbf24",
    bg: "rgba(251,191,36,0.07)",
    border: "rgba(251,191,36,0.18)",
  },
  {
    path: "/keys",
    label: "API Keys",
    icon: Key,
    desc: "Manage API keys for external integrations",
    color: "#34d399",
    bg: "rgba(52,211,153,0.07)",
    border: "rgba(52,211,153,0.16)",
  },
  {
    path: "/training",
    label: "Training",
    icon: Activity,
    desc: "Interactive phishing detection quiz",
    color: "#34d399",
    bg: "rgba(52,211,153,0.07)",
    border: "rgba(52,211,153,0.16)",
  },
  {
    path: "/onboarding",
    label: "Onboarding",
    icon: Activity,
    desc: "Replay the platform setup guide",
    color: "#a78bfa",
    bg: "rgba(167,139,250,0.07)",
    border: "rgba(167,139,250,0.18)",
  },
];

const SOC_NAV = [
  {
    path: "/complaints",
    label: "Cyber Complaints",
    icon: FileText,
    desc: "Cybercrime complaint intelligence",
    color: "#fb923c",
    bg: "rgba(251,146,60,0.07)",
    border: "rgba(251,146,60,0.18)",
  },
  {
    path: "/incidents",
    label: "Incident Response",
    icon: Activity,
    desc: "Automated IR playbooks",
    color: "#f87171",
    bg: "rgba(248,113,113,0.07)",
    border: "rgba(248,113,113,0.18)",
  },
  {
    path: "/evidence",
    label: "Evidence Vault",
    icon: Lock,
    desc: "Digital evidence & chain of custody",
    color: "#60a5fa",
    bg: "rgba(96,165,250,0.07)",
    border: "rgba(96,165,250,0.18)",
  },
  {
    path: "/ransomware",
    label: "Ransomware Watch",
    icon: Shield,
    desc: "Ransomware early warning system",
    color: "#f87171",
    bg: "rgba(248,113,113,0.07)",
    border: "rgba(248,113,113,0.18)",
  },
  {
    path: "/network-anomaly",
    label: "Network Anomaly",
    icon: Cpu,
    desc: "AI network anomaly detection",
    color: "#a78bfa",
    bg: "rgba(167,139,250,0.07)",
    border: "rgba(167,139,250,0.18)",
  },
];

export default function Layout() {
  const location = useLocation();
  const [mobileOpen, setMobileOpen] = useState(false);
  const [toolsOpen, setToolsOpen] = useState(false);
  const [moreOpen, setMoreOpen] = useState(false);
  const [socOpen, setSocOpen] = useState(false);
  const [wsConnected, setWsConnected] = useState(() => isSocketConnected());
  const [liveThreats, setLiveThreats] = useState(0);
  const { theme, toggleTheme } = useTheme();
  const toolsRef = useRef<HTMLDivElement>(null);
  const moreRef = useRef<HTMLDivElement>(null);
  const socRef = useRef<HTMLDivElement>(null);

  useSocket({
    connect: () => setWsConnected(true),
    disconnect: () => setWsConnected(false),
    threat_detected: () => setLiveThreats((n) => n + 1),
    ids_alert: () => setLiveThreats((n) => n + 1),
  });

  useEffect(() => {
    const token = localStorage.getItem("pg_token");
    if (!token && location.pathname !== "/login")
      window.location.href = "/login";
  }, [location.pathname]);

  useEffect(() => {
    const h = (e: MouseEvent) => {
      if (toolsRef.current && !toolsRef.current.contains(e.target as Node))
        setToolsOpen(false);
      if (moreRef.current && !moreRef.current.contains(e.target as Node))
        setMoreOpen(false);
      if (socRef.current && !socRef.current.contains(e.target as Node))
        setSocOpen(false);
    };
    document.addEventListener("mousedown", h);
    return () => document.removeEventListener("mousedown", h);
  }, []);

  useEffect(() => {
    setMobileOpen(false);
  }, [location.pathname]);

  const user = JSON.parse(localStorage.getItem("pg_user") || "null");
  const isActive = (path: string) =>
    path === "/"
      ? location.pathname === "/"
      : location.pathname.startsWith(path);

  const roleColor = (r: string) =>
    r === "admin" ? "#f87171" : r === "analyst" ? "#fbbf24" : "#34d399";
  const roleBg = (r: string) =>
    r === "admin"
      ? "rgba(248,113,113,0.08)"
      : r === "analyst"
        ? "rgba(251,191,36,0.08)"
        : "rgba(52,211,153,0.08)";

  const DropdownItems = ({
    items,
    onClose,
  }: {
    items: typeof TOOLS_NAV;
    onClose: () => void;
  }) => (
    <div className="p-1.5">
      {items.map((item) => {
        const Icon = item.icon;
        const active = isActive(item.path);
        return (
          <Link
            key={item.path}
            to={item.path}
            onClick={onClose}
            className="flex items-center gap-3 px-3 py-2.5 rounded-xl transition-colors"
            style={{ background: active ? item.bg : "transparent" }}
          >
            <div
              className="w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0"
              style={{
                background: item.bg,
                border: `1px solid ${item.border}`,
              }}
            >
              <Icon className="size-4" style={{ color: item.color }} />
            </div>
            <div className="flex-1 min-w-0">
              <div
                className="text-sm font-medium leading-none mb-0.5"
                style={{ color: active ? item.color : "var(--text-primary)" }}
              >
                {item.label}
              </div>
              <div
                className="text-xs truncate"
                style={{
                  color: "var(--text-muted)",
                  fontFamily: "var(--font-mono)",
                }}
              >
                {item.desc}
              </div>
            </div>
          </Link>
        );
      })}
    </div>
  );

  const dropdownStyle = {
    background: "var(--bg-elevated)",
    border: "1px solid var(--bg-border)",
    borderRadius: "14px",
    boxShadow: "var(--shadow-xl), inset 0 1px 0 rgba(255,255,255,0.04)",
  };

  return (
    <div
      className="min-h-dvh flex flex-col"
      style={{ background: "var(--bg-base)" }}
    >
      {/* ── NAVBAR ── */}
      <nav
        className="sticky top-0 z-50"
        style={{
          background: "rgba(8,12,20,0.92)",
          borderBottom: "1px solid var(--bg-border)",
          backdropFilter: "blur(20px)",
          WebkitBackdropFilter: "blur(20px)",
        }}
      >
        <div className="max-w-7xl mx-auto px-5 h-[60px] flex items-center gap-2">
          {/* Logo */}
          <Link to="/" className="flex items-center gap-2.5 flex-shrink-0 mr-3">
            <div
              className="w-8 h-8 rounded-xl flex items-center justify-center"
              style={{
                background: "var(--accent-subtle)",
                border: "1px solid var(--accent-border)",
              }}
            >
              <img
                src="/logo-icon.png"
                alt="PhishNetra"
                className="w-5 h-5 object-contain"
              />
            </div>
            <div className="flex flex-col leading-none">
              <span
                className="text-sm font-bold"
                style={{
                  color: "var(--text-primary)",
                  letterSpacing: "-0.02em",
                }}
              >
                PhishNetra
              </span>
              <span
                className="text-[9px] font-medium"
                style={{
                  color: "var(--accent)",
                  fontFamily: "var(--font-mono)",
                  letterSpacing: "0.14em",
                }}
              >
                AI · v6.0
              </span>
            </div>
          </Link>

          {/* Desktop nav */}
          <div className="hidden lg:flex items-center gap-0.5 flex-1">
            {PRIMARY_NAV.map((item) => {
              const active = isActive(item.path);
              const Icon = (item as any).icon;
              return (
                <Link
                  key={item.path}
                  to={item.path}
                  className="relative px-3.5 py-2 text-sm font-medium rounded-lg flex items-center gap-1.5 transition-colors"
                  style={{
                    color: active ? "var(--accent)" : "var(--text-secondary)",
                  }}
                >
                  {active && (
                    <motion.div
                      layoutId="nav-active-pill"
                      className="absolute inset-0 rounded-lg"
                      style={{
                        background: "var(--accent-subtle)",
                        border: "1px solid var(--accent-border)",
                      }}
                      transition={{
                        type: "spring",
                        bounce: 0.15,
                        duration: 0.35,
                      }}
                    />
                  )}
                  {Icon && (
                    <Icon className="size-3.5 relative z-10 flex-shrink-0" />
                  )}
                  <span className="relative z-10">{item.label}</span>
                </Link>
              );
            })}

            {/* Tools dropdown */}
            <div ref={toolsRef} className="relative">
              <button
                onClick={() => {
                  setToolsOpen((o) => !o);
                  setMoreOpen(false);
                }}
                className="px-3.5 py-2 text-sm font-medium rounded-lg flex items-center gap-1.5 transition-colors"
                style={{
                  color: toolsOpen ? "var(--accent)" : "var(--text-secondary)",
                  background: toolsOpen
                    ? "var(--accent-subtle)"
                    : "transparent",
                }}
              >
                Tools
                <ChevronDown
                  className="size-3.5 transition-transform duration-200"
                  style={{ transform: toolsOpen ? "rotate(180deg)" : "none" }}
                />
              </button>
              <AnimatePresence>
                {toolsOpen && (
                  <motion.div
                    initial={{ opacity: 0, y: 6, scale: 0.97 }}
                    animate={{ opacity: 1, y: 0, scale: 1 }}
                    exit={{ opacity: 0, y: 6, scale: 0.97 }}
                    transition={{ duration: 0.16, ease: [0.23, 1, 0.32, 1] }}
                    className="absolute top-full left-0 mt-1.5 w-72"
                    style={dropdownStyle}
                  >
                    <DropdownItems
                      items={TOOLS_NAV}
                      onClose={() => setToolsOpen(false)}
                    />
                  </motion.div>
                )}
              </AnimatePresence>
            </div>

            {/* SOC Tools dropdown */}
            <div ref={socRef} className="relative">
              <button
                onClick={() => {
                  setSocOpen((o) => !o);
                  setToolsOpen(false);
                  setMoreOpen(false);
                }}
                className="px-3.5 py-2 text-sm font-medium rounded-lg flex items-center gap-1.5 transition-colors"
                style={{
                  color: socOpen ? "var(--accent)" : "var(--text-secondary)",
                  background: socOpen ? "var(--accent-subtle)" : "transparent",
                }}
              >
                SOC
                <ChevronDown
                  className="size-3.5 transition-transform duration-200"
                  style={{ transform: socOpen ? "rotate(180deg)" : "none" }}
                />
              </button>
              <AnimatePresence>
                {socOpen && (
                  <motion.div
                    initial={{ opacity: 0, y: 6, scale: 0.97 }}
                    animate={{ opacity: 1, y: 0, scale: 1 }}
                    exit={{ opacity: 0, y: 6, scale: 0.97 }}
                    transition={{ duration: 0.16, ease: [0.23, 1, 0.32, 1] }}
                    className="absolute top-full left-0 mt-1.5 w-72"
                    style={dropdownStyle}
                  >
                    <DropdownItems
                      items={SOC_NAV}
                      onClose={() => setSocOpen(false)}
                    />
                  </motion.div>
                )}
              </AnimatePresence>
            </div>

            {/* More dropdown */}
            <div ref={moreRef} className="relative">
              <button
                onClick={() => {
                  setMoreOpen((o) => !o);
                  setToolsOpen(false);
                  setSocOpen(false);
                }}
                className="px-3.5 py-2 text-sm font-medium rounded-lg flex items-center gap-1.5 transition-colors"
                style={{
                  color: moreOpen ? "var(--accent)" : "var(--text-secondary)",
                  background: moreOpen ? "var(--accent-subtle)" : "transparent",
                }}
              >
                <MoreHorizontal className="size-4" />
              </button>
              <AnimatePresence>
                {moreOpen && (
                  <motion.div
                    initial={{ opacity: 0, y: 6, scale: 0.97 }}
                    animate={{ opacity: 1, y: 0, scale: 1 }}
                    exit={{ opacity: 0, y: 6, scale: 0.97 }}
                    transition={{ duration: 0.16, ease: [0.23, 1, 0.32, 1] }}
                    className="absolute top-full right-0 mt-1.5 w-72"
                    style={dropdownStyle}
                  >
                    <DropdownItems
                      items={MORE_NAV}
                      onClose={() => setMoreOpen(false)}
                    />
                  </motion.div>
                )}
              </AnimatePresence>
            </div>
          </div>

          {/* Right side */}
          <div className="flex items-center gap-2 ml-auto">
            {/* Live threats badge */}
            {liveThreats > 0 && (
              <motion.div
                initial={{ opacity: 0, scale: 0.8 }}
                animate={{ opacity: 1, scale: 1 }}
                className="hidden md:flex items-center gap-1.5 px-2.5 py-1 rounded-full"
                style={{
                  background: "rgba(248,113,113,0.08)",
                  border: "1px solid rgba(248,113,113,0.2)",
                }}
              >
                <div
                  className="w-1.5 h-1.5 rounded-full threat-pulse"
                  style={{ background: "var(--color-danger)" }}
                />
                <span
                  className="text-[10px] font-semibold"
                  style={{
                    color: "var(--color-danger)",
                    fontFamily: "var(--font-mono)",
                  }}
                >
                  {liveThreats} LIVE
                </span>
              </motion.div>
            )}

            {/* WebSocket status */}
            <div
              className="hidden lg:flex items-center gap-1.5 px-2.5 py-1 rounded-full"
              style={{
                background: "var(--bg-elevated)",
                border: "1px solid var(--bg-border)",
              }}
            >
              <div
                className={`w-1.5 h-1.5 rounded-full ${wsConnected ? "safe-pulse" : ""}`}
                style={{
                  background: wsConnected
                    ? "var(--accent)"
                    : "var(--text-muted)",
                }}
              />
              <span
                className="text-[10px] font-medium"
                style={{
                  color: wsConnected ? "var(--accent)" : "var(--text-muted)",
                  fontFamily: "var(--font-mono)",
                  letterSpacing: "0.06em",
                }}
              >
                {wsConnected ? "LIVE" : "OFFLINE"}
              </span>
            </div>

            {/* User badge */}
            {user && (
              <div
                className="hidden md:flex items-center gap-1.5 px-3 py-1.5 rounded-lg"
                style={{
                  background: "var(--bg-elevated)",
                  border: "1px solid var(--bg-border)",
                }}
              >
                <div
                  className="w-1.5 h-1.5 rounded-full"
                  style={{ background: roleColor(user.role) }}
                />
                <span
                  className="text-xs font-medium"
                  style={{
                    color: "var(--text-secondary)",
                    fontFamily: "var(--font-mono)",
                  }}
                >
                  {user.username}
                </span>
                <span
                  className="text-[9px] font-semibold px-1.5 py-0.5 rounded"
                  style={{
                    color: roleColor(user.role),
                    background: roleBg(user.role),
                    letterSpacing: "0.08em",
                  }}
                >
                  {user.role?.toUpperCase()}
                </span>
                <button
                  onClick={() => {
                    localStorage.removeItem("pg_token");
                    localStorage.removeItem("pg_user");
                    window.location.href = "/login";
                  }}
                  className="text-[10px] ml-1 transition-colors"
                  style={{
                    color: "var(--text-muted)",
                    fontFamily: "var(--font-mono)",
                  }}
                >
                  ⏏
                </button>
              </div>
            )}

            {/* Theme toggle */}
            <button
              onClick={toggleTheme}
              aria-label={`Switch to ${theme === "dark" ? "light" : "dark"} mode`}
              title={`Switch to ${theme === "dark" ? "light" : "dark"} mode`}
              className="relative flex items-center gap-1.5 px-3 py-1.5 rounded-xl transition-all"
              style={{
                background:
                  theme === "light"
                    ? "rgba(15,23,42,0.06)"
                    : "rgba(255,255,255,0.05)",
                border:
                  theme === "light"
                    ? "1px solid #e2e8f0"
                    : "1px solid rgba(255,255,255,0.08)",
                color: theme === "light" ? "#334155" : "#94a3b8",
              }}
            >
              {theme === "dark" ? (
                <>
                  <Sun className="size-3.5" style={{ color: "#fbbf24" }} />
                  <span
                    className="text-[10px] font-medium hidden sm:inline"
                    style={{
                      fontFamily: "var(--font-mono)",
                      letterSpacing: "0.05em",
                    }}
                  >
                    Light
                  </span>
                </>
              ) : (
                <>
                  <Moon className="size-3.5" style={{ color: "#6366f1" }} />
                  <span
                    className="text-[10px] font-medium hidden sm:inline"
                    style={{
                      fontFamily: "var(--font-mono)",
                      letterSpacing: "0.05em",
                    }}
                  >
                    Dark
                  </span>
                </>
              )}
            </button>

            {/* Scan CTA */}
            <Link
              to="/scan"
              className="hidden md:flex items-center gap-2 px-4 py-2 text-sm font-semibold rounded-lg btn-primary"
            >
              <Terminal className="size-3.5" />
              Scan
            </Link>

            {/* Mobile hamburger */}
            <button
              className="lg:hidden p-2 rounded-lg"
              style={{
                color: "var(--text-secondary)",
                border: "1px solid var(--bg-border)",
              }}
              onClick={() => setMobileOpen((o) => !o)}
            >
              {mobileOpen ? (
                <X className="size-4" />
              ) : (
                <Menu className="size-4" />
              )}
            </button>
          </div>
        </div>

        {/* Mobile menu */}
        <AnimatePresence>
          {mobileOpen && (
            <motion.div
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: "auto" }}
              exit={{ opacity: 0, height: 0 }}
              transition={{ duration: 0.2, ease: [0.23, 1, 0.32, 1] }}
              className="lg:hidden overflow-hidden border-t"
              style={{
                borderColor: "var(--bg-border)",
                background: "var(--bg-surface)",
              }}
            >
              <div className="px-4 py-3 flex flex-col gap-0.5">
                {[...PRIMARY_NAV, ...TOOLS_NAV, ...SOC_NAV, ...MORE_NAV].map(
                  (item) => {
                    const active = isActive(item.path);
                    const Icon = (item as any).icon;
                    const color = (item as any).color || "var(--accent)";
                    const bg = (item as any).bg || "var(--accent-subtle)";
                    return (
                      <Link
                        key={item.path}
                        to={item.path}
                        className="px-4 py-2.5 rounded-xl text-sm font-medium flex items-center gap-3 transition-colors"
                        style={{
                          color: active ? color : "var(--text-secondary)",
                          background: active ? bg : "transparent",
                        }}
                      >
                        {Icon && (
                          <Icon
                            className="size-4 flex-shrink-0"
                            style={{
                              color: active ? color : "var(--text-muted)",
                            }}
                          />
                        )}
                        <span>{item.label}</span>
                      </Link>
                    );
                  },
                )}
                <div
                  className="pt-2 mt-1 border-t"
                  style={{ borderColor: "var(--bg-border)" }}
                >
                  <Link
                    to="/scan"
                    className="flex items-center justify-center gap-2 px-4 py-3 rounded-xl text-sm font-semibold btn-primary w-full"
                  >
                    <Terminal className="size-4" /> Scan Now
                  </Link>
                </div>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </nav>

      {/* PAGE CONTENT */}
      <main className="flex-1 relative z-10 min-h-0">
        <Outlet />
      </main>

      {/* FOOTER */}
      <footer
        className="border-t relative z-10"
        style={{
          borderColor: "var(--bg-border)",
          background: "var(--bg-surface)",
        }}
      >
        <div className="max-w-7xl mx-auto px-6 py-6">
          <div className="flex flex-col md:flex-row items-center justify-between gap-4">
            <div className="flex items-center gap-2.5">
              <div
                className="w-6 h-6 rounded-lg flex items-center justify-center"
                style={{
                  background: "var(--accent-subtle)",
                  border: "1px solid var(--accent-border)",
                }}
              >
                <img
                  src="/logo-icon.png"
                  alt="PhishNetra"
                  className="w-4 h-4 object-contain"
                />
              </div>
              <span
                className="text-sm font-semibold"
                style={{
                  color: "var(--text-primary)",
                  letterSpacing: "-0.01em",
                }}
              >
                PhishNetra AI
              </span>
              <span
                className="text-[10px] px-1.5 py-0.5 rounded font-medium"
                style={{
                  color: "var(--accent)",
                  background: "var(--accent-subtle)",
                  border: "1px solid var(--accent-border)",
                  fontFamily: "var(--font-mono)",
                }}
              >
                v6.0
              </span>
            </div>
            <div className="flex items-center gap-4 flex-wrap justify-center">
              {PRIMARY_NAV.map((item) => (
                <Link
                  key={item.path}
                  to={item.path}
                  className="text-xs transition-colors hover:text-white"
                  style={{ color: "var(--text-muted)" }}
                >
                  {item.label}
                </Link>
              ))}
            </div>
            <div className="flex items-center gap-2">
              <div
                className={`w-1.5 h-1.5 rounded-full ${wsConnected ? "safe-pulse" : ""}`}
                style={{
                  background: wsConnected
                    ? "var(--accent)"
                    : "var(--text-muted)",
                }}
              />
              <span
                className="text-xs"
                style={{
                  color: "var(--text-muted)",
                  fontFamily: "var(--font-mono)",
                }}
              >
                © 2026 PhishNetra · SentinelCore SIEM
              </span>
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
}
