// FILE: src/pages/ThreatMap.tsx — FULL REPLACEMENT
// Real geolocation from scanned phishing domains via DNS resolution.
// No more empty map — every phishing/suspicious URL scan produces a data point.

import { useEffect, useState, useCallback, useRef } from "react";
import { motion, AnimatePresence } from "motion/react";
import {
  Globe,
  RefreshCw,
  Activity,
  AlertTriangle,
  Zap,
  Shield,
  X,
  ExternalLink,
  MapPin,
  Server,
  Clock,
  Wifi,
} from "lucide-react";
import { API_BASE } from "../config";
import { useSocket } from "../hooks/useSocket";
import { useNavigate } from "react-router-dom";

// ── Types ──
interface GeoPoint {
  ip: string;
  domain?: string;
  country: string;
  region?: string;
  city?: string;
  lat: number;
  lon: number;
  org?: string;
  category: string;
  severity: number;
  timestamp: string;
  source?: string;
  riskScore?: number;
  isFallback?: boolean; // FIX ISSUE 1+2: true = estimated location (expired DNS)
}

interface GeoData {
  points: GeoPoint[];
  total: number;
  topCountries: TopCountry[];
  scannedSince: string;
  resolvedAt: string;
  fallbackCount: number; // FIX ISSUE 1+2: how many points used fallback geo
}

interface TopCountry {
  country: string;
  count: number;
  critical: number;
}

// ── Map helpers ──
const W = 900;
const H = 440;

function project(lat: number, lon: number): { x: number; y: number } {
  return {
    x: ((lon + 180) / 360) * W,
    y: ((90 - lat) / 180) * H,
  };
}

function sevColor(s: number): string {
  if (s >= 5) return "#f87171";
  if (s >= 4) return "#fb923c";
  if (s >= 3) return "#fbbf24";
  return "#60a5fa";
}

const CAT_LABEL: Record<string, string> = {
  phishing: "Phishing",
  brute_force: "Brute Force",
  ids: "IDS Alert",
  malware: "Malware",
  suspicious: "Suspicious",
  system: "System",
};

const FLAG: Record<string, string> = {
  US: "🇺🇸",
  GB: "🇬🇧",
  CN: "🇨🇳",
  RU: "🇷🇺",
  DE: "🇩🇪",
  FR: "🇫🇷",
  IN: "🇮🇳",
  BR: "🇧🇷",
  NG: "🇳🇬",
  UA: "🇺🇦",
  RO: "🇷🇴",
  PH: "🇵🇭",
  VN: "🇻🇳",
  ID: "🇮🇩",
  PK: "🇵🇰",
  KE: "🇰🇪",
  TR: "🇹🇷",
  CA: "🇨🇦",
  JP: "🇯🇵",
  KR: "🇰🇷",
  AU: "🇦🇺",
  NL: "🇳🇱",
  SG: "🇸🇬",
  HK: "🇭🇰",
  ZA: "🇿🇦",
  MX: "🇲🇽",
  AR: "🇦🇷",
  EG: "🇪🇬",
  IT: "🇮🇹",
  ES: "🇪🇸",
  PL: "🇵🇱",
  SE: "🇸🇪",
  TH: "🇹🇭",
  MY: "🇲🇾",
};

// Approximate centroids for top-origin country labels on map
const COUNTRY_COORDS: Record<string, [number, number]> = {
  US: [38, -97],
  CN: [35, 105],
  RU: [60, 90],
  DE: [51, 10],
  GB: [54, -2],
  NG: [9, 8],
  BR: [-10, -55],
  UA: [49, 32],
  IN: [20, 78],
  FR: [46, 2],
  RO: [46, 25],
  PH: [13, 122],
  VN: [16, 108],
  ID: [-5, 120],
  PK: [30, 69],
  KE: [-1, 38],
  TR: [39, 35],
  CA: [56, -106],
  JP: [36, 138],
  KR: [37, 127],
  AU: [-25, 133],
  NL: [52, 5],
  SG: [1, 104],
  ZA: [-29, 25],
  MX: [23, -102],
};

// ── Continent SVG paths (equirectangular) ──
const LAND_PATHS = [
  // North America
  "M75 60 L108 50 L145 44 L178 47 L205 54 L225 70 L240 88 L248 108 L244 130 L233 148 L217 165 L196 178 L174 183 L156 194 L138 205 L120 202 L102 193 L88 179 L76 162 L66 142 L60 120 L58 96 L62 76Z",
  // Mexico / Central America
  "M132 202 L158 193 L178 202 L170 218 L158 228 L147 222 L136 212Z",
  // South America
  "M155 218 L182 210 L208 218 L224 234 L228 260 L224 290 L216 320 L200 350 L184 368 L165 378 L147 370 L130 350 L120 325 L116 296 L118 266 L126 242 L138 224Z",
  // Greenland
  "M237 20 L285 14 L322 20 L330 37 L318 52 L285 60 L252 58 L235 44Z",
  // Iceland
  "M352 36 L370 32 L380 39 L374 50 L358 53 L346 46Z",
  // W Europe
  "M390 50 L422 44 L450 47 L468 58 L474 72 L468 86 L452 94 L432 97 L414 92 L397 81 L387 68Z",
  // Scandinavia / E Europe
  "M450 33 L482 26 L510 30 L525 44 L518 60 L497 68 L474 72 L468 58 L450 47Z",
  // Africa
  "M396 104 L442 97 L480 104 L504 122 L518 150 L520 180 L514 217 L502 253 L480 284 L455 310 L425 320 L397 312 L374 290 L360 258 L356 222 L360 188 L371 158 L381 132 L390 115Z",
  // Madagascar
  "M512 230 L522 222 L530 238 L527 260 L516 267 L506 253 L504 238Z",
  // Middle East
  "M476 90 L512 83 L542 88 L557 104 L550 122 L526 132 L498 130 L478 117 L470 100Z",
  // Central Asia
  "M522 58 L583 50 L628 53 L653 66 L650 84 L626 96 L590 100 L558 93 L528 82 L518 70Z",
  // Russia (simplified west+east)
  "M482 26 L565 16 L665 13 L765 20 L818 33 L822 53 L794 67 L742 74 L690 71 L640 67 L598 60 L558 53 L520 46 L490 38Z",
  // South Asia
  "M562 93 L613 86 L643 94 L658 113 L650 136 L626 150 L598 154 L572 147 L554 130 L547 110Z",
  // SE Asia
  "M652 118 L700 110 L728 118 L737 138 L722 153 L695 160 L668 153 L648 138Z",
  // East Asia (China/Korea area)
  "M650 66 L723 56 L775 60 L803 73 L810 94 L800 115 L771 130 L736 134 L698 127 L668 113 L652 95 L646 78Z",
  // Japan
  "M810 73 L824 70 L830 80 L824 96 L812 99 L804 88Z",
  // British Isles
  "M371 50 L387 44 L396 50 L391 65 L378 68 L370 60Z",
  // Australia
  "M673 237 L748 227 L794 237 L815 258 L820 287 L808 317 L783 340 L747 344 L710 337 L681 316 L663 288 L660 261Z",
  // New Zealand
  "M830 318 L838 308 L846 318 L844 337 L833 342 L825 330Z",
  // Greenland ice cap
  "M250 28 L284 22 L316 28 L320 40 L306 50 L280 55 L254 50Z",
];

// ── Attack arc component ──
function AttackArc({
  from,
  to,
  color,
  delay,
}: {
  from: { x: number; y: number };
  to: { x: number; y: number };
  color: string;
  delay: number;
}) {
  const mx = (from.x + to.x) / 2;
  const my = Math.min(from.y, to.y) - Math.abs(from.x - to.x) * 0.18;
  const d = `M ${from.x} ${from.y} Q ${mx} ${my} ${to.x} ${to.y}`;
  const dur = `${2.2 + delay * 0.4}s`;
  return (
    <g>
      <path d={d} fill="none" stroke={color} strokeWidth="0.7" opacity="0.12" />
      <path
        d={d}
        fill="none"
        stroke={color}
        strokeWidth="1.4"
        opacity="0.55"
        strokeDasharray="5 200"
      >
        <animate
          attributeName="stroke-dashoffset"
          values="200;-200"
          dur={dur}
          repeatCount="indefinite"
        />
      </path>
    </g>
  );
}

// ── Main component ──
export default function ThreatMap() {
  const [points, setPoints] = useState<GeoPoint[]>([]);
  const [topCountries, setTopCountries] = useState<TopCountry[]>([]);
  const [total, setTotal] = useState(0);
  const [fallbackCount, setFallbackCount] = useState(0); // FIX ISSUE 1+2
  const [loading, setLoading] = useState(true);
  const [hovered, setHovered] = useState<GeoPoint | null>(null);
  const [tooltipPos, setTooltipPos] = useState({ x: 0, y: 0 });
  const leaveTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const [selectedPoint, setSelectedPoint] = useState<GeoPoint | null>(null);
  const navigate = useNavigate();
  const [filterCat, setFilterCat] = useState("all");
  const [filterSev, setFilterSev] = useState(0);
  const [showArcs, setShowArcs] = useState(true);
  const [liveCount, setLiveCount] = useState(0);
  const [lastRefresh, setLastRefresh] = useState(new Date());
  const svgRef = useRef<SVGSVGElement>(null);

  const fetchGeo = useCallback(async () => {
    setLoading(true);
    try {
      // FIX ISSUE 6: Send Authorization header so requireAuth guard passes
      const token = localStorage.getItem("pg_token") || "";
      const res = await fetch(`${API_BASE}/api/siem/geo`, {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });
      if (res.ok) {
        const data: GeoData = await res.json();
        setPoints(data.points || []);
        setTopCountries(data.topCountries || []);
        setTotal(data.total || 0);
        setFallbackCount(data.fallbackCount || 0); // FIX ISSUE 1+2
        setLastRefresh(new Date());
      }
    } catch {
      /* backend offline */
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchGeo();
  }, [fetchGeo]);

  // Auto-refresh every 60 s
  useEffect(() => {
    const t = setInterval(fetchGeo, 60_000);
    return () => clearInterval(t);
  }, [fetchGeo]);

  // Live socket updates
  useSocket({
    threat_detected: () => {
      setLiveCount((c) => c + 1);
      fetchGeo();
    },
    ids_alert: () => fetchGeo(), // IDS middleware events
    siem_alert: () => fetchGeo(), // FIX ISSUE 3: manual SIEM event ingest
    honeypot_triggered: () => {
      // FIX ISSUE 3: honeypot hit = real attacker IP
      setLiveCount((c) => c + 1);
      fetchGeo();
    },
    new_scan: () => fetchGeo(), // FIX ISSUE 4: now properly emitted by scan.js
  });

  // Close detail panel on Escape
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.key === "Escape") setSelectedPoint(null);
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, []);

  // Derived
  const categories = [
    "all",
    ...Array.from(new Set(points.map((p) => p.category))),
  ];
  const filtered = points.filter(
    (p) =>
      (filterCat === "all" || p.category === filterCat) &&
      (filterSev === 0 || p.severity >= filterSev),
  );
  const critical = points.filter((p) => p.severity >= 5).length;
  const high = points.filter((p) => p.severity === 4).length;
  const center = project(20, 78); // FIX ISSUE 7: India — default deployment target (was Africa 15,5)

  // Convert SVG coords to screen coords for tooltip
  function svgToScreen(sx: number, sy: number) {
    const svg = svgRef.current;
    if (!svg) return { x: 0, y: 0 };
    const rect = svg.getBoundingClientRect();
    return {
      x: rect.left + (sx / W) * rect.width,
      y: rect.top + (sy / H) * rect.height,
    };
  }
  return (
    <div
      className="min-h-full py-10 px-4 md:px-8"
      style={{ background: "var(--bg-base)" }}
    >
      <div className="max-w-7xl mx-auto">
        {/* ── Header ── */}
        <motion.div
          initial={{ opacity: 0, y: 14 }}
          animate={{ opacity: 1, y: 0 }}
          className="flex items-start justify-between flex-wrap gap-4 mb-6"
        >
          <div>
            <div className="tag-green inline-flex items-center gap-1.5 mb-4">
              <Globe className="size-3" /> LIVE THREAT MAP
            </div>
            <h1
              className="font-display text-4xl mb-1.5"
              style={{ color: "var(--text-primary)" }}
            >
              Global Attack Geolocation
            </h1>
            <div className="flex items-center gap-3 flex-wrap">
              <span
                className="text-xs"
                style={{
                  color: "var(--text-muted)",
                  fontFamily: "var(--font-mono)",
                }}
              >
                {total} events · last 7 days · refreshed{" "}
                {lastRefresh.toLocaleTimeString()}
              </span>
              {/* FIX ISSUE 1+2: Show estimated location count so analysts
                  know which points used fallback geo (expired phishing DNS) */}
              {fallbackCount > 0 && (
                <span
                  className="text-[10px]"
                  style={{
                    color: "var(--text-muted)",
                    fontFamily: "var(--font-mono)",
                  }}
                >
                  {fallbackCount} estimated locations
                  <span title="Phishing domains with expired DNS — location estimated from known hosting patterns">
                    {" "}
                    (?)
                  </span>
                </span>
              )}
              {liveCount > 0 && (
                <span
                  className="text-xs font-bold px-2 py-0.5 rounded"
                  style={{
                    color: "#f87171",
                    background: "rgba(248,113,113,0.08)",
                    border: "1px solid rgba(248,113,113,0.2)",
                    fontFamily: "var(--font-mono)",
                  }}
                >
                  +{liveCount} LIVE
                </span>
              )}
            </div>
          </div>

          {/* Controls */}
          <div className="flex flex-wrap items-center gap-2">
            {/* Category tabs */}
            <div
              className="flex items-center gap-1 p-1 rounded-lg"
              style={{
                background: "var(--bg-elevated)",
                border: "1px solid var(--bg-border)",
              }}
            >
              {categories.slice(0, 5).map((cat) => (
                <button
                  key={cat}
                  onClick={() => setFilterCat(cat)}
                  className="px-2.5 py-1 rounded text-xs font-medium capitalize transition-all"
                  style={{
                    background:
                      filterCat === cat
                        ? "var(--accent-subtle)"
                        : "transparent",
                    color:
                      filterCat === cat ? "var(--accent)" : "var(--text-muted)",
                    border:
                      filterCat === cat
                        ? "1px solid var(--accent-border)"
                        : "1px solid transparent",
                  }}
                >
                  {cat === "all" ? "All" : CAT_LABEL[cat] || cat}
                </button>
              ))}
            </div>

            {/* Severity filter */}
            <select
              value={filterSev}
              onChange={(e) => setFilterSev(Number(e.target.value))}
              className="text-xs px-2.5 py-1.5 rounded-lg appearance-none"
              style={{
                background: "var(--bg-elevated)",
                border: "1px solid var(--bg-border)",
                color: "var(--text-secondary)",
                fontFamily: "var(--font-mono)",
              }}
            >
              <option value={0}>All severity</option>
              <option value={3}>Medium+</option>
              <option value={4}>High+</option>
              <option value={5}>Critical only</option>
            </select>

            {/* Arcs toggle */}
            <button
              onClick={() => setShowArcs((v) => !v)}
              className="text-xs px-3 py-1.5 rounded-lg transition-all"
              style={{
                background: showArcs
                  ? "var(--accent-subtle)"
                  : "var(--bg-elevated)",
                border: showArcs
                  ? "1px solid var(--accent-border)"
                  : "1px solid var(--bg-border)",
                color: showArcs ? "var(--accent)" : "var(--text-muted)",
              }}
            >
              Attack Arcs
            </button>

            <button
              onClick={fetchGeo}
              disabled={loading}
              className="btn-ghost flex items-center gap-2 px-3.5 py-2 text-sm"
            >
              <RefreshCw
                className={`size-4 ${loading ? "animate-spin" : ""}`}
              />
              Refresh
            </button>
          </div>
        </motion.div>

        {/* ── Stat strip ── */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-5">
          {[
            {
              label: "Total Events",
              value: total,
              color: "var(--accent)",
              icon: Activity,
            },
            {
              label: "Critical",
              value: critical,
              color: "var(--color-danger)",
              icon: AlertTriangle,
            },
            { label: "High", value: high, color: "#fb923c", icon: Zap },
            {
              label: "Countries",
              value: topCountries.length,
              color: "var(--color-info)",
              icon: Globe,
            },
          ].map((s, i) => (
            <motion.div
              key={s.label}
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: i * 0.05 }}
              className="card p-4 flex items-center gap-3"
            >
              <div
                className="w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0"
                style={{
                  background: `${s.color}14`,
                  border: `1px solid ${s.color}25`,
                }}
              >
                <s.icon className="size-4" style={{ color: s.color }} />
              </div>
              <div>
                <div
                  className="text-xl font-bold font-display"
                  style={{ color: s.color }}
                >
                  {s.value}
                </div>
                <div className="label-caps">{s.label}</div>
              </div>
            </motion.div>
          ))}
        </div>

        {/* ── Main: Map + Sidebar ── */}
        <div className="grid lg:grid-cols-4 gap-4">
          {/* ── Map — 3 cols ── */}
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: 0.15 }}
            className="lg:col-span-3 card overflow-hidden"
            style={{ background: "var(--bg-card)" }}
          >
            {/* Terminal bar */}
            <div
              className="flex items-center gap-3 px-5 py-2.5 border-b"
              style={{
                borderColor: "var(--bg-border)",
                background: "rgba(0,0,0,0.38)",
              }}
            >
              <div className="flex gap-1.5">
                {["#ff5f57", "#febc2e", "#28c840"].map((c) => (
                  <div
                    key={c}
                    className="w-2.5 h-2.5 rounded-full"
                    style={{ background: c }}
                  />
                ))}
              </div>
              <span
                className="text-xs"
                style={{
                  color: "var(--text-muted)",
                  fontFamily: "var(--font-mono)",
                }}
              >
                phishnetra::threat_map — {filtered.length} events rendered
              </span>
              <div
                className="ml-auto hidden md:flex items-center gap-4 text-xs"
                style={{ fontFamily: "var(--font-mono)" }}
              >
                {[
                  ["#f87171", "Critical"],
                  ["#fb923c", "High"],
                  ["#fbbf24", "Medium"],
                  ["#60a5fa", "Low"],
                ].map(([c, l]) => (
                  <span key={l} style={{ color: c }}>
                    ● {l}
                  </span>
                ))}
              </div>
            </div>

            {/* Empty state */}
            {!loading && filtered.length === 0 && (
              <div
                className="flex flex-col items-center justify-center py-24"
                style={{ background: "#060c14" }}
              >
                <Globe
                  className="size-14 mb-4 opacity-30"
                  style={{ color: "var(--accent)" }}
                />
                <p
                  className="font-semibold mb-1 text-sm"
                  style={{ color: "var(--text-secondary)" }}
                >
                  No threat events to plot
                </p>
                <p
                  className="text-xs text-center max-w-xs"
                  style={{ color: "var(--text-muted)" }}
                >
                  Scan phishing or suspicious URLs — each scan resolves the
                  hosting domain to a real-world location and appears here
                  within seconds.
                </p>
              </div>
            )}

            {/* SVG World Map */}
            <div
              className="relative"
              onMouseMove={(e) => {
                setTooltipPos({ x: e.clientX, y: e.clientY });
              }}
              onMouseLeave={() => {
                leaveTimer.current = setTimeout(() => setHovered(null), 120);
              }}
              style={{
                background: "#060c14",
                boxShadow:
                  points.length > 10
                    ? "inset 0 0 60px rgba(255,68,68,0.04)"
                    : "none",
                transition: "box-shadow 1s ease",
              }}
            >
              <svg
                ref={svgRef}
                viewBox={`0 0 ${W} ${H}`}
                style={{ width: "100%", height: "auto", display: "block" }}
              >
                <defs>
                  <radialGradient id="ocean" cx="50%" cy="50%" r="70%">
                    <stop offset="0%" stopColor="#0c1a2e" stopOpacity="0.9" />
                    <stop offset="100%" stopColor="#060c14" stopOpacity="0" />
                  </radialGradient>
                  <filter id="glow">
                    <feGaussianBlur stdDeviation="2" result="blur" />
                    <feMerge>
                      <feMergeNode in="blur" />
                      <feMergeNode in="SourceGraphic" />
                    </feMerge>
                  </filter>
                </defs>

                {/* Ocean */}
                <rect width={W} height={H} fill="#060c14" />
                <rect width={W} height={H} fill="url(#ocean)" />

                {/* Grid */}
                {[-60, -30, 0, 30, 60].map((lat) => {
                  const { y } = project(lat, 0);
                  return (
                    <line
                      key={`lat${lat}`}
                      x1={0}
                      y1={y}
                      x2={W}
                      y2={y}
                      stroke="rgba(30,46,72,0.7)"
                      strokeWidth="0.35"
                      strokeDasharray="4,6"
                    />
                  );
                })}
                {[-150, -120, -90, -60, -30, 0, 30, 60, 90, 120, 150].map(
                  (lon) => {
                    const { x } = project(0, lon);
                    return (
                      <line
                        key={`lon${lon}`}
                        x1={x}
                        y1={0}
                        x2={x}
                        y2={H}
                        stroke="rgba(30,46,72,0.7)"
                        strokeWidth="0.35"
                        strokeDasharray="4,6"
                      />
                    );
                  },
                )}

                {/* Land */}
                <g fill="#0f1e34" stroke="#1a2f4a" strokeWidth="0.5">
                  {LAND_PATHS.map((d, i) => (
                    <path key={i} d={d} />
                  ))}
                </g>

                {/* Attack arcs */}
                {showArcs &&
                  filtered
                    .slice(0, 80)
                    .map((p, i) => (
                      <AttackArc
                        key={`arc-${p.ip}-${i}`}
                        from={project(p.lat, p.lon)}
                        to={center}
                        color={sevColor(p.severity)}
                        delay={i % 5}
                      />
                    ))}

                {/* Threat dots */}
                {filtered.map((p, i) => {
                  const { x, y } = project(p.lat, p.lon);
                  const col = sevColor(p.severity);
                  const isHov =
                    hovered?.ip === p.ip && hovered?.domain === p.domain;
                  const r = isHov ? 7.5 : p.severity >= 5 ? 5.5 : 4.5;
                  const dur = `${2.2 + (i % 4) * 0.4}s`;
                  return (
                    <g key={`pt-${p.ip}-${i}`}>
                      {/* Pulse ring */}
                      <circle
                        cx={x}
                        cy={y}
                        r={r + 3}
                        fill="none"
                        stroke={col}
                        strokeWidth="0.8"
                        opacity="0.25"
                        style={{ pointerEvents: "none" }}
                      >
                        <animate
                          attributeName="r"
                          values={`${r + 1};${r + 12};${r + 1}`}
                          dur={dur}
                          repeatCount="indefinite"
                        />
                        <animate
                          attributeName="opacity"
                          values="0.28;0;0.28"
                          dur={dur}
                          repeatCount="indefinite"
                        />
                      </circle>

                      {/* Visible dot */}
                      <circle
                        cx={x}
                        cy={y}
                        r={p.isFallback ? r * 0.8 : r}
                        fill={p.isFallback ? "none" : col}
                        stroke={col}
                        strokeWidth={p.isFallback ? "1.2" : "0"}
                        strokeDasharray={p.isFallback ? "2 2" : "none"}
                        opacity={p.isFallback ? 0.5 : 0.85}
                        style={{ pointerEvents: "none" }}
                        filter={isHov ? "url(#glow)" : undefined}
                      />

                      {/* Highlight */}
                      {!p.isFallback && (
                        <circle
                          cx={x - r * 0.28}
                          cy={y - r * 0.28}
                          r={r * 0.28}
                          fill="white"
                          opacity="0.3"
                          style={{ pointerEvents: "none" }}
                        />
                      )}

                      {/* Invisible hit area — large enough to click reliably */}
                      <circle
                        cx={x}
                        cy={y}
                        r={14}
                        fill="transparent"
                        style={{ cursor: "pointer" }}
                        onMouseEnter={() => {
                          if (leaveTimer.current)
                            clearTimeout(leaveTimer.current);
                          setHovered(p);
                        }}
                        onMouseLeave={() => {
                          leaveTimer.current = setTimeout(
                            () => setHovered(null),
                            120,
                          );
                        }}
                        onClick={() => setSelectedPoint(p)}
                      />
                    </g>
                  );
                })}

                {/* Country labels for top origins */}
                {topCountries.slice(0, 6).map((tc) => {
                  const coords = COUNTRY_COORDS[tc.country];
                  if (!coords) return null;
                  const { x, y } = project(coords[0], coords[1]);
                  return (
                    <g key={`lbl-${tc.country}`}>
                      <text
                        x={x}
                        y={y - 7}
                        textAnchor="middle"
                        fontSize="7"
                        fill="rgba(148,163,184,0.65)"
                        fontFamily="monospace"
                      >
                        {tc.country}
                      </text>
                      <text
                        x={x}
                        y={y + 14}
                        textAnchor="middle"
                        fontSize="6"
                        fill="rgba(248,113,113,0.65)"
                        fontFamily="monospace"
                      >
                        {tc.count}
                      </text>
                    </g>
                  );
                })}
              </svg>

              {/* Loading overlay */}
              {loading && (
                <div
                  className="absolute inset-0 flex flex-col items-center justify-center gap-3"
                  style={{
                    background: "rgba(6,12,20,0.72)",
                    backdropFilter: "blur(4px)",
                  }}
                >
                  <div
                    className="w-9 h-9 rounded-full border-2 animate-spin"
                    style={{
                      borderColor: "var(--accent)",
                      borderTopColor: "transparent",
                    }}
                  />
                  <span
                    className="text-xs"
                    style={{
                      color: "var(--text-muted)",
                      fontFamily: "var(--font-mono)",
                    }}
                  >
                    Resolving threat locations via DNS...
                  </span>
                </div>
              )}
            </div>
          </motion.div>

          {/* ── Sidebar ── */}
          <div className="space-y-4">
            {/* Country heatmap */}
            <motion.div
              initial={{ opacity: 0, x: 12 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: 0.25 }}
              className="card p-5"
              style={{ background: "var(--bg-card)" }}
            >
              <div className="flex items-center gap-2 mb-4">
                <Globe className="size-4" style={{ color: "var(--accent)" }} />
                <span
                  className="text-sm font-semibold"
                  style={{ color: "var(--text-primary)" }}
                >
                  Top Threat Origins
                </span>
              </div>

              {topCountries.length === 0 ? (
                <p className="text-xs" style={{ color: "var(--text-muted)" }}>
                  Scan some URLs to populate this
                </p>
              ) : (
                <div className="space-y-3">
                  {topCountries.map((tc, i) => {
                    const max = topCountries[0]?.count || 1;
                    const pct = (tc.count / max) * 100;
                    return (
                      <div key={tc.country}>
                        <div className="flex items-center justify-between mb-1">
                          <div className="flex items-center gap-2">
                            <span>{FLAG[tc.country] || "🌐"}</span>
                            <span
                              className="text-xs font-semibold"
                              style={{
                                color: "var(--text-primary)",
                                fontFamily: "var(--font-mono)",
                              }}
                            >
                              {tc.country}
                            </span>
                          </div>
                          <div className="flex items-center gap-2">
                            {tc.critical > 0 && (
                              <span
                                className="text-[9px] px-1.5 py-0.5 rounded font-bold"
                                style={{
                                  color: "#f87171",
                                  background: "rgba(248,113,113,0.1)",
                                  fontFamily: "var(--font-mono)",
                                }}
                              >
                                {tc.critical}×crit
                              </span>
                            )}
                            <span
                              className="text-xs font-bold"
                              style={{
                                color: "var(--accent)",
                                fontFamily: "var(--font-mono)",
                              }}
                            >
                              {tc.count}
                            </span>
                          </div>
                        </div>
                        <div
                          className="rounded-full overflow-hidden"
                          style={{ height: 3, background: "var(--bg-border)" }}
                        >
                          <motion.div
                            className="h-full rounded-full"
                            initial={{ width: 0 }}
                            animate={{ width: `${pct}%` }}
                            transition={{
                              delay: 0.3 + i * 0.06,
                              duration: 0.7,
                              ease: [0.23, 1, 0.32, 1],
                            }}
                            style={{
                              background:
                                tc.critical > 0
                                  ? "linear-gradient(90deg,#f87171,#fb923c)"
                                  : "linear-gradient(90deg,var(--accent-dim),var(--accent))",
                            }}
                          />
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </motion.div>

            {/* Live event feed */}
            <motion.div
              initial={{ opacity: 0, x: 12 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: 0.35 }}
              className="card overflow-hidden"
              style={{ background: "var(--bg-card)" }}
            >
              <div
                className="px-4 py-3 border-b flex items-center gap-2"
                style={{ borderColor: "var(--bg-border)" }}
              >
                <Activity
                  className="size-3.5"
                  style={{ color: "var(--accent)" }}
                />
                <span
                  className="text-xs font-semibold"
                  style={{ color: "var(--text-primary)" }}
                >
                  Recent Events
                </span>
                <span
                  className="ml-auto text-[9px] font-bold"
                  style={{
                    color: "var(--text-muted)",
                    fontFamily: "var(--font-mono)",
                  }}
                >
                  <motion.span
                    key={filtered.length}
                    initial={{ scale: 1.3, color: "#ff4444" }}
                    animate={{ scale: 1, color: "var(--text-primary)" }}
                    transition={{ duration: 0.4 }}
                  >
                    {filtered.length}
                  </motion.span>{" "}
                  plotted
                </span>
              </div>

              <div
                className="divide-y overflow-y-auto"
                style={{ borderColor: "var(--bg-border)", maxHeight: 310 }}
              >
                {filtered.length === 0 ? (
                  <div className="px-4 py-8 text-center">
                    <Shield
                      className="size-8 mx-auto mb-2 opacity-20"
                      style={{ color: "var(--text-muted)" }}
                    />
                    <p
                      className="text-xs"
                      style={{ color: "var(--text-muted)" }}
                    >
                      No events to display
                    </p>
                  </div>
                ) : (
                  [...filtered]
                    .sort(
                      (a, b) =>
                        new Date(b.timestamp).getTime() -
                        new Date(a.timestamp).getTime(),
                    )
                    .slice(0, 25)
                    .map((p, i) => {
                      const col = sevColor(p.severity);
                      const isHov = hovered?.ip === p.ip;
                      return (
                        <div
                          key={`feed-${i}`}
                          className="px-4 py-2.5 transition-colors cursor-default"
                          style={{
                            background: isHov ? "var(--bg-hover)" : undefined,
                            borderColor: "var(--bg-border)",
                          }}
                          onMouseEnter={() => setHovered(p)}
                          onMouseLeave={() => setHovered(null)}
                        >
                          <div className="flex items-center gap-2 mb-0.5">
                            <div
                              className="w-1.5 h-1.5 rounded-full flex-shrink-0"
                              style={{ background: col }}
                            />
                            <span
                              className="text-xs font-medium truncate"
                              style={{
                                color: "var(--text-primary)",
                                fontFamily: "var(--font-mono)",
                                maxWidth: 130,
                              }}
                            >
                              {p.domain || p.ip}
                            </span>
                            <span
                              className="text-[9px] ml-auto flex-shrink-0"
                              style={{
                                color: col,
                                fontFamily: "var(--font-mono)",
                              }}
                            >
                              {FLAG[p.country] || "🌐"} {p.country}
                            </span>
                          </div>
                          <div className="flex items-center gap-2 pl-3.5">
                            <span
                              className="text-[9px] capitalize"
                              style={{
                                color: "var(--text-muted)",
                                fontFamily: "var(--font-mono)",
                              }}
                            >
                              {CAT_LABEL[p.category] || p.category}
                            </span>
                            <span
                              className="text-[9px] ml-auto"
                              style={{
                                color: "var(--text-muted)",
                                fontFamily: "var(--font-mono)",
                              }}
                            >
                              {new Date(p.timestamp).toLocaleTimeString()}
                            </span>
                          </div>
                        </div>
                      );
                    })
                )}
              </div>
            </motion.div>
          </div>
        </div>
      </div>

      {/* ── Hover tooltip (fixed, follows cursor) ── */}
      <AnimatePresence>
        {hovered && (
          <motion.div
            initial={{ opacity: 0, scale: 0.94 }}
            animate={{ opacity: 1, scale: 1 }}
            exit={{ opacity: 0, scale: 0.94 }}
            transition={{ duration: 0.1 }}
            style={{
              position: "fixed",
              left: Math.min(tooltipPos.x + 14, window.innerWidth - 230),
              top: Math.max(tooltipPos.y - 90, 72),
              zIndex: 200,
              pointerEvents: "none",
              minWidth: 200,
            }}
          >
            <div
              className="card-glass px-4 py-3"
              style={{
                boxShadow: "var(--shadow-xl)",
                border: `1px solid ${sevColor(hovered.severity)}30`,
              }}
            >
              <div className="flex items-center gap-2 mb-2">
                <div
                  className="w-2 h-2 rounded-full flex-shrink-0"
                  style={{ background: sevColor(hovered.severity) }}
                />
                <span
                  className="text-xs font-bold"
                  style={{
                    color: sevColor(hovered.severity),
                    fontFamily: "var(--font-mono)",
                  }}
                >
                  SEV-{hovered.severity} ·{" "}
                  {CAT_LABEL[hovered.category] || hovered.category}
                </span>
              </div>
              {hovered.domain && (
                <p
                  className="text-xs font-medium mb-1 truncate"
                  style={{
                    color: "var(--text-primary)",
                    fontFamily: "var(--font-mono)",
                    maxWidth: 200,
                  }}
                >
                  {hovered.domain}
                </p>
              )}
              <p
                className="text-xs"
                style={{
                  color: "var(--text-secondary)",
                  fontFamily: "var(--font-mono)",
                }}
              >
                {FLAG[hovered.country] || "🌐"}{" "}
                {hovered.city ? `${hovered.city}, ` : ""}
                {hovered.country}
              </p>
              <p
                className="text-xs mt-0.5"
                style={{
                  color: "var(--text-muted)",
                  fontFamily: "var(--font-mono)",
                }}
              >
                {hovered.ip}
              </p>
              {hovered.org && (
                <p
                  className="text-xs mt-0.5 truncate"
                  style={{
                    color: "var(--text-muted)",
                    fontFamily: "var(--font-mono)",
                    maxWidth: 200,
                  }}
                >
                  {hovered.org}
                </p>
              )}
              {hovered.riskScore !== undefined && (
                <p
                  className="text-xs mt-1 font-bold"
                  style={{
                    color: sevColor(hovered.severity),
                    fontFamily: "var(--font-mono)",
                  }}
                >
                  Risk: {hovered.riskScore}%
                </p>
              )}
              <p
                className="text-[10px] mt-1"
                style={{
                  color: "var(--text-muted)",
                  fontFamily: "var(--font-mono)",
                }}
              >
                {new Date(hovered.timestamp).toLocaleString()}
              </p>
              <p
                className="text-[10px] mt-2"
                style={{
                  color: "var(--text-muted)",
                  fontFamily: "var(--font-mono)",
                }}
              >
                Click dot for full details
              </p>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* ── Click detail panel ── */}
      <AnimatePresence>
        {selectedPoint && (
          <>
            {/* Backdrop */}
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              transition={{ duration: 0.18 }}
              className="fixed inset-0 z-40"
              style={{
                background: "rgba(0,0,0,0.55)",
                backdropFilter: "blur(2px)",
              }}
              onClick={() => setSelectedPoint(null)}
            />

            {/* Panel — slides up from bottom */}
            <motion.div
              initial={{ opacity: 0, y: 60 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: 60 }}
              transition={{ duration: 0.22, ease: [0.23, 1, 0.32, 1] }}
              className="fixed bottom-0 left-0 right-0 z-50 mx-auto"
              style={{ maxWidth: 560, padding: "0 16px 24px" }}
            >
              <div
                className="rounded-2xl overflow-hidden"
                style={{
                  background: "var(--bg-elevated)",
                  border: `1px solid ${sevColor(selectedPoint.severity)}40`,
                  boxShadow: `0 -4px 40px rgba(0,0,0,0.5), 0 0 0 1px ${sevColor(selectedPoint.severity)}20`,
                }}
              >
                {/* Header strip */}
                <div
                  className="flex items-center justify-between px-5 py-3"
                  style={{
                    background: `${sevColor(selectedPoint.severity)}12`,
                    borderBottom: `1px solid ${sevColor(selectedPoint.severity)}25`,
                  }}
                >
                  <div className="flex items-center gap-2.5">
                    <div
                      className="w-2.5 h-2.5 rounded-full"
                      style={{
                        background: sevColor(selectedPoint.severity),
                        boxShadow: `0 0 8px ${sevColor(selectedPoint.severity)}`,
                      }}
                    />
                    <span
                      className="text-sm font-bold"
                      style={{
                        color: sevColor(selectedPoint.severity),
                        fontFamily: "var(--font-mono)",
                      }}
                    >
                      SEV-{selectedPoint.severity} ·{" "}
                      {CAT_LABEL[selectedPoint.category] ||
                        selectedPoint.category}
                    </span>
                  </div>
                  <button
                    onClick={() => setSelectedPoint(null)}
                    className="p-1 rounded-lg transition-colors"
                    style={{ color: "var(--text-muted)" }}
                    onMouseEnter={(e) =>
                      (e.currentTarget.style.color = "var(--text-primary)")
                    }
                    onMouseLeave={(e) =>
                      (e.currentTarget.style.color = "var(--text-muted)")
                    }
                  >
                    <X className="size-4" />
                  </button>
                </div>

                {/* Body */}
                <div className="px-5 py-4 grid grid-cols-2 gap-x-6 gap-y-3">
                  {/* Domain / IP */}
                  <div className="col-span-2">
                    <p
                      className="text-[10px] mb-0.5"
                      style={{
                        color: "var(--text-muted)",
                        fontFamily: "var(--font-mono)",
                        letterSpacing: "0.08em",
                      }}
                    >
                      TARGET
                    </p>
                    <p
                      className="text-sm font-bold truncate"
                      style={{
                        color: "var(--text-primary)",
                        fontFamily: "var(--font-mono)",
                      }}
                    >
                      {selectedPoint.domain || selectedPoint.ip}
                    </p>
                  </div>

                  {/* IP */}
                  <div>
                    <div className="flex items-center gap-1.5 mb-0.5">
                      <Server
                        className="size-3"
                        style={{ color: "var(--text-muted)" }}
                      />
                      <p
                        className="text-[10px]"
                        style={{
                          color: "var(--text-muted)",
                          fontFamily: "var(--font-mono)",
                          letterSpacing: "0.08em",
                        }}
                      >
                        IP ADDRESS
                      </p>
                    </div>
                    <p
                      className="text-xs font-medium"
                      style={{
                        color: "var(--text-secondary)",
                        fontFamily: "var(--font-mono)",
                      }}
                    >
                      {selectedPoint.ip}
                    </p>
                  </div>

                  {/* Location */}
                  <div>
                    <div className="flex items-center gap-1.5 mb-0.5">
                      <MapPin
                        className="size-3"
                        style={{ color: "var(--text-muted)" }}
                      />
                      <p
                        className="text-[10px]"
                        style={{
                          color: "var(--text-muted)",
                          fontFamily: "var(--font-mono)",
                          letterSpacing: "0.08em",
                        }}
                      >
                        LOCATION
                      </p>
                    </div>
                    <p
                      className="text-xs font-medium"
                      style={{
                        color: "var(--text-secondary)",
                        fontFamily: "var(--font-mono)",
                      }}
                    >
                      {FLAG[selectedPoint.country] || "🌐"}{" "}
                      {[
                        selectedPoint.city,
                        selectedPoint.region,
                        selectedPoint.country,
                      ]
                        .filter(Boolean)
                        .join(", ")}
                    </p>
                  </div>

                  {/* Org / ISP */}
                  {selectedPoint.org && (
                    <div>
                      <div className="flex items-center gap-1.5 mb-0.5">
                        <Wifi
                          className="size-3"
                          style={{ color: "var(--text-muted)" }}
                        />
                        <p
                          className="text-[10px]"
                          style={{
                            color: "var(--text-muted)",
                            fontFamily: "var(--font-mono)",
                            letterSpacing: "0.08em",
                          }}
                        >
                          ORG / ISP
                        </p>
                      </div>
                      <p
                        className="text-xs font-medium truncate"
                        style={{
                          color: "var(--text-secondary)",
                          fontFamily: "var(--font-mono)",
                        }}
                      >
                        {selectedPoint.org}
                      </p>
                    </div>
                  )}

                  {/* Risk score */}
                  {selectedPoint.riskScore !== undefined && (
                    <div>
                      <div className="flex items-center gap-1.5 mb-0.5">
                        <AlertTriangle
                          className="size-3"
                          style={{ color: "var(--text-muted)" }}
                        />
                        <p
                          className="text-[10px]"
                          style={{
                            color: "var(--text-muted)",
                            fontFamily: "var(--font-mono)",
                            letterSpacing: "0.08em",
                          }}
                        >
                          RISK SCORE
                        </p>
                      </div>
                      <p
                        className="text-xs font-bold"
                        style={{
                          color: sevColor(selectedPoint.severity),
                          fontFamily: "var(--font-mono)",
                        }}
                      >
                        {selectedPoint.riskScore}/100
                      </p>
                    </div>
                  )}

                  {/* Source */}
                  <div>
                    <div className="flex items-center gap-1.5 mb-0.5">
                      <Activity
                        className="size-3"
                        style={{ color: "var(--text-muted)" }}
                      />
                      <p
                        className="text-[10px]"
                        style={{
                          color: "var(--text-muted)",
                          fontFamily: "var(--font-mono)",
                          letterSpacing: "0.08em",
                        }}
                      >
                        SOURCE
                      </p>
                    </div>
                    <p
                      className="text-xs font-medium capitalize"
                      style={{
                        color: "var(--text-secondary)",
                        fontFamily: "var(--font-mono)",
                      }}
                    >
                      {selectedPoint.source || "scan"}
                    </p>
                  </div>

                  {/* Timestamp */}
                  <div className="col-span-2">
                    <div className="flex items-center gap-1.5 mb-0.5">
                      <Clock
                        className="size-3"
                        style={{ color: "var(--text-muted)" }}
                      />
                      <p
                        className="text-[10px]"
                        style={{
                          color: "var(--text-muted)",
                          fontFamily: "var(--font-mono)",
                          letterSpacing: "0.08em",
                        }}
                      >
                        DETECTED
                      </p>
                    </div>
                    <p
                      className="text-xs"
                      style={{
                        color: "var(--text-secondary)",
                        fontFamily: "var(--font-mono)",
                      }}
                    >
                      {new Date(selectedPoint.timestamp).toLocaleString()}
                    </p>
                  </div>
                </div>

                {/* Footer actions */}
                <div
                  className="flex items-center gap-2 px-5 py-3"
                  style={{ borderTop: "1px solid var(--bg-border)" }}
                >
                  <button
                    onClick={() => {
                      setSelectedPoint(null);
                      navigate("/siem");
                    }}
                    className="flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-semibold transition-all"
                    style={{
                      background: "var(--accent-subtle)",
                      border: "1px solid var(--accent-border)",
                      color: "var(--accent)",
                    }}
                    onMouseEnter={(e) =>
                      (e.currentTarget.style.background =
                        "var(--accent-border)")
                    }
                    onMouseLeave={(e) =>
                      (e.currentTarget.style.background =
                        "var(--accent-subtle)")
                    }
                  >
                    <ExternalLink className="size-3.5" />
                    View in SIEM
                  </button>
                  <button
                    onClick={() =>
                      navigate(`/scan`, {
                        state: {
                          url: selectedPoint.domain || selectedPoint.ip,
                        },
                      })
                    }
                    className="flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-medium transition-all"
                    style={{
                      background: "var(--bg-card)",
                      border: "1px solid var(--bg-border)",
                      color: "var(--text-secondary)",
                    }}
                    onMouseEnter={(e) =>
                      (e.currentTarget.style.borderColor =
                        "var(--bg-border-hover, #334155)")
                    }
                    onMouseLeave={(e) =>
                      (e.currentTarget.style.borderColor = "var(--bg-border)")
                    }
                  >
                    Re-scan
                  </button>
                  <button
                    onClick={() => setSelectedPoint(null)}
                    className="ml-auto text-xs transition-colors"
                    style={{
                      color: "var(--text-muted)",
                      fontFamily: "var(--font-mono)",
                    }}
                  >
                    ESC to close
                  </button>
                </div>
              </div>
            </motion.div>
          </>
        )}
      </AnimatePresence>
    </div>
  );
}
