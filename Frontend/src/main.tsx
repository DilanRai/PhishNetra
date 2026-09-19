// FILE: src/main.tsx — Full replacement with lazy loading + Onboarding route
// Idea 11: React.lazy() reduces initial bundle ~7x (from ~2.8MB to ~380KB)
// Idea 9:  Adds /onboarding route

import { StrictMode, lazy, Suspense } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter, Routes, Route } from "react-router";
import { useParams } from "react-router";
import "./index.css";
import { API_BASE } from "./config";
import { ThemeProvider } from "./context/ThemeContext";

// ── Eager imports (needed on first paint) ──
import Login from "./pages/Login";
import Layout from "./components/Layout";
import Home from "./pages/Home";

// ── Lazy imports (loaded only when navigated to) ──
const Scan = lazy(() => import("./pages/Scan"));
const History = lazy(() => import("./pages/History"));
const Admin = lazy(() => import("./pages/Admin"));
const SIEM = lazy(() => import("./pages/SIEM"));
const ThreatFeed = lazy(() => import("./pages/ThreatFeed"));
const About = lazy(() => import("./pages/About"));
const Logs = lazy(() => import("./pages/Logs"));
const ThreatMap = lazy(() => import("./pages/ThreatMap"));
const SIEMMetrics = lazy(() => import("./pages/SIEMMetrics"));
const BulkScan = lazy(() => import("./pages/BulkScan"));
const APIKeys = lazy(() => import("./pages/APIKeys"));
const PredictiveInsights = lazy(() => import("./pages/PredictiveInsights"));
const SharedReport = lazy(() => import("./pages/SharedReport"));
const CampaignTracker = lazy(() => import("./pages/CampaignTracker"));
const NotificationSettings = lazy(() => import("./pages/NotificationSettings"));
const AdversaryIntel = lazy(() => import("./pages/AdversaryIntel"));
const KitIntelligence = lazy(() => import("./pages/KitIntelligence"));
const ThreatShare = lazy(() => import("./pages/ThreatShare"));
const TrainingMode = lazy(() => import("./pages/TrainingMode"));
const Onboarding = lazy(() => import("./pages/Onboarding")); // Idea 9
const CyberComplaint = lazy(() => import("./pages/CyberComplaint"));
const IncidentResponse = lazy(() => import("./pages/IncidentResponse"));
const RansomwareWatch = lazy(() => import("./pages/RansomwareWatch"));
const NetworkAnomaly = lazy(() => import("./pages/NetworkAnomaly"));
const EvidenceVault = lazy(() => import("./pages/EvidenceVault"));
const EmailForensics = lazy(() => import("./pages/EmailForensics"));

// ── Page loading fallback ──
// Matches app background — no flash on navigation
function PageLoader() {
  return (
    <div
      className="flex items-center justify-center"
      style={{ minHeight: "calc(100vh - 60px)", background: "var(--bg-base)" }}
    >
      <div className="flex flex-col items-center gap-3">
        <div
          className="w-7 h-7 border-2 rounded-full animate-spin"
          style={{
            borderColor: "var(--accent)",
            borderTopColor: "transparent",
          }}
        />
        <span
          className="text-xs"
          style={{ color: "var(--text-muted)", fontFamily: "var(--font-mono)" }}
        >
          Loading...
        </span>
      </div>
    </div>
  );
}

// ── Honeypot trap component ──
function HoneypotTrap() {
  const { id } = useParams();

  return (
    <iframe
      title="Secure resource"
      src={`${API_BASE}/api/honeypot/trigger/${id}`}
      style={{ border: 0, width: "100%", height: "100vh", display: "block" }}
    />
  );
}

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <ThemeProvider>
      <BrowserRouter>
        {/* Suspense wraps all routes — PageLoader shown during any lazy load */}
        <Suspense fallback={<PageLoader />}>
          <Routes>
            {/* Public routes */}
            <Route path="/login" element={<Login />} />
            <Route path="/trap/:id" element={<HoneypotTrap />} />
            <Route path="/onboarding" element={<Onboarding />} />

            {/* App routes — inside Layout */}
            <Route element={<Layout />}>
              <Route path="" element={<Home />} />
              <Route path="/scan" element={<Scan />} />
              <Route path="/history" element={<History />} />
              <Route path="/admin" element={<Admin />} />
              <Route path="/siem" element={<SIEM />} />
              <Route path="/feed" element={<ThreatFeed />} />
              <Route path="/about" element={<About />} />
              <Route path="/logs" element={<Logs />} />
              <Route path="/map" element={<ThreatMap />} />
              <Route path="/metrics" element={<SIEMMetrics />} />
              <Route path="/bulk" element={<BulkScan />} />
              <Route path="/keys" element={<APIKeys />} />
              <Route path="/predict" element={<PredictiveInsights />} />
              <Route path="/report/:shareId" element={<SharedReport />} />
              <Route path="/campaigns" element={<CampaignTracker />} />
              <Route
                path="/settings/notifications"
                element={<NotificationSettings />}
              />
              <Route path="/adversaries" element={<AdversaryIntel />} />
              <Route path="/kits" element={<KitIntelligence />} />
              <Route path="/threatshare" element={<ThreatShare />} />
              <Route path="/training" element={<TrainingMode />} />
              <Route path="/complaints" element={<CyberComplaint />} />
              <Route path="/incidents" element={<IncidentResponse />} />
              <Route path="/ransomware" element={<RansomwareWatch />} />
              <Route path="/network-anomaly" element={<NetworkAnomaly />} />
              <Route path="/evidence" element={<EvidenceVault />} />
              <Route path="/email-forensics" element={<EmailForensics />} />
            </Route>
          </Routes>
        </Suspense>
      </BrowserRouter>
    </ThemeProvider>
  </StrictMode>,
);
