// FILE: extension/popup.js (FULL REPLACEMENT)
// PhishNetra AI v2.1 — Popup UI

var API_BASE = "http://localhost:5000/api/scan";
var API_LOGIN = "http://localhost:5000/api/auth/login";

// ── Token helpers ──────────────────────────────────────────────────
async function getStoredToken() {
  const data = await chrome.storage.local.get("pg_token");
  return data.pg_token || null;
}

async function doLogin(username, password) {
  try {
    const res = await fetch(API_LOGIN, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
      signal: AbortSignal.timeout(8000),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || "Login failed");
    // Store token and user info accessible from both popup and background service worker
    await chrome.storage.local.set({
      pg_token: data.token,
      pg_user: JSON.stringify(data.user),
      pg_username: data.user?.username || username,
      pg_role: data.user?.role || "analyst",
    });
    return { ok: true };
  } catch (err) {
    return { ok: false, error: err.message };
  }
}

async function doLogout() {
  await chrome.storage.local.remove([
    "pg_token",
    "pg_user",
    "pg_username",
    "pg_role",
  ]);
}

// ── Auth-gated entry point ─────────────────────────────────────────
document.addEventListener("DOMContentLoaded", async () => {
  const token = await getStoredToken();
  if (!token) {
    showLoginScreen();
    return;
  }
  // Check token expiry
  try {
    const payload = JSON.parse(atob(token.split(".")[1]));
    if (payload.exp && payload.exp * 1000 < Date.now()) {
      await doLogout();
      showLoginScreen("Session expired — please log in again");
      return;
    }
  } catch {
    /* malformed token — proceed anyway */
  }
  // Token valid — initialize normal popup
  initPopup();
});

function showLoginScreen(errorMsg) {
  document.body.innerHTML = `
    <div style="padding:20px;min-width:300px;background:#080c14;color:#f1f5f9;font-family:system-ui">
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:20px">
        <div style="width:32px;height:32px;background:rgba(0,255,136,0.08);border:1px solid rgba(0,255,136,0.2);border-radius:8px;display:flex;align-items:center;justify-content:center;font-size:16px">🛡️</div>
        <div>
          <div style="font-weight:700;font-size:15px">PhishNetra AI</div>
          <div style="font-size:10px;color:#64748b;font-family:monospace">v2.1 · Sign In</div>
        </div>
      </div>
      ${errorMsg ? `<div style="color:#f87171;font-size:12px;margin-bottom:12px;padding:8px;background:rgba(248,113,113,0.08);border-radius:8px;border:1px solid rgba(248,113,113,0.2)">${errorMsg}</div>` : ""}
      <div style="margin-bottom:10px">
        <input id="ext-username" type="text" placeholder="Username"
          style="width:100%;box-sizing:border-box;padding:8px 12px;background:#111827;border:1px solid #1c2840;border-radius:8px;color:#f1f5f9;font-size:13px;outline:none"/>
      </div>
      <div style="margin-bottom:14px">
        <input id="ext-password" type="password" placeholder="Password"
          style="width:100%;box-sizing:border-box;padding:8px 12px;background:#111827;border:1px solid #1c2840;border-radius:8px;color:#f1f5f9;font-size:13px;outline:none"/>
      </div>
      <button id="ext-login-btn"
        style="width:100%;padding:9px;background:#3b82f6;border:none;border-radius:8px;color:#fff;font-weight:600;font-size:13px;cursor:pointer">
        Sign In
      </button>
      <div id="ext-login-error" style="color:#f87171;font-size:11px;margin-top:8px;text-align:center;display:none"></div>
      <div style="margin-top:12px;font-size:10px;color:#475569;text-align:center">Use your PhishNetra dashboard credentials</div>
    </div>`;

  const btn = document.getElementById("ext-login-btn");
  const errEl = document.getElementById("ext-login-error");
  const usernameEl = document.getElementById("ext-username");
  const passwordEl = document.getElementById("ext-password");

  const attemptLogin = async () => {
    const username = usernameEl.value.trim();
    const password = passwordEl.value;
    if (!username || !password) {
      errEl.textContent = "Enter username and password";
      errEl.style.display = "block";
      return;
    }
    btn.textContent = "Signing in...";
    btn.disabled = true;
    const result = await doLogin(username, password);
    if (result.ok) {
      initPopup();
    } else {
      errEl.textContent = result.error || "Login failed";
      errEl.style.display = "block";
      btn.textContent = "Sign In";
      btn.disabled = false;
    }
  };

  btn.addEventListener("click", attemptLogin);
  passwordEl.addEventListener("keydown", (e) => {
    if (e.key === "Enter") attemptLogin();
  });
  usernameEl.addEventListener("keydown", (e) => {
    if (e.key === "Enter") passwordEl.focus();
  });
}

// ── Main popup (only reached when token is valid) ──────────────────
async function initPopup() {
  var resultArea = document.getElementById("resultArea");
  var manualInput = document.getElementById("manualInput");
  var manualBtn = document.getElementById("manualBtn");
  var apiDot = document.getElementById("apiDot");
  var apiStatus = document.getElementById("apiStatus");
  var scanCountEl = document.getElementById("scanCount");
  var openDash = document.getElementById("openDash");
  var refreshBtn = document.getElementById("refresh");

  var statusCfg = {
    safe: { icon: "✅", label: "SAFE", color: "#00ff88", bar: "#00ff88" },
    suspicious: {
      icon: "⚠️",
      label: "SUSPICIOUS",
      color: "#f5a623",
      bar: "#f5a623",
    },
    phishing: {
      icon: "🚨",
      label: "PHISHING",
      color: "#ff4444",
      bar: "#ff4444",
    },
  };

  function getDomain(url) {
    try {
      return new URL(url).hostname;
    } catch {
      return url.substring(0, 40);
    }
  }

  function isEmailHost(url) {
    return (
      url &&
      (url.includes("mail.google.com") ||
        url.includes("outlook.live.com") ||
        url.includes("outlook.office.com") ||
        url.includes("outlook.office365.com"))
    );
  }

  function detectEmailPlatformFromUrl(url) {
    if (!url) return null;
    if (url.includes("mail.google.com")) return "gmail";
    if (
      url.includes("outlook.live.com") ||
      url.includes("outlook.office.com") ||
      url.includes("outlook.office365.com")
    ) {
      return "outlook";
    }
    return null;
  }

  function escapeHtml(str) {
    if (!str) return "";
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function renderResult(url, result) {
    var cfg = statusCfg[result.status] || {
      icon: "❓",
      label: "UNKNOWN",
      color: "#8b95a8",
      bar: "#8b95a8",
    };
    var domain = getDomain(url);
    var issues = (result.issues || []).slice(0, 3);

    // ── Issues list ──
    var issuesHTML = "";
    if (issues.length > 0) {
      var items = issues
        .map(function (i) {
          // Color-code by severity keyword
          var dotColor = "#f5a623";
          if (/homoglyph|otp|impersonat|credential|defanged|aitm|kit/i.test(i))
            dotColor = "#ff4444";
          else if (/corporate|conversation|payment|evasion|punycode/i.test(i))
            dotColor = "#f97316";
          return (
            '<div class="issue-item">' +
            '<div class="issue-dot" style="background:' +
            dotColor +
            '"></div>' +
            "<span>" +
            escapeHtml(i.substring(0, 90)) +
            "</span>" +
            "</div>"
          );
        })
        .join("");
      issuesHTML =
        '<div class="issues"><div class="issues-title">DETECTED ISSUES</div>' +
        items +
        "</div>";
    } else {
      issuesHTML =
        '<div style="padding:0 14px 12px;font-size:11px;color:#00ff88;font-family:monospace;">No threats detected</div>';
    }

    // ── ML score row ──
    var mlHTML = "";
    if (result.mlEnabled && result.mlScore != null) {
      mlHTML =
        '<div class="ml-row">' +
        '<div class="ml-badge">' +
        '<div class="ml-dot"></div>' +
        "ML HYBRID · Neural: " +
        result.mlScore +
        " · Rules: " +
        (result.ruleScore || 0) +
        "</div>" +
        "</div>";
    }

    // ── CSV Dataset Match ──
    var csvHTML = "";
    if (
      result.csvMatch &&
      result.csvMatch.matched &&
      result.csvMatch.label === "phishing"
    ) {
      var matchColor =
        result.csvMatch.matchLevel === "exact"
          ? "#f87171"
          : result.csvMatch.matchLevel === "domain+path"
            ? "#fb923c"
            : "#fbbf24";
      var matchLabel =
        result.csvMatch.matchLevel === "exact"
          ? "EXACT MATCH"
          : result.csvMatch.matchLevel === "domain+path"
            ? "DOMAIN+PATH"
            : "DOMAIN MATCH";
      csvHTML =
        '<div class="tag-row">' +
        '<div class="tag" style="color:' +
        matchColor +
        ";border-color:" +
        matchColor +
        "22;background:" +
        matchColor +
        '11;max-width:310px">' +
        "📂 Dataset: " +
        escapeHtml(result.csvMatch.source || "CSV") +
        " · " +
        matchLabel +
        (result.csvMatch.count > 1 ? " · " + result.csvMatch.count + "×" : "") +
        "</div>" +
        "</div>";
    }

    // ── PhishDNA fingerprint ──
    var dnaHTML = "";
    if (result.dna && result.dna.fingerprint) {
      var technique = result.dna.technique
        ? result.dna.technique.replace(/_/g, " ")
        : "";
      var brand =
        result.dna.brand && result.dna.brand !== "unknown"
          ? " · " + result.dna.brand
          : "";
      dnaHTML =
        '<div class="tag-row">' +
        '<div class="tag tag-purple">' +
        "🧬 #" +
        escapeHtml(result.dna.fingerprint) +
        (technique ? " · " + escapeHtml(technique) : "") +
        escapeHtml(brand) +
        "</div>" +
        "</div>";
    }

    // ── Kit match ──
    var kitHTML = "";
    if (result.kitMatch && result.kitMatch.kitName) {
      var sophColor =
        result.kitMatch.sophistication === "expert"
          ? "#ff4444"
          : result.kitMatch.sophistication === "high"
            ? "#f97316"
            : result.kitMatch.sophistication === "medium"
              ? "#f5a623"
              : "#00ff88";
      kitHTML =
        '<div class="tag-row">' +
        '<div class="tag" style="color:' +
        sophColor +
        ";border-color:" +
        sophColor +
        "33;background:" +
        sophColor +
        '11">' +
        "🏗 Kit: " +
        escapeHtml(result.kitMatch.kitName) +
        " · " +
        result.kitMatch.confidence +
        "%" +
        " · " +
        escapeHtml(result.kitMatch.sophistication || "").toUpperCase() +
        "</div>" +
        "</div>";
    }

    // ── Evasion detection ──
    var evasionHTML = "";
    if (result.evasion && result.evasion.detected) {
      var evColor =
        result.evasion.level === "SOPHISTICATED"
          ? "#ff4444"
          : result.evasion.level === "MODERATE"
            ? "#f97316"
            : "#f5a623";
      evasionHTML =
        '<div class="tag-row">' +
        '<div class="tag" style="color:' +
        evColor +
        ";border-color:" +
        evColor +
        "33;background:" +
        evColor +
        '11">' +
        "🛡 Evasion: " +
        escapeHtml(result.evasion.level) +
        " · " +
        result.evasion.signals +
        " signal" +
        (result.evasion.signals !== 1 ? "s" : "") +
        "</div>" +
        "</div>";
    }

    // ── Community confirmed ──
    var communityHTML = "";
    if (result.communityMatch && result.communityMatch.found) {
      communityHTML =
        '<div class="community-banner">' +
        "🌐 Community Confirmed — " +
        result.communityMatch.reportCount +
        " org" +
        (result.communityMatch.reportCount !== 1 ? "s" : "") +
        " flagged · " +
        result.communityMatch.confidence +
        "% confidence" +
        "</div>";
    }

    resultArea.innerHTML =
      '<div class="result-card status-' +
      result.status +
      '">' +
      communityHTML +
      '<div class="result-header">' +
      '<div class="result-icon">' +
      cfg.icon +
      "</div>" +
      '<div class="result-info">' +
      '<div class="result-label">' +
      cfg.label +
      "</div>" +
      '<div class="result-url" title="' +
      escapeHtml(url) +
      '">' +
      escapeHtml(domain) +
      "</div>" +
      "</div>" +
      "<div>" +
      '<div class="result-score" style="color:' +
      cfg.color +
      '">' +
      result.riskScore +
      "</div>" +
      '<div class="score-label">/ 100</div>' +
      "</div>" +
      "</div>" +
      '<div class="score-bar-wrap">' +
      '<div class="score-bar-bg">' +
      '<div class="score-bar-fill" style="width:' +
      Math.min(result.riskScore, 100) +
      "%;background:" +
      cfg.bar +
      '"></div>' +
      "</div>" +
      "</div>" +
      issuesHTML +
      csvHTML +
      dnaHTML +
      kitHTML +
      evasionHTML +
      mlHTML +
      "</div>";
  }

  function renderLoading(url) {
    var domain = getDomain(url);
    resultArea.innerHTML =
      '<div class="result-card status-scanning" style="margin:12px;">' +
      '<div class="loading-wrap">' +
      '<div class="spinner"></div>' +
      '<div class="loading-text">Scanning...</div>' +
      '<div class="loading-url">' +
      escapeHtml(domain) +
      "</div>" +
      "</div>" +
      "</div>";
  }

  function renderError(msg) {
    resultArea.innerHTML =
      '<div class="error-box">⚠ ' + escapeHtml(msg) + "</div>";
  }

  async function callAPI(input) {
    const token = await getStoredToken();
    if (!token) {
      showLoginScreen("Not logged in — please sign in to scan");
      throw new Error("Not authenticated");
    }
    var res = await fetch(API_BASE, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({ input }),
    });
    if (res.status === 401) {
      await doLogout();
      showLoginScreen("Session expired — please log in again");
      throw new Error("Session expired");
    }
    if (!res.ok) {
      const errBody = await res.json().catch(() => ({}));
      throw new Error(errBody.error || `API error ${res.status}`);
    }
    return res.json();
  }

  async function checkHealth() {
    try {
      var res = await fetch("http://localhost:5000/api/health", {
        signal: AbortSignal.timeout(3000),
      });
      if (res.ok) {
        apiDot.classList.remove("offline");
        apiStatus.textContent = "ONLINE";
        apiStatus.style.color = "#00ff88";
      } else throw new Error();
    } catch {
      apiDot.classList.add("offline");
      apiStatus.textContent = "OFFLINE";
      apiStatus.style.color = "#ff4444";
    }
  }

  async function updateCount() {
    try {
      var data = await chrome.storage.local.get("todayScans");
      var today = new Date().toDateString();
      var counts = data.todayScans || {};
      var n = counts[today] || 0;
      scanCountEl.textContent = n + " scan" + (n !== 1 ? "s" : "") + " today";
    } catch {}
  }

  async function incCount() {
    try {
      var data = await chrome.storage.local.get("todayScans");
      var today = new Date().toDateString();
      var counts = data.todayScans || {};
      counts[today] = (counts[today] || 0) + 1;
      await chrome.storage.local.set({ todayScans: counts });
      await updateCount();
    } catch {}
  }

  async function loadSIEMStatus() {
    try {
      const token = await getStoredToken();
      const headers = token
        ? {
            "Content-Type": "application/json",
            Authorization: `Bearer ${token}`,
          }
        : { "Content-Type": "application/json" };

      const [statsRes, policyRes, queueRes] = await Promise.all([
        fetch("http://localhost:5000/api/siem/stats", {
          headers,
          signal: AbortSignal.timeout(3000),
        }),
        fetch("http://localhost:5000/api/siem/enterprise-policy", {
          headers,
          signal: AbortSignal.timeout(3000),
        }),
        new Promise((resolve) =>
          chrome.runtime.sendMessage({ type: "GET_QUEUE_SIZE" }, resolve),
        ),
      ]);

      const overview = statsRes.ok
        ? (await statsRes.json()).overview || {}
        : {};
      const policy = policyRes.ok ? await policyRes.json() : null;
      const queueSize = queueRes?.size || 0;

      const el = document.getElementById("siemStatus");
      if (!el) return;

      el.innerHTML =
        '<div style="padding:8px 12px 8px;border-top:1px solid #1e2736">' +
        '<span style="font-size:9px;color:#4a5a78;font-family:monospace;letter-spacing:.1em;display:block;margin-bottom:5px">' +
        "SENTINELCORE SIEM" +
        "</span>" +
        '<div style="display:flex;gap:6px;margin-bottom:5px">' +
        [
          { label: "Alerts", val: overview.totalAlerts || 0, color: "#a78bfa" },
          {
            label: "Open",
            val: overview.openAlerts || 0,
            color: (overview.openAlerts || 0) > 0 ? "#f5a623" : "#4a5a78",
          },
          {
            label: "Critical",
            val: overview.criticalAlerts || 0,
            color: (overview.criticalAlerts || 0) > 0 ? "#ff4444" : "#4a5a78",
          },
        ]
          .map(function (s) {
            return (
              '<div style="flex:1;text-align:center;background:#0d1117;border:1px solid #1e2736;border-radius:6px;padding:4px">' +
              '<div style="font-size:14px;font-weight:700;color:' +
              s.color +
              ';font-family:monospace">' +
              s.val +
              "</div>" +
              '<div style="font-size:8px;color:#4a5a78;font-family:monospace">' +
              s.label +
              "</div>" +
              "</div>"
            );
          })
          .join("") +
        "</div>" +
        (policy
          ? '<div style="display:flex;gap:5px;align-items:center">' +
            '<div style="flex:1;padding:3px 6px;background:#0d1117;border:1px solid ' +
            (policy.autoReportToSIEM ? "rgba(0,255,136,0.2)" : "#1e2736") +
            ';border-radius:5px">' +
            '<span style="font-size:9px;color:' +
            (policy.autoReportToSIEM ? "#00ff88" : "#4a5a78") +
            ';font-family:monospace">' +
            (policy.autoReportToSIEM
              ? "● Auto-report ON"
              : "○ Auto-report OFF") +
            "</span>" +
            "</div>" +
            (queueSize > 0
              ? '<div style="padding:3px 6px;background:rgba(245,166,35,0.08);border:1px solid rgba(245,166,35,0.2);border-radius:5px">' +
                '<span style="font-size:9px;color:#f5a623;font-family:monospace">⚡ Queue: ' +
                queueSize +
                "</span>" +
                "</div>"
              : "") +
            "</div>"
          : "") +
        "</div>";
    } catch {
      /* SIEM offline — fail silently */
    }
  }

  async function init() {
    await checkHealth();
    await updateCount();
    await loadSIEMStatus();

    // GAP 11: Read current inbox threat count from extension badge text
    try {
      var tabs = await chrome.tabs.query({ active: true, currentWindow: true });
      var activeTab = tabs[0];
      if (activeTab) {
        var badgeText = await chrome.action.getBadgeText({
          tabId: activeTab.id,
        });
        var count = parseInt(badgeText, 10) || 0;
        renderInboxStatus(count);
      }
    } catch {
      renderInboxStatus(0);
    }

    try {
      var tabs = await chrome.tabs.query({ active: true, currentWindow: true });
      var tab = tabs[0];

      if (!tab || !tab.url || tab.url.startsWith("chrome://")) {
        renderError("Cannot scan browser internal pages.");
        return;
      }

      var emailPlatform = null;
      if (isEmailHost(tab.url)) {
        emailPlatform = detectEmailPlatformFromUrl(tab.url);
        try {
          var platformResp = await chrome.tabs.sendMessage(tab.id, {
            type: "GET_PLATFORM",
          });
          emailPlatform = platformResp?.platform || emailPlatform;
        } catch {
          /* content script not ready yet; URL fallback still works */
        }

        var platformLabel = emailPlatform === "gmail" ? "Gmail" : "Outlook";
        var platformIcon = emailPlatform === "gmail" ? "📧" : "📨";

        var emailSection = document.createElement("div");
        emailSection.id = "email-scan-section";
        emailSection.style.cssText =
          "margin-bottom:12px;padding:10px;background:rgba(167,139,250,0.08);border:1px solid rgba(167,139,250,0.2);border-radius:10px";
        emailSection.innerHTML =
          '<div style="display:flex;align-items:center;gap:8px;margin-bottom:8px">' +
          '<span style="font-size:14px">' +
          platformIcon +
          "</span>" +
          "<div>" +
          '<div style="font-size:12px;font-weight:600;color:#a78bfa">' +
          platformLabel +
          " Detected</div>" +
          '<div style="font-size:10px;color:#64748b;font-family:monospace" id="email-preview-label">Open an email to scan it</div>' +
          "</div>" +
          "</div>" +
          '<button id="scan-email-btn" style="width:100%;padding:8px;background:rgba(167,139,250,0.15);border:1px solid rgba(167,139,250,0.35);border-radius:8px;color:#a78bfa;font-size:12px;font-weight:600;cursor:pointer;display:flex;align-items:center;justify-content:center;gap:6px">' +
          platformIcon +
          " Scan This Email</button>" +
          '<div id="email-scan-status" style="font-size:10px;color:#64748b;text-align:center;margin-top:6px;display:none"></div>';

        var container =
          document.getElementById("container") ||
          document.querySelector(".container") ||
          document.body;
        container.insertBefore(emailSection, container.firstChild);

        try {
          var previewResp = await chrome.tabs.sendMessage(tab.id, {
            type: "EXTRACT_EMAIL",
          });
          if (previewResp?.emailData?.subject) {
            var previewLabel = document.getElementById("email-preview-label");
            if (previewLabel) {
              previewLabel.textContent =
                "📬 " +
                previewResp.emailData.subject.substring(0, 45) +
                (previewResp.emailData.subject.length > 45 ? "…" : "");
              previewLabel.style.color = "#94a3b8";
            }
          }
        } catch {
          /* no open email yet */
        }

        var scanEmailBtn = document.getElementById("scan-email-btn");
        if (scanEmailBtn) {
          scanEmailBtn.addEventListener("click", async function () {
            var btn = this;
            var statusEl = document.getElementById("email-scan-status");

            btn.textContent = "⏳ Extracting email...";
            btn.disabled = true;
            statusEl.style.display = "block";
            statusEl.textContent = "";

            try {
              var resp = await chrome.tabs.sendMessage(tab.id, {
                type: "EXTRACT_EMAIL",
              });

              if (!resp?.emailData) {
                statusEl.textContent =
                  "⚠ No email open — open an email first then click scan";
                statusEl.style.color = "#f87171";
                btn.textContent = platformIcon + " Scan This Email";
                btn.disabled = false;
                return;
              }

              var emailData = resp.emailData;
              statusEl.textContent =
                '📤 Scanning: "' +
                (emailData.subject || "email").substring(0, 40) +
                '"';
              statusEl.style.color = "#a78bfa";
              btn.textContent = "🧠 Scanning...";

              var scanResp = await chrome.runtime.sendMessage({
                type: "EMAIL_SCAN_REQUEST",
                emailText: emailData.emailText,
              });

              if (scanResp?._authError) {
                showLoginScreen("Session expired — please log in again");
                return;
              }

              if (scanResp?.error) {
                statusEl.textContent = "✗ " + scanResp.error;
                statusEl.style.color = "#f87171";
                btn.textContent = platformIcon + " Scan This Email";
                btn.disabled = false;
                return;
              }

              var result = scanResp?.result;
              if (!result) {
                statusEl.textContent = "✗ No response from backend";
                statusEl.style.color = "#f87171";
                btn.textContent = platformIcon + " Scan This Email";
                btn.disabled = false;
                return;
              }

              var scanLabel = emailData.subject
                ? 'EMAIL: "' + emailData.subject.substring(0, 50) + '"'
                : "EMAIL from " + (emailData.sender || "unknown sender");

              renderResult(scanLabel, result);

              if (emailData.sender || emailData.senderName) {
                var senderBadge = document.createElement("div");
                senderBadge.style.cssText =
                  "margin-top:8px;padding:6px 10px;background:rgba(96,165,250,0.07);border:1px solid rgba(96,165,250,0.18);border-radius:8px;font-size:10px;font-family:monospace";
                senderBadge.innerHTML =
                  '<span style="color:#64748b">From: </span>' +
                  '<span style="color:#94a3b8">' +
                  escapeHtml(emailData.senderName || "") +
                  " &lt;" +
                  escapeHtml(emailData.sender || "unknown") +
                  "&gt;</span>" +
                  (emailData.hasLinks > 0
                    ? '<span style="color:#64748b;margin-left:8px">' +
                      emailData.hasLinks +
                      " link" +
                      (emailData.hasLinks > 1 ? "s" : "") +
                      " found</span>"
                    : "");
                resultArea.appendChild(senderBadge);
              }

              await incCount();

              statusEl.style.display = "none";
              btn.textContent = platformIcon + " Scan Another Email";
              btn.disabled = false;
            } catch {
              statusEl.textContent =
                "✗ Extraction failed — refresh the page and try again";
              statusEl.style.color = "#f87171";
              btn.textContent = platformIcon + " Scan This Email";
              btn.disabled = false;
            }
          });
        }
      }

      if (!emailPlatform) {
        // Try cached result from background
        var stored = await new Promise(function (resolve) {
          chrome.runtime.sendMessage(
            { type: "GET_TAB_RESULT", tabId: tab.id },
            function (r) {
              resolve(r);
            },
          );
        });

        if (stored && stored.result) {
          renderResult(stored.url, stored.result);
          return;
        }

        // Not cached — scan now
        renderLoading(tab.url);
        var result = await callAPI(tab.url);
        renderResult(tab.url, result);
        await incCount();
      }
    } catch (e) {
      var msg =
        e.message === "Failed to fetch"
          ? "Cannot reach backend on localhost:5000 — make sure PhishNetra server is running"
          : e.message === "Not authenticated" || e.message === "Session expired"
            ? "" // showLoginScreen already called inside callAPI
            : "Scan failed: " + e.message;
      if (msg) renderError(msg);
    }
  }

  // ── Manual scan ──
  manualBtn.addEventListener("click", async function () {
    var input = manualInput.value.trim();
    if (!input) return;
    manualBtn.disabled = true;
    manualBtn.textContent = "...";
    renderLoading(input);
    try {
      var result = await callAPI(input);
      renderResult(input, result);
      await incCount();
    } catch (e) {
      if (
        e.message !== "Not authenticated" &&
        e.message !== "Session expired"
      ) {
        renderError(
          e.message === "Failed to fetch"
            ? "Cannot reach backend on localhost:5000 — make sure PhishNetra server is running"
            : "Scan failed: " + e.message,
        );
      }
    } finally {
      manualBtn.disabled = false;
      manualBtn.textContent = "Scan";
    }
  });

  manualInput.addEventListener("keydown", function (e) {
    if (e.key === "Enter") manualBtn.click();
  });

  document.getElementById("openDash").addEventListener("click", function () {
    chrome.tabs.create({ url: "http://localhost:5173/admin" });
  });

  document.getElementById("refresh").addEventListener("click", function () {
    resultArea.innerHTML = "";
    initPopup();
  });

  // ── Logout button (if present in HTML) ──
  const logoutBtn = document.getElementById("logout-btn");
  if (logoutBtn) {
    logoutBtn.addEventListener("click", async () => {
      await doLogout();
      showLoginScreen();
    });
  }

  init();
  // ── GAP 11: Inbox threat summary ─────────────────────────────────
  function renderInboxStatus(threats) {
    var el = document.getElementById("inbox-status");
    if (!el) return;
    if (threats > 0) {
      el.innerHTML = [
        "<div style='margin-top:10px;padding:10px;border-radius:8px;",
        "background:rgba(248,113,113,0.1);border:1px solid rgba(248,113,113,0.3)'>",
        "<div style='font-size:11px;font-weight:700;color:#f87171'>",
        "\u26a0 " +
          threats +
          " threat" +
          (threats > 1 ? "s" : "") +
          " in inbox</div>",
        "<div style='font-size:10px;color:#999;margin-top:3px'>",
        "Suspicious emails marked in list view</div>",
        "</div>",
      ].join("");
    } else {
      el.innerHTML = [
        "<div style='margin-top:10px;padding:10px;border-radius:8px;",
        "background:rgba(52,211,153,0.08);border:1px solid rgba(52,211,153,0.2)'>",
        "<div style='font-size:11px;color:#34d399'>\u2713 Inbox scan active \u2014 no threats</div>",
        "</div>",
      ].join("");
    }
  }

  // Expose so background can call it via message if needed
  window.__renderInboxStatus = renderInboxStatus;
} // end initPopup
