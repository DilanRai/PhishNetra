// FILE: extension/background.js (FULL REPLACEMENT)
// PhishNetra AI v2.1 — Chrome Extension Background Service Worker

var API_BASE = "http://localhost:5000/api/scan";
var SIEM_BASE = "http://localhost:5000/api/siem";
var CACHE_TTL = 5 * 60 * 1000; // 5 minutes
var scanCache = {};

// ── Token helper — reads from chrome.storage.local (where popup.js saves it at login) ──
async function getToken() {
  try {
    const data = await chrome.storage.local.get("pg_token");
    return data.pg_token || null;
  } catch {
    return null;
  }
}

// ── Auth headers helper — always call this before any protected API request ──
async function authHeaders(extra = {}) {
  const token = await getToken();
  return {
    "Content-Type": "application/json",
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
    ...extra,
  };
}

// ── Offline event queue — stores SIEM events when backend is down ──
var siemQueue = [];
var MAX_QUEUE = 50;

// ──────────────────────────────────────────────────────────────────
// ENTERPRISE POLICY — cached to avoid fetch on every tab load
// ──────────────────────────────────────────────────────────────────
var policyCache = null;
var policyCacheTime = 0;
var POLICY_TTL = 2 * 60 * 1000; // 2 minutes

async function getEnterprisePolicy() {
  const now = Date.now();
  if (policyCache && now - policyCacheTime < POLICY_TTL) return policyCache;
  try {
    const policyHeaders = await authHeaders();
    const res = await fetch(`${SIEM_BASE}/enterprise-policy`, {
      headers: policyHeaders,
      signal: AbortSignal.timeout(2000),
    });
    if (!res.ok) return null;
    policyCache = await res.json();
    policyCacheTime = now;
    return policyCache;
  } catch {
    return policyCache || null;
  }
}

// ── FIX: Check policy BEFORE making scan API call ──
async function checkPolicyBeforeScan(url, tabId) {
  const policy = await getEnterprisePolicy();
  if (!policy) return false;

  // Check whitelist first
  try {
    const domain = new URL(url).hostname.replace(/^www\./, "");
    if (policy.whitelistedDomains?.includes(domain)) return "whitelisted";
  } catch {}

  // Check blocked TLDs
  const lowerUrl = url.toLowerCase();
  const blocked = policy.blockedTLDs?.find((tld) => {
    try {
      return new URL(url).hostname.endsWith(tld);
    } catch {
      return lowerUrl.includes(tld);
    }
  });

  if (blocked) {
    // Redirect to blocked page
    chrome.tabs.update(tabId, {
      url:
        chrome.runtime.getURL("blocked.html") +
        "?url=" +
        encodeURIComponent(url) +
        "&tld=" +
        encodeURIComponent(blocked),
    });
    // Auto-report to SIEM
    if (policy.autoReportToSIEM) {
      feedToSIEM(url, {
        status: "phishing",
        riskScore: 90,
        issues: [`Blocked by enterprise policy — TLD: ${blocked}`],
        attackTypes: ["policy_block"],
      });
    }
    return "blocked";
  }

  return false;
}

// ──────────────────────────────────────────────────────────────────
// AUTO-SCAN on every tab load
// ──────────────────────────────────────────────────────────────────

// ── Domains that should NEVER be scanned by the extension ──
// These are internal/safe pages — scanning them wastes API calls
// and pollutes history with safe noise
var SKIP_DOMAINS = ["localhost", "127.0.0.1", "0.0.0.0", "::1"];

var SKIP_PORTS = ["5173", "5000", "3000", "8080", "4173"];

function shouldSkipUrl(url) {
  try {
    const u = new URL(url);
    // Skip localhost and loopback (PhishNetra's own frontend/backend)
    if (SKIP_DOMAINS.includes(u.hostname)) return true;
    // Skip any localhost-style port (dev servers)
    if (SKIP_PORTS.includes(u.port)) return true;
    // Skip internal IP ranges
    if (/^192\.168\.|^10\.|^172\.(1[6-9]|2\d|3[01])\./.test(u.hostname))
      return true;
    return false;
  } catch {
    return false;
  }
}

chrome.tabs.onUpdated.addListener(function (tabId, changeInfo, tab) {
  if (changeInfo.status !== "complete") return;
  if (!tab.url) return;
  if (tab.url.startsWith("chrome://")) return;
  if (tab.url.startsWith("chrome-extension://")) return;
  if (tab.url === "about:blank") return;
  if (tab.url.startsWith("file://")) return;
  // ★ FIX: skip localhost / PhishNetra's own pages
  if (shouldSkipUrl(tab.url)) return;
  scanTab(tabId, tab.url);
});

async function scanTab(tabId, url) {
  try {
    // Step 1: Check policy FIRST (no wasted API call if blocked)
    const policyResult = await checkPolicyBeforeScan(url, tabId);
    if (policyResult === "blocked") return;
    if (policyResult === "whitelisted") {
      setBadge(tabId, "safe", 0);
      return;
    }

    // Step 2: Check cache
    const cached = scanCache[url];
    if (cached && Date.now() - cached.timestamp < CACHE_TTL) {
      handleResult(tabId, url, cached.result);
      return;
    }

    // Step 3: API scan
    const result = await callAPI(url);
    if (!result) return;
    // Auth/network errors — show badge but don't block user
    if (result._authError) {
      chrome.action.setBadgeText({ text: "LOGIN", tabId });
      chrome.action.setBadgeBackgroundColor({ color: "#64748b", tabId });
      return;
    }
    if (result._networkError || result._apiError) {
      chrome.action.setBadgeText({ text: "ERR", tabId });
      chrome.action.setBadgeBackgroundColor({ color: "#64748b", tabId });
      return;
    }
    scanCache[url] = { result, timestamp: Date.now() };

    // ★ FIX: only call handleResult for threats — safe URLs just get badge
    if (result.status === "safe") {
      // Just show the green badge — don't save to history, don't feed SIEM
      setBadge(tabId, "safe", result.riskScore);
      return;
    }

    handleResult(tabId, url, result);
  } catch (e) {
    console.log("PhishNetra scan error:", e.message);
  }
}

async function callAPI(input) {
  try {
    const token = await getToken();
    if (!token) {
      console.warn(
        "PhishNetra: no auth token — open extension popup to log in",
      );
      return {
        _authError: true,
        message: "Not logged in — open PhishNetra extension and log in",
      };
    }
    const res = await fetch(API_BASE, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
        // ★ FIX: tell backend this came from the extension
        // backend uses this to skip saving safe URLs to history
        "X-Source": "chrome-extension",
      },
      body: JSON.stringify({ input }),
      signal: AbortSignal.timeout(8000),
    });
    if (res.status === 401) {
      // Token expired — clear it so popup shows login screen
      await chrome.storage.local.remove("pg_token");
      return {
        _authError: true,
        message: "Session expired — please log in again",
      };
    }
    if (!res.ok) {
      const errBody = await res.json().catch(() => ({}));
      return {
        _apiError: true,
        message: errBody.error || `Server error ${res.status}`,
      };
    }
    return await res.json();
  } catch (err) {
    return {
      _networkError: true,
      message: "Cannot reach backend — is it running on localhost:5000?",
    };
  }
}

// ──────────────────────────────────────────────────────────────────
// RESULT HANDLER
// ──────────────────────────────────────────────────────────────────
async function handleResult(tabId, url, result) {
  // Store for popup retrieval
  try {
    const data = {};
    data["tab_" + tabId] = { url, result, scannedAt: Date.now() };
    await chrome.storage.session.set(data);
  } catch {}

  setBadge(tabId, result.status, result.riskScore);

  // Feed to SIEM (non-blocking, with offline queue)
  if (result.status !== "safe" || result.riskScore >= 20) {
    feedToSIEM(url, result);
  }

  // Show notification for critical threats
  if (result.status === "phishing" && result.riskScore >= 70) {
    showNotification(url, result);
    injectBanner(tabId, result);
  } else if (result.status === "suspicious" && result.riskScore >= 50) {
    injectBanner(tabId, result);
  }
}

function setBadge(tabId, status, score) {
  const text = status === "safe" ? "OK" : status === "suspicious" ? "!" : "X";
  const color =
    status === "safe"
      ? "#00ff88"
      : status === "suspicious"
        ? "#f5a623"
        : "#ff4444";
  chrome.action.setBadgeText({ tabId, text });
  chrome.action.setBadgeBackgroundColor({ tabId, color });
  chrome.action.setTitle({
    tabId,
    title: `PhishNetra: ${status.toUpperCase()} (${score}/100)`,
  });
}

function showNotification(url, result) {
  let domain = url;
  try {
    domain = new URL(url).hostname;
  } catch {}

  const kitInfo = result.kitMatch?.kitName
    ? ` · Kit: ${result.kitMatch.kitName}`
    : "";
  const dnaInfo = result.dna?.fingerprint
    ? ` · DNA: #${result.dna.fingerprint}`
    : "";

  chrome.notifications.create({
    type: "basic",
    iconUrl: "icons/icon48.png",
    title: "PhishNetra: Phishing Detected!",
    message: `${domain} — Score: ${result.riskScore}/100${kitInfo}${dnaInfo}`,
    priority: 2,
  });
}

async function injectBanner(tabId, result) {
  try {
    await chrome.scripting.executeScript({
      target: { tabId },
      func: function (
        status,
        score,
        issues,
        dna,
        kitMatch,
        evasion,
        community,
      ) {
        if (document.getElementById("phishNetra-banner")) return;

        const color = status === "phishing" ? "#ff4444" : "#f5a623";
        const icon = status === "phishing" ? "🚨" : "⚠️";
        const label =
          status === "phishing" ? "PHISHING DETECTED" : "SUSPICIOUS SITE";

        const banner = document.createElement("div");
        banner.id = "phishNetra-banner";
        banner.style.cssText = [
          "position:fixed",
          "top:0",
          "left:0",
          "right:0",
          "z-index:2147483647",
          "background:#0d0d0d",
          "border-bottom:3px solid " + color,
          "font-family:system-ui,sans-serif",
          "padding:10px 20px",
          "display:flex",
          "align-items:center",
          "gap:12px",
          "box-shadow:0 2px 30px rgba(0,0,0,0.8)",
        ].join(";");

        // Build detail tags
        const tags = [];
        if (dna?.technique) tags.push("🧬 " + dna.technique.replace(/_/g, " "));
        if (kitMatch?.kitName) tags.push("🏗 Kit: " + kitMatch.kitName);
        if (evasion?.level) tags.push("🛡 Evasion: " + evasion.level);
        if (community?.found)
          tags.push(
            "🌐 Community: " + community.reportCount + " orgs confirmed",
          );
        const tagsHTML =
          tags.length > 0
            ? "<div style='font-size:9px;color:#666;margin-top:3px;font-family:monospace'>" +
              tags.join(" · ") +
              "</div>"
            : "";

        const topIssue = issues && issues[0] ? issues[0] : "Threat detected";

        banner.innerHTML =
          "<span style='font-size:20px;flex-shrink:0'>" +
          icon +
          "</span>" +
          "<div style='flex:1;min-width:0'>" +
          "<strong style='color:" +
          color +
          ";font-size:13px'>" +
          "PhishNetra AI: " +
          label +
          " — " +
          score +
          "/100" +
          "</strong>" +
          "<div style='color:#888;font-size:11px;margin-top:1px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis'>" +
          topIssue +
          "</div>" +
          tagsHTML +
          "</div>" +
          "<button id='phishNetra-close' style='" +
          "background:transparent;border:1px solid " +
          color +
          ";" +
          "color:" +
          color +
          ";padding:4px 10px;border-radius:6px;" +
          "cursor:pointer;font-size:11px;flex-shrink:0'" +
          ">Dismiss</button>";

        document.body.prepend(banner);
        document.getElementById("phishNetra-close").onclick = () =>
          banner.remove();
      },
      args: [
        result.status,
        result.riskScore,
        result.issues || [],
        result.dna || null,
        result.kitMatch || null,
        result.evasion || null,
        result.communityMatch || null,
      ],
    });
  } catch {}
}

// ──────────────────────────────────────────────────────────────────
// SIEM FEED with offline queue
// ──────────────────────────────────────────────────────────────────
async function feedToSIEM(url, result) {
  const event = {
    type: "extension_scan",
    sourceType: "extension",
    agent: "PhishNetra Chrome Extension v2.1",
    data: {
      url,
      status: result.status,
      riskScore: result.riskScore,
      issues: (result.issues || []).slice(0, 5),
      attackTypes: result.attackTypes || [],
      mlScore: result.mlScore,
      ruleScore: result.ruleScore,
      kitMatch: result.kitMatch || null,
      evasionLevel: result.evasion?.level || null,
      dnaFingerprint: result.dna?.fingerprint || null,
    },
  };

  // Try to flush queue first
  await flushSIEMQueue();

  try {
    const siemHeaders = await authHeaders();
    const res = await fetch(`${SIEM_BASE}/event`, {
      method: "POST",
      headers: siemHeaders,
      body: JSON.stringify(event),
      signal: AbortSignal.timeout(3000),
    });
    if (!res.ok) throw new Error("SIEM unavailable");
  } catch {
    // Queue for later delivery
    if (siemQueue.length < MAX_QUEUE) {
      siemQueue.push({ event, queuedAt: Date.now() });
    }
  }
}

async function flushSIEMQueue() {
  if (siemQueue.length === 0) return;
  const toFlush = [...siemQueue];
  siemQueue = [];

  for (const item of toFlush) {
    // Drop events older than 1 hour
    if (Date.now() - item.queuedAt > 60 * 60 * 1000) continue;
    try {
      const flushHeaders = await authHeaders();
      await fetch(`${SIEM_BASE}/event`, {
        method: "POST",
        headers: flushHeaders,
        body: JSON.stringify(item.event),
        signal: AbortSignal.timeout(2000),
      });
    } catch {
      siemQueue.push(item); // re-queue if still failing
      break;
    }
  }
}

// ──────────────────────────────────────────────────────────────────
// CONTEXT MENU
// ──────────────────────────────────────────────────────────────────
chrome.runtime.onInstalled.addListener(function () {
  chrome.contextMenus.create({
    id: "scan-link",
    title: "🛡 PhishNetra: Scan this link",
    contexts: ["link"],
  });
  chrome.contextMenus.create({
    id: "scan-page",
    title: "🛡 PhishNetra: Scan this page",
    contexts: ["page"],
  });
  chrome.contextMenus.create({
    id: "scan-selection",
    title: "🛡 PhishNetra: Scan selected text",
    contexts: ["selection"],
  });
});

chrome.contextMenus.onClicked.addListener(async function (info, tab) {
  let target;
  if (info.menuItemId === "scan-link") target = info.linkUrl;
  else if (info.menuItemId === "scan-page") target = tab.url;
  else if (info.menuItemId === "scan-selection") target = info.selectionText;

  if (!target || !tab?.id) return;

  chrome.action.setBadgeText({ tabId: tab.id, text: "..." });
  chrome.action.setBadgeBackgroundColor({ tabId: tab.id, color: "#6366f1" });

  const result = await callAPI(target);
  if (result) {
    scanCache[target] = { result, timestamp: Date.now() };
    // Context menu scans: always show result (user explicitly asked)
    // but for safe URLs just show badge + popup — don't pollute history
    if (result.status === "safe") {
      setBadge(tab.id, "safe", result.riskScore);
    } else {
      handleResult(tab.id, target, result);
    }
  }
});

// ──────────────────────────────────────────────────────────────────
// MESSAGE HANDLER — for popup and content script
// ──────────────────────────────────────────────────────────────────
chrome.runtime.onMessage.addListener(function (msg, sender, sendResponse) {
  if (msg.type === "GET_TAB_RESULT") {
    chrome.storage.session.get("tab_" + msg.tabId).then((data) => {
      sendResponse(data["tab_" + msg.tabId] || null);
    });
    return true;
  }

  if (msg.type === "SCAN_URL") {
    callAPI(msg.url).then((result) => sendResponse({ result }));
    return true;
  }

  if (msg.type === "EMAIL_SCAN_REQUEST") {
    (async () => {
      try {
        const token = await getToken();
        if (!token) {
          sendResponse({ error: "Not logged in", _authError: true });
          return;
        }

        const res = await fetch(API_BASE, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${token}`,
          },
          body: JSON.stringify({ input: msg.emailText }),
          signal: AbortSignal.timeout(12000),
        });

        if (res.status === 401) {
          await chrome.storage.local.remove("pg_token");
          sendResponse({ error: "Session expired", _authError: true });
          return;
        }

        if (!res.ok) {
          const errBody = await res.json().catch(() => ({}));
          sendResponse({
            error: errBody.error || `Server error ${res.status}`,
          });
          return;
        }

        const result = await res.json();
        sendResponse({ result });
      } catch {
        sendResponse({
          error: "Cannot reach backend — is PhishNetra running?",
        });
      }
    })();
    return true;
  }

  if (msg.type === "GET_QUEUE_SIZE") {
    sendResponse({ size: siemQueue.length });
    return true;
  }

  if (msg.type === "GET_POLICY") {
    getEnterprisePolicy().then((policy) => sendResponse({ policy }));
    return true;
  }

  if (msg.type === "CONTENT_SIGNALS") {
    // Content script found suspicious signals on the page
    // Trigger a backend scan if not already cached
    const cached = scanCache[msg.url];
    if (!cached || Date.now() - cached.timestamp > 5 * 60 * 1000) {
      callAPI(msg.url).then((result) => {
        if (!result || result._authError || result._networkError) return;
        scanCache[msg.url] = { result, timestamp: Date.now() };
        handleResult(sender.tab.id, msg.url, result);
        // If backend confirms phishing/suspicious, send banner instruction
        if (result.status === "phishing" || result.status === "suspicious") {
          chrome.tabs
            .sendMessage(sender.tab.id, {
              type: "SHOW_WARNING_BANNER",
              url: msg.url,
              verdict: result.status,
              riskScore: result.riskScore,
              signals: msg.signals,
            })
            .catch(() => {});
        }
      });
    }
    return false;
  }
});

// ── Periodic queue flush every 5 minutes ──
setInterval(flushSIEMQueue, 5 * 60 * 1000);

// ──────────────────────────────────────────────────────────────────
// GAP 11: INBOX BADGE UPDATE — from content script inbox scanner
// Updates the extension action badge with inbox threat count
// ──────────────────────────────────────────────────────────────────
chrome.runtime.onMessage.addListener(function (msg, sender, sendResponse) {
  if (msg.type === "SET_BADGE") {
    var tabId = sender.tab && sender.tab.id;
    if (!tabId) return;
    if (msg.count > 0) {
      chrome.action.setBadgeText({ text: String(msg.count), tabId: tabId });
      chrome.action.setBadgeBackgroundColor({
        color: msg.color || "#f87171",
        tabId: tabId,
      });
    } else {
      chrome.action.setBadgeText({ text: "", tabId: tabId });
    }
  }
});
