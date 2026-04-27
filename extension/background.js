// FILE: extension/background.js

var API_BASE  = "http://localhost:5000/api/scan";
var scanCache = {};
var CACHE_TTL = 5 * 60 * 1000;

// Auto-scan every tab when it finishes loading
chrome.tabs.onUpdated.addListener(function(tabId, changeInfo, tab) {
  if (changeInfo.status !== "complete") return;
  if (!tab.url) return;
  if (tab.url.indexOf("chrome://") === 0) return;
  if (tab.url.indexOf("chrome-extension://") === 0) return;
  if (tab.url === "about:blank") return;
  scanTab(tabId, tab.url);
});

async function scanTab(tabId, url) {
  try {
    var cached = scanCache[url];
    if (cached && Date.now() - cached.timestamp < CACHE_TTL) {
      handleResult(tabId, url, cached.result);
      return;
    }
    var result = await callAPI(url);
    if (!result) return;
    scanCache[url] = { result: result, timestamp: Date.now() };
    handleResult(tabId, url, result);
  } catch (e) {
    console.log("PhishGuard scan error:", e.message);
  }
}

async function callAPI(input) {
  try {
    var res = await fetch(API_BASE, {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({ input: input }),
    });
    if (!res.ok) return null;
    return await res.json();
  } catch (e) {
    return null;
  }
}

async function handleResult(tabId, url, result) {
  try {
    var data = {};
    data["tab_" + tabId] = { url: url, result: result, scannedAt: Date.now() };
    await chrome.storage.session.set(data);
  } catch (e) {}

  setBadge(tabId, result.status, result.riskScore);

  // Feed to SIEM (only if flagged — skip safe to avoid noise)
  if (result.status !== "safe" || result.riskScore >= 20) {
    feedToSIEM(url, result); // fire-and-forget
  }

  if (result.status === "phishing" && result.riskScore >= 70) {

    showNotification(url, result);
    injectBanner(tabId, result);
  } else if (result.status === "suspicious" && result.riskScore >= 50) {
    injectBanner(tabId, result);
  }
}

function setBadge(tabId, status, score) {
  var text  = status === "safe" ? "OK" : status === "suspicious" ? "!" : "X";
  var color = status === "safe" ? "#00ff88" : status === "suspicious" ? "#f5a623" : "#ff4444";
  chrome.action.setBadgeText({ tabId: tabId, text: text });
  chrome.action.setBadgeBackgroundColor({ tabId: tabId, color: color });
  chrome.action.setTitle({ tabId: tabId, title: "PhishGuard: " + status.toUpperCase() + " (" + score + "/100)" });
}

function showNotification(url, result) {
  var domain = url;
  try { domain = new URL(url).hostname; } catch(e) {}
  chrome.notifications.create({
    type:    "basic",
    iconUrl: "icons/icon48.png",
    title:   "PhishGuard: Phishing Detected!",
    message: domain + " is flagged as phishing (score: " + result.riskScore + "/100).",
    priority: 2,
  });
}

async function injectBanner(tabId, result) {
  try {
    await chrome.scripting.executeScript({
      target: { tabId: tabId },
      func: function(status, score, issues) {
        if (document.getElementById("phishguard-banner")) return;
        var color  = status === "phishing" ? "#ff4444" : "#f5a623";
        var icon   = status === "phishing" ? "🚨" : "⚠️";
        var label  = status === "phishing" ? "PHISHING DETECTED" : "SUSPICIOUS SITE";
        var banner = document.createElement("div");
        banner.id  = "phishguard-banner";
        banner.style.cssText = [
          "position:fixed", "top:0", "left:0", "right:0", "z-index:2147483647",
          "background:#0d0d0d", "border-bottom:2px solid " + color,
          "font-family:system-ui,sans-serif", "padding:10px 20px",
          "display:flex", "align-items:center", "gap:12px",
          "box-shadow:0 2px 20px rgba(0,0,0,0.6)",
        ].join(";");
        var topIssue = issues && issues[0] ? issues[0] : "Threat detected";
        banner.innerHTML = (
          "<span style='font-size:18px'>" + icon + "</span>" +
          "<div style='flex:1'>" +
            "<strong style='color:" + color + ";font-size:13px'>PhishGuard AI: " + label + " — Score: " + score + "/100</strong>" +
            "<div style='color:#888;font-size:11px;margin-top:2px'>" + topIssue + "</div>" +
          "</div>" +
          "<button id='phishguard-close' style='background:transparent;border:1px solid " + color + ";color:" + color + ";padding:4px 10px;border-radius:6px;cursor:pointer;font-size:11px'>Dismiss</button>"
        );
        document.body.prepend(banner);
        document.getElementById("phishguard-close").onclick = function() { banner.remove(); };
      },
      args: [result.status, result.riskScore, result.issues || []],
    });
  } catch(e) {}
}

async function feedToSIEM(url, result) {
  try {
    await fetch("http://localhost:5000/api/siem/event", {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        type:       "extension_scan",
        sourceType: "extension",
        agent:      "PhishGuard Chrome Extension",
        data: {
          url,
          status:    result.status,
          riskScore: result.riskScore,
          issues:    result.issues || [],
          mlScore:   result.mlScore,
          ruleScore: result.ruleScore,
        },
      }),
    });
  } catch {
    // SIEM offline — fail silently, don't break the extension
  }
}

// Context menu

chrome.runtime.onInstalled.addListener(function() {
  chrome.contextMenus.create({ id:"scan-link", title:"PhishGuard: Scan this link", contexts:["link"]   });
  chrome.contextMenus.create({ id:"scan-page", title:"PhishGuard: Scan this page", contexts:["page"]   });
});

chrome.contextMenus.onClicked.addListener(async function(info, tab) {
  var target = info.menuItemId === "scan-link" ? info.linkUrl : tab.url;
  if (!target || !tab || !tab.id) return;
  chrome.action.setBadgeText({ tabId: tab.id, text: "..." });
  chrome.action.setBadgeBackgroundColor({ tabId: tab.id, color: "#6366f1" });
  var result = await callAPI(target);
  if (result) {
    scanCache[target] = { result: result, timestamp: Date.now() };
    handleResult(tab.id, target, result);
  }
});

// Message handler for popup
chrome.runtime.onMessage.addListener(function(msg, sender, sendResponse) {
  if (msg.type === "GET_TAB_RESULT") {
    chrome.storage.session.get("tab_" + msg.tabId).then(function(data) {
      sendResponse(data["tab_" + msg.tabId] || null);
    });
    return true;
  }
  if (msg.type === "SCAN_URL") {
    callAPI(msg.url).then(function(result) { sendResponse({ result: result }); });
    return true;
  }
});