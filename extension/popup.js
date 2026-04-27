// FILE: extension/popup.js

var API_BASE = "http://localhost:5000/api/scan";

var resultArea  = document.getElementById("resultArea");
var manualInput = document.getElementById("manualInput");
var manualBtn   = document.getElementById("manualBtn");
var apiDot      = document.getElementById("apiDot");
var apiStatus   = document.getElementById("apiStatus");
var scanCountEl = document.getElementById("scanCount");
var openDash    = document.getElementById("openDash");
var refreshBtn  = document.getElementById("refresh");

var statusCfg = {
  safe:       { icon:"✅", label:"SAFE",       color:"#00ff88", bar:"#00ff88" },
  suspicious: { icon:"⚠️",  label:"SUSPICIOUS", color:"#f5a623", bar:"#f5a623" },
  phishing:   { icon:"🚨", label:"PHISHING",   color:"#ff4444", bar:"#ff4444" },
};

function getDomain(url) {
  try { return new URL(url).hostname; } catch(e) { return url.substring(0, 40); }
}

function renderResult(url, result) {
  var cfg    = statusCfg[result.status] || { icon:"❓", label:"UNKNOWN", color:"#8b95a8", bar:"#8b95a8" };
  var domain = getDomain(url);
  var issues = (result.issues || []).slice(0, 3);

  var issuesHTML = "";
  if (issues.length > 0) {
    var items = issues.map(function(i) {
      return '<div class="issue-item"><div class="issue-dot"></div><span>' + i + '</span></div>';
    }).join("");
    issuesHTML = '<div class="issues"><div class="issues-title">DETECTED ISSUES</div>' + items + '</div>';
  } else {
    issuesHTML = '<div style="padding:0 14px 12px;font-size:11px;color:#00ff88;font-family:monospace;">No threats detected</div>';
  }

  var mlHTML = "";
  if (result.mlEnabled && result.mlScore !== null && result.mlScore !== undefined) {
    mlHTML = '<div class="ml-row"><div class="ml-badge"><div class="ml-dot"></div>ML HYBRID · Neural: ' + result.mlScore + ' · Rules: ' + result.ruleScore + '</div></div>';
  }

  resultArea.innerHTML =
    '<div class="result-card status-' + result.status + '">' +
      '<div class="result-header">' +
        '<div class="result-icon">' + cfg.icon + '</div>' +
        '<div class="result-info">' +
          '<div class="result-label">' + cfg.label + '</div>' +
          '<div class="result-url" title="' + url + '">' + domain + '</div>' +
        '</div>' +
        '<div>' +
          '<div class="result-score" style="color:' + cfg.color + '">' + result.riskScore + '</div>' +
          '<div class="score-label">/ 100</div>' +
        '</div>' +
      '</div>' +
      '<div class="score-bar-wrap">' +
        '<div class="score-bar-bg">' +
          '<div class="score-bar-fill" style="width:' + result.riskScore + '%;background:' + cfg.bar + '"></div>' +
        '</div>' +
      '</div>' +
      issuesHTML +
      mlHTML +
    '</div>';
}

function renderLoading(url) {
  var domain = getDomain(url);
  resultArea.innerHTML =
    '<div class="result-card status-scanning" style="margin:12px;">' +
      '<div class="loading-wrap">' +
        '<div class="spinner"></div>' +
        '<div class="loading-text">Scanning...</div>' +
        '<div class="loading-url">' + domain + '</div>' +
      '</div>' +
    '</div>';
}

function renderError(msg) {
  resultArea.innerHTML = '<div class="error-box">⚠ ' + msg + '</div>';
}

async function callAPI(input) {
  var res = await fetch(API_BASE, {
    method:  "POST",
    headers: { "Content-Type": "application/json" },
    body:    JSON.stringify({ input: input }),
  });
  if (!res.ok) throw new Error("API error " + res.status);
  return res.json();
}

async function checkHealth() {
  try {
    var res = await fetch("http://localhost:5000/api/health", { signal: AbortSignal.timeout(3000) });
    if (res.ok) {
      apiDot.classList.remove("offline");
      apiStatus.textContent = "ONLINE";
    } else throw new Error();
  } catch(e) {
    apiDot.classList.add("offline");
    apiStatus.textContent  = "OFFLINE";
    apiStatus.style.color  = "#ff4444";
  }
}

async function updateCount() {
  try {
    var data  = await chrome.storage.local.get("todayScans");
    var today = new Date().toDateString();
    var counts = data.todayScans || {};
    scanCountEl.textContent = (counts[today] || 0) + " scans today";
  } catch(e) {}
}

async function incCount() {
  try {
    var data   = await chrome.storage.local.get("todayScans");
    var today  = new Date().toDateString();
    var counts = data.todayScans || {};
    counts[today] = (counts[today] || 0) + 1;
    await chrome.storage.local.set({ todayScans: counts });
    await updateCount();
  } catch(e) {}
}

async function init() {
  await checkHealth();
  await updateCount();

  try {
    var tabs = await chrome.tabs.query({ active:true, currentWindow:true });
    var tab  = tabs[0];
    if (!tab || !tab.url || tab.url.indexOf("chrome://") === 0) {
      renderError("Cannot scan browser internal pages.");
      return;
    }

    // Try to get cached result from background
    var stored = await new Promise(function(resolve) {
      chrome.runtime.sendMessage({ type:"GET_TAB_RESULT", tabId:tab.id }, function(r) { resolve(r); });
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
  } catch(e) {
    var msg = e.message === "Failed to fetch"
      ? "Backend offline. Run: cd backend && npm run dev"
      : "Scan failed: " + e.message;
    renderError(msg);
  }
}

// Manual scan
manualBtn.addEventListener("click", async function() {
  var input = manualInput.value.trim();
  if (!input) return;
  manualBtn.disabled    = true;
  manualBtn.textContent = "...";
  renderLoading(input);
  try {
    var result = await callAPI(input);
    renderResult(input, result);
    await incCount();
  } catch(e) {
    renderError("Scan failed. Is the backend running?");
  } finally {
    manualBtn.disabled    = false;
    manualBtn.textContent = "Scan";
  }
});

manualInput.addEventListener("keydown", function(e) {
  if (e.key === "Enter") manualBtn.click();
});

openDash.addEventListener("click", function() {
  chrome.tabs.create({ url:"http://localhost:5173/admin" });
});

refreshBtn.addEventListener("click", function() {
  resultArea.innerHTML = "";
  init();
});

init();