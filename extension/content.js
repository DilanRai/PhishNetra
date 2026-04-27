// FILE: extension/content.js
// Runs on every webpage — scans external links and highlights threats

(function() {
  "use strict";
  if (window.self !== window.top) return;

  var API_BASE = "http://localhost:5000/api/scan";
  var scanning = false;

  async function scanPageLinks() {
    if (scanning) return;
    scanning = true;

    var links = [];
    var allLinks = document.querySelectorAll("a[href]");
    for (var i = 0; i < allLinks.length && links.length < 20; i++) {
      var href = allLinks[i].href;
      if (href && href.indexOf("http") === 0 && href.indexOf(window.location.hostname) === -1) {
        links.push(href);
      }
    }

    for (var j = 0; j < links.length; j++) {
      if (!scanning) break;
      try {
        var res = await fetch(API_BASE, {
          method:  "POST",
          headers: { "Content-Type": "application/json" },
          body:    JSON.stringify({ input: links[j] }),
        });
        var data = await res.json();
        if (data.status === "phishing" || (data.status === "suspicious" && data.riskScore >= 55)) {
          highlightLink(links[j], data);
        }
      } catch(e) {
        break;
      }
      await new Promise(function(r){ setTimeout(r, 300); });
    }

    scanning = false;
  }

  function highlightLink(href, result) {
    var isPhishing = result.status === "phishing";
    var color      = isPhishing ? "#ff4444" : "#f5a623";
    var labelText  = isPhishing ? "Phishing" : "Suspicious";
    var border     = isPhishing ? "2px solid #ff4444" : "2px dashed #f5a623";

    var els = document.querySelectorAll('a[href="' + href + '"]');
    for (var i = 0; i < els.length; i++) {
      var el = els[i];
      if (el.dataset.pgScanned) continue;
      el.dataset.pgScanned = "true";
      el.style.outline       = border;
      el.style.outlineOffset = "2px";
      el.style.borderRadius  = "3px";

      var badge      = document.createElement("span");
      badge.style.cssText = [
        "display:inline-block", "margin-left:4px", "font-size:10px", "font-weight:700",
        "padding:1px 5px", "background:" + color + "20", "color:" + color,
        "border:1px solid " + color, "border-radius:4px", "font-family:monospace",
        "vertical-align:middle", "cursor:help",
      ].join(";");
      badge.textContent = "⚠ " + labelText;
      badge.title       = "PhishGuard: " + (result.issues && result.issues[0] ? result.issues[0] : "Suspicious link") + " (score: " + result.riskScore + "/100)";
      el.after(badge);
    }
  }

  // Run scan 2 seconds after page loads
  setTimeout(scanPageLinks, 2000);

  // Re-scan on DOM changes (SPAs)
  var timer;
  var observer = new MutationObserver(function() {
    clearTimeout(timer);
    timer = setTimeout(scanPageLinks, 3000);
  });
  observer.observe(document.body, { childList: true, subtree: true });

})();