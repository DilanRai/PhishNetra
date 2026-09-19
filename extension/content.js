// FILE: extension/content.js (FULL REPLACEMENT)
// PhishNetra AI v2.1 — Content Script
// Scans external links on page, highlights threats, persists across SPA navigation

(function () {
  "use strict";

  // Only run in top frame
  if (window.self !== window.top) return;

  var API_BASE = "http://localhost:5000/api/scan";
  var scanning = false;
  var scannedSet = new Set(); // track already-scanned URLs
  var MAX_LINKS = 15; // FIX: reduced from 20 to avoid backend hammering
  var DELAY_MS = 500; // FIX: increased from 300ms to 500ms between requests
  var MIN_SCORE = 50; // FIX: was 55 — catch more suspicious links

  // ── Rate limiter — max 10 requests per 30 seconds ──
  var requestLog = [];
  var RATE_WINDOW = 30 * 1000;
  var RATE_MAX = 10;

  function isRateLimited() {
    var now = Date.now();
    requestLog = requestLog.filter(function (t) {
      return now - t < RATE_WINDOW;
    });
    if (requestLog.length >= RATE_MAX) return true;
    requestLog.push(now);
    return false;
  }

  // ── Extract unique external links from the page ──
  function getExternalLinks() {
    var links = [];
    var seen = new Set();
    var host = window.location.hostname;
    var allAncs = document.querySelectorAll("a[href]");

    for (var i = 0; i < allAncs.length && links.length < MAX_LINKS; i++) {
      var href = allAncs[i].href;
      if (!href || !href.startsWith("http")) continue;
      // Skip same-domain links
      try {
        if (new URL(href).hostname === host) continue;
      } catch {
        continue;
      }
      // Skip already scanned
      if (scannedSet.has(href) || seen.has(href)) continue;
      seen.add(href);
      links.push(href);
    }
    return links;
  }

  // ── Scan links on page ──
  async function scanPageLinks() {
    if (scanning) return;
    scanning = true;

    var links = getExternalLinks();

    for (var j = 0; j < links.length; j++) {
      if (!scanning) break;

      var url = links[j];
      scannedSet.add(url); // mark before scan to avoid duplicate scans

      // Rate limiting check
      if (isRateLimited()) {
        console.log("PhishNetra: rate limit reached, pausing link scan");
        break;
      }

      try {
        var res = await fetch(API_BASE, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ input: url }),
          signal: AbortSignal.timeout(5000),
        });
        if (!res.ok) break; // backend error — stop scanning

        var data = await res.json();
        if (
          data.status === "phishing" ||
          (data.status === "suspicious" && data.riskScore >= MIN_SCORE)
        ) {
          highlightLinks(url, data);
        }
      } catch {
        break; // connection error — stop scanning
      }

      // Delay between requests
      await new Promise(function (r) {
        setTimeout(r, DELAY_MS);
      });
    }

    scanning = false;
  }

  // ── Highlight a threat link wherever it appears on the page ──
  function highlightLinks(href, result) {
    var isPhishing = result.status === "phishing";
    var color = isPhishing ? "#ff4444" : "#f5a623";
    var labelText = isPhishing ? "Phishing" : "Suspicious";
    var border = isPhishing ? "2px solid #ff4444" : "2px dashed #f5a623";

    // Select by both exact href and as text content
    var selectors = [
      'a[href="' + CSS.escape(href) + '"]',
      'a[href^="' + CSS.escape(href.substring(0, 60)) + '"]',
    ];

    selectors.forEach(function (sel) {
      var els;
      try {
        els = document.querySelectorAll(sel);
      } catch {
        return;
      }

      for (var i = 0; i < els.length; i++) {
        var el = els[i];
        if (el.dataset.pgScanned === "true") continue;
        el.dataset.pgScanned = "true";
        el.style.outline = border;
        el.style.outlineOffset = "2px";
        el.style.borderRadius = "3px";

        var badge = document.createElement("span");
        badge.dataset.pgBadge = href; // FIX: store href for re-injection on SPA nav
        badge.style.cssText = [
          "display:inline-block",
          "margin-left:4px",
          "font-size:10px",
          "font-weight:700",
          "padding:1px 5px",
          "background:" + color + "20",
          "color:" + color,
          "border:1px solid " + color,
          "border-radius:4px",
          "font-family:monospace",
          "vertical-align:middle",
          "cursor:help",
          "flex-shrink:0",
        ].join(";");

        // Build tooltip with DNA if available
        var tooltip = "PhishNetra: ";
        if (result.dna?.technique)
          tooltip += result.dna.technique.replace(/_/g, " ") + " · ";
        if (result.kitMatch?.kitName)
          tooltip += "Kit: " + result.kitMatch.kitName + " · ";
        tooltip += "Score: " + result.riskScore + "/100";
        if (result.issues?.[0]) tooltip += " · " + result.issues[0];

        badge.textContent = "⚠ " + labelText;
        badge.title = tooltip;
        el.after(badge);
      }
    });
  }

  // ── Delay initial scan to let page fully render ──
  setTimeout(scanPageLinks, 2000);

  // ── SPA navigation: re-scan when DOM changes significantly ──
  // FIX: track last scan time to avoid re-scanning too often
  var lastScanTime = 0;
  var SPA_DEBOUNCE = 4000; // at least 4s between re-scans

  var mutationTimer;
  var observer = new MutationObserver(function (mutations) {
    // Only re-scan if meaningful content was added (not just style changes)
    var meaningful = mutations.some(function (m) {
      return (
        m.addedNodes.length > 0 &&
        Array.from(m.addedNodes).some(function (n) {
          return (
            n.nodeType === 1 && // Element node
            (n.tagName === "A" || n.querySelector("a"))
          );
        })
      );
    });
    if (!meaningful) return;

    clearTimeout(mutationTimer);
    mutationTimer = setTimeout(function () {
      var now = Date.now();
      if (now - lastScanTime < SPA_DEBOUNCE) return;
      lastScanTime = now;
      scanPageLinks();
    }, SPA_DEBOUNCE);
  });

  if (document.body) {
    observer.observe(document.body, { childList: true, subtree: true });
  }
})();

// ── Email scanning support for Gmail and Outlook ──────────────────
(function () {
  "use strict";

  if (window.self !== window.top) return;

  function detectEmailPlatform() {
    var host = window.location.hostname;
    if (host === "mail.google.com") return "gmail";
    if (
      host.includes("outlook.live.com") ||
      host.includes("outlook.office.com") ||
      host.includes("outlook.office365.com")
    ) {
      return "outlook";
    }
    return null;
  }

  function extractGmailEmail() {
    try {
      var subjectEl =
        document.querySelector("h2.hP") ||
        document.querySelector("[data-thread-perm-id] h2") ||
        document.querySelector(".ha h2");

      var senderEl =
        document.querySelector(".gD[email]") ||
        document.querySelector(".go span[email]") ||
        document.querySelector("[data-hovercard-id]");

      var senderNameEl =
        document.querySelector(".gD") || document.querySelector(".go .gD");

      var bodyEl =
        document.querySelector(".a3s.aiL") ||
        document.querySelector(".a3s") ||
        document.querySelector("[data-message-id] .ii.gt div");

      var replyToEl = document.querySelector(".ajz span[email]");

      var dateEl =
        document.querySelector(".g3") || document.querySelector("span[title]");

      if (!bodyEl && !subjectEl) return null;

      var subject = (subjectEl?.textContent || "").trim();
      var sender =
        senderEl?.getAttribute("email") || senderEl?.textContent?.trim() || "";
      var senderName = senderNameEl?.textContent?.trim() || "";
      var body = bodyEl?.innerText?.trim() || "";
      var replyTo = replyToEl?.getAttribute("email") || "";
      var date = dateEl?.title || dateEl?.textContent?.trim() || "";

      if (!body && !subject) return null;

      var emailText = [
        subject ? "Subject: " + subject : "",
        sender ? "From: " + senderName + " <" + sender + ">" : "",
        replyTo ? "Reply-To: " + replyTo : "",
        date ? "Date: " + date : "",
        "",
        body,
      ]
        .filter(Boolean)
        .join("\n");

      return {
        platform: "gmail",
        subject: subject,
        sender: sender,
        senderName: senderName,
        replyTo: replyTo,
        body: body.substring(0, 5000),
        emailText: emailText.substring(0, 6000),
        hasLinks: (body.match(/https?:\/\//g) || []).length,
        extractedAt: new Date().toISOString(),
      };
    } catch (err) {
      console.error("PhishNetra: Gmail extraction error", err);
      return null;
    }
  }

  function extractOutlookEmail() {
    try {
      var subjectEl =
        document.querySelector("[role='heading'][tabindex='-1']") ||
        document.querySelector(
          ".allowTextSelection.customScrollBar [role='heading']",
        ) ||
        document.querySelector(".f10pixqe span") ||
        document.querySelector("[aria-label*='Subject'] span") ||
        document.querySelector("[data-app='ReadingPane'] [role='heading']");

      var senderEl =
        document.querySelector("[aria-label^='From'] .jKo79 span") ||
        document.querySelector(".pe.mfMhoc [role='link']") ||
        document.querySelector("[aria-label^='From'] span") ||
        document.querySelector("[class*='sender'] [role='link']");

      var senderEmailEl =
        document.querySelector("[aria-label^='From'] [title*='@']") ||
        document.querySelector("[class*='sender'] [title*='@']");

      var bodyEl =
        document.querySelector("[aria-label='Message body']") ||
        document.querySelector(".allowTextSelection.customScrollBar") ||
        document.querySelector("[role='document']") ||
        document.querySelector("[data-app='ReadingPane'] [role='region']");

      var dateEl =
        document.querySelector("[aria-label^='Sent']") ||
        document.querySelector("time");

      if (!bodyEl && !subjectEl) return null;

      var subject = subjectEl?.textContent?.trim() || "";
      var senderName = senderEl?.textContent?.trim() || "";
      var sender =
        senderEmailEl?.title ||
        senderEmailEl?.textContent?.trim() ||
        senderName;
      var body = bodyEl?.innerText?.trim() || "";
      var date =
        dateEl?.textContent?.trim() || dateEl?.getAttribute("datetime") || "";

      if (!body && !subject) return null;

      var emailText = [
        subject ? "Subject: " + subject : "",
        sender ? "From: " + senderName + " <" + sender + ">" : "",
        date ? "Date: " + date : "",
        "",
        body,
      ]
        .filter(Boolean)
        .join("\n");

      return {
        platform: "outlook",
        subject: subject,
        sender: sender,
        senderName: senderName,
        body: body.substring(0, 5000),
        emailText: emailText.substring(0, 6000),
        hasLinks: (body.match(/https?:\/\//g) || []).length,
        extractedAt: new Date().toISOString(),
      };
    } catch (err) {
      console.error("PhishNetra: Outlook extraction error", err);
      return null;
    }
  }

  function extractCurrentEmail() {
    var platform = detectEmailPlatform();
    if (!platform) return null;
    if (platform === "gmail") return extractGmailEmail();
    if (platform === "outlook") return extractOutlookEmail();
    return null;
  }

  chrome.runtime.onMessage.addListener(function (msg, sender, sendResponse) {
    if (msg.type === "EXTRACT_EMAIL") {
      sendResponse({ emailData: extractCurrentEmail() });
      return false;
    }

    if (msg.type === "GET_PLATFORM") {
      sendResponse({ platform: detectEmailPlatform() });
      return false;
    }
  });

  var platform = detectEmailPlatform();
  if (platform) {
    chrome.runtime
      .sendMessage({
        type: "EMAIL_PLATFORM_DETECTED",
        platform: platform,
        hasEmail: !!extractCurrentEmail(),
      })
      .catch(function () {});
  }
})();

// ── Live page analysis — runs alongside link scanner ──────────────
(function () {
  "use strict";

  // Avoid duplicate runs
  if (window.__phishnetra_checked) return;
  window.__phishnetra_checked = true;

  const SAFE_BRANDS = [
    "paypal",
    "google",
    "microsoft",
    "apple",
    "amazon",
    "facebook",
    "instagram",
    "twitter",
    "netflix",
    "spotify",
    "linkedin",
    "dropbox",
    "yahoo",
    "outlook",
    "chase",
    "wellsfargo",
    "bankofamerica",
    "citibank",
    "coinbase",
    "binance",
    "discord",
    "steam",
    "roblox",
    "tiktok",
    "whatsapp",
    "zoom",
    "docusign",
  ];

  const pageUrl = window.location.href.toLowerCase();
  const pageDomain = window.location.hostname
    .toLowerCase()
    .replace(/^www\./, "");
  const pageTitle = document.title.toLowerCase();
  const signals = [];

  // 1. Page title claims a brand the URL doesn't belong to
  const titleBrand = SAFE_BRANDS.find((b) => pageTitle.includes(b));
  const domainBrand = SAFE_BRANDS.find((b) => pageDomain.includes(b));
  if (titleBrand && !domainBrand && !pageDomain.includes(titleBrand)) {
    signals.push(
      `Page title claims to be "${titleBrand}" but domain is "${pageDomain}"`,
    );
  }

  // 2. Password input on a non-HTTPS page
  const pwdFields = document.querySelectorAll("input[type=password]");
  if (pwdFields.length > 0 && !pageUrl.startsWith("https://")) {
    signals.push(
      "Password field on non-HTTPS page — credentials will be sent unencrypted",
    );
  }

  // 3. Form submits to a different domain
  const forms = document.querySelectorAll("form[action]");
  forms.forEach((form) => {
    const action = form.getAttribute("action");
    if (action && action.startsWith("http")) {
      try {
        const actionDomain = new URL(action).hostname.replace(/^www\./, "");
        if (actionDomain !== pageDomain) {
          signals.push(
            `Form submits to external domain: ${actionDomain} (page is on ${pageDomain})`,
          );
        }
      } catch {}
    }
  });

  // 4. Right-click disabled (common phishing kit evasion)
  if (
    document.body?.getAttribute("oncontextmenu") === "return false" ||
    document.documentElement?.getAttribute("oncontextmenu") === "return false"
  ) {
    signals.push(
      "Right-click is disabled on this page — common phishing evasion technique",
    );
  }

  // 5. Suspicious redirect meta tag
  const metaRefresh = document.querySelector("meta[http-equiv='refresh']");
  if (metaRefresh) {
    signals.push(
      "Page has automatic redirect — may be forwarding to a different destination",
    );
  }

  // 6. Homoglyph / Unicode in domain
  const UNICODE_RANGES = /[\u0400-\u04FF\u0370-\u03FF\u0250-\u02AF]/;
  if (UNICODE_RANGES.test(pageDomain)) {
    signals.push(
      `Unicode characters in domain "${pageDomain}" — possible homoglyph attack`,
    );
  }

  // If suspicious signals found — send to background for backend confirmation
  if (signals.length > 0) {
    chrome.runtime.sendMessage({
      type: "CONTENT_SIGNALS",
      url: window.location.href,
      signals: signals,
      domain: pageDomain,
    });
  }

  // Listen for scan results from background
  chrome.runtime.onMessage.addListener((msg) => {
    if (
      msg.type === "SHOW_WARNING_BANNER" &&
      msg.url === window.location.href
    ) {
      showWarningBanner(msg.verdict, msg.riskScore, msg.signals);
    }
  });

  function showWarningBanner(verdict, riskScore, signals) {
    if (document.getElementById("__phishnetra_banner")) return; // already shown
    const isPhishing = verdict === "phishing";
    const isSuspicious = verdict === "suspicious";
    if (!isPhishing && !isSuspicious) return;

    const bgColor = isPhishing
      ? "rgba(248,113,113,0.97)"
      : "rgba(251,191,36,0.97)";
    const textColor = isPhishing ? "#fff" : "#1a1a1a";
    const icon = isPhishing ? "⚠️" : "🔶";
    const label = isPhishing ? "PHISHING SITE DETECTED" : "SUSPICIOUS SITE";

    const banner = document.createElement("div");
    banner.id = "__phishnetra_banner";
    banner.style.cssText = [
      `position:fixed`,
      `top:0`,
      `left:0`,
      `right:0`,
      `z-index:2147483647`,
      `background:${bgColor}`,
      `color:${textColor}`,
      `padding:10px 16px`,
      `font-family:system-ui,sans-serif`,
      `font-size:13px`,
      `display:flex`,
      `align-items:center`,
      `gap:10px`,
      `box-shadow:0 2px 12px rgba(0,0,0,0.4)`,
    ].join(";");

    banner.innerHTML =
      `<span style="font-size:18px">${icon}</span>` +
      `<div style="flex:1">` +
      `<strong style="font-size:14px">PhishNetra: ${label}</strong>` +
      `<div style="font-size:11px;margin-top:2px;opacity:0.9">` +
      `Risk Score: ${riskScore}/100 · ${signals?.[0] || "Phishing indicators detected"}` +
      `</div>` +
      `</div>` +
      `<button onclick="this.parentElement.remove()"` +
      ` style="background:rgba(0,0,0,0.15);border:none;color:inherit;padding:4px 10px;border-radius:6px;cursor:pointer;font-size:12px;font-weight:600">` +
      `Dismiss` +
      `</button>`;

    document.body.prepend(banner);
  }
})();

// ── PhishNetra Inbox Scanner — Inbox-level threat detection ──────
// GAP 11: Scans Gmail / Outlook inbox rows BEFORE the user opens emails.
// Shows ⚠ PHISHING / ⚠ SUSPICIOUS badges on risky rows.
// Two-phase: instant local check → async backend deep-scan.
(function () {
  "use strict";

  if (window.self !== window.top) return;

  var API_BASE = "http://localhost:5000/api/scan";
  var scanCache = new Map(); // key: sender+subject hash → result
  var scanQueue = [];
  var badgeCount = 0;

  // ── Local urgency keyword patterns (no API call needed) ─────────
  var URGENCY_PATTERNS = [
    /urgent|immediate|action required|verify now|confirm now/i,
    /account.*(suspend|block|limit|restrict)/i,
    /password.*(expire|reset|confirm)/i,
    /click here.*(now|immediate|urgent)/i,
    /winner|you.*(won|selected|chosen)/i,
    /invoice.*(attach|due|overdue|payment)/i,
    /wire transfer|fund transfer|payment.*request/i,
    /dear customer|dear user|dear valued/i,
    /verify.*(account|identity|email)/i,
    /limited time|expires in|last chance/i,
    /unusual.*activit|suspicious.*login|security.*alert/i,
    /claim.*prize|free.*gift|congratulation/i,
  ];

  // ── High-risk sender domain patterns (local check) ──────────────
  var HIGH_RISK_TLDS = /\.(tk|ml|ga|cf|gq|xyz|top|icu|sbs|click|link|pw)$/i;
  var BRAND_LOOKALIKE =
    /(paypal|amazon|google|microsoft|apple|netflix|facebook|sbi|hdfc|icici|irctc|uidai|paytm|phonepe|flipkart|gpay)/i;

  // Score sender + subject locally (fast, no API)
  function quickRisk(sender, subject, senderName) {
    var score = 0;
    var flags = [];

    if (sender) {
      var domain = sender.split("@")[1] || "";

      if (HIGH_RISK_TLDS.test(domain)) {
        score += 40;
        flags.push("High-risk TLD: " + domain);
      }

      if (BRAND_LOOKALIKE.test(domain)) {
        var isReal =
          /(@paypal\.com|@amazon\.com|@google\.com|@microsoft\.com|@apple\.com|@netflix\.com|@sbi\.co\.in|@hdfcbank\.com|@icicibank\.com|@irctc\.co\.in|@uidai\.gov\.in|@paytm\.com)$/i.test(
            sender,
          );
        if (!isReal) {
          score += 35;
          flags.push("Brand lookalike domain");
        }
      }

      if (
        senderName &&
        BRAND_LOOKALIKE.test(senderName) &&
        !BRAND_LOOKALIKE.test(domain)
      ) {
        score += 30;
        flags.push('Display name spoofing: "' + senderName + '" via ' + domain);
      }
    }

    if (subject) {
      var urgencyHits = URGENCY_PATTERNS.filter(function (p) {
        return p.test(subject);
      });
      score += urgencyHits.length * 15;
      if (urgencyHits.length > 0) flags.push("Urgency language in subject");
    }

    return { score: score, flags: flags };
  }

  // ── Map score to verdict ─────────────────────────────────────────
  function scoreToVerdict(score) {
    if (score >= 65) return "phishing";
    if (score >= 35) return "suspicious";
    return "safe";
  }

  // ── Build badge element ──────────────────────────────────────────
  function makeBadge(verdict, score, tooltip) {
    var cfg = {
      phishing: {
        bg: "rgba(248,113,113,0.15)",
        color: "#f87171",
        border: "rgba(248,113,113,0.5)",
        text: "\u26a0 PHISHING",
      },
      suspicious: {
        bg: "rgba(251,191,36,0.15)",
        color: "#fbbf24",
        border: "rgba(251,191,36,0.5)",
        text: "\u26a0 SUSPICIOUS",
      },
      safe: {
        bg: "rgba(52,211,153,0.1)",
        color: "#34d399",
        border: "rgba(52,211,153,0.3)",
        text: "\u2713 OK",
      },
    };
    var c = cfg[verdict] || cfg.safe;
    var badge = document.createElement("span");
    badge.setAttribute("data-phishnetra-inbox-badge", "true");
    badge.style.cssText = [
      "display:inline-flex",
      "align-items:center",
      "gap:2px",
      "font-size:9px",
      "font-weight:700",
      "padding:1px 6px",
      "border-radius:4px",
      "font-family:monospace",
      "white-space:nowrap",
      "cursor:help",
      "vertical-align:middle",
      "flex-shrink:0",
      "background:" + c.bg,
      "color:" + c.color,
      "border:1px solid " + c.border,
      "margin-left:4px",
    ].join(";");
    badge.textContent = c.text;
    badge.title =
      "PhishNetra: " + (score ? score + "/100 \u00b7 " : "") + tooltip;
    return badge;
  }

  // ══════════════════════════════════════════════════════════════
  // GMAIL INBOX SCANNER
  // Gmail inbox rows: <tr class="zA">
  // Subject: span.bog  |  Sender name: span.zF  |  Sender email: span.zF[email]
  // ══════════════════════════════════════════════════════════════
  function scanGmailInbox() {
    if (window.location.hostname !== "mail.google.com") return;

    var rows = document.querySelectorAll("tr.zA:not([data-pn-scanned])");
    if (!rows.length) return;

    rows.forEach(function (row) {
      row.setAttribute("data-pn-scanned", "true");

      var senderEl = row.querySelector(".zF");
      var senderEmail = senderEl ? senderEl.getAttribute("email") || "" : "";
      var senderName = senderEl ? senderEl.textContent.trim() : "";

      var subjectEl =
        row.querySelector(".bog") || row.querySelector(".y6 span");
      var subject = subjectEl ? subjectEl.textContent.trim() : "";

      if (!senderEmail && !subject) return;

      var quick = quickRisk(senderEmail, subject, senderName);
      var cacheKey = btoa(
        encodeURIComponent((senderEmail + "|" + subject).substring(0, 100)),
      );

      if (scanCache.has(cacheKey)) {
        injectGmailBadge(row, scanCache.get(cacheKey));
        return;
      }

      if (quick.score >= 30) {
        var quickResult = {
          verdict: scoreToVerdict(quick.score),
          score: quick.score,
          tooltip: quick.flags.join(" \u00b7 ") || "Risk detected",
          deepScanned: false,
        };
        scanCache.set(cacheKey, quickResult);
        injectGmailBadge(row, quickResult);
        if (quick.score >= 40) {
          scanQueue.push({
            cacheKey: cacheKey,
            senderEmail: senderEmail,
            senderName: senderName,
            subject: subject,
            row: row,
            platform: "gmail",
          });
        }
        return;
      }

      scanQueue.push({
        cacheKey: cacheKey,
        senderEmail: senderEmail,
        senderName: senderName,
        subject: subject,
        row: row,
        platform: "gmail",
      });
    });

    processQueue();
  }

  function injectGmailBadge(row, result) {
    var existing = row.querySelector("[data-phishnetra-inbox-badge]");
    if (existing) existing.remove();
    if (result.verdict === "safe") return;

    var subjectCell =
      row.querySelector(".bog") || row.querySelector(".y6 span");
    if (!subjectCell) return;

    var badge = makeBadge(result.verdict, result.score, result.tooltip);
    subjectCell.after(badge);

    var color = result.verdict === "phishing" ? "#f87171" : "#fbbf24";
    row.style.borderLeft = "3px solid " + color;
    row.style.backgroundColor =
      result.verdict === "phishing"
        ? "rgba(248,113,113,0.04)"
        : "rgba(251,191,36,0.03)";

    badgeCount++;
    updateExtensionBadge();
  }

  // ══════════════════════════════════════════════════════════════
  // OUTLOOK INBOX SCANNER
  // Outlook rows: [data-convid] or [role="option"]
  // ══════════════════════════════════════════════════════════════
  function scanOutlookInbox() {
    var host = window.location.hostname;
    if (!host.includes("outlook")) return;

    var rows = document.querySelectorAll(
      "[data-convid]:not([data-pn-scanned]), " +
        "[role='option'][aria-label]:not([data-pn-scanned])",
    );
    if (!rows.length) return;

    rows.forEach(function (row) {
      row.setAttribute("data-pn-scanned", "true");

      var senderEl =
        row.querySelector("[class*='sender'] span") ||
        row.querySelector(".pe span") ||
        row.querySelector("[aria-label*='@']");
      var senderText = senderEl ? senderEl.textContent.trim() : "";
      var emailMatch = senderText.match(/<([^>]+@[^>]+)>/);
      var senderEmail = emailMatch ? emailMatch[1] : senderText;

      var subjectEl =
        row.querySelector("[class*='subject'] span") ||
        row.querySelector(".NormalWeight span") ||
        row.querySelector("[class*='Subject']");
      var subject = subjectEl ? subjectEl.textContent.trim() : "";

      if (!senderEmail && !subject) return;

      var quick = quickRisk(senderEmail, subject, "");
      var cacheKey = btoa(
        encodeURIComponent((senderEmail + "|" + subject).substring(0, 100)),
      );

      if (scanCache.has(cacheKey)) {
        injectOutlookBadge(row, scanCache.get(cacheKey));
        return;
      }

      if (quick.score >= 30) {
        var quickResult = {
          verdict: scoreToVerdict(quick.score),
          score: quick.score,
          tooltip: quick.flags.join(" \u00b7 ") || "Risk detected",
          deepScanned: false,
        };
        scanCache.set(cacheKey, quickResult);
        injectOutlookBadge(row, quickResult);
        if (quick.score >= 40) {
          scanQueue.push({
            cacheKey: cacheKey,
            senderEmail: senderEmail,
            subject: subject,
            row: row,
            platform: "outlook",
          });
        }
        return;
      }

      scanQueue.push({
        cacheKey: cacheKey,
        senderEmail: senderEmail,
        subject: subject,
        row: row,
        platform: "outlook",
      });
    });

    processQueue();
  }

  function injectOutlookBadge(row, result) {
    var existing = row.querySelector("[data-phishnetra-inbox-badge]");
    if (existing) existing.remove();
    if (result.verdict === "safe") return;

    var subjectEl =
      row.querySelector("[class*='subject'] span") ||
      row.querySelector(".NormalWeight span");
    if (!subjectEl) return;

    var badge = makeBadge(result.verdict, result.score, result.tooltip);
    subjectEl.after(badge);

    var color = result.verdict === "phishing" ? "#f87171" : "#fbbf24";
    row.style.borderLeft = "3px solid " + color;

    badgeCount++;
    updateExtensionBadge();
  }

  // ── Process the backend deep-scan queue (rate-limited 500ms) ────
  var processingQueue = false;

  async function processQueue() {
    if (processingQueue || !scanQueue.length) return;
    processingQueue = true;

    while (scanQueue.length > 0) {
      var item = scanQueue.shift();

      var emailText = [
        item.subject ? "Subject: " + item.subject : "",
        item.senderEmail
          ? "From: " + (item.senderName || "") + " <" + item.senderEmail + ">"
          : "",
      ]
        .filter(Boolean)
        .join("\n");

      if (!emailText.trim()) continue;

      try {
        var res = await fetch(API_BASE, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ input: emailText }),
          signal: AbortSignal.timeout(5000),
        });

        if (!res.ok) break;

        var data = await res.json();
        var result = {
          verdict: data.status || "safe",
          score: data.riskScore || 0,
          tooltip:
            (data.issues || []).slice(0, 2).join(" \u00b7 ") ||
            "Scanned by PhishNetra",
          deepScanned: true,
        };

        // Only update badge if backend result is worse than local quick-scan
        var existing = scanCache.get(item.cacheKey);
        if (!existing || result.score > existing.score) {
          scanCache.set(item.cacheKey, result);
          if (item.platform === "gmail") {
            injectGmailBadge(item.row, result);
          } else {
            injectOutlookBadge(item.row, result);
          }
        }
      } catch {
        /* network error — skip this item */
      }

      // Rate-limit: 500ms between backend calls
      await new Promise(function (r) {
        setTimeout(r, 500);
      });
    }

    processingQueue = false;
  }

  // ── Notify background to update extension badge icon count ──────
  function updateExtensionBadge() {
    try {
      chrome.runtime.sendMessage({
        type: "SET_BADGE",
        count: badgeCount,
        color: badgeCount > 0 ? "#f87171" : "#34d399",
      });
    } catch {
      /* extension context may not be available */
    }
  }

  // ── Dispatch to correct platform scanner ────────────────────────
  function runInboxScan() {
    var host = window.location.hostname;
    if (host === "mail.google.com") {
      scanGmailInbox();
    } else if (host.includes("outlook")) {
      scanOutlookInbox();
    }
  }

  // ── Initial scan after page fully renders ───────────────────────
  setTimeout(runInboxScan, 1500);

  // ── MutationObserver: catch new emails loaded by SPA ────────────
  var inboxObserver = new MutationObserver(function (mutations) {
    var hasNewRows = mutations.some(function (m) {
      return Array.from(m.addedNodes).some(function (n) {
        if (n.nodeType !== 1) return false;
        if (n.classList && n.classList.contains("zA")) return true;
        if (n.querySelector && n.querySelector("tr.zA")) return true;
        if (n.getAttribute && n.getAttribute("data-convid")) return true;
        if (n.querySelector && n.querySelector("[data-convid]")) return true;
        return false;
      });
    });

    if (hasNewRows) {
      clearTimeout(window._pnInboxTimer);
      window._pnInboxTimer = setTimeout(runInboxScan, 800);
    }
  });

  if (document.body) {
    inboxObserver.observe(document.body, { childList: true, subtree: true });
  }

  // ── URL-change detection for SPA navigation ─────────────────────
  var lastUrl = location.href;
  new MutationObserver(function () {
    if (location.href !== lastUrl) {
      lastUrl = location.href;
      badgeCount = 0; // reset count for new inbox view

      setTimeout(function () {
        // Clear scan markers so rows are re-evaluated in the new view
        document.querySelectorAll("[data-pn-scanned]").forEach(function (el) {
          el.removeAttribute("data-pn-scanned");
        });
        runInboxScan();
      }, 1200);
    }
  }).observe(document.body, { childList: true, subtree: true });
})();
