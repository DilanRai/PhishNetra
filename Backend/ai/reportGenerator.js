// ================================================================
// FILE: Backend/ai/reportGenerator.js — FULL REPLACE
// Professional, print-friendly, information-rich PDF report
// Light theme — readable on paper and screen
// ================================================================

const PDFDocument = require("pdfkit");

// ── Colour palette (light/professional theme) ──
const C = {
  // Page
  pageBg: "#FFFFFF",
  // Verdict colours
  phishing: "#C0392B",
  suspicious: "#D68910",
  safe: "#1E8449",
  // Accent
  navy: "#1A3A5C",
  accent: "#2E86AB",
  purple: "#7B2FBE",
  // Text
  textDark: "#1C1C1C",
  textMid: "#3D3D3D",
  textMuted: "#6C757D",
  // Backgrounds
  headerBg: "#1A3A5C",
  sectionBg: "#F0F4F8",
  rowAlt: "#F8FAFC",
  cardBorder: "#CBD5E1",
  // Score zones
  zoneGreen: "#D5F5E3",
  zoneYellow: "#FEF9E7",
  zoneRed: "#FADBD8",
};

function verdictColor(status) {
  return status === "phishing"
    ? C.phishing
    : status === "suspicious"
      ? C.suspicious
      : C.safe;
}

function hexToRgb(hex) {
  const r = parseInt(hex.slice(1, 3), 16);
  const g = parseInt(hex.slice(3, 5), 16);
  const b = parseInt(hex.slice(5, 7), 16);
  return [r, g, b];
}

function fillRect(doc, x, y, w, h, hex, opacity = 1) {
  const [r, g, b] = hexToRgb(hex);
  doc
    .save()
    .fillOpacity(opacity)
    .rect(x, y, w, h)
    .fill(`rgb(${r},${g},${b})`)
    .restore();
}

function strokeRect(doc, x, y, w, h, hex, lineWidth = 0.5) {
  const [r, g, b] = hexToRgb(hex);
  doc
    .save()
    .lineWidth(lineWidth)
    .rect(x, y, w, h)
    .stroke(`rgb(${r},${g},${b})`)
    .restore();
}

// ── Divider line ──
function divider(doc, y, col, colW, hex = C.cardBorder) {
  const [r, g, b] = hexToRgb(hex);
  doc
    .save()
    .lineWidth(0.5)
    .moveTo(col, y)
    .lineTo(col + colW, y)
    .stroke(`rgb(${r},${g},${b})`)
    .restore();
}

// ── Section heading ──
function sectionHead(doc, num, title, y, col, colW) {
  fillRect(doc, col, y, colW, 24, C.sectionBg);
  strokeRect(doc, col, y, colW, 24, C.cardBorder);
  // Left accent bar
  fillRect(doc, col, y, 4, 24, C.navy);
  doc
    .fontSize(7.5)
    .font("Helvetica-Bold")
    .fillColor(C.textMuted)
    .text(num, col + 12, y + 8, { characterSpacing: 0.8 });
  doc
    .fontSize(9)
    .font("Helvetica-Bold")
    .fillColor(C.navy)
    .text(title, col + 38, y + 8);
  return y + 32;
}

// ── Key/value row ──
function kvRow(
  doc,
  key,
  val,
  x,
  y,
  keyW,
  totalW,
  alt = false,
  valColor = null,
) {
  if (alt) fillRect(doc, x, y, totalW, 18, C.rowAlt);
  doc
    .fontSize(7.5)
    .font("Helvetica-Bold")
    .fillColor(C.textMuted)
    .text(key, x + 8, y + 5, { width: keyW - 10, ellipsis: true });
  doc
    .fontSize(7.5)
    .font("Helvetica")
    .fillColor(valColor || C.textDark)
    .text(String(val || "—"), x + keyW + 6, y + 5, {
      width: totalW - keyW - 14,
      ellipsis: true,
    });
  return y + 18;
}

// ── Wrap text and return new y ──
function wrappedText(
  doc,
  text,
  x,
  y,
  width,
  fontSize = 8,
  color = C.textMid,
  leading = 14,
) {
  doc
    .fontSize(fontSize)
    .font("Helvetica")
    .fillColor(color)
    .text(String(text), x, y, { width, lineGap: 2 });
  return doc.y + 4;
}

// ════════════════════════════════════════════════════════════════
// MAIN REPORT GENERATOR
// ════════════════════════════════════════════════════════════════
function generateReport(res, scanData) {
  const {
    input = "",
    status = "safe",
    riskScore = 0,
    issues = [],
    inputType = "url",
    confidence = "low",
    detectionVersion = "3.0",
    mlEnabled = true,
    mlScore = null,
    ruleScore = 0,
    dna = null,
    remediation = null,
    scannedAt = new Date(),
    mitreAttack = [],
    attackVectors = [],
    cveReferences = [],
    threatIntel = null,
  } = scanData;

  const doc = new PDFDocument({
    size: "A4",
    margins: { top: 0, bottom: 0, left: 0, right: 0 },
    info: {
      Title: "PhishNetra — Threat Analysis Report",
      Author: `PhishNetra AI v${detectionVersion}`,
      Subject: `${status.toUpperCase()} — Risk Score ${riskScore}/100`,
      Keywords: "phishing, cybersecurity, threat analysis",
      Creator: "PhishNetra SentinelCore",
    },
  });

  res.setHeader("Content-Type", "application/pdf");
  res.setHeader(
    "Content-Disposition",
    `attachment; filename="PhishNetra-Report-${Date.now()}.pdf"`,
  );
  doc.pipe(res);

  const PAGE_W = 595;
  const MARGIN = 36;
  const CONTENT_W = PAGE_W - MARGIN * 2;
  const vc = verdictColor(status);

  let y = 0;

  // ════════════════════════════════════════════════════════════════
  // HEADER BANNER
  // ════════════════════════════════════════════════════════════════
  fillRect(doc, 0, 0, PAGE_W, 100, C.headerBg);

  // Logo area
  doc
    .fontSize(18)
    .font("Helvetica-Bold")
    .fillColor("#FFFFFF")
    .text("PhishNetra", MARGIN, 22);
  doc
    .fontSize(8.5)
    .font("Helvetica")
    .fillColor("#A0BDD8")
    .text("AI-Powered Phishing Detection  ·  SentinelCore SIEM", MARGIN, 44);
  doc
    .fontSize(7.5)
    .font("Helvetica")
    .fillColor("#6B8CAD")
    .text(
      `THREAT ANALYSIS REPORT  ·  Detection Engine v${detectionVersion}`,
      MARGIN,
      58,
    );
  doc
    .fontSize(7)
    .font("Helvetica")
    .fillColor("#5A7A96")
    .text(
      `Generated: ${new Date().toLocaleString("en-IN", { timeZone: "Asia/Kolkata" })} IST`,
      MARGIN,
      72,
    );

  // Verdict badge (top-right)
  const BADGE_W = 130;
  const BADGE_H = 82;
  const BADGE_X = PAGE_W - BADGE_W - MARGIN;
  fillRect(doc, BADGE_X, 9, BADGE_W, BADGE_H, vc, 0.12);
  strokeRect(doc, BADGE_X, 9, BADGE_W, BADGE_H, vc, 1.5);

  // Status label
  doc
    .fontSize(10)
    .font("Helvetica-Bold")
    .fillColor(vc)
    .text(status.toUpperCase(), BADGE_X, 20, {
      width: BADGE_W,
      align: "center",
    });

  // Big risk score
  doc
    .fontSize(34)
    .font("Helvetica-Bold")
    .fillColor(vc)
    .text(`${riskScore}`, BADGE_X, 32, { width: BADGE_W, align: "center" });
  doc
    .fontSize(8.5)
    .font("Helvetica")
    .fillColor(vc)
    .text("RISK SCORE / 100", BADGE_X, 67, { width: BADGE_W, align: "center" });

  // Bottom accent strip
  fillRect(doc, 0, 100, PAGE_W, 5, vc);

  y = 114;

  // ════════════════════════════════════════════════════════════════
  // SECTION 1 — SCAN TARGET
  // ════════════════════════════════════════════════════════════════
  y = sectionHead(doc, "01", "SCAN TARGET", y, MARGIN, CONTENT_W);

  fillRect(doc, MARGIN, y, CONTENT_W, 64, "#F8FAFC");
  strokeRect(doc, MARGIN, y, CONTENT_W, 64, C.cardBorder);
  fillRect(doc, MARGIN, y, 4, 64, vc);

  // Input value
  doc
    .fontSize(7)
    .font("Helvetica-Bold")
    .fillColor(C.textMuted)
    .text("INPUT ANALYZED", MARGIN + 12, y + 8, { characterSpacing: 0.8 });
  const inputStr = String(input).substring(0, 120);
  doc
    .fontSize(8.5)
    .font("Courier")
    .fillColor(C.textDark)
    .text(inputStr, MARGIN + 12, y + 20, {
      width: CONTENT_W - 20,
      ellipsis: true,
    });

  // Meta pills row
  const metaItems = [
    { k: "Type", v: inputType || "URL" },
    { k: "Confidence", v: (confidence || "—").toUpperCase() },
    { k: "Scanned", v: new Date(scannedAt).toLocaleString("en-IN") },
    { k: "Source IP", v: scanData.sourceIp || "—" },
  ];

  let px = MARGIN + 12;
  metaItems.forEach(({ k, v }) => {
    doc
      .fontSize(7)
      .font("Helvetica-Bold")
      .fillColor(C.textMuted)
      .text(`${k}: `, px, y + 46, { continued: true });
    doc
      .fontSize(7)
      .font("Helvetica")
      .fillColor(C.textDark)
      .text(v + "   ");
    px += 120;
  });

  y += 76;

  // ════════════════════════════════════════════════════════════════
  // SECTION 2 — RISK ASSESSMENT
  // ════════════════════════════════════════════════════════════════
  y = sectionHead(doc, "02", "RISK ASSESSMENT", y, MARGIN, CONTENT_W);

  // Score bar
  const BAR_H = 18;
  // Zone backgrounds
  fillRect(doc, MARGIN, y, CONTENT_W * 0.3, BAR_H, C.zoneGreen);
  fillRect(
    doc,
    MARGIN + CONTENT_W * 0.3,
    y,
    CONTENT_W * 0.4,
    BAR_H,
    C.zoneYellow,
  );
  fillRect(doc, MARGIN + CONTENT_W * 0.7, y, CONTENT_W * 0.3, BAR_H, C.zoneRed);
  // Fill bar
  const fillW = Math.max((riskScore / 100) * CONTENT_W, 4);
  fillRect(doc, MARGIN, y, fillW, BAR_H, vc, 0.85);
  // Border
  strokeRect(doc, MARGIN, y, CONTENT_W, BAR_H, C.cardBorder);
  // Zone boundary lines
  doc
    .save()
    .lineWidth(0.5)
    .moveTo(MARGIN + CONTENT_W * 0.3, y)
    .lineTo(MARGIN + CONTENT_W * 0.3, y + BAR_H)
    .stroke(C.cardBorder)
    .moveTo(MARGIN + CONTENT_W * 0.7, y)
    .lineTo(MARGIN + CONTENT_W * 0.7, y + BAR_H)
    .stroke(C.cardBorder)
    .restore();

  // Zone labels below bar
  doc
    .fontSize(7)
    .font("Helvetica-Bold")
    .fillColor(C.safe)
    .text("SAFE  (0–29)", MARGIN, y + BAR_H + 4);
  doc
    .fillColor(C.suspicious)
    .text("SUSPICIOUS  (30–69)", MARGIN + CONTENT_W * 0.3 + 2, y + BAR_H + 4);
  doc
    .fillColor(C.phishing)
    .text("PHISHING  (70–100)", MARGIN + CONTENT_W * 0.7 + 2, y + BAR_H + 4);

  y += BAR_H + 22;

  // Score cards row — 4 cards
  const CARD_W = (CONTENT_W - 9) / 4;
  const scoreCards = [
    { label: "Final Risk Score", val: `${riskScore}/100`, color: vc },
    {
      label: "ML Neural Score",
      val: mlEnabled && mlScore !== null ? `${mlScore}/100` : "N/A",
      color: C.accent,
    },
    { label: "Rule Engine Score", val: `${ruleScore || 0}/100`, color: C.navy },
    {
      label: "Confidence Level",
      val: (confidence || "—").toUpperCase(),
      color: C.textMid,
    },
  ];

  scoreCards.forEach(({ label, val, color }, i) => {
    const cx = MARGIN + i * (CARD_W + 3);
    fillRect(doc, cx, y, CARD_W, 48, "#FFFFFF");
    strokeRect(doc, cx, y, CARD_W, 48, C.cardBorder);
    fillRect(doc, cx, y, CARD_W, 3, color); // top colour accent
    doc
      .fontSize(7)
      .font("Helvetica")
      .fillColor(C.textMuted)
      .text(label, cx + 6, y + 10, { width: CARD_W - 12 });
    doc
      .fontSize(16)
      .font("Helvetica-Bold")
      .fillColor(color)
      .text(val, cx + 6, y + 22, { width: CARD_W - 12 });
  });

  y += 60;

  // ════════════════════════════════════════════════════════════════
  // SECTION 3 — PHISHDNA FINGERPRINT (if available)
  // ════════════════════════════════════════════════════════════════
  if (dna && dna.fingerprint) {
    y = sectionHead(doc, "03", "PHISH DNA™ FINGERPRINT", y, MARGIN, CONTENT_W);

    fillRect(doc, MARGIN, y, CONTENT_W, 52, "#FAF5FF");
    strokeRect(doc, MARGIN, y, CONTENT_W, 52, "#D6BCFA");
    fillRect(doc, MARGIN, y, 4, 52, C.purple);

    // Fingerprint ID
    const FP_W = 110;
    fillRect(doc, MARGIN + 12, y + 8, FP_W, 34, "#EDE9FE");
    strokeRect(doc, MARGIN + 12, y + 8, FP_W, 34, "#C4B5FD");
    doc
      .fontSize(6.5)
      .font("Helvetica-Bold")
      .fillColor(C.purple)
      .text("DNA FINGERPRINT ID", MARGIN + 16, y + 12, {
        characterSpacing: 0.5,
      });
    doc
      .fontSize(10)
      .font("Courier-Bold")
      .fillColor(C.purple)
      .text(`#${dna.fingerprint}`, MARGIN + 16, y + 23);

    // DNA fields
    const dnaFields = [
      {
        k: "Brand Targeted",
        v:
          dna.brand && dna.brand !== "unknown"
            ? dna.brand.toUpperCase()
            : "None",
      },
      {
        k: "Attack Technique",
        v: (dna.technique || "—").replace(/_/g, " ").toUpperCase(),
      },
      { k: "TLD Used", v: dna.tld || "—" },
      { k: "Severity Class", v: (dna.severity || "—").toUpperCase() },
    ];

    let dfx = MARGIN + 134;
    dnaFields.forEach(({ k, v }) => {
      doc
        .fontSize(7)
        .font("Helvetica-Bold")
        .fillColor(C.textMuted)
        .text(k, dfx, y + 12, { width: 92 });
      doc
        .fontSize(8.5)
        .font("Helvetica-Bold")
        .fillColor(C.purple)
        .text(v, dfx, y + 24, { width: 92, ellipsis: true });
      dfx += 95;
    });

    y += 64;
  }

  // ════════════════════════════════════════════════════════════════
  // SECTION 4 — DETECTED ISSUES
  // ════════════════════════════════════════════════════════════════
  if (issues.length > 0) {
    const sNum = dna ? "04" : "03";
    y = sectionHead(
      doc,
      sNum,
      `DETECTED ISSUES  (${issues.length} found)`,
      y,
      MARGIN,
      CONTENT_W,
    );

    // Column headers
    fillRect(doc, MARGIN, y, CONTENT_W, 16, C.navy);
    doc
      .fontSize(7)
      .font("Helvetica-Bold")
      .fillColor("#FFFFFF")
      .text("SEVERITY", MARGIN + 8, y + 5);
    doc.text("ISSUE DESCRIPTION", MARGIN + 72, y + 5);
    y += 16;

    const displayIssues = issues.slice(0, 12);
    displayIssues.forEach((issue, i) => {
      const rowH = 20;
      if (i % 2 === 0) fillRect(doc, MARGIN, y, CONTENT_W, rowH, C.rowAlt);
      strokeRect(doc, MARGIN, y, CONTENT_W, rowH, C.cardBorder, 0.3);

      // Severity tag
      const isCrit =
        /otp|impersonat|spoof|display.name|credential|harvest/i.test(issue);
      const isHigh = /typosquat|redirect|punycode|homoglyph|suspicious/i.test(
        issue,
      );
      const sevLabel = isCrit ? "CRITICAL" : isHigh ? "HIGH" : "MEDIUM";
      const sevColor = isCrit ? C.phishing : isHigh ? C.suspicious : "#D68910";
      const sevBg = isCrit ? "#FADBD8" : isHigh ? "#FEF9E7" : "#FEF9E7";

      fillRect(doc, MARGIN + 6, y + 4, 56, 12, sevBg);
      doc
        .fontSize(6.5)
        .font("Helvetica-Bold")
        .fillColor(sevColor)
        .text(sevLabel, MARGIN + 8, y + 7, { width: 52, align: "center" });
      doc
        .fontSize(7.5)
        .font("Helvetica")
        .fillColor(C.textDark)
        .text(issue.substring(0, 100), MARGIN + 70, y + 7, {
          width: CONTENT_W - 80,
          ellipsis: true,
        });
      y += rowH;
    });

    if (issues.length > 12) {
      fillRect(doc, MARGIN, y, CONTENT_W, 16, "#FEF9E7");
      doc
        .fontSize(7.5)
        .font("Helvetica")
        .fillColor(C.textMuted)
        .text(
          `+ ${issues.length - 12} additional issues detected (see full scan in PhishNetra dashboard)`,
          MARGIN + 8,
          y + 4,
        );
      y += 16;
    }

    y += 8;
  }

  // ════════════════════════════════════════════════════════════════
  // SECTION 5 — MITRE ATT&CK (full detail if available)
  // ════════════════════════════════════════════════════════════════
  // Check if we need a new page
  if (y > 640) {
    doc.addPage();
    y = MARGIN;
  }

  const sNumMitre = issues.length > 0 ? (dna ? 5 : 4) : dna ? 4 : 3;
  y = sectionHead(
    doc,
    String(sNumMitre).padStart(2, "0"),
    "MITRE ATT&CK® MAPPING",
    y,
    MARGIN,
    CONTENT_W,
  );

  // Build MITRE data from mitreAttack array or fallback from dna
  const mitreEntries =
    mitreAttack && mitreAttack.length > 0
      ? mitreAttack
      : (() => {
          const t = dna?.technique;
          if (!t) return [];
          const map = {
            credential_harvest: {
              id: "T1056",
              tactic: "TA0009 – Collection",
              technique: "T1056 – Input Capture",
              desc: "Adversary intercepts user credentials entered on phishing form.",
            },
            brand_impersonation: {
              id: "T1566.002",
              tactic: "TA0001 – Initial Access",
              technique: "T1566.002 – Spearphishing Link",
              desc: "Phishing using a link impersonating a trusted brand.",
            },
            typosquatting: {
              id: "T1583.001",
              tactic: "TA0042 – Resource Dev.",
              technique: "T1583.001 – Acquire Domains",
              desc: "Attacker registered a typosquatted domain to deceive users.",
            },
            open_redirect: {
              id: "T1027.006",
              tactic: "TA0005 – Defense Evasion",
              technique: "T1027.006 – HTML Smuggling (redirect chain)",
              desc: "Open redirect used to bypass URL scanners.",
            },
            homoglyph: {
              id: "T1036.005",
              tactic: "TA0005 – Defense Evasion",
              technique: "T1036.005 – Match Legitimate Name",
              desc: "Unicode lookalike characters used in domain to deceive.",
            },
          };
          const entry = map[t] || {
            id: "T1566",
            tactic: "TA0001 – Initial Access",
            technique: "T1566 – Phishing",
            desc: "Phishing attack vector detected.",
          };
          return [entry];
        })();

  if (mitreEntries.length === 0) {
    fillRect(doc, MARGIN, y, CONTENT_W, 20, C.rowAlt);
    strokeRect(doc, MARGIN, y, CONTENT_W, 20, C.cardBorder);
    doc
      .fontSize(7.5)
      .font("Helvetica")
      .fillColor(C.textMuted)
      .text(
        "No MITRE ATT&CK techniques mapped for this scan.",
        MARGIN + 10,
        y + 6,
      );
    y += 28;
  } else {
    // Header row
    fillRect(doc, MARGIN, y, CONTENT_W, 16, C.navy);
    const mCols = [MARGIN + 8, MARGIN + 68, MARGIN + 178, MARGIN + 310];
    ["ID", "TACTIC", "TECHNIQUE", "DESCRIPTION"].forEach((h, i) =>
      doc
        .fontSize(7)
        .font("Helvetica-Bold")
        .fillColor("#FFFFFF")
        .text(h, mCols[i], y + 5),
    );
    y += 16;

    mitreEntries.slice(0, 6).forEach((m, i) => {
      const rH = 22;
      if (i % 2 === 0) fillRect(doc, MARGIN, y, CONTENT_W, rH, C.rowAlt);
      strokeRect(doc, MARGIN, y, CONTENT_W, rH, C.cardBorder, 0.3);

      // ID badge
      fillRect(doc, MARGIN + 6, y + 4, 56, 13, "#EDE9FE");
      doc
        .fontSize(7)
        .font("Courier-Bold")
        .fillColor(C.purple)
        .text(m.id || "T1566", MARGIN + 8, y + 8, {
          width: 52,
          align: "center",
        });
      doc
        .fontSize(7)
        .font("Helvetica")
        .fillColor(C.textMid)
        .text(m.tactic || "—", mCols[1], y + 7, { width: 106, ellipsis: true });
      doc
        .fontSize(7)
        .font("Helvetica-Bold")
        .fillColor(C.navy)
        .text(m.technique || m.name || "—", mCols[2], y + 7, {
          width: 128,
          ellipsis: true,
        });
      doc
        .fontSize(7)
        .font("Helvetica")
        .fillColor(C.textMuted)
        .text(m.desc || m.description || "—", mCols[3], y + 7, {
          width: CONTENT_W - (mCols[3] - MARGIN) - 6,
          ellipsis: true,
        });
      y += rH;
    });

    y += 8;
  }

  // ════════════════════════════════════════════════════════════════
  // SECTION 6 — CVE REFERENCES (if any)
  // ════════════════════════════════════════════════════════════════
  if (cveReferences && cveReferences.length > 0) {
    if (y > 640) {
      doc.addPage();
      y = MARGIN;
    }
    const sN = String(sNumMitre + 1).padStart(2, "0");
    y = sectionHead(
      doc,
      sN,
      "CVE VULNERABILITY REFERENCES",
      y,
      MARGIN,
      CONTENT_W,
    );

    fillRect(doc, MARGIN, y, CONTENT_W, 16, C.navy);
    ["CVE ID", "VULNERABILITY CLASS", "SEVERITY", "DESCRIPTION"].forEach(
      (h, i) =>
        doc
          .fontSize(7)
          .font("Helvetica-Bold")
          .fillColor("#FFFFFF")
          .text(h, MARGIN + [8, 90, 210, 280][i], y + 5),
    );
    y += 16;

    cveReferences.slice(0, 6).forEach((cve, i) => {
      const rH = 20;
      if (i % 2 === 0) fillRect(doc, MARGIN, y, CONTENT_W, rH, C.rowAlt);
      strokeRect(doc, MARGIN, y, CONTENT_W, rH, C.cardBorder, 0.3);

      const sevC =
        cve.severity === "CRITICAL"
          ? C.phishing
          : cve.severity === "HIGH"
            ? C.suspicious
            : C.textMid;

      doc
        .fontSize(7)
        .font("Courier-Bold")
        .fillColor(C.accent)
        .text(cve.id || "CVE-—", MARGIN + 8, y + 6, { width: 78 });
      doc
        .fontSize(7)
        .font("Helvetica")
        .fillColor(C.textDark)
        .text(cve.class || "—", MARGIN + 90, y + 6, {
          width: 116,
          ellipsis: true,
        });
      doc
        .fontSize(7)
        .font("Helvetica-Bold")
        .fillColor(sevC)
        .text(cve.severity || "—", MARGIN + 210, y + 6, { width: 66 });
      doc
        .fontSize(7)
        .font("Helvetica")
        .fillColor(C.textMuted)
        .text(cve.description || "—", MARGIN + 280, y + 6, {
          width: CONTENT_W - 284,
          ellipsis: true,
        });
      y += rH;
    });

    y += 8;
  }

  // ════════════════════════════════════════════════════════════════
  // SECTION 7 — ATTACK VECTORS
  // ════════════════════════════════════════════════════════════════
  if (attackVectors && attackVectors.length > 0) {
    if (y > 650) {
      doc.addPage();
      y = MARGIN;
    }
    const sN = String(sNumMitre + (cveReferences?.length > 0 ? 2 : 1)).padStart(
      2,
      "0",
    );
    y = sectionHead(doc, sN, "ATTACK VECTORS IDENTIFIED", y, MARGIN, CONTENT_W);

    const cols = 3;
    const cellW = (CONTENT_W - (cols - 1) * 6) / cols;

    attackVectors.slice(0, 9).forEach((vec, i) => {
      const cx = MARGIN + (i % cols) * (cellW + 6);
      const cy = y + Math.floor(i / cols) * 26;
      fillRect(doc, cx, cy, cellW, 22, "#FEF3C7");
      strokeRect(doc, cx, cy, cellW, 22, "#F59E0B", 0.5);
      fillRect(doc, cx, cy, 3, 22, C.suspicious);
      doc
        .fontSize(7.5)
        .font("Helvetica-Bold")
        .fillColor(C.textDark)
        .text(String(vec).replace(/_/g, " "), cx + 8, cy + 7, {
          width: cellW - 12,
          ellipsis: true,
        });
    });

    y += Math.ceil(attackVectors.slice(0, 9).length / cols) * 26 + 8;
  }

  // ════════════════════════════════════════════════════════════════
  // SECTION 8 — THREAT INTELLIGENCE
  // ════════════════════════════════════════════════════════════════
  if (
    threatIntel &&
    (threatIntel.inPhishTank ||
      threatIntel.inOpenPhish ||
      threatIntel.abuseScore > 0)
  ) {
    if (y > 640) {
      doc.addPage();
      y = MARGIN;
    }
    const sN = String(sNumMitre + (cveReferences?.length > 0 ? 3 : 2)).padStart(
      2,
      "0",
    );
    y = sectionHead(doc, sN, "THREAT INTELLIGENCE", y, MARGIN, CONTENT_W);

    const TI_CARD_W = (CONTENT_W - 12) / 3;
    const tiItems = [
      {
        label: "PhishTank",
        val: threatIntel.inPhishTank ? "CONFIRMED" : "NOT LISTED",
        color: threatIntel.inPhishTank ? C.phishing : C.safe,
      },
      {
        label: "OpenPhish",
        val: threatIntel.inOpenPhish ? "CONFIRMED" : "NOT LISTED",
        color: threatIntel.inOpenPhish ? C.phishing : C.safe,
      },
      {
        label: "Abuse Score",
        val: `${threatIntel.abuseScore || 0}/100`,
        color: (threatIntel.abuseScore || 0) > 50 ? C.phishing : C.safe,
      },
    ];

    tiItems.forEach(({ label, val, color }, i) => {
      const cx = MARGIN + i * (TI_CARD_W + 6);
      fillRect(doc, cx, y, TI_CARD_W, 40, "#FFFFFF");
      strokeRect(doc, cx, y, TI_CARD_W, 40, C.cardBorder);
      fillRect(doc, cx, y, TI_CARD_W, 3, color);
      doc
        .fontSize(7)
        .font("Helvetica")
        .fillColor(C.textMuted)
        .text(label, cx + 8, y + 10, { width: TI_CARD_W - 16 });
      doc
        .fontSize(11)
        .font("Helvetica-Bold")
        .fillColor(color)
        .text(val, cx + 8, y + 22, { width: TI_CARD_W - 16 });
    });

    y += 50;
  }

  // ════════════════════════════════════════════════════════════════
  // SECTION 9 — RECOMMENDED ACTIONS
  // ════════════════════════════════════════════════════════════════
  if (y > 600) {
    doc.addPage();
    y = MARGIN;
  }

  const lastSNum =
    sNumMitre +
    (cveReferences?.length > 0 ? 1 : 0) +
    (attackVectors?.length > 0 ? 1 : 0) +
    (threatIntel &&
    (threatIntel.inPhishTank ||
      threatIntel.inOpenPhish ||
      threatIntel.abuseScore > 0)
      ? 1
      : 0) +
    1;
  const sNAct = String(lastSNum).padStart(2, "0");
  y = sectionHead(doc, sNAct, "RECOMMENDED ACTIONS", y, MARGIN, CONTENT_W);

  const actions =
    status === "phishing"
      ? [
          {
            pri: "IMMEDIATE",
            act: "Do NOT click any links or open attachments in this message",
            color: C.phishing,
          },
          {
            pri: "IMMEDIATE",
            act: "Block the domain at firewall/DNS level to protect all users",
            color: C.phishing,
          },
          {
            pri: "URGENT",
            act: "Report URL to Google Safe Browsing: safebrowsing.google.com/safebrowsing/report_phish",
            color: "#C0392B",
          },
          {
            pri: "URGENT",
            act: "Alert all users who may have received this message or visited this URL",
            color: C.suspicious,
          },
          {
            pri: "URGENT",
            act: "Check server/proxy logs for any users who already accessed this URL",
            color: C.suspicious,
          },
          {
            pri: "HIGH",
            act: "If credentials were entered — force immediate password reset for affected accounts",
            color: C.suspicious,
          },
          {
            pri: "HIGH",
            act: "Enable MFA on all affected accounts as additional protection",
            color: C.navy,
          },
          {
            pri: "MEDIUM",
            act: "Submit IOCs (domain, IP) to your threat intelligence platform",
            color: C.textMid,
          },
          {
            pri: "MEDIUM",
            act: "Document incident in your incident response system (e.g. PhishNetra Incidents)",
            color: C.textMid,
          },
          {
            pri: "LOW",
            act: "Monitor for related phishing activity using the PhishDNA fingerprint",
            color: C.textMuted,
          },
        ]
      : status === "suspicious"
        ? [
            {
              pri: "HIGH",
              act: "Proceed with caution — verify sender through an alternative trusted channel",
              color: C.phishing,
            },
            {
              pri: "HIGH",
              act: "Do NOT enter credentials or personal information on this site/form",
              color: C.phishing,
            },
            {
              pri: "MEDIUM",
              act: "Report to your security team for manual investigation",
              color: C.suspicious,
            },
            {
              pri: "MEDIUM",
              act: "Check if the domain was recently registered (< 30 days)",
              color: C.suspicious,
            },
            {
              pri: "LOW",
              act: "Run a WHOIS lookup on the domain to identify ownership",
              color: C.textMid,
            },
            {
              pri: "LOW",
              act: "Monitor for further suspicious activity from this source",
              color: C.textMuted,
            },
          ]
        : [
            {
              pri: "INFO",
              act: "No immediate action required — URL appears legitimate",
              color: C.safe,
            },
            {
              pri: "INFO",
              act: "Continue to monitor for changes to this domain",
              color: C.textMid,
            },
            {
              pri: "INFO",
              act: "If unexpected, verify the URL was typed correctly to avoid typosquatting",
              color: C.textMuted,
            },
          ];

  const remedSteps = remediation?.steps || [];
  const allActions = [
    ...actions,
    ...remedSteps.slice(0, 4).map((s) => ({
      pri: s.priority || "MEDIUM",
      act: s.action || "",
      color:
        s.priority === "CRITICAL"
          ? C.phishing
          : s.priority === "HIGH"
            ? C.suspicious
            : s.priority === "MEDIUM"
              ? C.navy
              : C.textMid,
    })),
  ];

  // Header
  fillRect(doc, MARGIN, y, CONTENT_W, 16, C.navy);
  doc
    .fontSize(7)
    .font("Helvetica-Bold")
    .fillColor("#FFFFFF")
    .text("PRIORITY", MARGIN + 8, y + 5);
  doc.text("ACTION", MARGIN + 80, y + 5);
  y += 16;

  allActions.slice(0, 12).forEach((a, i) => {
    const rH = 20;
    if (i % 2 === 0) fillRect(doc, MARGIN, y, CONTENT_W, rH, C.rowAlt);
    strokeRect(doc, MARGIN, y, CONTENT_W, rH, C.cardBorder, 0.3);

    // Priority badge
    const bgMap = {
      IMMEDIATE: "#FADBD8",
      URGENT: "#FEF0CD",
      HIGH: "#FEF9E7",
      MEDIUM: "#EBF5FB",
      LOW: "#EAFAF1",
      INFO: "#F0F4F8",
    };
    fillRect(doc, MARGIN + 6, y + 4, 66, 12, bgMap[a.pri] || "#F0F4F8");
    doc
      .fontSize(6.5)
      .font("Helvetica-Bold")
      .fillColor(a.color)
      .text(a.pri, MARGIN + 8, y + 7, { width: 62, align: "center" });

    // Step number
    doc
      .fontSize(7)
      .font("Helvetica-Bold")
      .fillColor(a.color)
      .text(`${i + 1}.`, MARGIN + 78, y + 7, { width: 14 });
    doc
      .fontSize(7.5)
      .font("Helvetica")
      .fillColor(C.textDark)
      .text(a.act, MARGIN + 94, y + 7, {
        width: CONTENT_W - 100,
        ellipsis: true,
      });

    y += rH;
  });

  y += 10;

  // ════════════════════════════════════════════════════════════════
  // REPORT LINKS (from remediation)
  // ════════════════════════════════════════════════════════════════
  if (remediation?.reportLinks && remediation.reportLinks.length > 0) {
    if (y > 660) {
      doc.addPage();
      y = MARGIN;
    }
    y = sectionHead(
      doc,
      String(lastSNum + 1).padStart(2, "0"),
      "REPORTING RESOURCES",
      y,
      MARGIN,
      CONTENT_W,
    );

    remediation.reportLinks.slice(0, 5).forEach((link, i) => {
      if (i % 2 === 0) fillRect(doc, MARGIN, y, CONTENT_W, 18, C.rowAlt);
      strokeRect(doc, MARGIN, y, CONTENT_W, 18, C.cardBorder, 0.3);
      doc
        .fontSize(7)
        .font("Helvetica-Bold")
        .fillColor(C.textMuted)
        .text(`${i + 1}.`, MARGIN + 8, y + 5);
      doc
        .fontSize(7)
        .font("Helvetica")
        .fillColor(C.accent)
        .text(link.label || link.url || link, MARGIN + 22, y + 5, {
          width: CONTENT_W - 30,
          ellipsis: true,
        });
      y += 18;
    });

    y += 8;
  }

  // ════════════════════════════════════════════════════════════════
  // FOOTER (on last page)
  // ════════════════════════════════════════════════════════════════
  // Always push to page bottom
  const FOOTER_Y = 800;
  if (y < FOOTER_Y) {
    // Light rule above footer
    divider(doc, FOOTER_Y - 5, MARGIN, CONTENT_W, C.cardBorder);
  }

  fillRect(doc, 0, FOOTER_Y, PAGE_W, 42, "#F8FAFC");
  divider(doc, FOOTER_Y, MARGIN, CONTENT_W, C.cardBorder);

  // Left: branding
  doc
    .fontSize(7.5)
    .font("Helvetica-Bold")
    .fillColor(C.navy)
    .text("PhishNetra AI  ·  SentinelCore SIEM", MARGIN, FOOTER_Y + 8);
  doc
    .fontSize(6.5)
    .font("Helvetica")
    .fillColor(C.textMuted)
    .text(
      `Detection Engine v${detectionVersion}  ·  Team 64, Jain University Bengaluru`,
      MARGIN,
      FOOTER_Y + 20,
    );

  // Center: disclaimer
  doc
    .fontSize(6.5)
    .font("Helvetica")
    .fillColor(C.textMuted)
    .text(
      "This report is auto-generated by an AI system. Always verify findings with a qualified security analyst.",
      MARGIN,
      FOOTER_Y + 30,
      { width: CONTENT_W, align: "center" },
    );

  // Right: report ID
  const reportId = `RPT-${Date.now().toString(36).toUpperCase()}`;
  doc
    .fontSize(7)
    .font("Courier")
    .fillColor(C.textMuted)
    .text(reportId, PAGE_W - MARGIN - 100, FOOTER_Y + 8, {
      width: 100,
      align: "right",
    });
  doc
    .fontSize(6.5)
    .font("Helvetica")
    .fillColor(C.textMuted)
    .text(
      new Date().toLocaleDateString("en-IN"),
      PAGE_W - MARGIN - 100,
      FOOTER_Y + 20,
      { width: 100, align: "right" },
    );

  doc.end();
}

module.exports = { generateReport };
