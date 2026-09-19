"use strict";
const https = require("https");
const http = require("http");
const yauzl = require("yauzl");
const { Writable } = require("stream");

// ── VirusTotal API (free tier: 4 req/min, 500/day, no upload) ─
// Only needs your API key — no file upload, just hash lookup
// Get free key at: https://www.virustotal.com/gui/join-us
const VT_API_KEY = process.env.VIRUSTOTAL_API_KEY || null;
const VT_CACHE = new Map();
const VT_CACHE_TTL = 24 * 60 * 60 * 1000; // 24 hours (hashes don't change)

async function checkVirusTotal(sha256) {
  if (!VT_API_KEY)
    return {
      available: false,
      reason: "No VT API key — set VIRUSTOTAL_API_KEY in .env",
    };
  if (!sha256) return null;

  // Check cache
  const cached = VT_CACHE.get(sha256);
  if (cached && Date.now() - cached.ts < VT_CACHE_TTL) return cached.data;

  return new Promise((resolve) => {
    const options = {
      hostname: "www.virustotal.com",
      path: `/api/v3/files/${sha256}`,
      method: "GET",
      headers: { "x-apikey": VT_API_KEY, Accept: "application/json" },
    };

    const req = https.request(options, (res) => {
      let body = "";
      res.on("data", (c) => (body += c));
      res.on("end", () => {
        try {
          const d = JSON.parse(body);
          if (res.statusCode === 404) {
            // Hash not in VT database — file is unknown (could be new malware)
            const result = {
              found: false,
              sha256,
              detectionCount: 0,
              totalEngines: 0,
              malwareFamily: null,
              threatNames: [],
              verdict: "unknown",
              vtLink: `https://www.virustotal.com/gui/file/${sha256}`,
              note: "Hash not found in VirusTotal — file is unknown or has never been scanned",
            };
            VT_CACHE.set(sha256, { ts: Date.now(), data: result });
            return resolve(result);
          }
          if (res.statusCode !== 200) {
            return resolve({
              available: false,
              reason: `VT API error: ${res.statusCode}`,
            });
          }

          const attrs = d?.data?.attributes;
          if (!attrs) return resolve(null);

          const stats = attrs.last_analysis_stats || {};
          const detectionCount =
            (stats.malicious || 0) + (stats.suspicious || 0);
          const totalEngines = Object.values(stats).reduce((a, b) => a + b, 0);
          const results = attrs.last_analysis_results || {};
          const threatNames = Object.values(results)
            .filter(
              (r) => r.category === "malicious" || r.category === "suspicious",
            )
            .map((r) => r.result)
            .filter(Boolean)
            .slice(0, 5);

          // Extract malware family from popular AV names
          const malwareFamily = extractMalwareFamily(threatNames);

          const result = {
            found: true,
            sha256,
            detectionCount,
            totalEngines,
            cleanCount: stats.undetected || 0,
            malwareFamily,
            threatNames,
            verdict:
              detectionCount >= 5
                ? "malicious"
                : detectionCount >= 1
                  ? "suspicious"
                  : "clean",
            vtLink: `https://www.virustotal.com/gui/file/${sha256}`,
            lastAnalysisDate: attrs.last_analysis_date
              ? new Date(attrs.last_analysis_date * 1000).toISOString()
              : null,
          };
          VT_CACHE.set(sha256, { ts: Date.now(), data: result });
          resolve(result);
        } catch {
          resolve({ available: false, reason: "VT response parse error" });
        }
      });
    });
    req.setTimeout(5000, () => {
      req.destroy();
      resolve({ available: false, reason: "VT API timeout" });
    });
    req.on("error", () =>
      resolve({ available: false, reason: "VT API unreachable" }),
    );
    req.end();
  });
}

function extractMalwareFamily(threatNames) {
  if (!threatNames?.length) return null;
  // Common malware family patterns
  const families = [
    "Emotet",
    "Qakbot",
    "QBot",
    "IcedID",
    "Dridex",
    "TrickBot",
    "BazarLoader",
    "Cobalt",
    "Meterpreter",
    "AgentTesla",
    "FormBook",
    "RedLine",
    "AsyncRAT",
    "Raccoon",
    "Vidar",
    "LokiBot",
    "NanoCore",
    "RemcosRAT",
    "njRAT",
    "Ursnif",
    "Ryuk",
    "LockBit",
    "Conti",
    "Phobos",
    "Dharma",
    "STOP",
    "BlackCat",
    "Hive",
    "Hancitor",
    "Bumblebee",
    "GootLoader",
    "SocGholish",
    "ZLoader",
    "NetSupport",
  ];
  const combined = threatNames.join(" ");
  for (const family of families) {
    if (new RegExp(family, "i").test(combined)) return family;
  }
  // Try to extract from naming convention e.g. "Trojan.GenericKD.12345" → "Generic"
  const generic = combined.match(
    /(?:Trojan|Backdoor|Ransomware|Downloader|Dropper)\.(\w+)/i,
  );
  return generic?.[1] || null;
}

// ── Office Document Deep Analysis (DOCX/XLSX/PPTX = ZIP+XML) ─
function readZipEntry(zipfile, entry) {
  return new Promise((resolve, reject) => {
    zipfile.openReadStream(entry, (err, stream) => {
      if (err) return reject(err);
      const chunks = [];
      stream.on("data", (c) => chunks.push(c));
      stream.on("end", () =>
        resolve(Buffer.concat(chunks).toString("utf8", 0, 50000)),
      );
      stream.on("error", reject);
    });
  });
}

async function analyzeOfficeDocument(buffer, ext) {
  const result = {
    hyperlinks: [], // URLs found in hyperlinks
    templateUrl: null, // Remote template injection URL
    externalQueries: [], // External data connections (XLSX)
    macroEnabled: false,
    vbaProjectFound: false,
    metadata: {}, // author, lastModifiedBy, created
    oleCompound: false,
    findings: [],
    riskBoost: 0,
  };

  // ── Macro-enabled format detection ──────────────────────────
  const MACRO_EXTS = [
    "xlsm",
    "docm",
    "pptm",
    "xltm",
    "dotm",
    "potm",
    "ppam",
    "xlam",
  ];
  if (MACRO_EXTS.includes(ext)) {
    result.macroEnabled = true;
    result.findings.push({
      category: "macro",
      severity: "high",
      detail: `Macro-enabled Office format (.${ext}) — file can execute VBA code automatically. This is the primary malware delivery format since Microsoft blocked XLS macros.`,
      risk: 40,
    });
    result.riskBoost += 40;
  }

  // ── OLE Compound Document (legacy .doc/.xls/.ppt) ────────────
  // OLE magic: D0 CF 11 E0 A1 B1 1A E1
  const OLE_MAGIC = Buffer.from([
    0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1,
  ]);
  if (buffer.slice(0, 8).equals(OLE_MAGIC)) {
    result.oleCompound = true;
    // VBA project stream check — search for "VBA" string in OLE
    const bufStr = buffer.toString("latin1");
    if (/\x56\x42\x41/.test(bufStr) || bufStr.includes("VBA")) {
      result.vbaProjectFound = true;
      result.findings.push({
        category: "macro",
        severity: "critical",
        detail: `VBA macro project detected in legacy Office document (.${ext}) — contains executable Visual Basic code. Can auto-run on document open via AutoOpen/Document_Open.`,
        risk: 50,
      });
      result.riskBoost += 50;
    }
    // XLM legacy macro (4.0 macros) — search for macro sheet markers
    if (
      bufStr.includes("MACRO") ||
      bufStr.includes("XLM") ||
      /\x18\x00.{0,20}MACRO/s.test(bufStr)
    ) {
      result.findings.push({
        category: "macro",
        severity: "critical",
        detail: `XLM 4.0 macro indicators in legacy Excel file — Excel 4.0 macros execute at sheet level, evade many AV tools, and were heavily used by Emotet and QakBot.`,
        risk: 45,
      });
      result.riskBoost += 45;
    }
  }

  // ── ZIP-based Office format (DOCX/XLSX/PPTX) ─────────────────
  const ZIP_MAGIC = Buffer.from([0x50, 0x4b, 0x03, 0x04]);
  const isZIPOffice =
    buffer.slice(0, 4).equals(ZIP_MAGIC) &&
    [
      "docx",
      "xlsx",
      "pptx",
      "docm",
      "xlsm",
      "pptm",
      "odt",
      "ods",
      "odp",
    ].includes(ext);

  if (isZIPOffice) {
    await new Promise((resolve) => {
      yauzl.fromBuffer(buffer, { lazyEntries: true }, (err, zipfile) => {
        if (err) return resolve(null);

        const entries = [];
        zipfile.on("entry", (entry) => {
          entries.push(entry);
          zipfile.readEntry();
        });
        zipfile.on("end", async () => {
          for (const entry of entries) {
            const name = entry.fileName.toLowerCase();

            try {
              // ── Relationships XML (hyperlinks) ──
              if (name.endsWith(".rels")) {
                const content = await readZipEntry(zipfile, entry);
                // Extract hyperlinks from relationship files
                const hrefs =
                  content.match(/Target="(https?:\/\/[^"]{6,})"/gi) || [];
                for (const href of hrefs) {
                  const url = href.match(/Target="([^"]+)"/)?.[1];
                  if (url) result.hyperlinks.push(url);
                }
                // Template injection — external template URL
                if (
                  name.includes("settings.xml.rels") ||
                  name.includes("document.xml.rels")
                ) {
                  const templateMatch = content.match(
                    /Type="[^"]*template[^"]*"[^>]*Target="(https?:\/\/[^"]+)"/i,
                  );
                  if (templateMatch) {
                    result.templateUrl = templateMatch[1];
                    result.findings.push({
                      category: "injection",
                      severity: "critical",
                      detail: `Remote template injection URL: ${templateMatch[1]} — document loads a remote .dotm template on open, executing embedded macros from attacker server.`,
                      risk: 65,
                    });
                    result.riskBoost += 65;
                  }
                }
              }

              // ── Core properties (metadata) ──
              if (name === "docprops/core.xml") {
                const content = await readZipEntry(zipfile, entry);
                const creator = content.match(
                  /<dc:creator>([^<]+)<\/dc:creator>/,
                )?.[1];
                const modified = content.match(
                  /<cp:lastModifiedBy>([^<]+)<\/cp:lastModifiedBy>/,
                )?.[1];
                const created = content.match(
                  /<dcterms:created[^>]*>([^<]+)<\/dcterms:created>/,
                )?.[1];
                result.metadata = {
                  creator,
                  lastModifiedBy: modified,
                  created,
                };

                // Flag suspicious metadata
                if (creator && /[а-яА-Я]/.test(creator)) {
                  result.findings.push({
                    category: "metadata",
                    severity: "medium",
                    detail: `Author name contains Cyrillic characters: "${creator}" — possible Russian/Ukrainian/Bulgarian origin.`,
                    risk: 15,
                  });
                  result.riskBoost += 15;
                }
              }

              // ── Excel external connections ──
              if (
                name === "xl/connections.xml" ||
                name.includes("queryTable")
              ) {
                const content = await readZipEntry(zipfile, entry);
                const connUrls = content.match(/url="([^"]+)"/gi) || [];
                for (const u of connUrls) {
                  const url = u.match(/url="([^"]+)"/)?.[1];
                  if (url && url.startsWith("http"))
                    result.externalQueries.push(url);
                }
                if (result.externalQueries.length > 0) {
                  result.findings.push({
                    category: "exfil",
                    severity: "high",
                    detail: `Excel external data connections to: ${result.externalQueries.slice(0, 2).join(", ")} — can auto-load malicious data or exfiltrate worksheet contents.`,
                    risk: 35,
                  });
                  result.riskBoost += 35;
                }
              }
            } catch {}
          }
          resolve(null);
        });
        zipfile.readEntry();
      });
    });

    // Deduplicate hyperlinks
    result.hyperlinks = [...new Set(result.hyperlinks)];

    // Flag suspicious hyperlinks
    const suspiciousLinks = result.hyperlinks.filter((url) => {
      const HIGH_RISK_TLDS = [
        ".tk",
        ".ml",
        ".ga",
        ".cf",
        ".gq",
        ".xyz",
        ".top",
        ".icu",
        ".sbs",
      ];
      return (
        HIGH_RISK_TLDS.some((t) => url.includes(t)) ||
        url.includes("bit.ly") ||
        url.includes("tinyurl") ||
        url.includes("t.co") ||
        url.includes("ow.ly") ||
        /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(url)
      ); // IP-based URL
    });

    if (suspiciousLinks.length > 0) {
      result.findings.push({
        category: "url",
        severity: "high",
        detail: `Suspicious URLs in document: ${suspiciousLinks.slice(0, 3).join(", ")} — high-risk TLD or URL shortener used to hide destination.`,
        risk: 30,
      });
      result.riskBoost += 30;
    }
  }

  return result;
}

// ── PDF Deep Analysis ─────────────────────────────────────────
function analyzePDF(buffer) {
  const result = {
    findings: [],
    riskBoost: 0,
    embeddedJS: false,
    hasLaunchAction: false,
    hasOpenAction: false,
    hasEmbeddedFiles: false,
    hasAutoForm: false,
    embeddedUrls: [],
  };

  if (buffer.slice(0, 4).toString() !== "%PDF") return result;

  // Work with raw buffer as Latin1 string for binary-safe regex
  const content = buffer.toString("latin1", 0, Math.min(buffer.length, 200000));

  // JavaScript embedded in PDF
  if (/\/JS\s*[(<]|\/JavaScript\s*[(<]/i.test(content)) {
    result.embeddedJS = true;
    result.findings.push({
      category: "script",
      severity: "critical",
      detail:
        "PDF contains embedded JavaScript (/JS or /JavaScript dictionary entry) — can execute code when opened in Adobe Reader or browser PDF viewer.",
      risk: 60,
    });
    result.riskBoost += 60;
  }

  // /Launch action — opens external program
  if (/\/Launch\s*<</.test(content)) {
    result.hasLaunchAction = true;
    result.findings.push({
      category: "execution",
      severity: "critical",
      detail:
        "PDF contains /Launch action — can silently execute external programs (cmd.exe, PowerShell) when opened. Classic technique for dropping malware.",
      risk: 70,
    });
    result.riskBoost += 70;
  }

  // /OpenAction — auto-executes on open
  if (/\/OpenAction/.test(content)) {
    result.hasOpenAction = true;
    result.findings.push({
      category: "execution",
      severity: "high",
      detail:
        "PDF contains /OpenAction — automatically triggers an action (JavaScript, URL, or program launch) when the document is opened.",
      risk: 40,
    });
    result.riskBoost += 40;
  }

  // /EmbeddedFile — files embedded inside PDF
  if (/\/EmbeddedFile/.test(content)) {
    result.hasEmbeddedFiles = true;
    // Check what kind of file is embedded
    const embeddedExe = /\.exe|\.bat|\.cmd|\.ps1|\.vbs|\.js\b/i.test(content);
    result.findings.push({
      category: "embedded",
      severity: embeddedExe ? "critical" : "high",
      detail: embeddedExe
        ? "PDF contains /EmbeddedFile with executable reference — malware payload embedded inside PDF container."
        : "PDF contains /EmbeddedFile — additional files are embedded within this PDF.",
      risk: embeddedExe ? 65 : 30,
    });
    result.riskBoost += embeddedExe ? 65 : 30;
  }

  // /AcroForm + suspicious field actions (credential phishing forms)
  if (/\/AcroForm/.test(content)) {
    result.hasAutoForm = true;
    // Check for form submission to external URL
    const formActions = content.match(/\/F\s*\(https?:\/\/[^)]+\)/g) || [];
    if (formActions.length > 0) {
      const submitUrl = formActions[0].match(/\((https?:\/\/[^)]+)\)/)?.[1];
      result.findings.push({
        category: "phishing",
        severity: "critical",
        detail: `PDF form submits to external URL: ${submitUrl || "unknown"} — credential harvesting via PDF form, bypassing email link scanners.`,
        risk: 55,
      });
      result.riskBoost += 55;
    }
  }

  // /URI — embedded clickable URLs
  const uriMatches = content.match(/\/URI\s*\(([^)]+)\)/g) || [];
  result.embeddedUrls = uriMatches
    .map((m) => m.match(/\(([^)]+)\)/)?.[1])
    .filter(Boolean)
    .slice(0, 10);

  // Flag suspicious embedded URLs
  const HIGH_RISK_TLDS = [".tk", ".ml", ".ga", ".cf", ".xyz", ".top", ".icu"];
  const suspUrls = result.embeddedUrls.filter(
    (u) =>
      HIGH_RISK_TLDS.some((t) => u.includes(t)) ||
      /\d{3,}\.\d+\.\d+\.\d+/.test(u),
  );
  if (suspUrls.length > 0) {
    result.findings.push({
      category: "url",
      severity: "high",
      detail: `Suspicious embedded URL(s): ${suspUrls.slice(0, 2).join(", ")}`,
      risk: 25,
    });
    result.riskBoost += 25;
  }

  result.riskBoost = Math.min(result.riskBoost, 90); // cap PDF risk at 90
  return result;
}

// ════════════════════════════════════════════════════════════════
// MAIN FUNCTION — deepAnalyzeAttachment()
// Called from the existing /attachment route in scan.js
// ════════════════════════════════════════════════════════════════
async function deepAnalyzeAttachment(buffer, filename, mimetype) {
  const ext = filename.split(".").pop()?.toLowerCase() || "";
  const sha256 = require("crypto")
    .createHash("sha256")
    .update(buffer)
    .digest("hex");
  const results = {
    ext,
    sha256,
    vtResult: null,
    officeAnalysis: null,
    pdfAnalysis: null,
    deepFindings: [],
    deepRiskBoost: 0,
  };

  // Run all analyses in parallel
  const OFFICE_EXTS = [
    "docx",
    "xlsx",
    "pptx",
    "docm",
    "xlsm",
    "pptm",
    "doc",
    "xls",
    "ppt",
    "odt",
    "ods",
    "odp",
    "dotm",
    "xltm",
  ];
  const PDF_EXTS = ["pdf"];

  const [vtResult, officeResult, pdfResult] = await Promise.all([
    checkVirusTotal(sha256),
    OFFICE_EXTS.includes(ext)
      ? analyzeOfficeDocument(buffer, ext)
      : Promise.resolve(null),
    PDF_EXTS.includes(ext) ? analyzePDF(buffer) : Promise.resolve(null),
  ]);

  // ── VirusTotal results ──
  results.vtResult = vtResult;
  if (vtResult?.found && vtResult.detectionCount > 0) {
    const risk =
      vtResult.detectionCount >= 10
        ? 80
        : vtResult.detectionCount >= 5
          ? 60
          : vtResult.detectionCount >= 1
            ? 35
            : 0;
    results.deepFindings.push({
      category: "virustotal",
      severity: vtResult.detectionCount >= 5 ? "critical" : "high",
      detail:
        `VirusTotal: ${vtResult.detectionCount}/${vtResult.totalEngines} engines detect this file as malicious.` +
        (vtResult.malwareFamily ? ` Family: ${vtResult.malwareFamily}.` : "") +
        (vtResult.threatNames?.length
          ? ` Names: ${vtResult.threatNames.slice(0, 3).join(", ")}`
          : ""),
      risk,
      vtLink: vtResult.vtLink,
    });
    results.deepRiskBoost += risk;
  } else if (vtResult?.found === false) {
    results.deepFindings.push({
      category: "virustotal",
      severity: "info",
      detail: `VirusTotal: Hash not in database — file has never been scanned. This does NOT mean it's clean — could be a novel/custom payload.`,
      risk: 10, // slight risk bump for unknown files if they're executable
    });
    if (["exe", "dll", "ps1", "vbs", "bat", "cmd", "hta"].includes(ext))
      results.deepRiskBoost += 10;
  }

  // ── Office analysis results ──
  results.officeAnalysis = officeResult;
  if (officeResult) {
    results.deepFindings.push(...officeResult.findings);
    results.deepRiskBoost += officeResult.riskBoost;
  }

  // ── PDF analysis results ──
  results.pdfAnalysis = pdfResult;
  if (pdfResult) {
    results.deepFindings.push(...pdfResult.findings);
    results.deepRiskBoost += pdfResult.riskBoost;
  }

  results.deepRiskBoost = Math.min(results.deepRiskBoost, 95);
  return results;
}

module.exports = { deepAnalyzeAttachment, checkVirusTotal };
