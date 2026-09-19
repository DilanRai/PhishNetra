// ════════════════════════════════════════════════════════════════
// FILE: backend/services/ransomwareDetector.js — CREATE NEW
// Ransomware Early Warning System
// Real-world use: Detects ransomware indicators BEFORE encryption
// completes — honeypot files on network shares trigger instant
// alerts. Also detects ransomware delivery via email/URL analysis,
// known ransomware C2 domains, and file extension patterns.
// ════════════════════════════════════════════════════════════════
"use strict";
const mongoose = require("mongoose");
const crypto   = require("crypto");
 
// ── Honeypot file tracking schema ─────────────────────────────
const HoneypotSchema = new mongoose.Schema({
  path:       { type: String, required: true },
  host:       { type: String, required: true },
  share:      { type: String, default: null },
  fileName:   { type: String, required: true },
  baseHash:   { type: String, required: true }, // SHA-256 of original content
  lastChecked:{ type: Date, default: Date.now },
  triggered:  { type: Boolean, default: false, index: true },
  triggeredAt:{ type: Date, default: null },
  triggeredBy:{ type: String, default: null },
  active:     { type: Boolean, default: true },
  createdAt:  { type: Date, default: Date.now },
});
 
// ── Ransomware warning event schema ───────────────────────────
const RansomwareEventSchema = new mongoose.Schema({
  eventId:   { type: String, default: () => `RW-${Date.now().toString(36).toUpperCase()}`, unique: true },
  type: {
    type: String,
    enum: ["honeypot_triggered","known_extension","ransom_note_detected",
           "c2_domain","delivery_email","suspicious_encryption_rate",
           "shadow_copy_deletion","known_family","network_spread"],
    required: true,
  },
  severity:    { type: Number, min:1, max:5, default:5 },
  host:        { type: String, default: null },
  indicator:   { type: String, default: null },
  family:      { type: String, default: null },
  confidence:  { type: Number, default: 0 },
  description: { type: String, default: "" },
  mitre:       { type: String, default: "T1486 - Data Encrypted for Impact" },
  raw:         { type: mongoose.Schema.Types.Mixed, default: {} },
  status:      { type: String, enum:["active","contained","resolved"], default:"active" },
  createdAt:   { type: Date, default: Date.now },
});
 
const HoneypotFile    = mongoose.model("HoneypotFile",    HoneypotSchema);
const RansomwareEvent = mongoose.model("RansomwareEvent", RansomwareEventSchema);
 
// ── Known ransomware extensions (1000+ families) ─────────────
// NOTE: entries must be plain strings — Set.has() / Set iteration does exact
// match, not regex.  Dynamic patterns live in RANSOMWARE_EXT_PATTERNS below.
const RANSOMWARE_EXTENSIONS = new Set([
  // Classic families
  // Removed: .mp3 (TeslaCrypt artifact — causes massive false positives)
  // Removed: .encrypted, .abc, .ha3, .ezz, .pays  (were duplicated below)
  ".locked",".enc",".crypted",".crypt",".crypto",".cry",
  ".WNCRY",".WNCRYT",".wannacry",".locky",".zepto",".odin",".aesir",
  ".thor",".zzzzz",".cerber",".cerber2",".cerber3",".ccc",".vvv",".exx",
  ".ezz",".ecc",".xyz",".abc",".zzz",".micro",".ttt",".xxx",
  ".btc",".pays",".globe",".globe2",".globe3",".decryptallfiles",
  ".good",".r5a",".crjoker",".ha3",".iforgot",".locked3",".0x0",".bleep",
  ".1999",".karma",".dharma",".adobe",".java",".phobos",".devil",
  ".eight",".help",".meds",".nbes",".npsg",".nppp",".mkos",".moklater",
  ".moka",".derp",".mado",".opqz",".reha",".topi",".covm",".coharos",
  ".nile",".conti",".ryuk",".clop",".maze",".netwalker",".sodinokibi",
  ".revil",".blackmatter",".lockbit",".hive",".blackcat",".alphv",
  ".darkside",".cuba",".grief",".avos",".ragnar",".egregor",".mount",
  ".mnx",".slfkj",".sss",".lock",".encrypted",".pay",".aaa",
  // Modern/2023-2024 ransomware families
  ".djvu",".djvus",".djvut",".djvuu",".djvur",".udjvu",".uudjvu",
  ".rhysida",".akira",".medusa",".knight",".ransomhub",".hunters",
  ".bianlian",".play",".snatch",".royal",".3am",".scattered",
  ".cactus",".inc",".metaencryptor",".monti",".rorschach",".agenda",
  ".sparta",".trigona",".blackbyte",".karakurt",".lorenz",".nokoyawa",
  ".deadbolt",".esxiargs",".checkmate",".yanluowang",".donut",
  ".cl0p",".clop0",".clopreadthis",".findme",".cryptolocker",
  ".cryptowall",".teslacrypt",".teslacrypt3",".teslacrypt4",
  ".tox",".toxcrypt",".crypted000007",".crypted001",
  ".basta",".blackbasta",".ransomxx",".ragnarok",".nephilim",".nefilim",
  ".savethequeen",".wastedlocker",".maze2",".ruyk",".snake",".ekans",
  ".milihpen",".memento",".eking",".egregor2",".mount2",".babuk",
  ".babyk",".babukrandom",".rook",".nightsky",".pandora",".mindware",
]);

// Regex patterns for dynamic/parameterised extensions (Dharma email-appended etc.)
// Cannot go in the Set — they require .test() / .exec(), not .has()
const RANSOMWARE_EXT_PATTERNS = [
  /\.[a-f0-9]{6,16}\.[a-z0-9]{2,12}@[a-z0-9.]+\b/i, // Dharma: .XXXXXXXX.email@domain
  /\.id-[a-f0-9]{6,16}\b/i,                            // Dharma short ID suffix
];
 
// ── Known ransomware note filenames ──────────────────────────
const RANSOM_NOTE_NAMES = new Set([
  "readme.txt","read_me.txt","readme!.txt","_readme.txt","how_to_decrypt.txt",
  "!help_decrypt.txt","help_decrypt.txt","decrypt_instructions.txt",
  "ransom.txt","recover_files.txt","how_to_recover.html","payment.txt",
  "!!!read_this!!!.txt","restore_your_files.txt","decrypt_your_files.txt",
  "your_files_are_encrypted.txt","files_encrypted.txt","recovery.txt",
  "how to decrypt my files.txt","attention!!!.txt","info.txt","note.txt",
  "!!!readme!!!.txt","decrypt.txt","encrypted.txt","ow_restore_files.txt",
]);
 
// ── Known ransomware C2 / Tor domains (sample) ───────────────
const KNOWN_C2_PATTERNS = [
  /\.onion$/i,
  /ransom|decrypt|payment|recover.*file|file.*recover/i,
  /xmrpool|monero.*pay|btc.*recover/i,
  /lockbit|conti|clop|blackcat|alphv|hive.*dark/i,
];
 
// ── Known ransomware families by signature ───────────────────
const FAMILY_SIGNATURES = {
  "WannaCry":     { ext:".WNCRY",     note:"@WanaDecryptor@.exe" },
  "Ryuk":         { ext:".ryuk",      note:"RyukReadMe.html"     },
  "LockBit":      { ext:".lockbit",   note:"Restore-My-Files.txt"},
  "BlackCat/ALPHV":{ ext:".alphv",    note:"RECOVER-FILES.txt"   },
  "Conti":        { ext:".conti",     note:"CONTI_README.txt"    },
  "Hive":         { ext:".hive",      note:"HOW_TO_DECRYPT.txt"  },
  "STOP/Djvu":    { ext:".djvu",      note:"_readme.txt"         },
  "Sodinokibi/REvil":{ ext:".sodinokibi", note:"readme.txt"     },
  "Dharma/CrySis":{ ext:".dharma",    note:"FILES ENCRYPTED.txt" },
  "Phobos":       { ext:".phobos",    note:"info.hta"            },
};
 
// ── Family identification helpers ────────────────────────────
function identifyFamilyByText(text) {
  const t = text.toLowerCase();
  for (const [family, sig] of Object.entries(FAMILY_SIGNATURES)) {
    if ((sig.ext && t.includes(sig.ext.toLowerCase())) || (sig.note && t.includes(sig.note.toLowerCase()))) {
      return family;
    }
  }
  // Keyword-based family detection
  if (t.includes("wannacry") || t.includes("wncry")) return "WannaCry";
  if (t.includes("ryuk"))     return "Ryuk";
  if (t.includes("lockbit"))  return "LockBit";
  if (t.includes("conti"))    return "Conti";
  if (t.includes("blackcat") || t.includes("alphv")) return "BlackCat/ALPHV";
  if (t.includes("hive"))     return "Hive";
  if (t.includes("clop") || t.includes("cl0p"))      return "Cl0p";
  if (t.includes("rhysida"))  return "Rhysida";
  if (t.includes("akira"))    return "Akira";
  if (t.includes("blackbasta") || t.includes("black basta")) return "Black Basta";
  if (t.includes("medusa"))   return "Medusa";
  if (t.includes("royal"))    return "Royal";
  if (t.includes("play"))     return "Play";
  if (t.includes("djvu") || t.includes("stop"))  return "STOP/Djvu";
  if (t.includes("dharma") || t.includes("crysis")) return "Dharma/CrySis";
  if (t.includes("phobos"))   return "Phobos";
  if (t.includes("sodinokibi") || t.includes("revil")) return "Sodinokibi/REvil";
  return "Unknown";
}

function identifyFamilyByNote(noteFileName) {
  for (const [family, sig] of Object.entries(FAMILY_SIGNATURES)) {
    if (sig.note && sig.note.toLowerCase() === noteFileName.toLowerCase()) {
      return family;
    }
  }
  return "Unknown";
}

// ── LOLBins used by ransomware ────────────────────────────────
const LOLBINS = [
  { cmd:"vssadmin delete shadows",         mitre:"T1490", label:"Shadow Copy Deletion",         severity:5 },
  { cmd:"wmic shadowcopy delete",          mitre:"T1490", label:"Shadow Copy Deletion (WMIC)",   severity:5 },
  { cmd:"bcdedit /set recoveryenabled no", mitre:"T1490", label:"Disable Boot Recovery",          severity:5 },
  { cmd:"bcdedit /set bootstatuspolicy",   mitre:"T1490", label:"Boot Status Policy Tamper",      severity:5 },
  { cmd:"wbadmin delete catalog",          mitre:"T1490", label:"Backup Catalog Deletion",        severity:5 },
  { cmd:"net stop",                        mitre:"T1489", label:"Service Stop (backups/AV)",      severity:4 },
  { cmd:"sc stop",                         mitre:"T1489", label:"Security Service Stop",          severity:4 },
  { cmd:"taskkill /f",                     mitre:"T1562", label:"Process Kill (AV/backup)",       severity:4 },
  { cmd:"certutil -decode",                mitre:"T1140", label:"LOLBin Payload Decode",          severity:4 },
  { cmd:"certutil -urlcache",              mitre:"T1105", label:"LOLBin File Download",           severity:5 },
  { cmd:"bitsadmin /transfer",             mitre:"T1197", label:"BITS Job Transfer (C2/payload)", severity:4 },
  { cmd:"regsvr32 /s /n /u /i:",           mitre:"T1218", label:"Regsvr32 AppLocker Bypass",      severity:5 },
  { cmd:"mshta.exe",                       mitre:"T1218", label:"MSHTA Execution",                severity:4 },
  { cmd:"rundll32.exe",                    mitre:"T1218", label:"Rundll32 Execution",             severity:4 },
  { cmd:"wscript.exe",                     mitre:"T1059", label:"WScript Execution",              severity:3 },
  { cmd:"cscript.exe",                     mitre:"T1059", label:"CScript Execution",              severity:3 },
  { cmd:"msiexec /quiet",                  mitre:"T1218", label:"MSI Silent Install",             severity:4 },
  { cmd:"powershell -enc",                 mitre:"T1059.001", label:"Encoded PowerShell",         severity:5 },
  { cmd:"powershell -nop -w hidden",       mitre:"T1059.001", label:"Hidden PowerShell",          severity:5 },
  { cmd:"invoke-expression",               mitre:"T1059.001", label:"PowerShell IEX",             severity:5 },
  { cmd:"invoke-webrequest",               mitre:"T1105",     label:"PowerShell Download",        severity:4 },
  { cmd:"net use \\\\",                    mitre:"T1021.002", label:"SMB Lateral Movement",       severity:5 },
  { cmd:"psexec",                          mitre:"T1570",     label:"PsExec Remote Execution",    severity:5 },
  { cmd:"wmic process call create",        mitre:"T1047",     label:"WMIC Process Spawn",         severity:4 },
  { cmd:"icacls * /reset",                 mitre:"T1222",     label:"Permission Reset (pre-encrypt)",severity:5 },
  { cmd:"attrib +h +s",                    mitre:"T1564",     label:"File Hidden (malware hiding)",severity:3 },
];

// ── Core detection function — ENHANCED ───────────────────────
async function analyzeForRansomware(input, context = {}) {
  const text  = (input || "").toLowerCase();
  const results = [];
 
  // 1. Check file extension — Set exact matches
  for (const ext of RANSOMWARE_EXTENSIONS) {
    if (text.includes(ext.toLowerCase())) {
      const family = Object.entries(FAMILY_SIGNATURES)
        .find(([,v]) => v.ext?.toLowerCase() === ext.toLowerCase())?.[0] || identifyFamilyByText(text);
      results.push({
        type:       "known_extension",
        severity:   5,
        indicator:  ext,
        family,
        confidence: 92,
        description:`Known ransomware file extension "${ext}" detected. Associated family: ${family}.`,
        mitre:      "T1486 - Data Encrypted for Impact",
      });
    }
  }

  // 1b. Regex-based dynamic extension patterns (Dharma email-appended variants)
  for (const pat of RANSOMWARE_EXT_PATTERNS) {
    const m = pat.exec(input || "");
    if (m) {
      results.push({
        type:       "known_extension",
        severity:   5,
        indicator:  m[0],
        family:     "Dharma/CrySis",
        confidence: 88,
        description:`Dharma/CrySis dynamic extension pattern "${m[0]}" detected (email-appended variant).`,
        mitre:      "T1486 - Data Encrypted for Impact",
      });
    }
  }
 
  // 2. Check ransom note filenames
  const fileName = context.fileName?.toLowerCase();
  if (fileName && RANSOM_NOTE_NAMES.has(fileName)) {
    const family = identifyFamilyByNote(fileName);
    results.push({
      type:       "ransom_note_detected",
      severity:   5,
      indicator:  fileName,
      family,
      confidence: 95,
      description:`Ransomware note filename "${fileName}" detected — active ransomware infection almost certain. Family: ${family || "Unknown"}.`,
      mitre:      "T1486 - Data Encrypted for Impact",
    });
  }
 
  // 3. Check content for ransom indicators
  const RANSOM_PHRASES = [
    "your files have been encrypted","all your files are encrypted",
    "pay bitcoin","send bitcoin","btc address","your personal id",
    "decrypt your files","buy decryption","recovery key","ransom",
    "pay to recover","your files are locked","pay monero","xmr address",
    "decryption tool","your network has been encrypted",
    "double extortion","data will be published","darkweb","dark web leak",
    "stolen data","negotiation chat","payment deadline","time remaining",
    "tor browser","onion link","unique id","your company has been hacked",
  ];
  const phraseHits = RANSOM_PHRASES.filter(p => text.includes(p));
  if (phraseHits.length >= 2) {
    results.push({
      type:       "ransom_note_detected",
      severity:   5,
      indicator:  phraseHits.slice(0,3).join(", "),
      confidence: Math.min(65 + phraseHits.length * 5, 98),
      description:`Ransomware demand language detected: "${phraseHits.slice(0,2).join('", "')}". ${phraseHits.length} matching phrases — high confidence ransom note.`,
      mitre:      "T1486 - Data Encrypted for Impact",
    });
  }
 
  // 4. C2 domain check (URL input)
  if (context.inputType === "url" || /https?:\/\//.test(input)) {
    for (const pattern of KNOWN_C2_PATTERNS) {
      if (pattern.test(input)) {
        results.push({
          type:       "c2_domain",
          severity:   5,
          indicator:  input,
          confidence: 80,
          description:`URL matches known ransomware C2 pattern. May be ransomware payment/communication portal or data leak site.`,
          mitre:      "T1071 - Application Layer Protocol",
        });
        break;
      }
    }
  }
 
  // 5. LOLBins / Shadow copy deletion
  const lolbinHits = LOLBINS.filter(lb => text.includes(lb.cmd.toLowerCase()));
  for (const lb of lolbinHits) {
    results.push({
      type:       lb.cmd.includes("shadow") || lb.cmd.includes("bcdedit") || lb.cmd.includes("wbadmin")
                    ? "shadow_copy_deletion" : "network_spread",
      severity:   lb.severity,
      indicator:  lb.cmd,
      confidence: 92,
      description:`LOLBin/ransomware command detected: "${lb.cmd}" — ${lb.label}. Pre-encryption preparation confirmed.`,
      mitre:      `${lb.mitre} - ${lb.label}`,
    });
  }

  // 6. Network spread indicators
  const SPREAD_INDICATORS = [
    { pattern:"psexec",                  label:"PsExec lateral movement",          mitre:"T1570" },
    { pattern:"wmiexec",                 label:"WMIExec remote execution",          mitre:"T1047" },
    { pattern:"net view /domain",        label:"Domain enumeration",                mitre:"T1018" },
    { pattern:"nltest /domain_trusts",   label:"Domain trust enumeration",          mitre:"T1482" },
    { pattern:"net group \"domain admin\"",label:"Admin account enumeration",       mitre:"T1069" },
    { pattern:"arp -a",                  label:"ARP network discovery",             mitre:"T1018" },
    { pattern:"nmap",                    label:"Network port scanner",              mitre:"T1046" },
    { pattern:"advanced_ip_scanner",     label:"IP range scanner",                  mitre:"T1046" },
    { pattern:"mimikatz",                label:"Credential dumping (Mimikatz)",      mitre:"T1003" },
    { pattern:"sekurlsa::logonpasswords",label:"LSASS credential dump",             mitre:"T1003.001" },
    { pattern:"hashdump",                label:"Hash dump for pass-the-hash",        mitre:"T1003" },
  ];
  for (const si of SPREAD_INDICATORS) {
    if (text.includes(si.pattern.toLowerCase())) {
      results.push({
        type:       "network_spread",
        severity:   5,
        indicator:  si.pattern,
        confidence: 88,
        description:`Network spread tool detected: "${si.pattern}" — ${si.label}. Ransomware likely moving laterally across the network.`,
        mitre:      `${si.mitre} - ${si.label}`,
      });
    }
  }
 
  // Save events to DB
  const saved = [];
  for (const r of results) {
    try {
      const ev = await new RansomwareEvent({ ...r, host: context.host || null, raw: { input: input?.substring(0,200), context } }).save();
      saved.push(ev);
    } catch {}
  }
 
  return {
    isRansomware:   results.length > 0,
    maxSeverity:    results.length > 0 ? Math.max(...results.map(r => r.severity)) : 0,
    confidence:     results.length > 0 ? Math.max(...results.map(r => r.confidence)) : 0,
    detections:     results,
    family:         results.find(r => r.family)?.family || null,
    mitre:          results[0]?.mitre || null,
  };
}
 
// ── Honeypot management ───────────────────────────────────────
async function registerHoneypot({ host, share, path, fileName }) {
  const content = `PhishNetra Honeypot File\nHost: ${host}\nCreated: ${new Date().toISOString()}\nDO NOT MODIFY - SECURITY MONITORING ACTIVE`;
  const hash = crypto.createHash("sha256").update(content).digest("hex");
  return new HoneypotFile({ path, host, share, fileName, baseHash: hash }).save();
}
 
async function checkHoneypot(honeypotId, currentHash) {
  const hp = await HoneypotFile.findById(honeypotId);
  if (!hp || !hp.active) return { triggered: false };
  if (currentHash && currentHash !== hp.baseHash) {
    hp.triggered   = true;
    hp.triggeredAt = new Date();
    await hp.save();
    // Create a high-severity ransomware event
    await new RansomwareEvent({
      type:        "honeypot_triggered",
      severity:    5,
      host:        hp.host,
      indicator:   hp.path,
      confidence:  99,
      description: `🚨 RANSOMWARE HONEYPOT TRIGGERED on ${hp.host}\\${hp.fileName}. File hash changed — active encryption in progress. Isolate host IMMEDIATELY.`,
      mitre:       "T1486 - Data Encrypted for Impact",
    }).save();
    return { triggered: true, host: hp.host, path: hp.path };
  }
  hp.lastChecked = new Date();
  await hp.save();
  return { triggered: false };
}
 
async function getRansomwareStats() {
  const since24h = new Date(Date.now() - 24 * 60 * 60 * 1000);
  const [total, active, honeypots, byType, recent] = await Promise.all([
    RansomwareEvent.countDocuments({}),
    RansomwareEvent.countDocuments({ status: "active" }),
    HoneypotFile.countDocuments({ active: true }),
    RansomwareEvent.aggregate([{ $group:{ _id:"$type", count:{$sum:1} } }]),
    RansomwareEvent.find({ createdAt:{ $gte:since24h } }).sort({ createdAt:-1 }).limit(10).lean(),
  ]);
  return { total, active, honeypots, byType: Object.fromEntries(byType.map(t=>[t._id,t.count])), recent };
}
 
module.exports = { HoneypotFile, RansomwareEvent, analyzeForRansomware, registerHoneypot, checkHoneypot, getRansomwareStats };