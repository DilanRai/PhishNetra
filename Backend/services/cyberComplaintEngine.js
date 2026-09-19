// ════════════════════════════════════════════════════════════════
// FILE: backend/services/cyberComplaintEngine.js
// Cybercrime Complaint Intelligence Platform — ENHANCED
// ════════════════════════════════════════════════════════════════

"use strict";
const mongoose = require("mongoose");
const crypto   = require("crypto");

// ── Complaint Schema ──────────────────────────────────────────
const ComplaintSchema = new mongoose.Schema({
  complaintId: {
    type: String,
    default: () => `CMP-${Date.now().toString(36).toUpperCase()}-${crypto.randomBytes(2).toString("hex").toUpperCase()}`,
    unique: true, index: true,
  },
  victimName:    { type: String, default: "Anonymous" },
  victimContact: { type: String, default: null },
  victimState:   { type: String, default: null },
  victimCity:    { type: String, default: null },
  incidentDate:  { type: Date, default: Date.now },
  reportedAt:    { type: Date, default: Date.now },

  description:   { type: String, required: true },
  fraudType:     {
    type: String,
    enum: [
      "upi_fraud","bank_fraud","investment_scam","job_scam","romance_scam",
      "sextortion","ransomware","phishing","vishing","smishing","govt_impersonation",
      "lottery_scam","fake_ecommerce","courier_scam","electricity_scam",
      "police_impersonation","custom_officer_scam","aadhaar_fraud","sim_swap",
      "cyber_bullying","online_gaming_fraud","insurance_fraud","tech_support_scam","other",
    ],
    default: "other",
  },
  amountLost:    { type: Number, default: 0 },
  currency:      { type: String, default: "INR" },
  paymentMethod: {
    type: String,
    enum: ["upi","neft","rtgs","card","crypto","wallet","cash","other","unknown"],
    default: "unknown",
  },

  iocs: {
    urls:        { type: [String], default: [] },
    phones:      { type: [String], default: [] },
    emails:      { type: [String], default: [] },
    upiIds:      { type: [String], default: [] },
    bankAccounts:{ type: [String], default: [] },
    domains:     { type: [String], default: [] },
    ips:         { type: [String], default: [] },
    walletAddrs: { type: [String], default: [] },
    aadhaarNums: { type: [String], default: [] }, // NEW
    panNums:     { type: [String], default: [] }, // NEW
    imeiNums:    { type: [String], default: [] }, // NEW
  },

  classificationConfidence: { type: Number, default: 0 },
  mlTags:           { type: [String], default: [] },
  relatedScans:     { type: [String], default: [] },
  severityScore:    { type: Number, default: 0, min: 0, max: 100 }, // NEW
  riskCategory:     { type: String, enum: ["low","medium","high","critical"], default: "medium" }, // NEW
  slaDeadlineHours: { type: Number, default: 72 }, // NEW — hours to resolve

  status:      { type: String, enum: ["new","investigating","escalated","resolved","closed"], default: "new", index: true },
  priority:    { type: String, enum: ["low","medium","high","critical"], default: "medium" },
  assignedTo:  { type: String, default: null },
  resolution:  { type: String, default: null },
  ncrbRefId:   { type: String, default: null },
  mitre:       { type: String, default: null },
  attachments: { type: [String], default: [] },

  clusterHash:      { type: String, default: null, index: true },
  linkedComplaints: { type: [String], default: [] },
  escalationHistory: { type: [{ at: Date, reason: String, by: String }], default: [] }, // NEW

  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
}, { timestamps: true });

ComplaintSchema.index({ fraudType: 1, status: 1 });
ComplaintSchema.index({ "iocs.upiIds": 1 });
ComplaintSchema.index({ "iocs.phones": 1 });
ComplaintSchema.index({ "iocs.bankAccounts": 1 });
ComplaintSchema.index({ "iocs.walletAddrs": 1 });
ComplaintSchema.index({ incidentDate: -1 });
ComplaintSchema.index({ severityScore: -1 });

const Complaint = mongoose.model("CyberComplaint", ComplaintSchema);

// ── Fraud type keyword classifier — EXPANDED ─────────────────
const FRAUD_CLASSIFIERS = [
  { type:"upi_fraud",           weight:3, keywords:["upi","gpay","phonepe","paytm","bhim","qr code","scan and pay","google pay","@ok","@ybl","@ibl","@axl","collect request","upi id","phonepe link"] },
  { type:"bank_fraud",          weight:3, keywords:["bank account","kyc","debit card","credit card","otp","neft","rtgs","account frozen","transaction failed","net banking","internet banking","mobile banking","ifsc"] },
  { type:"investment_scam",     weight:3, keywords:["investment","returns","profit","trading","stock","crypto","bitcoin","doubling","high returns","guaranteed profit","withdrawal","portfolio","demat","broker"] },
  { type:"job_scam",            weight:3, keywords:["job offer","work from home","part time","data entry","likes","youtube","instagram","task","commission","earning","freelance","hired","telegram group earn"] },
  { type:"romance_scam",        weight:3, keywords:["dating","relationship","friend request","facebook friend","love","meet","foreign national","military","oil rig","divorce","matrimonial","shaadi","jeevansathi"] },
  { type:"sextortion",          weight:3, keywords:["nude","video call","screenshot","blackmail","morphed","vulgar","intimate","webcam","adult","compromising","threatening video","private video"] },
  { type:"ransomware",          weight:3, keywords:["files encrypted","ransom","bitcoin payment","decrypt","pay to recover","all files locked","readme.txt","your files","wncry","locked files","decryption key"] },
  { type:"govt_impersonation",  weight:3, keywords:["aadhaar","pan card","income tax","cci","trai","cbi","police","arrest","court notice","cbdt","customs","ita","enforcement directorate","ed officer","dgci"] },
  { type:"lottery_scam",        weight:3, keywords:["lottery","winner","prize money","lucky draw","congratulations","claim prize","reward","you have won","jackpot","kbc","kaun banega"] },
  { type:"fake_ecommerce",      weight:3, keywords:["flipkart","amazon","meesho","olx","quikr","seller","buyer","product not delivered","fake order","cashback fraud","return fraud","refund"] },
  { type:"courier_scam",        weight:3, keywords:["courier","fedex","dhl","parcel","customs duty","package held","delivery failed","narcotics","drug parcel","seized","arrested for parcel"] },
  { type:"electricity_scam",    weight:3, keywords:["electricity","power cut","meter","bijli","bescom","msedcl","bill pending","disconnect","lineman","je call","npcl","cesc","tneb"] },
  { type:"vishing",             weight:2, keywords:["phone call","called me","caller","voice call","received call","he told","she said","spoke to","he asked me to"] },
  { type:"smishing",            weight:2, keywords:["sms","message","text message","received sms","link in message","whatsapp link","message link"] },
  { type:"phishing",            weight:2, keywords:["link","website","login","password","click here","verify account","email","fake site","credentials","username password"] },
  { type:"police_impersonation",weight:3, keywords:["police","inspector","constable","arrest warrant","digital arrest","cybercrime officer","fir","bail","station"] },
  { type:"aadhaar_fraud",       weight:3, keywords:["aadhaar otp","update aadhaar","aadhaar kyc","uid update","aadhaar biometric","virtual id","aadhaar link mobile","aadhaar verification"] },
  { type:"sim_swap",            weight:3, keywords:["sim swap","new sim","port request","number porting","sim upgrade","duplicate sim","sim blocked","operator called"] },
  { type:"cyber_bullying",      weight:2, keywords:["harass","threatening","abuse online","fake profile","morphed photo","viral photo","social media abuse","stalking","doxing"] },
  { type:"online_gaming_fraud", weight:2, keywords:["gaming","rummy","dream11","fantasy","ludo earn","pubg hack","free fire","chess earn","gaming wallet"] },
  { type:"insurance_fraud",     weight:2, keywords:["insurance","policy","claim","premium","fake agent","lic","term plan","health insurance refund","insurance company called"] },
  { type:"tech_support_scam",   weight:3, keywords:["microsoft called","windows virus","remote access","anydesk","teamviewer","tech support","your computer hacked","call toll free","popup warning"] },
];

// ── IOC extraction — ENHANCED ─────────────────────────────────
function extractIOCsFromComplaint(text) {
  const t = text || "";
  return {
    urls:         (t.match(/https?:\/\/[^\s<>"]+/gi)    || []).map(u => u.trim()).slice(0,10),
    phones:       (t.match(/(?:\+91[-\s]?)?[6-9]\d{9}/g) || []).map(p => p.replace(/[\s-]/g,"")).slice(0,10),
    emails:       (t.match(/[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/gi) || []).slice(0,10),
    upiIds:       (t.match(/[a-zA-Z0-9.\-_]{2,256}@(?:okaxis|okicici|okhdfcbank|oksbi|ybl|ibl|axl|paytm|okbizaxis|[a-zA-Z]{2,20})/g) || []).slice(0,10),
    bankAccounts: (t.match(/\b\d{9,18}\b/g) || []).filter(n => n.length >= 9).slice(0,5),
    domains:      (t.match(/(?:www\.)?[a-zA-Z0-9\-]{2,63}\.[a-zA-Z]{2,10}(?:\/[^\s]*)?/g) || []).filter(d => !d.includes("@") && !d.startsWith("0")).slice(0,10),
    ips:          (t.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || []).filter(ip => !ip.startsWith("0")).slice(0,5),
    walletAddrs:  (t.match(/\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b|\b0x[a-fA-F0-9]{40}\b|\b[a-z0-9]{32,60}\.near\b/g) || []).slice(0,5),
    aadhaarNums:  (t.match(/\b[2-9]\d{3}\s?\d{4}\s?\d{4}\b/g) || []).slice(0,3),
    panNums:      (t.match(/\b[A-Z]{5}[0-9]{4}[A-Z]\b/g) || []).slice(0,3),
    imeiNums:     (t.match(/\b\d{15,16}\b/g) || []).slice(0,3),
  };
}

// ── Classify fraud — returns type + confidence + all matches ──
function classifyFraud(description) {
  const text = (description || "").toLowerCase();
  const scores = {};
  for (const cls of FRAUD_CLASSIFIERS) {
    const hits = cls.keywords.filter(k => text.includes(k)).length;
    if (hits > 0) scores[cls.type] = (hits * cls.weight);
  }
  if (Object.keys(scores).length === 0) return { type:"other", confidence:0, tags:[], allMatches:[] };
  const sorted = Object.entries(scores).sort((a,b) => b[1]-a[1]);
  const topType = sorted[0][0];
  const totalHits = sorted[0][1];
  const confidence = Math.min(Math.round((totalHits / 5) * 100), 97);
  const tags = sorted.slice(0,4).map(([t]) => t);
  const allMatches = sorted.map(([type, score]) => ({ type, score }));
  return { type:topType, confidence, tags, allMatches };
}

// ── Severity score (0-100) based on multiple signals ─────────
function calcSeverityScore(amountLost, fraudType, iocs, classification) {
  let score = 0;
  // Amount lost contribution (up to 40 points)
  if (amountLost >= 1000000) score += 40;       // 10 lakh+
  else if (amountLost >= 500000) score += 35;   // 5 lakh+
  else if (amountLost >= 100000) score += 28;   // 1 lakh+
  else if (amountLost >= 50000) score += 22;
  else if (amountLost >= 10000) score += 15;
  else if (amountLost > 0) score += 8;

  // Fraud type severity contribution (up to 30 points)
  const typeScore = {
    ransomware:30, sextortion:28, police_impersonation:26, sim_swap:24,
    bank_fraud:22, aadhaar_fraud:22, investment_scam:20, upi_fraud:18,
    govt_impersonation:18, courier_scam:16, phishing:14, vishing:14,
  };
  score += typeScore[fraudType] || 10;

  // IOC density (up to 20 points)
  const iocCount = (iocs.phones?.length||0) + (iocs.upiIds?.length||0) + (iocs.urls?.length||0) + (iocs.emails?.length||0);
  score += Math.min(iocCount * 4, 20);

  // Classification confidence contribution (up to 10 points)
  score += Math.round((classification?.confidence || 0) / 10);

  return Math.min(Math.round(score), 100);
}

// ── Priority ──────────────────────────────────────────────────
function calcPriority(amountLost, fraudType, iocs) {
  if (["ransomware","sextortion","sim_swap","police_impersonation","aadhaar_fraud"].includes(fraudType)) return "critical";
  if (amountLost >= 500000) return "critical";
  if (amountLost >= 100000) return "high";
  if (amountLost >= 10000)  return "medium";
  if (iocs?.phones?.length > 0 || iocs?.upiIds?.length > 0 || iocs?.walletAddrs?.length > 0) return "medium";
  return "low";
}

// ── SLA hours by priority ─────────────────────────────────────
function calcSlaHours(priority) {
  return { critical:6, high:24, medium:72, low:168 }[priority] || 72;
}

// ── MITRE mapping — EXPANDED ──────────────────────────────────
const MITRE_MAP = {
  upi_fraud:            "T1660 - Phishing via Financial Platform",
  bank_fraud:           "T1556 - Modify Authentication Process",
  investment_scam:      "T1566 - Phishing (Financial Fraud)",
  job_scam:             "T1566.003 - Spearphishing via Service",
  romance_scam:         "T1566 - Phishing (Social Engineering)",
  sextortion:           "T1534 - Internal Spearphishing",
  ransomware:           "T1486 - Data Encrypted for Impact",
  govt_impersonation:   "T1036.005 - Masquerading: Match Legitimate Name",
  phishing:             "T1566.002 - Spearphishing Link",
  police_impersonation: "T1036 - Masquerading (Authority Impersonation)",
  aadhaar_fraud:        "T1078 - Valid Accounts (Identity Theft)",
  sim_swap:             "T1556 - Modify Authentication (SIM Swap)",
  courier_scam:         "T1566 - Phishing (Parcel Scam)",
  electricity_scam:     "T1566 - Phishing (Utility Fraud)",
  lottery_scam:         "T1566 - Phishing (Advance Fee Fraud)",
  vishing:              "T1566.004 - Spearphishing via Voice",
  smishing:             "T1566.001 - Spearphishing via SMS",
  tech_support_scam:    "T1219 - Remote Access Software (Fraud)",
  online_gaming_fraud:  "T1566 - Phishing (Gaming Platform)",
  insurance_fraud:      "T1566 - Phishing (Insurance Scam)",
};

// ── Generate NCRP complaint draft — ENHANCED ─────────────────
function generateNCRPDraft(complaint) {
  const dateStr   = new Date(complaint.incidentDate).toLocaleDateString("en-IN");
  const reportStr = new Date(complaint.reportedAt || complaint.createdAt).toLocaleDateString("en-IN");
  const iocs      = complaint.iocs || {};
  const sev       = complaint.severityScore || 0;
  const sevLabel  = sev >= 80 ? "CRITICAL" : sev >= 60 ? "HIGH" : sev >= 40 ? "MEDIUM" : "LOW";

  const lines = [
    `╔══════════════════════════════════════════════════════╗`,
    `║         CYBERCRIME COMPLAINT REPORT                  ║`,
    `║    Generated by PhishNetra AI Intelligence           ║`,
    `╚══════════════════════════════════════════════════════╝`,
    ``,
    `Reference No : ${complaint.complaintId}`,
    `Report Date  : ${reportStr}`,
    `Severity     : ${sevLabel} (Score: ${sev}/100)`,
    `Priority     : ${(complaint.priority||"medium").toUpperCase()}`,
    `SLA Deadline : ${complaint.slaDeadlineHours || 72} hours from report date`,
    ``,
    `━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`,
    `COMPLAINANT INFORMATION`,
    `━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`,
    `Name    : ${complaint.victimName || "Anonymous"}`,
    `Contact : ${complaint.victimContact || "Not provided"}`,
    `State   : ${complaint.victimState  || "Not specified"}`,
    `City    : ${complaint.victimCity   || "Not specified"}`,
    ``,
    `━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`,
    `INCIDENT DETAILS`,
    `━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`,
    `Incident Date    : ${dateStr}`,
    `Fraud Category   : ${(complaint.fraudType||"other").replace(/_/g," ").toUpperCase()}`,
    `Amount Lost      : ${complaint.currency || "INR"} ${(complaint.amountLost||0).toLocaleString("en-IN")}`,
    `Payment Method   : ${(complaint.paymentMethod||"unknown").toUpperCase()}`,
    `Classification % : ${complaint.classificationConfidence || 0}% AI confidence`,
    `MITRE ATT&CK     : ${complaint.mitre || "T1566 - Phishing"}`,
    ``,
    `━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`,
    `COMPLAINT DESCRIPTION`,
    `━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`,
    complaint.description,
    ``,
    `━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`,
    `EXTRACTED DIGITAL EVIDENCE (for investigation)`,
    `━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`,
    iocs.upiIds?.length      ? `UPI IDs          : ${iocs.upiIds.join(", ")}` : "",
    iocs.phones?.length      ? `Phone Numbers    : ${iocs.phones.join(", ")}` : "",
    iocs.emails?.length      ? `Email Addresses  : ${iocs.emails.join(", ")}` : "",
    iocs.urls?.length        ? `URLs/Websites    : ${iocs.urls.join(", ")}` : "",
    iocs.bankAccounts?.length? `Bank Accounts    : ${iocs.bankAccounts.join(", ")}` : "",
    iocs.walletAddrs?.length ? `Crypto Wallets   : ${iocs.walletAddrs.join(", ")}` : "",
    iocs.aadhaarNums?.length ? `Aadhaar Numbers  : [REDACTED - share only with LEA]` : "",
    iocs.panNums?.length     ? `PAN Numbers      : [REDACTED - share only with LEA]` : "",
    iocs.domains?.length     ? `Domains          : ${iocs.domains.slice(0,5).join(", ")}` : "",
    iocs.ips?.length         ? `IP Addresses     : ${iocs.ips.join(", ")}` : "",
    ``,
    complaint.linkedComplaints?.length > 0
      ? `Linked Complaints: ${complaint.linkedComplaints.join(", ")} (same IOCs)`
      : "",
    ``,
    `━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`,
    `IMMEDIATE ACTION STEPS`,
    `━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`,
    `1. File at: https://cybercrime.gov.in`,
    `2. Call National Cyber Crime Helpline: 1930 (24/7)`,
    `3. Freeze suspicious accounts: Contact your bank immediately`,
    `4. Preserve evidence: Do NOT delete messages/calls`,
    `5. State police cyber cell: cybercrime.gov.in/state-portals`,
    ``,
    `━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`,
    `Auto-generated by PhishNetra AI Intelligence Platform`,
    `Review extracted IOCs before submission to law enforcement.`,
    `Case ID: ${complaint.complaintId} | Platform: PhishNetra v3.0`,
  ].filter(l => l !== null && l !== undefined);
  return lines.join("\n");
}

// ── Related complaint finder — ENHANCED ──────────────────────
async function findRelatedComplaints(iocs, excludeId) {
  const orClauses = [];
  if (iocs.upiIds?.length)      orClauses.push({ "iocs.upiIds":      { $in: iocs.upiIds } });
  if (iocs.phones?.length)      orClauses.push({ "iocs.phones":      { $in: iocs.phones } });
  if (iocs.emails?.length)      orClauses.push({ "iocs.emails":      { $in: iocs.emails } });
  if (iocs.domains?.length)     orClauses.push({ "iocs.domains":     { $in: iocs.domains } });
  if (iocs.bankAccounts?.length)orClauses.push({ "iocs.bankAccounts":{ $in: iocs.bankAccounts } });
  if (iocs.walletAddrs?.length) orClauses.push({ "iocs.walletAddrs": { $in: iocs.walletAddrs } });
  if (!orClauses.length) return [];
  return Complaint.find({ $or: orClauses, _id: { $ne: excludeId } })
    .select("complaintId fraudType amountLost status victimCity incidentDate priority severityScore")
    .sort({ severityScore: -1 })
    .limit(15).lean();
}

// ── Stats ─────────────────────────────────────────────────────
async function getComplaintStats() {
  const since30d = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
  const since7d  = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
  const [total, byType, byStatus, amountStats, recent30d, recent7d, byPriority, topStates] = await Promise.all([
    Complaint.countDocuments({}),
    Complaint.aggregate([{ $group: { _id:"$fraudType", count:{$sum:1}, totalLost:{$sum:"$amountLost"}, avgSeverity:{$avg:"$severityScore"} } }, { $sort:{count:-1} }, { $limit:15 }]),
    Complaint.aggregate([{ $group: { _id:"$status", count:{$sum:1} } }]),
    Complaint.aggregate([{ $group: { _id:null, totalLost:{$sum:"$amountLost"}, avgLost:{$avg:"$amountLost"}, maxLost:{$max:"$amountLost"}, totalCases:{$sum:1} } }]),
    Complaint.countDocuments({ createdAt:{ $gte:since30d } }),
    Complaint.countDocuments({ createdAt:{ $gte:since7d } }),
    Complaint.aggregate([{ $group: { _id:"$priority", count:{$sum:1} } }]),
    Complaint.aggregate([{ $match:{ victimState:{ $ne:null } } }, { $group:{ _id:"$victimState", count:{$sum:1}, totalLost:{$sum:"$amountLost"} } }, { $sort:{count:-1} }, { $limit:10 }]),
  ]);
  return {
    total, recent30d, recent7d,
    byType:     byType.map(t => ({ type:t._id, count:t.count, totalLost:t.totalLost, avgSeverity:Math.round(t.avgSeverity||0) })),
    byStatus:   Object.fromEntries(byStatus.map(s => [s._id, s.count])),
    byPriority: Object.fromEntries(byPriority.map(p => [p._id, p.count])),
    topStates:  topStates.map(s => ({ state:s._id, count:s.count, totalLost:s.totalLost })),
    financial:  amountStats[0] || { totalLost:0, avgLost:0, maxLost:0, totalCases:0 },
  };
}

module.exports = {
  Complaint,
  classifyFraud,
  extractIOCsFromComplaint,
  calcPriority,
  calcSeverityScore,
  calcSlaHours,
  MITRE_MAP,
  generateNCRPDraft,
  findRelatedComplaints,
  getComplaintStats,
};
