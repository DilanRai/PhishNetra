// ════════════════════════════════════════════════════════════════
// FILE: backend/services/incidentResponseEngine.js — CREATE NEW
// Automated Incident Response Platform
// Real-world use: When a phishing/ransomware incident fires, this
// engine auto-generates a structured IR playbook, assigns tasks to
// analysts based on role, tracks containment steps, and provides
// a full timeline for post-incident review.
// ════════════════════════════════════════════════════════════════
"use strict";
const mongoose = require("mongoose");
const crypto   = require("crypto");
 
// ── Incident Schema ───────────────────────────────────────────
const IncidentSchema = new mongoose.Schema({
  incidentId: {
    type: String,
    default: () => `INC-${Date.now().toString(36).toUpperCase()}`,
    unique: true, index: true,
  },
  title:       { type: String, required: true },
  description: { type: String, default: "" },
  severity:    { type: Number, enum:[1,2,3,4,5], required: true },
  category:    {
    type: String,
    enum:["phishing","ransomware","bec","data_breach","account_takeover",
          "malware","insider_threat","ddos","supply_chain","other"],
    required: true,
  },
  status: {
    type: String,
    enum:["detected","triage","containment","eradication","recovery","post_incident","closed"],
    default:"detected", index:true,
  },
  // Source — what triggered this incident
  sourceType:  { type: String, enum:["siem_alert","complaint","manual","scan","log"], default:"manual" },
  sourceId:    { type: String, default: null },
  alertId:     { type: String, default: null },
 
  // Scope
  affectedAssets:  { type: [String], default:[] },
  affectedUsers:   { type: [String], default:[] },
  affectedSystems: { type: [String], default:[] },
  iocs:            { type: mongoose.Schema.Types.Mixed, default:{} },
 
  // Playbook steps — auto-generated based on category
  playbook: [{
    stepId:      { type: String },
    phase:       { type: String, enum:["detection","triage","containment","eradication","recovery","lessons_learned"] },
    title:       { type: String },
    description: { type: String },
    role:        { type: String, enum:["admin","analyst","viewer","all"], default:"analyst" },
    priority:    { type: String, enum:["immediate","high","medium","low"], default:"high" },
    status:      { type: String, enum:["pending","in_progress","done","skipped"], default:"pending" },
    completedBy: { type: String, default: null },
    completedAt: { type: Date,   default: null },
    notes:       { type: String, default: "" },
    automated:   { type: Boolean, default: false },
    automationResult: { type: String, default: null },
  }],
 
  // Timeline (every action logged)
  timeline: [{
    ts:      { type: Date, default: Date.now },
    action:  { type: String },
    by:      { type: String, default: "system" },
    detail:  { type: String, default: "" },
    phase:   { type: String, default: "detection" },
  }],
 
  // Assignment
  leadAnalyst:  { type: String, default: null },
  assignedTeam: { type: [String], default:[] },
 
  // Metrics
  detectedAt:    { type: Date, default: Date.now },
  containedAt:   { type: Date, default: null },
  resolvedAt:    { type: Date, default: null },
  mttr:          { type: Number, default: null }, // minutes to resolve
  mttc:          { type: Number, default: null }, // minutes to contain
 
  // MITRE ATT&CK
  mitreTactics:    { type: [String], default:[] },
  mitreTechniques: { type: [String], default:[] },
 
  // Evidence links
  evidenceIds: { type: [String], default:[] },
  complaintId: { type: String, default: null },
 
  createdAt: { type: Date, default: Date.now },
}, { timestamps: true });
 
const Incident = mongoose.model("Incident", IncidentSchema);
 
// ── Playbook templates per incident category ──────────────────
const PLAYBOOKS = {
  phishing: [
    { phase:"detection",    title:"Confirm phishing verdict",         description:"Verify URL/email analysis results. Check PhishNetra score ≥70. Confirm SIEM alert is not false positive.", role:"analyst", priority:"immediate" },
    { phase:"triage",       title:"Identify affected users",          description:"Check email logs for all recipients of the phishing email. Cross-reference with active sessions.", role:"analyst", priority:"immediate" },
    { phase:"triage",       title:"Assess credential exposure",       description:"Check if any user clicked the link or submitted credentials via URL preview form detection.", role:"analyst", priority:"immediate" },
    { phase:"containment",  title:"Block phishing URL at gateway",    description:"Add domain/URL to web proxy blocklist. Push IOC to email gateway. Block sender domain.", role:"admin", priority:"immediate" },
    { phase:"containment",  title:"Force password reset if clicked",  description:"For any user who clicked the phishing link, force an immediate password reset and terminate active sessions.", role:"admin", priority:"high" },
    { phase:"containment",  title:"Enable MFA on affected accounts",  description:"Ensure all potentially compromised accounts have MFA enabled before allowing login.", role:"admin", priority:"high" },
    { phase:"eradication",  title:"Remove phishing emails",           description:"Purge phishing email from all user mailboxes. Check archived and sent items.", role:"admin", priority:"high" },
    { phase:"eradication",  title:"Submit URL to takedown service",   description:"Submit phishing URL to Google Safe Browsing, PhishTank, and hosting provider abuse team.", role:"analyst", priority:"medium" },
    { phase:"recovery",     title:"Monitor affected accounts 72h",    description:"Watch for unusual login patterns, forwarding rules, or data access on potentially compromised accounts.", role:"analyst", priority:"medium" },
    { phase:"lessons_learned","title":"Update detection rules",       description:"Add phishing indicators to custom SIEM rules. Update email filter signatures. Document in IOC database.", role:"analyst", priority:"low" },
  ],
  ransomware: [
    { phase:"detection",    title:"ISOLATE IMMEDIATELY — Do not delay", description:"⚠ CRITICAL: Immediately isolate affected systems from network. Pull ethernet. Disable WiFi. Do NOT shut down (preserves memory for forensics).", role:"admin", priority:"immediate" },
    { phase:"detection",    title:"Identify ransomware family",         description:"Note ransom note filename, extension (.locked/.encrypted/.WNCRY etc), check ransomware.live and ID Ransomware to identify family.", role:"analyst", priority:"immediate" },
    { phase:"triage",       title:"Map blast radius",                   description:"Identify all networked drives, NAS, backups affected. Check Active Directory for lateral movement signs.", role:"analyst", priority:"immediate" },
    { phase:"triage",       title:"Check backup integrity",             description:"Verify offline/cloud backups are NOT encrypted. Confirm backup dates. DO NOT connect backup drives to infected systems.", role:"admin", priority:"immediate" },
    { phase:"containment",  title:"Disable network shares",             description:"Disable all SMB shares, mapped drives, and cloud sync clients on the network segment.", role:"admin", priority:"immediate" },
    { phase:"containment",  title:"Preserve memory dump",               description:"Take a memory dump of affected systems before any shutdown. Use WinPmem or Magnet RAM Capture.", role:"analyst", priority:"high" },
    { phase:"containment",  title:"Notify law enforcement",             description:"File report at CyberCrime.gov.in, call 1930. For corporate: notify CERT-In within 6 hours (mandatory under IT Act).", role:"admin", priority:"high" },
    { phase:"eradication",  title:"DO NOT PAY RANSOM",                  description:"Paying ransom does not guarantee file recovery and funds criminal operations. Explore decryptors at nomoreransom.org first.", role:"admin", priority:"immediate" },
    { phase:"eradication",  title:"Wipe and rebuild from clean backup", description:"Reimage affected systems. Restore from pre-infection backup. Verify backup integrity before restore.", role:"admin", priority:"high" },
    { phase:"recovery",     title:"Patch initial attack vector",        description:"Identify entry point (phishing email, exposed RDP, unpatched software). Patch before reconnecting to network.", role:"admin", priority:"high" },
    { phase:"lessons_learned","title":"Deploy ransomware early warning", description:"Enable PhishNetra Ransomware Early Warning module. Configure honeypot files on all network shares.", role:"admin", priority:"medium" },
  ],
  bec: [
    { phase:"detection",    title:"Verify email authenticity",         description:"Check SPF/DKIM/DMARC headers. Verify sender domain vs display name. Check Reply-To field for mismatch. Use email header analyser.", role:"analyst", priority:"immediate" },
    { phase:"triage",       title:"Contact requester out-of-band",     description:"Call the alleged sender on a known/trusted phone number to verify the request. Do NOT reply to the suspicious email.", role:"analyst", priority:"immediate" },
    { phase:"triage",       title:"Trace email routing path",          description:"Examine full email headers to identify original sending server. Map IP hops and check against threat intel.", role:"analyst", priority:"high" },
    { phase:"containment",  title:"Stop any pending transaction",      description:"Contact your bank/payment processor immediately to recall the wire transfer. Act within 24 hours — after that recovery is unlikely.", role:"admin", priority:"immediate" },
    { phase:"containment",  title:"Check for email forwarding rules",  description:"Inspect mailbox for attacker-created forwarding rules that silently redirect emails to external addresses.", role:"analyst", priority:"high" },
    { phase:"containment",  title:"Block sender domain at gateway",    description:"Add sender domain and IP to email gateway blocklist. Enable DMARC reject policy if not already active.", role:"admin", priority:"high" },
    { phase:"eradication",  title:"Reset compromised mailbox",         description:"If mailbox was compromised, reset password, revoke all active sessions, remove suspicious rules and delegates.", role:"admin", priority:"high" },
    { phase:"eradication",  title:"Audit all mail rules and delegates",description:"Check ALL accounts for unauthorized forwarding, delegates, or auto-reply rules. Export rules list for evidence.", role:"analyst", priority:"high" },
    { phase:"recovery",     title:"File bank fraud complaint",         description:"File complaint with bank, RBI (if Indian bank), and CyberCrime.gov.in. Provide transaction ID and beneficiary account. Call 1930.", role:"admin", priority:"high" },
    { phase:"lessons_learned","title":"Implement payment verification protocol",description:"Establish mandatory out-of-band voice verification for all wire transfers above threshold. Enable dual approval.", role:"admin", priority:"medium" },
  ],
  account_takeover: [
    { phase:"detection",    title:"Confirm unauthorized access",   description:"Check login logs for unusual geolocation, new device, or impossible travel. Correlate with PhishNetra AiTM alerts.", role:"analyst", priority:"immediate" },
    { phase:"triage",       title:"Determine access scope",        description:"What data/systems did the attacker access? List all resources touched during unauthorized session.", role:"analyst", priority:"immediate" },
    { phase:"containment",  title:"Terminate all sessions",        description:"Force sign-out of all active sessions for the compromised account across all devices.", role:"admin", priority:"immediate" },
    { phase:"containment",  title:"Reset credentials and MFA",     description:"Reset password. Reset MFA (check for attacker-registered MFA device). Verify recovery email/phone not changed.", role:"admin", priority:"immediate" },
    { phase:"eradication",  title:"Audit account changes",         description:"Review all changes made during unauthorized access: data accessed, emails sent, settings changed, forwarding rules.", role:"analyst", priority:"high" },
    { phase:"eradication",  title:"Revoke all OAuth tokens",       description:"Revoke all third-party app authorizations. Check for suspicious connected apps the attacker may have authorized.", role:"admin", priority:"high" },
    { phase:"recovery",     title:"Notify affected parties",       description:"If attacker sent emails from compromised account, notify all recipients. Offer to provide security advisory.", role:"analyst", priority:"medium" },
    { phase:"lessons_learned","title":"Enforce MFA across all accounts",description:"Mandate MFA for all user accounts. Implement risk-based authentication. Consider passwordless login.", role:"admin", priority:"medium" },
  ],
  data_breach: [
    { phase:"detection",    title:"Identify breach scope",         description:"Determine which systems, databases, and data types were accessed. Check SIEM for unusual data access patterns.", role:"analyst", priority:"immediate" },
    { phase:"detection",    title:"Preserve evidence immediately", description:"Take snapshots of affected systems. Capture network traffic if still active. Do NOT wipe systems before forensics.", role:"analyst", priority:"immediate" },
    { phase:"triage",       title:"Classify data sensitivity",     description:"Identify if PII, financial, health (HIPAA), or payment (PCI) data was exposed. Determines legal notification requirements.", role:"analyst", priority:"immediate" },
    { phase:"containment",  title:"Revoke exposed credentials",    description:"Immediately rotate all API keys, DB passwords, service accounts that may have been compromised.", role:"admin", priority:"immediate" },
    { phase:"containment",  title:"Isolate affected systems",      description:"Take affected database servers/services offline or into read-only mode. Redirect traffic to clean instances.", role:"admin", priority:"immediate" },
    { phase:"eradication",  title:"Patch root cause vulnerability", description:"Identify and patch the initial attack vector (SQL injection, misconfigured S3, leaked credentials, unpatched CVE).", role:"admin", priority:"high" },
    { phase:"recovery",     title:"Notify CERT-In within 6 hours", description:"For Indian organizations: mandatory notification to CERT-In under IT (Amendment) Act within 6 hours. File at cert-in.org.in.", role:"admin", priority:"immediate" },
    { phase:"recovery",     title:"Notify affected users",         description:"Draft breach notification email. Include: what happened, data affected, actions taken, what users should do.", role:"admin", priority:"high" },
    { phase:"lessons_learned","title":"Implement data loss prevention",description:"Deploy DLP tools. Implement database activity monitoring. Enforce column-level encryption for PII.", role:"admin", priority:"medium" },
  ],
  ddos: [
    { phase:"detection",    title:"Confirm attack type",           description:"Identify DDoS type: volumetric (UDP/ICMP flood), protocol (SYN flood), or application layer (HTTP flood). Check traffic dashboards.", role:"analyst", priority:"immediate" },
    { phase:"triage",       title:"Measure impact scope",          description:"Determine affected services, estimated traffic volume (Gbps/Mpps), and source IP distribution.", role:"analyst", priority:"immediate" },
    { phase:"containment",  title:"Activate DDoS scrubbing",       description:"Enable CDN DDoS protection (Cloudflare/AWS Shield/Akamai). Route traffic through scrubbing center. Increase upstream bandwidth.", role:"admin", priority:"immediate" },
    { phase:"containment",  title:"Null-route attacking IPs",      description:"Block top attack source IPs at border router. Contact upstream ISP for black hole routing of attack traffic.", role:"admin", priority:"immediate" },
    { phase:"containment",  title:"Rate-limit at application",     description:"Enable rate limiting on web server/API gateway. Block suspicious user agents and referer patterns.", role:"admin", priority:"high" },
    { phase:"eradication",  title:"Identify attack orchestration", description:"Check if DDoS is from botnet (single ASN) or distributed. Report C2 IPs to ISP abuse teams.", role:"analyst", priority:"medium" },
    { phase:"recovery",     title:"Restore services gradually",    description:"Restore services in staged manner. Monitor traffic for attack resumption. Keep scrubbing active for 24h after attack stops.", role:"admin", priority:"high" },
    { phase:"lessons_learned","title":"Deploy permanent DDoS protection",description:"Implement always-on DDoS protection via CDN. Configure anycast routing. Prepare runbook for future attacks.", role:"admin", priority:"medium" },
  ],
  insider_threat: [
    { phase:"detection",    title:"Preserve all digital evidence", description:"Immediately preserve: email logs, file access logs, badge access, CCTV, print logs. Do NOT alert the suspect.", role:"admin", priority:"immediate" },
    { phase:"detection",    title:"Establish timeline of activity",description:"Build chronological timeline of suspected malicious activity from available logs.", role:"analyst", priority:"immediate" },
    { phase:"triage",       title:"Assess data exfiltration scope", description:"Check DLP alerts, USB activity, email attachments sent externally, cloud upload logs for data theft evidence.", role:"analyst", priority:"immediate" },
    { phase:"containment",  title:"Restrict access silently",      description:"Reduce permissions silently (do not alert suspect). Revoke remote access first. Coordinate with HR/Legal before any overt action.", role:"admin", priority:"high" },
    { phase:"containment",  title:"Monitor remaining access",      description:"Deploy enhanced monitoring on suspect's remaining access points. Capture all activity for evidence.", role:"admin", priority:"high" },
    { phase:"eradication",  title:"Legal/HR escalation",           description:"Escalate to HR and Legal with evidence package. Follow your organization's disciplinary/termination procedure.", role:"admin", priority:"high" },
    { phase:"recovery",     title:"Revoke all access upon confirmation",description:"Upon legal clearance, revoke all credentials, physical access, VPN tokens. Perform account audit.", role:"admin", priority:"immediate" },
    { phase:"lessons_learned","title":"Implement user behavior analytics",description:"Deploy UEBA solution. Implement least-privilege access. Schedule periodic access reviews.", role:"admin", priority:"medium" },
  ],
  supply_chain: [
    { phase:"detection",    title:"Identify compromised component",description:"Determine which third-party library, vendor, or software supply chain element is compromised.", role:"analyst", priority:"immediate" },
    { phase:"triage",       title:"Map blast radius",              description:"Identify all systems/services using the compromised component. Create dependency map.", role:"analyst", priority:"immediate" },
    { phase:"containment",  title:"Isolate affected systems",      description:"Take systems using compromised dependency offline or into isolated network segment.", role:"admin", priority:"immediate" },
    { phase:"containment",  title:"Pin to known-good version",     description:"Pin all dependencies to last known-good version. Disable auto-update mechanisms temporarily.", role:"admin", priority:"immediate" },
    { phase:"eradication",  title:"Rebuild from clean source",     description:"Rebuild affected systems from clean base images. Do not restore from potentially contaminated backups.", role:"admin", priority:"high" },
    { phase:"recovery",     title:"Verify integrity of all packages",description:"Run SHA256 verification of all third-party packages. Compare against official checksums.", role:"analyst", priority:"high" },
    { phase:"lessons_learned","title":"Implement software composition analysis",description:"Deploy SCA tooling (Snyk/OWASP Dependency Check). Implement signed package verification in CI/CD.", role:"admin", priority:"medium" },
  ],
};
 
// ── Generate playbook for incident category ───────────────────
function generatePlaybook(category) {
  const template = PLAYBOOKS[category] || PLAYBOOKS.phishing;
  return template.map((step, i) => ({
    stepId:      `STEP-${String(i+1).padStart(3,"0")}`,
    ...step,
    status:      "pending",
    completedBy: null,
    completedAt: null,
    notes:       "",
    automated:   false,
    automationResult: null,
  }));
}
 
// ── Auto-create incident from SIEM alert ──────────────────────
async function createFromAlert(alert) {
  const categoryMap = {
    phishing:"phishing", bec:"bec", quishing:"phishing",
    account_takeover:"account_takeover", brute_force:"account_takeover",
    attachment:"malware", execution:"malware", exfiltration:"data_breach",
    lateral_movement:"insider_threat",
  };
  const category = categoryMap[alert.category] || "other";
  const incident = new Incident({
    title:       `${alert.title} — Auto-generated from SIEM`,
    description: alert.description || "",
    severity:    alert.severity || 3,
    category,
    sourceType:  "siem_alert",
    sourceId:    alert._id?.toString(),
    alertId:     alert.alertId,
    iocs:        alert.target || {},
    mitreTactics:    alert.mitre?.tactic    ? [alert.mitre.tactic]    : [],
    mitreTechniques: alert.mitre?.technique ? [alert.mitre.technique] : [],
    playbook:    generatePlaybook(category),
    timeline:    [{ action:"Incident auto-created from SIEM alert", by:"system", phase:"detection", detail:`Alert: ${alert.alertId} · Rule: ${alert.ruleId}` }],
  });
  return incident.save();
}
 
// ── Stats ─────────────────────────────────────────────────────
async function getIncidentStats() {
  const [total, open, byCategory, byStatus, mttrData] = await Promise.all([
    Incident.countDocuments({}),
    Incident.countDocuments({ status:{ $nin:["closed","post_incident"] } }),
    Incident.aggregate([{ $group:{ _id:"$category", count:{$sum:1} } }]),
    Incident.aggregate([{ $group:{ _id:"$status",   count:{$sum:1} } }]),
    Incident.aggregate([{ $match:{ mttr:{ $ne:null } } }, { $group:{ _id:null, avgMttr:{$avg:"$mttr"}, avgMttc:{$avg:"$mttc"} } }]),
  ]);
  return {
    total, open,
    byCategory: Object.fromEntries(byCategory.map(c => [c._id, c.count])),
    byStatus:   Object.fromEntries(byStatus.map(s => [s._id, s.count])),
    avgMttr:    Math.round(mttrData[0]?.avgMttr || 0),
    avgMttc:    Math.round(mttrData[0]?.avgMttc || 0),
  };
}
 
module.exports = { Incident, generatePlaybook, createFromAlert, getIncidentStats };