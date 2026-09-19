// FILE: backend/services/notifier.js
// Multi-channel alert notifications: Email + Slack + Discord

const nodemailer = require("nodemailer");
const axios = require("axios");

// ── Email transport ──
let emailTransport = null;
if (process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS) {
  emailTransport = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: parseInt(process.env.SMTP_PORT || "587"),
    secure: process.env.SMTP_SECURE === "true",
    auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
  });
}

// ── Severity label + emoji ──
const SEV = {
  5: { label: "CRITICAL", emoji: "🚨", color: "#ff4444" },
  4: { label: "HIGH", emoji: "🔴", color: "#f97316" },
  3: { label: "MEDIUM", emoji: "⚠️", color: "#f5a623" },
  2: { label: "LOW", emoji: "🔵", color: "#00d4ff" },
  1: { label: "INFO", emoji: "ℹ️", color: "#8b95a8" },
};

// ── Email alert ──
async function sendEmailAlert(alert) {
  if (!emailTransport || !process.env.ALERT_EMAIL) return false;
  const s = SEV[alert.severity] || SEV[3];
  try {
    await emailTransport.sendMail({
      from: `"PhishNetra SIEM" <${process.env.SMTP_USER}>`,
      to: process.env.ALERT_EMAIL,
      subject: `${s.emoji} [${s.label}] ${alert.title}`,
      html: `
        <div style="font-family:monospace;background:#080b10;color:#e8edf5;padding:24px;border-radius:12px;border:1px solid ${s.color}">
          <h2 style="color:${s.color};margin:0 0 16px">${s.emoji} ${alert.title}</h2>
          <p><strong style="color:#8b95a8">Severity:</strong> <span style="color:${s.color}">${s.label}</span></p>
          <p><strong style="color:#8b95a8">Rule:</strong> ${alert.ruleId}</p>
          <p><strong style="color:#8b95a8">Description:</strong> ${alert.description}</p>
          ${alert.mitre ? `<p><strong style="color:#8b95a8">MITRE:</strong> <span style="color:#a78bfa">${alert.mitre.technique}</span></p>` : ""}
          <p style="color:#4a5568;font-size:11px;margin-top:16px">PhishNetra AI v3.0 — SentinelCore SIEM · ${new Date().toLocaleString()}</p>
        </div>`,
    });
    return true;
  } catch (err) {
    console.error("Email notify error:", err.message);
    return false;
  }
}

// ── Slack webhook alert ──
async function sendSlackAlert(alert) {
  const webhookUrl = process.env.SLACK_WEBHOOK_URL;
  if (!webhookUrl) return false;
  const s = SEV[alert.severity] || SEV[3];
  try {
    await axios.post(webhookUrl, {
      text: `${s.emoji} *[${s.label}]* ${alert.title}`,
      attachments: [{
        color: s.color,
        fields: [
          { title: "Rule", value: alert.ruleId, short: true },
          { title: "Category", value: alert.category, short: true },
          { title: "Risk Score", value: `${alert.riskScore}/100`, short: true },
          { title: "Description", value: alert.description, short: false },
          ...(alert.mitre ? [{ title: "MITRE", value: alert.mitre.technique, short: false }] : []),
        ],
        footer: "PhishNetra SentinelCore SIEM",
        ts: Math.floor(Date.now() / 1000),
      }],
    }, { timeout: 5000 });
    return true;
  } catch (err) {
    console.error("Slack notify error:", err.message);
    return false;
  }
}

// ── Discord webhook alert ──
async function sendDiscordAlert(alert) {
  const webhookUrl = process.env.DISCORD_WEBHOOK_URL;
  if (!webhookUrl) return false;
  const s = SEV[alert.severity] || SEV[3];
  const colorInt = parseInt(s.color.replace("#", ""), 16);
  try {
    await axios.post(webhookUrl, {
      embeds: [{
        title: `${s.emoji} [${s.label}] ${alert.title}`,
        description: alert.description,
        color: colorInt,
        fields: [
          { name: "Rule ID", value: alert.ruleId, inline: true },
          { name: "Category", value: alert.category, inline: true },
          { name: "Risk Score", value: `${alert.riskScore}/100`, inline: true },
          ...(alert.mitre ? [{ name: "MITRE", value: alert.mitre.technique, inline: false }] : []),
        ],
        footer: { text: "PhishNetra SentinelCore SIEM" },
        timestamp: new Date().toISOString(),
      }],
    }, { timeout: 5000 });
    return true;
  } catch (err) {
    console.error("Discord notify error:", err.message);
    return false;
  }
}

// Check notification prefs before sending
async function shouldNotify(severity, channel) {
  try {
    const NotificationPrefs = require("../models/NotificationPrefs");
    // Get any user's prefs (for now, global check)
    const prefs = await NotificationPrefs.findOne().lean();
    if (!prefs) return true;

    const ch = prefs.channels?.[channel];
    if (ch && !ch.enabled) return false;
    if (ch && severity < ch.minSeverity) return false;

    // Quiet hours check
    if (prefs.quietHours?.enabled) {
      const hour  = new Date().getHours();
      const start = prefs.quietHours.start;
      const end   = prefs.quietHours.end;
      const inQuiet = start > end
        ? (hour >= start || hour < end)   // crosses midnight
        : (hour >= start && hour < end);
      if (inQuiet) return false;
    }
    return true;
  } catch { return true; }
}

// ── Master notify function ──
// Only fires for HIGH (4) and CRITICAL (5) by default
async function notifyAlert(alert) {
  if (!alert || alert.severity < 4) return;
  const [doEmail, doSlack, doDiscord] = await Promise.all([
    shouldNotify(alert.severity, "email"),
    shouldNotify(alert.severity, "slack"),
    shouldNotify(alert.severity, "discord"),
  ]);
  const tasks = [];
  if (doEmail)   tasks.push(sendEmailAlert(alert));
  if (doSlack)   tasks.push(sendSlackAlert(alert));
  if (doDiscord) tasks.push(sendDiscordAlert(alert));
  if (tasks.length === 0) return;
  const results = await Promise.allSettled(tasks);
  const sent    = results.filter(r => r.status === "fulfilled" && r.value === true).length;
  if (sent > 0) console.log(`📣 Alert notified via ${sent} channel(s): ${alert.title}`);
}

module.exports = { notifyAlert, sendEmailAlert, sendSlackAlert, sendDiscordAlert };