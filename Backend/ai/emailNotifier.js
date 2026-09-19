// FILE: backend/ai/emailNotifier.js

const nodemailer = require("nodemailer");

// Only sends if SMTP env vars are configured
const isConfigured = !!(
  process.env.SMTP_HOST &&
  process.env.SMTP_USER &&
  process.env.SMTP_PASS &&
  process.env.ALERT_EMAIL
);

let transporter = null;
if (isConfigured) {
  transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: parseInt(process.env.SMTP_PORT || "587"),
    secure: process.env.SMTP_SECURE === "true",
    auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
  });
  console.log("📧 Email notifier: configured");
} else {
  console.log(
    "ℹ️  Email notifier: SMTP not configured — add SMTP_HOST/SMTP_USER/SMTP_PASS/ALERT_EMAIL to .env",
  );
}

async function sendCriticalAlert({
  status,
  riskScore,
  input,
  issues = [],
  dna = null,
}) {
  if (!isConfigured || !transporter) return false;
  try {
    const safeInput = typeof input === "string" ? input : "";
    const subject = `🚨 PhishNetra AI CRITICAL — ${status.toUpperCase()} Detected (${riskScore}/100)`;
    const html = `
      <div style="font-family:monospace;background:#080b10;color:#e8edf5;padding:24px;border-radius:12px">
        <h2 style="color:#ff4444;margin:0 0 16px">🚨 CRITICAL THREAT DETECTED</h2>
        <p><strong style="color:#8b95a8">Status:</strong>
           <span style="color:#ff4444;font-weight:700">${status.toUpperCase()}</span></p>
        <p><strong style="color:#8b95a8">Risk Score:</strong>
           <span style="color:#ff4444">${riskScore}/100</span></p>
        <p><strong style="color:#8b95a8">Input:</strong>
            <code style="color:#00d4ff">${safeInput.substring(0, 100)}</code></p>
        ${
          dna
            ? `<p><strong style="color:#8b95a8">PhishDNA:</strong>
           <span style="color:#a78bfa">#${dna.fingerprint} — ${dna.technique?.replace(/_/g, " ")}</span></p>`
            : ""
        }
        <hr style="border-color:#1e2736;margin:16px 0"/>
        <p style="color:#8b95a8;font-size:12px"><strong>Detected Issues:</strong></p>
        <ul style="color:#e8edf5;font-size:12px">
          ${issues
            .slice(0, 5)
            .map((i) => `<li>${i}</li>`)
            .join("")}
        </ul>
        <hr style="border-color:#1e2736;margin:16px 0"/>
        <p style="color:#4a5568;font-size:11px">PhishNetra AI v3.0 — SentinelCore SIEM</p>
      </div>
    `;
    await transporter.sendMail({
      from: `"PhishNetra AI" <${process.env.SMTP_USER}>`,
      to: process.env.ALERT_EMAIL,
      subject,
      html,
    });
    console.log(`📧 Critical alert email sent → ${process.env.ALERT_EMAIL}`);
    return true;
  } catch (err) {
    console.error("Email send error:", err.message);
    return false;
  }
}

async function sendWeeklyDigest(statsData) {
  if (!isConfigured || !transporter) return false;
  try {
    const {
      total,
      phishing,
      suspicious,
      safe,
      topBrands,
      topTechniques,
      mttd,
      mttr,
      period,
    } = statsData;
    const threatRate = total > 0 ? Math.round((phishing / total) * 100) : 0;

    const html = `
      <div style="font-family:monospace;background:#080b10;color:#e8edf5;padding:28px;border-radius:14px;max-width:600px">
        <div style="border-bottom:1px solid #1a2440;padding-bottom:16px;margin-bottom:20px">
          <h1 style="color:#00ff88;margin:0;font-size:20px">🛡️ PhishNetra Weekly Digest</h1>
          <p style="color:#4a5a78;margin:4px 0 0;font-size:12px">${period}</p>
        </div>

        <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:20px">
          ${[
            { label: "Total Scans", value: total, color: "#00ff88" },
            { label: "Phishing", value: phishing, color: "#ff4444" },
            { label: "Suspicious", value: suspicious, color: "#f5a623" },
            {
              label: "Threat Rate",
              value: threatRate + "%",
              color: threatRate > 30 ? "#ff4444" : "#f5a623",
            },
          ]
            .map(
              (c) => `
            <div style="background:#101828;border:1px solid #1a2440;border-radius:8px;padding:12px;text-align:center">
              <div style="color:${c.color};font-size:22px;font-weight:700">${c.value}</div>
              <div style="color:#4a5a78;font-size:10px;text-transform:uppercase;letter-spacing:0.1em">${c.label}</div>
            </div>`,
            )
            .join("")}
        </div>

        ${
          topBrands?.length > 0
            ? `
        <div style="margin-bottom:20px">
          <h3 style="color:#8b95a8;font-size:11px;text-transform:uppercase;letter-spacing:0.15em;margin:0 0 10px">
            TOP TARGETED BRANDS
          </h3>
          ${topBrands
            .slice(0, 5)
            .map(
              (b) => `
            <div style="display:flex;justify-content:space-between;padding:6px 0;border-bottom:1px solid #1a2440">
              <span style="color:#e8edf5;text-transform:capitalize">${b.brand}</span>
              <span style="color:#ff4444;font-weight:700">${b.count}</span>
            </div>`,
            )
            .join("")}
        </div>`
            : ""
        }

        ${
          topTechniques?.length > 0
            ? `
        <div style="margin-bottom:20px">
          <h3 style="color:#8b95a8;font-size:11px;text-transform:uppercase;letter-spacing:0.15em;margin:0 0 10px">
            TOP ATTACK TECHNIQUES
          </h3>
          ${topTechniques
            .slice(0, 5)
            .map(
              (t) => `
            <div style="display:flex;justify-content:space-between;padding:6px 0;border-bottom:1px solid #1a2440">
              <span style="color:#e8edf5;text-transform:capitalize">${t.technique?.replace(/_/g, " ") || t._id}</span>
              <span style="color:#f5a623;font-weight:700">${t.count}</span>
            </div>`,
            )
            .join("")}
        </div>`
            : ""
        }

        ${
          mttd || mttr
            ? `
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:20px">
          <div style="background:#101828;border:1px solid #1a2440;border-radius:8px;padding:12px;text-align:center">
            <div style="color:#a78bfa;font-size:18px;font-weight:700">${mttd ? mttd + "m" : "N/A"}</div>
            <div style="color:#4a5a78;font-size:10px;text-transform:uppercase;letter-spacing:0.1em">MTTD</div>
          </div>
          <div style="background:#101828;border:1px solid #1a2440;border-radius:8px;padding:12px;text-align:center">
            <div style="color:#00d4ff;font-size:18px;font-weight:700">${mttr ? mttr + "m" : "N/A"}</div>
            <div style="color:#4a5a78;font-size:10px;text-transform:uppercase;letter-spacing:0.1em">MTTR</div>
          </div>
        </div>`
            : ""
        }

        <div style="border-top:1px solid #1a2440;padding-top:16px;margin-top:8px">
          <p style="color:#4a5a78;font-size:11px;margin:0">
            PhishNetra AI v4.0 · SentinelCore SIEM · Auto-generated weekly report
          </p>
        </div>
      </div>`;

    await transporter.sendMail({
      from: `"PhishNetra AI" <${process.env.SMTP_USER}>`,
      to: process.env.ALERT_EMAIL,
      subject: `📊 PhishNetra Weekly Digest — ${threatRate}% Threat Rate · ${phishing} Phishing Detected`,
      html,
    });
    console.log("📧 Weekly digest sent");
    return true;
  } catch (err) {
    console.error("Weekly digest error:", err.message);
    return false;
  }
}

module.exports = {
  sendCriticalAlert,
  sendWeeklyDigest,
  isEmailConfigured: () => isConfigured,
};
