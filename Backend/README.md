# 🛡️ PhishNetra — AI Phishing Detection & SOC Platform

> Full-spectrum defensive security platform: phishing detection, SIEM, threat intelligence, India-specific fraud detection, adversary profiling, and more.

---

## 🚀 Quick Start (First Time)

### Prerequisites
- Node.js 18+ — https://nodejs.org
- MongoDB Community — https://mongodb.com/try/download/community
- Git

### Setup (one command)
```bash
git clone <your-repo>
cd TDPCL
bash setup.sh
```

This installs all dependencies, creates default users, and shows you the login credentials.

### Manual Setup (if setup.sh doesn't work on Windows)

```bash
# 1. Backend
cd Backend
npm install
npm install express-rate-limit helmet   # security packages
node seed.js                             # creates first admin user
node server.js                           # start backend

# 2. Frontend (new terminal)
cd Frontend
npm install
npm run dev
```

Open: **http://localhost:5173**

### Default Login Credentials
| Username | Password    | Role    |
|----------|-------------|---------|
| admin    | Admin@123   | Admin   |
| analyst  | Analyst@123 | Analyst |
| viewer   | Viewer@123  | Viewer  |

⚠️ **Change these passwords immediately after first login.**

---

## ⚙️ Configuration (Backend/.env)

```env
MONGODB_URI=mongodb://127.0.0.1:27017/phishnetra
PORT=5000
NODE_ENV=development

# Generate with: node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"
JWT_SECRET=your-64-char-random-secret

# Email alerts (optional)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASS=your-16-char-gmail-app-password
ALERT_EMAIL=your-email@gmail.com

# Slack/Discord (optional)
SLACK_WEBHOOK_URL=
DISCORD_WEBHOOK_URL=

# PhishTank API (free at phishtank.org — improves threat intel accuracy)
PHISHTANK_API_KEY=

# Rate limiting
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX=100
```

---

## 📁 Project Structure

```
TDPCL/
├── Backend/
│   ├── server.js                    ← Express entry point
│   ├── seed.js                      ← Run once to create admin user
│   ├── .env                         ← Config (never commit this)
│   ├── ai/
│   │   ├── phishingDetector.js      ← 28-feature hybrid detection engine
│   │   ├── mlModel.js               ← Synaptic neural network (24→18→12→6→1)
│   │   ├── autoTrainingEngine.js    ← Auto-retrains from datasets/
│   │   ├── emailHeaderAnalyzer.js   ← Email forensics
│   │   └── threatDNA.js             ← Phishing fingerprinting
│   ├── datasets/                    ← Drop CSV files here to auto-retrain
│   ├── middleware/
│   │   ├── ids.js                   ← Intrusion detection
│   │   └── apiKeyAuth.js            ← API key authentication
│   ├── models/                      ← Mongoose schemas
│   ├── routes/                      ← Express route handlers
│   ├── services/
│   │   ├── indiaFraudDetector.js    ← Digital Arrest, UPI, TRAI scams
│   │   ├── govtPortalDetector.js    ← Fake govt portal detection
│   │   ├── cyberComplaintEngine.js  ← Complaint intelligence
│   │   ├── adversaryEngine.js       ← Threat actor profiling
│   │   └── threatIntel.js           ← PhishTank + OpenPhish feeds
│   └── siem/                        ← SentinelCore SIEM engine
│
├── Frontend/
│   └── src/
│       ├── pages/                   ← 28 page components
│       ├── components/Layout.tsx    ← Navigation + auth guard
│       └── config.ts                ← API_BASE URL
│
└── extension/                       ← Chrome MV3 extension
```

---

## 🔑 User Roles

| Role    | Can Scan | View History | SIEM Alerts | Delete | Admin Panel |
|---------|----------|--------------|-------------|--------|-------------|
| Admin   | ✅       | ✅ Full      | ✅          | ✅     | ✅          |
| Analyst | ✅       | ✅ Full      | ✅          | ❌     | ❌          |
| Viewer  | ❌       | ✅ Limited   | ✅ Read     | ❌     | ❌          |

---

## 🌐 API Reference

### Auth
```
POST /api/auth/login      { username, password }
POST /api/auth/register   { username, password, role }
```

### Scanning
```
POST /api/scan            { input }           → requires auth (analyst/admin)
GET  /api/scan/stats                          → requires auth
GET  /api/scan/history                        → requires auth
POST /api/scan/headers    { headers }         → email header forensics
```

### SIEM
```
GET  /api/siem/alerts     ?status=open
GET  /api/siem/stats
GET  /api/siem/rules
PATCH /api/siem/alerts/:id { status }        → requires auth
POST  /api/siem/alerts/:id/comment { text }  → requires auth
```

### External API (API Key auth)
```
POST /api/scan
Header: X-API-Key: your-api-key
Body:   { input: "http://..." }
```

---

## 🧠 ML Auto-Training

Drop any CSV file into `Backend/datasets/` — the engine automatically:
1. Detects the schema (URL features, email text, label columns)
2. Extracts 28 features per row
3. Retrains the neural network
4. Hot-swaps the model without restarting

Supported CSV formats:
- URL + label columns (dataset_phishing.csv format)
- Email text + label (Phishing_Email.csv format)
- Feature vectors (dataset_phishing.csv format)

**Memory limit:** 10,000 rows per file, 25,000 total.

---

## 🔌 Chrome Extension

1. Open Chrome → `chrome://extensions/`
2. Enable "Developer mode"
3. Click "Load unpacked"
4. Select the `extension/` folder
5. Open the extension popup and log in

The extension automatically scans every URL you visit and shows:
- 🟢 Green badge = Safe
- 🟡 Yellow badge = Suspicious
- 🔴 Red badge = Phishing
- ⚪ "LOGIN" badge = Need to log in first

---

## 🇮🇳 India-Specific Features

| Feature | Route | What it detects |
|---------|-------|-----------------|
| India Cyber Fraud | `/india-fraud` | Digital Arrest, UPI fraud, TRAI scam, Aadhaar fraud |
| Govt Portal Check | `/govt-portal` | Fake income tax, IRCTC, DigiLocker, passport portals |
| Cyber Complaint | `/complaints` | Classifies complaint, extracts IOCs, drafts NCRP report |
| India Fraud Helpline | — | Auto-shows 1930 helpline for confirmed fraud |

---

## 🔒 Security Notes

- Never commit `.env` — it's in `.gitignore`
- Rotate JWT_SECRET if you suspect it was exposed
- Gmail app passwords: myaccount.google.com/apppasswords
- PhishTank API key: phishtank.org (free registration)
- For production: use HTTPS, set `NODE_ENV=production`

---

## 🐛 Common Issues

**"Invalid credentials" on first login**
→ Run `node seed.js` first. No default users exist until you seed.

**"CORS error" in browser console**
→ Add your IP to `ALLOWED_ORIGINS` in `.env`
→ Restart the backend

**"Cannot reach backend"**
→ Make sure MongoDB is running: `mongod`
→ Make sure backend is running: `node server.js`
→ Check port 5000 is free: `lsof -i :5000`

**Extension shows "LOGIN" badge on every site**
→ Open the extension popup and log in with your PhishNetra credentials

**Training never finishes / server crashes during training**
→ Reduce row count in `autoTrainingEngine.js`: `MAX_ROWS = 5000`
→ Check available RAM: need at least 4GB free

## All Backend and Frontend Done By Dilan Rai
---
