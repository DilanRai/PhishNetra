# 🛡️ AI Phishing Detection — Backend

Node.js + Express backend for the AI Phishing Detection System.

---

## 📁 Folder Structure

```
backend/
 ├── server.js              ← Main entry point
 ├── .env                   ← Environment variables
 ├── package.json           ← Dependencies
 │
 ├── routes/
 │    └── scan.js           ← POST /api/scan route
 │
 ├── ai/
 │    └── phishingDetector.js  ← Core detection engine
 │
 └── models/                ← (Future: MongoDB models)
```

---

## 🚀 How to Run

### 1. Install dependencies
```bash
cd backend
npm install
```

### 2. Start development server
```bash
npm run dev
```
Server runs on: **http://localhost:5000**

---

## 📡 API Endpoints

### POST /api/scan
Analyze a URL or text for phishing threats.

**Request:**
```json
{
  "input": "http://paypal-secure.tk/login"
}
```

**Response:**
```json
{
  "status": "phishing",
  "riskScore": 85,
  "issues": [
    "No HTTPS — connection is not secure",
    "Suspicious top-level domain — commonly used in phishing",
    "Possible brand impersonation — \"paypal\" in suspicious domain"
  ],
  "inputType": "url"
}
```

### GET /api/health
Check if the server is running.

### GET /api/scan/test
Run built-in test cases to verify detection is working.

---

## ⚙️ Environment Variables (.env)

```
PORT=5000
FRONTEND_URL=http://localhost:5173
NODE_ENV=development
```

---

## 🔮 Coming Next
- MongoDB + Mongoose for scan history
- User authentication
- Domain reputation API integration
