# PhishNetra

PhishNetra is an AI-assisted phishing-detection and security-operations platform. It combines URL and email analysis with threat intelligence, incident workflows, a SIEM dashboard, and a Chrome extension that can assess sites while you browse.

## What’s included

- **Frontend** — React, TypeScript, Vite, and Tailwind interface for scanning, investigations, dashboards, alerts, and security workflows.
- **Backend** — Node.js/Express API with MongoDB persistence, authentication, role-based access, Socket.IO updates, rate limiting, and security headers.
- **Detection engines** — Hybrid rule and neural-network phishing analysis, email-header forensics, URL intelligence, IOC correlation, anomaly detection, and threat-DNA fingerprinting.
- **SentinelCore SIEM** — Alerting, rule evaluation, event ingestion, correlation, and incident-response tooling.
- **Chrome extension** — Manifest V3 browser extension that scans visited URLs and presents safe, suspicious, phishing, or sign-in-required status.

## Key capabilities

- Scan URLs, emails, QR-code targets, and email headers for phishing indicators.
- Investigate campaigns, indicators of compromise, malware kits, and threat actors.
- Track alerts, bulk scans, API keys, threat feeds, logs, evidence, and response actions.
- Detect India-specific fraud patterns such as UPI scams, fake government portals, Digital Arrest scams, and TRAI impersonation.
- Train and refresh the detection model from supported CSV datasets.

## Project structure

```text
PhishNetra/
├── Backend/       Express API, MongoDB models, detection engines, SIEM, services
├── Frontend/      React/Vite web application
├── extension/     Chrome Manifest V3 extension
└── docs/          Supporting project documentation
```

## Prerequisites

- Node.js 18 or later
- MongoDB (local or hosted)
- Google Chrome or another Chromium-based browser for the extension

## Local setup

1. Clone the repository:

   ```bash
   git clone https://github.com/DilanRai/PhishNetra.git
   cd PhishNetra
   ```

2. Configure and start the backend:

   ```bash
   cd Backend
   npm install
   ```

   Create `Backend/.env` with at least:

   ```env
   MONGODB_URI=mongodb://127.0.0.1:27017/phishnetra
   PORT=5000
   JWT_SECRET=replace-with-a-long-random-secret
   ```

   Seed initial users if needed, then start the API:

   ```bash
   node seed.js
   npm run dev
   ```

3. In a second terminal, start the frontend:

   ```bash
   cd Frontend
   npm install
   npm run dev
   ```

   Open the Vite URL shown in the terminal (normally `http://localhost:5173`). The frontend calls the API on port `5000` by default.

## Chrome extension

1. Open `chrome://extensions` in Chrome.
2. Enable **Developer mode**.
3. Select **Load unpacked** and choose the repository’s `extension` folder.
4. Open the PhishNetra extension popup and sign in to connect it to the platform.

## Useful commands

| Area | Command | Purpose |
| --- | --- | --- |
| Backend | `npm run dev` | Run the API with automatic restarts |
| Backend | `npm test` | Run backend tests |
| Frontend | `npm run dev` | Start the development server |
| Frontend | `npm run build` | Type-check and build production assets |
| Frontend | `npm run lint` | Run frontend linting |

## Security notes

- Do not commit `.env` files, access tokens, or API keys. They are intentionally ignored by Git.
- Use a strong, unique `JWT_SECRET` and restrict `ALLOWED_ORIGINS` when deploying.
- Run production deployments behind HTTPS and use a managed MongoDB instance with appropriate access controls.

## License

No license has been specified. Contact the repository owner before reusing or distributing this project.
