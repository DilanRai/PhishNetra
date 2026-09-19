// FILE: backend/services/kitFingerprint.js
// Phishing Kit DNA Fingerprinting — passive URL pattern analysis
// Identifies which phishing kit was likely used based on URL/domain patterns
// Technique: same as Proofpoint TAP, VirusTotal, Recorded Future
// 100% passive — only analyzes URLs already flagged and stored in PhishNetra database

const crypto = require("crypto");

// ═══════════════════════════════════════════════════════
// KIT SIGNATURE DATABASE — 25 known phishing kits
// Signatures derived from publicly documented threat intel:
// - CISA Alerts, PhishTank research, Google TAG reports
// - Proofpoint TA reports, Microsoft MSTIC publications
// All patterns are URL/domain structural signals ONLY
// ═══════════════════════════════════════════════════════
const KIT_SIGNATURES = [

  // ── 1. 16Shop ──────────────────────────────────────────
  // Documented by: ZeroFOX, Trend Micro, INTERPOL (2020)
  {
    kitId:       "16SHOP",
    kitName:     "16Shop",
    version:     "v3.x",
    targetBrands:["apple","amazon","paypal"],
    sophistication:"high",
    description: "Commercial phishing-as-a-service kit, previously sold on dark forums. INTERPOL arrested operators in 2020.",
    urlSignals: [
      /\/apple(?:id)?\/(?:login|verify|secure)/i,
      /\/amazon\/(?:signin|login|verify)/i,
      /\/paypal\/(?:login|verify|secure)/i,
    ],
    domainSignals: [
      (d) => d.split(".").length >= 4, // deep subdomain structure
      (d) => /^[a-z0-9]{6,12}-[a-z0-9]{4,8}\./i.test(d), // random-hyphen domain
    ],
    pathSignals: [
      /\/(?:index\.php|login\.php|verify\.php)\?(?:id|token|ref)=/i,
    ],
    confidence: (matches) => Math.min(matches * 30, 90),
  },

  // ── 2. Evil Proxy (AiTM Kit) ───────────────────────────
  // Documented by: Microsoft MSTIC (2022), Resecurity
  {
    kitId:       "EVILPROXY",
    kitName:     "EvilProxy",
    version:     "2022+",
    targetBrands:["microsoft","google","github","apple"],
    sophistication:"expert",
    description: "Adversary-in-the-Middle reverse proxy kit. Bypasses MFA by relaying real sessions. Documented by Microsoft MSTIC.",
    urlSignals: [
      /\/(?:oauth|auth|sso)\/(?:authorize|callback|token)/i,
      /\/common\/oauth2\/v2\.0\/authorize/i,
    ],
    domainSignals: [
      (d) => /workers\.dev|pages\.dev|vercel\.app/i.test(d),
      (d) => /^[a-z]{3,6}-[a-z]{3,6}-[a-z]{3,6}\./i.test(d),
    ],
    pathSignals: [
      /\?.*(?:redirect_uri|state|nonce)=.{20,}/i,
      /\/login\.microsoftonline\./i,
    ],
    confidence: (matches) => Math.min(matches * 35, 95),
  },

  // ── 3. Evilginx2 (Framework) ──────────────────────────
  // Open source, extensively documented
  {
    kitId:       "EVILGINX2",
    kitName:     "Evilginx2",
    version:     "3.x",
    targetBrands:["microsoft","google","facebook","linkedin"],
    sophistication:"expert",
    description: "Open-source AiTM framework used for session hijacking. Documented extensively in security research.",
    urlSignals: [
      /\/(?:phishlets|sessions|lures)\//i,
    ],
    domainSignals: [
      (d) => { const sub = d.split("."); return sub.length >= 4 && sub[0].length >= 8; },
    ],
    pathSignals: [
      /\?a=[a-zA-Z0-9_-]{20,}$/,
      /\/[a-z0-9]{16,}$/,
    ],
    confidence: (matches) => Math.min(matches * 40, 90),
  },

  // ── 4. Zerokit / OpenBullet configs ───────────────────
  // Documented by: Group-IB, Secureworks
  {
    kitId:       "ZEROKIT",
    kitName:     "Zerokit",
    version:     "2021+",
    targetBrands:["paypal","chase","wells fargo","bank of america"],
    sophistication:"medium",
    description: "Banking credential harvester. Uses legitimate-looking login pages. Documented by Group-IB.",
    urlSignals: [
      /\/(?:auth|bank|account)\/(?:login|signin|verify)\.php/i,
      /\/(?:secure|online)banking\//i,
    ],
    domainSignals: [
      (d) => /(?:secure|online|my|web|portal)(?:bank|banking|chase|wells)/i.test(d),
    ],
    pathSignals: [
      /\?(?:step|page|tab)=(?:\d|[a-z]{1,10})/i,
    ],
    confidence: (matches) => Math.min(matches * 28, 85),
  },

  // ── 5. Kr3pto SMS Phishing Kit ────────────────────────
  // Documented by: RiskIQ (2021), CISA
  {
    kitId:       "KR3PTO",
    kitName:     "Kr3pto",
    version:     "2021+",
    targetBrands:["lloyds","barclays","natwest","hsbc"],
    sophistication:"medium",
    description: "UK banking smishing kit. Delivered via SMS. Documented by RiskIQ and CISA.",
    urlSignals: [
      /\/(?:lloyds|barclays|natwest|hsbc)\/(?:mobile|online|secure)/i,
    ],
    domainSignals: [
      (d) => /(?:lloyds|barclays|natwest|hsbc)(?:-?(?:bank|online|secure|mobile))/i.test(d),
    ],
    pathSignals: [
      /\/(?:m|mobile)\/(?:login|verify|auth)/i,
    ],
    confidence: (matches) => Math.min(matches * 30, 88),
  },

  // ── 6. iWebphish / Fake UPS Delivery ─────────────────
  // Documented by: Proofpoint (2022)
  {
    kitId:       "IWEBPHISH_DELIVERY",
    kitName:     "iWebphish Delivery",
    version:     "2022+",
    targetBrands:["ups","fedex","dhl","usps","royal mail"],
    sophistication:"low",
    description: "Delivery notification phishing kit. Harvests card details via fake delivery fee pages.",
    urlSignals: [
      /\/(?:tracking|delivery|parcel|shipment)\/(?:confirm|pay|fee)/i,
      /\/(?:ups|fedex|dhl|usps)\/(?:track|delivery|pending)/i,
    ],
    domainSignals: [
      (d) => /(?:ups|fedex|dhl|usps|parcel|delivery|tracking)(?:-?(?:alert|notify|secure|track))/i.test(d),
    ],
    pathSignals: [
      /\?(?:tracking|parcel|ref)=[A-Z0-9]{8,}/i,
    ],
    confidence: (matches) => Math.min(matches * 25, 80),
  },

  // ── 7. W3LL Panel (Microsoft 365 BEC) ────────────────
  // Documented by: Group-IB (2023)
  {
    kitId:       "W3LL_PANEL",
    kitName:     "W3LL Panel",
    version:     "2023+",
    targetBrands:["microsoft"],
    sophistication:"expert",
    description: "Business Email Compromise kit targeting Microsoft 365. Bypasses MFA. Documented by Group-IB 2023.",
    urlSignals: [
      /\/(?:office|microsoft|m365|o365)\/(?:login|auth|verify)/i,
    ],
    domainSignals: [
      (d) => /(?:office365|microsoft365|m365|o365)(?:-?(?:login|verify|secure|auth))/i.test(d),
      (d) => /^[a-z]{4,8}\.[a-z]{4,8}\.(?:tk|ml|ga|cf)$/i.test(d),
    ],
    pathSignals: [
      /\/common\/oauth2\/authorize\?/i,
      /\/login\.microsoftonline\./i,
    ],
    confidence: (matches) => Math.min(matches * 35, 92),
  },

  // ── 8. Caffeine (PhaaS Platform) ─────────────────────
  // Documented by: Mandiant (2022)
  {
    kitId:       "CAFFEINE_PHAAS",
    kitName:     "Caffeine PhaaS",
    version:     "2022+",
    targetBrands:["microsoft","google"],
    sophistication:"high",
    description: "Phishing-as-a-Service platform. Documented by Mandiant in 2022. Open registration, no vetting.",
    urlSignals: [
      /\/(?:autodiscover|ews|mapi)\/[a-z0-9]{8,}/i,
    ],
    domainSignals: [
      (d) => /[a-z0-9]{8,12}\.[a-z]{2,4}$/.test(d) && d.split(".").length === 2,
    ],
    pathSignals: [
      /\/[a-z0-9]{32,}\/(?:login|auth)/i,
    ],
    confidence: (matches) => Math.min(matches * 30, 85),
  },

  // ── 9. Generic PayPal Kit (common variant) ────────────
  {
    kitId:       "GENERIC_PAYPAL",
    kitName:     "Generic PayPal Kit",
    version:     "various",
    targetBrands:["paypal"],
    sophistication:"low",
    description: "Widely distributed PayPal credential harvester. Multiple variants in the wild.",
    urlSignals: [
      /\/paypal\/(?:login|verify|account|update|confirm)/i,
      /\/(?:myaccount|signin|billing)\/paypal/i,
    ],
    domainSignals: [
      (d) => /paypal/i.test(d) && !/^paypal\.com$/.test(d),
    ],
    pathSignals: [
      /\/(?:step[12]|page[12]|verification)\.php/i,
    ],
    confidence: (matches) => Math.min(matches * 25, 80),
  },

  // ── 10. Modlishka Framework ───────────────────────────
  // Open source, documented in security research
  {
    kitId:       "MODLISHKA",
    kitName:     "Modlishka",
    version:     "1.x",
    targetBrands:["google","microsoft","facebook"],
    sophistication:"expert",
    description: "Open-source reverse proxy phishing framework. Session token interception capability.",
    urlSignals: [
      /\/modlishka\//i,
    ],
    domainSignals: [
      (d) => /^[a-z]{6,10}-?[a-z]{4,8}\.[a-z]{2,4}$/.test(d),
    ],
    pathSignals: [
      /\?_o=https?%3A%2F%2F/i,
      /\?trk=[a-z0-9]{8,}/i,
    ],
    confidence: (matches) => Math.min(matches * 38, 88),
  },

  // ── 11. Fake IRS / Gov Tax Refund Kit ────────────────
  {
    kitId:       "GOV_TAX_KIT",
    kitName:     "Government Tax Refund Kit",
    version:     "various",
    targetBrands:["irs","hmrc","income tax"],
    sophistication:"medium",
    description: "Government impersonation kit targeting tax refund claims. Seasonal spikes around tax season.",
    urlSignals: [
      /\/(?:irs|hmrc|tax)\/(?:refund|return|claim|verify)/i,
      /\/(?:tax-refund|tax-return|tax-claim)/i,
    ],
    domainSignals: [
      (d) => /(?:irs|hmrc|gov|tax)(?:-?(?:refund|return|gov|secure|portal))/i.test(d),
    ],
    pathSignals: [
      /\?(?:refund|amount|ssn|nino)=\d+/i,
    ],
    confidence: (matches) => Math.min(matches * 28, 85),
  },

  // ── 12. Crypto Wallet Drain Kit ───────────────────────
  // Documented by: Chainalysis, ZachXBT
  {
    kitId:       "CRYPTO_DRAINER",
    kitName:     "Crypto Wallet Drainer",
    version:     "2023+",
    targetBrands:["metamask","coinbase","binance","opensea"],
    sophistication:"high",
    description: "Cryptocurrency wallet phishing. Captures seed phrases and private keys. Documented by Chainalysis.",
    urlSignals: [
      /\/(?:metamask|wallet|crypto|nft)\/(?:connect|verify|restore|import)/i,
      /\/(?:seed-phrase|recovery|restore-wallet)/i,
    ],
    domainSignals: [
      (d) => /(?:metamask|coinbase|binance|opensea|wallet)(?:-?(?:app|pro|secure|verify|connect))/i.test(d),
    ],
    pathSignals: [
      /\?(?:chain|network|wallet)=[a-z]+/i,
    ],
    confidence: (matches) => Math.min(matches * 32, 90),
  },

  // ── 13. Fake Microsoft Teams / O365 Login ────────────
  // Documented by: Microsoft Security Blog (2023)
  {
    kitId:       "FAKE_TEAMS_O365",
    kitName:     "Fake Teams/O365",
    version:     "2023+",
    targetBrands:["microsoft"],
    sophistication:"high",
    description: "Microsoft Teams/O365 impersonation. Targets enterprise users. Documented by Microsoft Security Blog.",
    urlSignals: [
      /\/teams\/(?:meeting|join|invite|auth)/i,
      /\/(?:teams|sharepoint|onedrive)\.microsoftonline\./i,
    ],
    domainSignals: [
      (d) => /(?:teams|sharepoint|onedrive|office)(?:-?(?:live|online|secure|login))/i.test(d),
    ],
    pathSignals: [
      /\/\?(?:meetingId|threadId|messageId)=[a-z0-9:_-]+/i,
    ],
    confidence: (matches) => Math.min(matches * 30, 88),
  },

  // ── 14. QR Code Phishing (Quishing Kit) ──────────────
  // Documented by: Abnormal Security, Cofense (2023)
  {
    kitId:       "QUISHING_KIT",
    kitName:     "QR Quishing Kit",
    version:     "2023+",
    targetBrands:["microsoft","paypal","generic"],
    sophistication:"medium",
    description: "QR code phishing bypasses email scanners. Landing page captures credentials. Documented by Abnormal Security.",
    urlSignals: [
      /\/qr\/(?:verify|scan|auth|login)/i,
      /\/(?:qrcode|scan-to-verify|qr-auth)/i,
    ],
    domainSignals: [
      (d) => /(?:qr|scan|verify)(?:-?(?:auth|login|verify|secure))/i.test(d),
    ],
    pathSignals: [
      /\?(?:qr|src|from)=[a-zA-Z0-9_-]{8,}/i,
    ],
    confidence: (matches) => Math.min(matches * 28, 82),
  },

  // ── 15. Smishing (SMS Phishing) USPS/FedEx Kit ────────
  {
    kitId:       "SMISHING_DELIVERY",
    kitName:     "Delivery Smishing Kit",
    version:     "various",
    targetBrands:["usps","fedex","ups","dhl","royal mail"],
    sophistication:"low",
    description: "SMS delivery notification phishing. Harvests card details via fake 'redelivery fee' pages.",
    urlSignals: [
      /\/(?:usps|fedex|ups|dhl)(?:\.com)?\/(?:tracking|delivery|package)/i,
      /\/(?:redelivery|delivery-fee|tracking-fee)/i,
    ],
    domainSignals: [
      (d) => /(?:usps|fedex|ups|dhl)(?:-?tracking|-?delivery|-?parcel)/i.test(d),
    ],
    pathSignals: [
      /\?(?:track|parcel)=[A-Z0-9]{10,}/i,
    ],
    confidence: (matches) => Math.min(matches * 22, 78),
  },

  // ── 16. Tycoon 2FA (AiTM PhaaS) ──────────────────────
  // Documented by: Sekoia.io (2024), Proofpoint
  {
    kitId:       "TYCOON_2FA",
    kitName:     "Tycoon 2FA",
    version:     "2024+",
    targetBrands:["microsoft","google"],
    sophistication:"expert",
    description: "AiTM PhaaS kit bypassing Microsoft and Google MFA. Documented by Sekoia.io in 2024. Uses Cloudflare Turnstile to block bots.",
    urlSignals: [
      /\/(?:auth|login|sso)\/[a-z0-9]{8,}\/(?:verify|challenge)/i,
      /\/turnstile\/v0\/api\.js/i,
    ],
    domainSignals: [
      (d) => /[a-z0-9]{6,10}\.(?:xyz|top|shop|online|site)$/.test(d),
      (d) => /^[a-z]{4,8}[0-9]{2,4}\.[a-z]{2,5}$/.test(d),
    ],
    pathSignals: [
      /\?[a-z0-9]{1,3}=[a-zA-Z0-9_-]{30,}/,
      /\/[a-f0-9]{32}(?:\/|$)/,
    ],
    confidence: (matches) => Math.min(matches * 38, 95),
  },

  // ── 17. Greatness PhaaS (Microsoft 365) ──────────────
  // Documented by: Cisco Talos (2023)
  {
    kitId:       "GREATNESS_PHAAS",
    kitName:     "Greatness PhaaS",
    version:     "2023+",
    targetBrands:["microsoft"],
    sophistication:"expert",
    description: "Microsoft 365 PhaaS kit with real-time MFA bypass. Documented by Cisco Talos in 2023. Targets enterprise users.",
    urlSignals: [
      /\/(?:microsoft|office365|m365)\/(?:auth|login|sso)\/[a-z0-9]{6,}/i,
    ],
    domainSignals: [
      (d) => /(?:microsoft|office|m365|sharepoint)(?:-?(?:auth|login|sso|portal))\./i.test(d),
      (d) => /^[a-z0-9]{5,10}\.(?:azurewebsites\.net|cloudapp\.net)$/.test(d),
    ],
    pathSignals: [
      /\/api\/auth\/(?:session|token|callback)/i,
      /\?(?:tenant|client_id|resource)=[a-z0-9-]{8,}/i,
    ],
    confidence: (matches) => Math.min(matches * 36, 93),
  },

  // ── 18. Robin Banks (PhaaS) ───────────────────────────
  // Documented by: IronNet (2022), Resecurity
  {
    kitId:       "ROBIN_BANKS",
    kitName:     "Robin Banks",
    version:     "2022+",
    targetBrands:["citibank","bank of america","wells fargo","capital one","chase"],
    sophistication:"high",
    description: "Banking PhaaS kit with Telegram-based C2. Documented by IronNet in 2022. Targets US and UK financial institutions.",
    urlSignals: [
      /\/(?:citi|bofa|wellsfargo|capitalone|chase)\/(?:login|signin|verify)/i,
      /\/(?:online|secure|my)banking\/(?:auth|login)/i,
    ],
    domainSignals: [
      (d) => /(?:citi|bofa|wellsfargo|capitalone|chase)(?:-?(?:bank|secure|online|verify))/i.test(d),
    ],
    pathSignals: [
      /\/(?:step|page)[123]\.php/i,
      /\?(?:session|token|ref)=[a-zA-Z0-9]{16,}/i,
    ],
    confidence: (matches) => Math.min(matches * 30, 88),
  },

  // ── 19. Darcula PhaaS (iMessage/RCS Smishing) ─────────
  // Documented by: Netcraft (2024), Sekoia.io
  {
    kitId:       "DARCULA_PHAAS",
    kitName:     "Darcula PhaaS",
    version:     "2024+",
    targetBrands:["usps","royal mail","at&t","verizon","netflix"],
    sophistication:"high",
    description: "PhaaS platform using iMessage and RCS for smishing. Documented by Netcraft in 2024. 200+ templates, 100+ countries.",
    urlSignals: [
      /\/(?:usps|royalmail|att|verizon|netflix)\/(?:verify|confirm|update)/i,
      /\/(?:package|parcel|delivery)\/(?:confirm|fee|pay)/i,
    ],
    domainSignals: [
      (d) => /[a-z]{4,8}-[a-z]{4,8}\.[a-z]{2,4}$/.test(d) && d.split(".").length === 2,
      (d) => /(?:usps|royalmail|att|verizon|netflix)(?:-?(?:verify|update|secure))/i.test(d),
    ],
    pathSignals: [
      /\/[a-z]{2}\/(?:verify|confirm|update)/i,
      /\?(?:id|ref|code)=[A-Z0-9]{8,16}/,
    ],
    confidence: (matches) => Math.min(matches * 28, 85),
  },

  // ── 20. Fake LinkedIn / Job Offer Kit ─────────────────
  // Documented by: Mandiant, ESET (2023)
  {
    kitId:       "FAKE_LINKEDIN",
    kitName:     "Fake LinkedIn / Job Offer Kit",
    version:     "2023+",
    targetBrands:["linkedin","indeed","glassdoor"],
    sophistication:"medium",
    description: "LinkedIn impersonation kit used for credential harvesting and BEC. Documented by Mandiant and ESET.",
    urlSignals: [
      /\/(?:linkedin|indeed|glassdoor)\/(?:jobs|apply|login|verify)/i,
      /\/(?:job-offer|career|recruitment)\/(?:apply|verify|confirm)/i,
    ],
    domainSignals: [
      (d) => /(?:linkedin|indeed|glassdoor)(?:-?(?:jobs|careers|apply|secure))/i.test(d),
    ],
    pathSignals: [
      /\?(?:jobId|position|ref)=[a-zA-Z0-9_-]{6,}/i,
    ],
    confidence: (matches) => Math.min(matches * 26, 82),
  },

  // ── 21. Fake DocuSign / E-Signature Kit ───────────────
  // Documented by: Abnormal Security, Cofense (2023)
  {
    kitId:       "FAKE_DOCUSIGN",
    kitName:     "Fake DocuSign / E-Signature Kit",
    version:     "2023+",
    targetBrands:["docusign","adobe sign","hellosign"],
    sophistication:"medium",
    description: "E-signature impersonation kit. Lures victims with fake document signing requests. Documented by Abnormal Security.",
    urlSignals: [
      /\/(?:docusign|adobesign|hellosign)\/(?:sign|review|complete|verify)/i,
      /\/(?:document|contract|agreement)\/(?:sign|review|complete)/i,
    ],
    domainSignals: [
      (d) => /(?:docusign|adobesign|hellosign|esign)(?:-?(?:secure|portal|verify|sign))/i.test(d),
    ],
    pathSignals: [
      /\?(?:envelopeId|docId|signingId)=[a-zA-Z0-9_-]{10,}/i,
      /\/(?:signing|envelope)\/[a-z0-9-]{8,}/i,
    ],
    confidence: (matches) => Math.min(matches * 27, 83),
  },

  // ── 22. Fake Zoom / Video Conference Kit ──────────────
  // Documented by: Proofpoint, CISA (2022-2023)
  {
    kitId:       "FAKE_ZOOM",
    kitName:     "Fake Zoom / Video Conference Kit",
    version:     "2022+",
    targetBrands:["zoom","webex","teams","google meet"],
    sophistication:"medium",
    description: "Video conferencing impersonation kit. Harvests credentials via fake meeting join pages. Documented by Proofpoint.",
    urlSignals: [
      /\/(?:zoom|webex|meet)\/(?:j|join|meeting|invite)\/[a-z0-9]{6,}/i,
      /\/(?:video-call|meeting-invite|conference)\/(?:join|verify)/i,
    ],
    domainSignals: [
      (d) => /(?:zoom|webex|googlemeet|teams)(?:-?(?:meeting|invite|join|secure))/i.test(d),
    ],
    pathSignals: [
      /\/j\/\d{9,11}(?:\?pwd=[a-zA-Z0-9]{20,})?/,
      /\?(?:meetingId|pwd|tk)=[a-zA-Z0-9_-]{10,}/i,
    ],
    confidence: (matches) => Math.min(matches * 26, 82),
  },

  // ── 23. Fake AWS / Cloud Console Kit ──────────────────
  // Documented by: Permiso Security, Sysdig (2023)
  {
    kitId:       "FAKE_AWS_CONSOLE",
    kitName:     "Fake AWS / Cloud Console Kit",
    version:     "2023+",
    targetBrands:["aws","azure","gcp","digitalocean"],
    sophistication:"high",
    description: "Cloud console impersonation targeting DevOps and cloud engineers. Documented by Permiso Security in 2023.",
    urlSignals: [
      /\/(?:aws|azure|gcp|console)\/(?:signin|login|iam|console)/i,
      /\/console\.aws\.amazon\./i,
    ],
    domainSignals: [
      (d) => /(?:aws|azure|gcp|cloud)(?:-?(?:console|signin|portal|iam|login))/i.test(d),
      (d) => /^[a-z0-9]{4,8}\.(?:aws|azure|cloud)\.[a-z]{2,4}$/.test(d),
    ],
    pathSignals: [
      /\/(?:iam|ec2|s3|lambda)\/(?:home|console|signin)/i,
      /\?(?:region|account|next)=[a-zA-Z0-9_-]+/i,
    ],
    confidence: (matches) => Math.min(matches * 32, 90),
  },

  // ── 24. Fake Coinbase / Crypto Exchange Kit ───────────
  // Documented by: Chainalysis, Unit42 (2023)
  {
    kitId:       "FAKE_COINBASE",
    kitName:     "Fake Coinbase / Crypto Exchange Kit",
    version:     "2023+",
    targetBrands:["coinbase","kraken","binance","crypto.com"],
    sophistication:"high",
    description: "Crypto exchange impersonation kit. Targets account credentials and 2FA codes. Documented by Unit42.",
    urlSignals: [
      /\/(?:coinbase|kraken|binance|crypto)\/(?:login|signin|verify|2fa)/i,
      /\/(?:exchange|trading|wallet)\/(?:login|verify|auth)/i,
    ],
    domainSignals: [
      (d) => /(?:coinbase|kraken|binance|crypto)(?:-?(?:pro|exchange|secure|verify|login))/i.test(d),
    ],
    pathSignals: [
      /\/(?:2fa|mfa|otp)\/(?:verify|confirm|enter)/i,
      /\?(?:next|redirect|ref)=https?%3A%2F%2F/i,
    ],
    confidence: (matches) => Math.min(matches * 30, 88),
  },

  // ── 25. Fake HR / Payroll Portal Kit ─────────────────
  // Documented by: Proofpoint TA4557, FBI IC3 (2023)
  {
    kitId:       "FAKE_HR_PAYROLL",
    kitName:     "Fake HR / Payroll Portal Kit",
    version:     "2023+",
    targetBrands:["adp","workday","paychex","bamboohr"],
    sophistication:"medium",
    description: "HR and payroll portal impersonation. Targets direct deposit changes and W-2 data. Documented by Proofpoint TA4557.",
    urlSignals: [
      /\/(?:adp|workday|paychex|bamboohr)\/(?:login|signin|portal|payroll)/i,
      /\/(?:hr|payroll|benefits|w2)\/(?:login|verify|update|portal)/i,
    ],
    domainSignals: [
      (d) => /(?:adp|workday|paychex|bamboohr|payroll)(?:-?(?:portal|secure|login|hr))/i.test(d),
    ],
    pathSignals: [
      /\/(?:direct-deposit|w2|paystub|benefits)\/(?:update|verify|confirm)/i,
      /\?(?:employeeId|companyId|token)=[a-zA-Z0-9_-]{6,}/i,
    ],
    confidence: (matches) => Math.min(matches * 27, 84),
  },

  // ── 26. Grozio Bankomat ───────────────────────────────
  // Documented by: Group-IB (2023)
  {
    kitId:       "GROZIO_BANKING",
    kitName:     "Grozio Bankomat",
    version:     "2023+",
    targetBrands:["various european banks","n26","revolut"],
    sophistication:"high",
    description: "European banking phishing kit sold as PhaaS on Telegram. Documented by Group-IB in 2023, targets card data and OTP interception.",
    urlSignals: [
      /\/(?:bankomat|n26|revolut)\/(?:login|verify|secure)/i,
      /\/card\/(?:verify|confirm|activate)/i,
    ],
    domainSignals: [
      (d) => /(?:n26|revolut|bankomat)(?:-?(?:secure|verify|login))/i.test(d),
    ],
    pathSignals: [
      /\?(?:cardnum|cvv|otp)=/i,
    ],
    confidence: (matches) => Math.min(matches * 30, 87),
  },

  // ── 27. Sneaky Log (AiTM PhaaS) ────────────────────────
  // Documented by: Sekoia.io (2024)
  {
    kitId:       "SNEAKY_LOG",
    kitName:     "Sneaky Log",
    version:     "2024+",
    targetBrands:["microsoft","google"],
    sophistication:"expert",
    description: "AiTM phishing-as-a-service kit sold on Telegram. Documented by Sekoia.io in 2024, bypasses MFA via real-time session relay similar to Tycoon 2FA.",
    urlSignals: [
      /\/(?:sl|sneaky)\/(?:auth|verify|session)/i,
    ],
    domainSignals: [
      (d) => /^[a-z0-9]{8,14}\.(?:xyz|top|sbs|cfd)$/.test(d),
    ],
    pathSignals: [
      /\?[a-z]{1,2}=[a-zA-Z0-9+/=]{40,}/,
    ],
    confidence: (matches) => Math.min(matches * 35, 92),
  },

  // ── 28. Mamba 2FA ───────────────────────────────────────
  // Documented by: Sekoia.io, Push Security (2024)
  {
    kitId:       "MAMBA_2FA",
    kitName:     "Mamba 2FA",
    version:     "2024+",
    targetBrands:["microsoft","google"],
    sophistication:"expert",
    description: "AiTM PhaaS platform documented by Sekoia.io and Push Security in 2024. Targets Microsoft 365 with real-time credential and session token relay.",
    urlSignals: [
      /\/(?:m2fa|mamba)\/(?:login|verify)/i,
      /\/common\/oauth2\/v2\.0\/authorize.*mamba/i,
    ],
    domainSignals: [
      (d) => /^[a-z]{5,9}\.(?:icu|cfd|sbs|cyou)$/.test(d),
    ],
    pathSignals: [
      /\?ref=[a-zA-Z0-9]{10,}&session=/i,
    ],
    confidence: (matches) => Math.min(matches * 36, 93),
  },

  // ── 29. Fake Instagram Copyright/Verification Kit ─────
  // Documented by: Meta threat reports
  {
    kitId:       "FAKE_INSTAGRAM",
    kitName:     "Fake Instagram Copyright/Verification Kit",
    version:     "2023+",
    targetBrands:["instagram","meta"],
    sophistication:"medium",
    description: "Instagram impersonation kit using fake copyright strikes or verification badges to harvest credentials. Widely documented by Meta's own threat reports.",
    urlSignals: [
      /\/instagram\/(?:appeal|copyright|verify|login)/i,
      /\/(?:ig|insta)-(?:help|support|appeal)/i,
    ],
    domainSignals: [
      (d) => /(?:instagram|insta)(?:-?(?:help|support|appeal|verify|copyright))/i.test(d),
    ],
    pathSignals: [
      /\?(?:case|appeal|ref)=[A-Z0-9]{8,}/i,
    ],
    confidence: (matches) => Math.min(matches * 25, 80),
  },

  // ── 30. Fake Facebook Page Suspension Kit ─────────────
  // Documented by: Meta transparency reports
  {
    kitId:       "FAKE_FACEBOOK",
    kitName:     "Fake Facebook Page Suspension Kit",
    version:     "various",
    targetBrands:["facebook","meta"],
    sophistication:"low",
    description: "Facebook page/account suspension scare kit. High volume, widely distributed, documented across multiple Meta transparency reports.",
    urlSignals: [
      /\/facebook\/(?:appeal|suspend|restricted|login)/i,
      /\/fb-(?:help|support|appeal|recover)/i,
    ],
    domainSignals: [
      (d) => /(?:facebook|fb)(?:-?(?:help|support|appeal|recover|suspended))/i.test(d),
    ],
    pathSignals: [
      /\?(?:pageid|appeal)=\d{6,}/i,
    ],
    confidence: (matches) => Math.min(matches * 22, 76),
  },

  // ── 31. Fake X/Twitter Verification Kit ───────────────
  // Documented by: multiple security vendors (2023)
  {
    kitId:       "FAKE_X_TWITTER",
    kitName:     "Fake X/Twitter Verification Kit",
    version:     "2023+",
    targetBrands:["twitter","x"],
    sophistication:"medium",
    description: "X (Twitter) blue-checkmark and account verification phishing kit, increased after platform's paid verification rollout. Documented by multiple security vendors in 2023.",
    urlSignals: [
      /\/(?:twitter|x)\/(?:verify|verified|checkmark|login)/i,
    ],
    domainSignals: [
      (d) => /(?:twitter|x-corp|x-verify)(?:-?(?:verify|secure|login))/i.test(d),
    ],
    pathSignals: [
      /\?(?:handle|username)=@?[a-zA-Z0-9_]{1,15}/i,
    ],
    confidence: (matches) => Math.min(matches * 24, 78),
  },

  // ── 32. Fake WhatsApp Business Verification ───────────
  // Documented by: Meta security advisories
  {
    kitId:       "FAKE_WHATSAPP_BUSINESS",
    kitName:     "Fake WhatsApp Business Verification",
    version:     "2023+",
    targetBrands:["whatsapp","meta"],
    sophistication:"medium",
    description: "WhatsApp Business API/verification impersonation kit targeting small business owners. Documented in Meta security advisories.",
    urlSignals: [
      /\/whatsapp\/(?:business|verify|api)/i,
    ],
    domainSignals: [
      (d) => /whatsapp(?:-?(?:business|verify|api|secure))/i.test(d),
    ],
    pathSignals: [
      /\?(?:phone|biz)=[\d+]{8,}/i,
    ],
    confidence: (matches) => Math.min(matches * 24, 78),
  },

  // ── 33. Fake TikTok Shop/Creator Fund Kit ─────────────
  // Documented by: TikTok trust & safety reports (2023-2024)
  {
    kitId:       "FAKE_TIKTOK",
    kitName:     "Fake TikTok Shop/Creator Fund Kit",
    version:     "2023+",
    targetBrands:["tiktok"],
    sophistication:"medium",
    description: "TikTok Shop and Creator Fund payout phishing kit targeting creators and sellers. Documented by TikTok trust & safety reports 2023-2024.",
    urlSignals: [
      /\/tiktok\/(?:shop|creator|payout|fund)/i,
    ],
    domainSignals: [
      (d) => /tiktok(?:-?(?:shop|creator|payout|fund|secure))/i.test(d),
    ],
    pathSignals: [
      /\?(?:creatorid|payout)=[a-zA-Z0-9]{8,}/i,
    ],
    confidence: (matches) => Math.min(matches * 24, 78),
  },

  // ── 34. Fake Amazon Order Confirmation Kit ────────────
  // Documented by: APWG quarterly reports
  {
    kitId:       "FAKE_AMAZON_ORDER",
    kitName:     "Fake Amazon Order Confirmation Kit",
    version:     "various",
    targetBrands:["amazon"],
    sophistication:"low",
    description: "High-volume Amazon order confirmation / refund phishing kit. One of the most reported brand-impersonation categories per APWG quarterly reports.",
    urlSignals: [
      /\/amazon\/(?:order|refund|cancel|review)/i,
      /\/(?:amzn|amazon)-(?:order|refund|review)/i,
    ],
    domainSignals: [
      (d) => /amaz[o0]n(?:-?(?:order|refund|review|secure|update))/i.test(d),
    ],
    pathSignals: [
      /\?(?:order|orderid)=\d{3}-\d{7}-\d{7}/i,
    ],
    confidence: (matches) => Math.min(matches * 22, 76),
  },

  // ── 35. Fake eBay Account/Listing Kit ─────────────────
  // Long-documented category, over a decade in circulation
  {
    kitId:       "FAKE_EBAY",
    kitName:     "Fake eBay Account/Listing Kit",
    version:     "various",
    targetBrands:["ebay"],
    sophistication:"low",
    description: "eBay account suspension and fake listing notification kit. Long-documented category dating back over a decade, still actively distributed.",
    urlSignals: [
      /\/ebay\/(?:account|listing|suspend|verify)/i,
    ],
    domainSignals: [
      (d) => /ebay(?:-?(?:account|listing|suspend|verify|secure))/i.test(d),
    ],
    pathSignals: [
      /\?(?:item|listing)=\d{9,12}/i,
    ],
    confidence: (matches) => Math.min(matches * 22, 75),
  },

  // ── 36. Fake Shopify Merchant Portal Kit ──────────────
  // Documented by: Shopify security team (2023)
  {
    kitId:       "FAKE_SHOPIFY",
    kitName:     "Fake Shopify Merchant Portal Kit",
    version:     "2023+",
    targetBrands:["shopify"],
    sophistication:"medium",
    description: "Shopify merchant account phishing targeting store owners, harvests payment processor credentials. Documented by Shopify security team 2023.",
    urlSignals: [
      /\/shopify\/(?:admin|merchant|payout|login)/i,
    ],
    domainSignals: [
      (d) => /shopify(?:-?(?:admin|merchant|payout|secure|login))/i.test(d),
    ],
    pathSignals: [
      /\?(?:store|shop)=[a-zA-Z0-9-]{4,}\.myshopify/i,
    ],
    confidence: (matches) => Math.min(matches * 27, 82),
  },

  // ── 37. Fake Etsy Seller Verification Kit ─────────────
  // Documented by: Etsy trust & safety advisories
  {
    kitId:       "FAKE_ETSY",
    kitName:     "Fake Etsy Seller Verification Kit",
    version:     "2022+",
    targetBrands:["etsy"],
    sophistication:"low",
    description: "Etsy seller account and payment verification phishing kit. Documented in Etsy trust & safety advisories.",
    urlSignals: [
      /\/etsy\/(?:seller|shop|payment|verify)/i,
    ],
    domainSignals: [
      (d) => /etsy(?:-?(?:seller|shop|payment|verify|secure))/i.test(d),
    ],
    pathSignals: [
      /\?(?:shopid|seller)=[a-zA-Z0-9]{6,}/i,
    ],
    confidence: (matches) => Math.min(matches * 22, 75),
  },

  // ── 38. Fake Best Buy/Geek Squad Renewal Kit ──────────
  // Documented by: FBI IC3 (multiple alerts)
  {
    kitId:       "FAKE_BESTBUY_GEEKSQUAD",
    kitName:     "Fake Best Buy/Geek Squad Renewal Kit",
    version:     "various",
    targetBrands:["best buy","geek squad"],
    sophistication:"low",
    description: "Geek Squad subscription auto-renewal phishing/vishing hybrid kit, frequently paired with phone scam follow-up. FBI IC3 has issued multiple alerts on this category.",
    urlSignals: [
      /\/(?:geeksquad|bestbuy)\/(?:renewal|cancel|invoice)/i,
    ],
    domainSignals: [
      (d) => /(?:geeksquad|bestbuy)(?:-?(?:renewal|invoice|support|secure))/i.test(d),
    ],
    pathSignals: [
      /\?(?:invoice|order)=[A-Z0-9]{8,}/i,
    ],
    confidence: (matches) => Math.min(matches * 22, 74),
  },

  // ── 39. Fake Telecom Bill/Suspension Kit ──────────────
  // Documented by: CISA consumer alerts
  {
    kitId:       "FAKE_TELECOM_BILL",
    kitName:     "Fake Telecom Bill/Suspension Kit",
    version:     "various",
    targetBrands:["at&t","verizon","t-mobile","vodafone","ee"],
    sophistication:"low",
    description: "Generic telecom billing/suspension phishing kit template reused across carriers globally. High-frequency category per CISA consumer alerts.",
    urlSignals: [
      /\/(?:att|verizon|tmobile|vodafone)\/(?:bill|suspend|pay|verify)/i,
    ],
    domainSignals: [
      (d) => /(?:att|verizon|tmobile|vodafone|ee)(?:-?(?:bill|pay|suspend|secure|verify))/i.test(d),
    ],
    pathSignals: [
      /\?(?:account|acct)=\d{9,12}/i,
    ],
    confidence: (matches) => Math.min(matches * 22, 75),
  },

  // ── 40. Fake SIM Swap / Port-Out Verification Kit ─────
  // Documented by: FCC, FBI advisories on SIM swapping fraud
  {
    kitId:       "FAKE_SIM_SWAP",
    kitName:     "Fake SIM Swap / Port-Out Verification Kit",
    version:     "2023+",
    targetBrands:["various carriers"],
    sophistication:"high",
    description: "SIM-swap precursor phishing kit harvesting carrier PIN and account credentials to enable account takeover. Documented in FCC and FBI advisories on SIM swapping fraud.",
    urlSignals: [
      /\/(?:sim|port)(?:-?(?:swap|transfer|out))\/(?:verify|confirm)/i,
    ],
    domainSignals: [
      (d) => /(?:sim|carrier)(?:-?(?:verify|transfer|secure))/i.test(d),
    ],
    pathSignals: [
      /\?(?:pin|iccid)=\d{4,20}/i,
    ],
    confidence: (matches) => Math.min(matches * 30, 86),
  },

  // ── 41. Fake Netflix Billing Update Kit ───────────────
  // Consistently in APWG top-10 impersonated brands
  {
    kitId:       "FAKE_NETFLIX_BILLING",
    kitName:     "Fake Netflix Billing Update Kit",
    version:     "various",
    targetBrands:["netflix"],
    sophistication:"low",
    description: "One of the most widely-templated phishing kits globally — fake billing/payment update lure. Consistently in APWG top-10 impersonated brands.",
    urlSignals: [
      /\/netflix\/(?:billing|payment|update|verify|account)/i,
    ],
    domainSignals: [
      (d) => /netflix(?:-?(?:billing|payment|update|verify|secure|account))/i.test(d),
    ],
    pathSignals: [
      /\?(?:member|account)=[a-zA-Z0-9]{8,}/i,
    ],
    confidence: (matches) => Math.min(matches * 22, 76),
  },

  // ── 42. Fake Spotify Premium/Family Kit ───────────────
  {
    kitId:       "FAKE_SPOTIFY",
    kitName:     "Fake Spotify Premium/Family Kit",
    version:     "2022+",
    targetBrands:["spotify"],
    sophistication:"low",
    description: "Spotify Premium/Family plan billing phishing kit, frequently distributed via SMS and social media ads.",
    urlSignals: [
      /\/spotify\/(?:premium|family|billing|verify)/i,
    ],
    domainSignals: [
      (d) => /spotify(?:-?(?:premium|family|billing|secure))/i.test(d),
    ],
    pathSignals: [
      /\?(?:plan|sub)=(?:premium|family)/i,
    ],
    confidence: (matches) => Math.min(matches * 20, 72),
  },

  // ── 43. Fake Disney+ Account Suspended Kit ────────────
  // Surged after platform's password-sharing crackdown (2023)
  {
    kitId:       "FAKE_DISNEY_PLUS",
    kitName:     "Fake Disney+ Account Suspended Kit",
    version:     "2022+",
    targetBrands:["disney+","disney"],
    sophistication:"low",
    description: "Disney+ account suspension/billing phishing kit. Surged following platform's password-sharing crackdown in 2023.",
    urlSignals: [
      /\/disney(?:plus)?\/(?:suspend|billing|verify|account)/i,
    ],
    domainSignals: [
      (d) => /disney(?:plus)?(?:-?(?:suspend|billing|verify|secure))/i.test(d),
    ],
    pathSignals: [
      /\?(?:profile|account)=[a-zA-Z0-9]{6,}/i,
    ],
    confidence: (matches) => Math.min(matches * 20, 72),
  },

  // ── 44. Fake Health Insurance Open Enrollment Kit ─────
  // Documented by: FTC, HHS-OIG (recurring annual warnings)
  {
    kitId:       "FAKE_HEALTH_INSURANCE",
    kitName:     "Fake Health Insurance Open Enrollment Kit",
    version:     "various",
    targetBrands:["various insurers","aca marketplace"],
    sophistication:"medium",
    description: "Open-enrollment season health insurance phishing kit, harvests SSN and Medicare numbers. FTC and HHS-OIG have issued repeated annual warnings on this category.",
    urlSignals: [
      /\/(?:insurance|medicare|aca)\/(?:enroll|verify|update)/i,
    ],
    domainSignals: [
      (d) => /(?:insurance|medicare|healthcare)(?:-?(?:enroll|verify|marketplace|secure))/i.test(d),
    ],
    pathSignals: [
      /\?(?:ssn|medicare)=[\dX-]{9,12}/i,
    ],
    confidence: (matches) => Math.min(matches * 28, 84),
  },

  // ── 45. Fake Pharmacy Refill/Prescription Kit ─────────
  // Documented by: FDA, FTC consumer alerts
  {
    kitId:       "FAKE_PHARMACY_REFILL",
    kitName:     "Fake Pharmacy Refill/Prescription Kit",
    version:     "various",
    targetBrands:["cvs","walgreens","various pharmacies"],
    sophistication:"low",
    description: "Pharmacy prescription refill reminder phishing kit, often paired with payment-card harvesting. Documented in FDA and FTC consumer alerts.",
    urlSignals: [
      /\/(?:cvs|walgreens|pharmacy)\/(?:refill|prescription|pay)/i,
    ],
    domainSignals: [
      (d) => /(?:cvs|walgreens|pharmacy)(?:-?(?:refill|prescription|secure))/i.test(d),
    ],
    pathSignals: [
      /\?(?:rx|script)=[A-Z0-9]{6,}/i,
    ],
    confidence: (matches) => Math.min(matches * 22, 75),
  },

  // ── 46. Fake Social Security Administration Kit ───────
  // Documented by: SSA-OIG (recurring public warnings)
  {
    kitId:       "FAKE_SOCIAL_SECURITY",
    kitName:     "Fake Social Security Administration Kit",
    version:     "various",
    targetBrands:["ssa","social security"],
    sophistication:"medium",
    description: "SSA benefit suspension/identity-theft scare kit, frequently vishing-paired. SSA-OIG publishes recurring public warnings on this exact pattern.",
    urlSignals: [
      /\/ssa\/(?:benefit|suspend|verify|identity)/i,
      /\/social-?security\/(?:verify|suspend)/i,
    ],
    domainSignals: [
      (d) => /(?:ssa|socialsecurity)(?:-?(?:gov|verify|benefit|secure))/i.test(d),
    ],
    pathSignals: [
      /\?(?:ssn|claim)=[\dX-]{9,11}/i,
    ],
    confidence: (matches) => Math.min(matches * 28, 84),
  },

  // ── 47. Fake DMV/Vehicle Registration Kit ─────────────
  // Documented by: FBI IC3 PSA (April 2024) due to high volume
  {
    kitId:       "FAKE_DMV_VEHICLE",
    kitName:     "Fake DMV/Vehicle Registration Kit",
    version:     "2023+",
    targetBrands:["dmv","various state agencies"],
    sophistication:"low",
    description: "Unpaid toll / vehicle registration renewal smishing kit. FBI IC3 issued a specific PSA on this exact pattern in April 2024 due to volume.",
    urlSignals: [
      /\/(?:dmv|toll|registration)\/(?:pay|renew|verify)/i,
    ],
    domainSignals: [
      (d) => /(?:dmv|toll|ezpass|fastrak)(?:-?(?:pay|renew|secure|gov))/i.test(d),
    ],
    pathSignals: [
      /\?(?:plate|vin)=[A-Z0-9]{6,17}/i,
    ],
    confidence: (matches) => Math.min(matches * 24, 78),
  },

  // ── 48. Fake Unemployment Benefits Kit ────────────────
  // Surged during 2020-2021 pandemic claims period
  {
    kitId:       "FAKE_UNEMPLOYMENT",
    kitName:     "Fake Unemployment Benefits Kit",
    version:     "2020+",
    targetBrands:["state unemployment agencies"],
    sophistication:"medium",
    description: "Unemployment benefits phishing kit, surged dramatically during 2020-2021 pandemic claims surge. Documented extensively by state labor department fraud units.",
    urlSignals: [
      /\/unemployment\/(?:claim|verify|benefit)/i,
    ],
    domainSignals: [
      (d) => /unemployment(?:-?(?:claim|verify|benefit|secure|gov))/i.test(d),
    ],
    pathSignals: [
      /\?(?:claimid|ssn)=[\dX-]{6,11}/i,
    ],
    confidence: (matches) => Math.min(matches * 26, 82),
  },

  // ── 49. Fake USPS Informed Delivery Kit ───────────────
  // Documented by: USPS Inspection Service
  {
    kitId:       "FAKE_USPS_INFORMED_DELIVERY",
    kitName:     "Fake USPS Informed Delivery Kit",
    version:     "2022+",
    targetBrands:["usps"],
    sophistication:"medium",
    description: "USPS Informed Delivery account phishing kit, distinct from generic package-delivery smishing — targets the actual USPS.com login. Documented by USPS Inspection Service.",
    urlSignals: [
      /\/usps\/(?:informed-?delivery|account|login)/i,
    ],
    domainSignals: [
      (d) => /usps(?:-?(?:informeddelivery|account|secure|gov))/i.test(d),
    ],
    pathSignals: [
      /\?(?:profile|account)=[a-zA-Z0-9]{8,}/i,
    ],
    confidence: (matches) => Math.min(matches * 25, 80),
  },

  // ── 50. Rockstar2FA / Rusty 2FA ───────────────────────
  // Documented by: Trustwave SpiderLabs (2024-2025)
  {
    kitId:       "RUSTY_2FA",
    kitName:     "Rockstar2FA / Rusty 2FA",
    version:     "2024+",
    targetBrands:["microsoft"],
    sophistication:"expert",
    description: "AiTM PhaaS platform built in Rust, successor lineage to Dadsec/Phoenix kits. Documented by Trustwave SpiderLabs in 2024-2025, evades static detection via compiled binary backend.",
    urlSignals: [
      /\/(?:rs2fa|rockstar)\/(?:auth|verify)/i,
    ],
    domainSignals: [
      (d) => /^[a-z]{4,7}-?[a-z]{4,7}\.(?:cfd|sbs|icu|cyou)$/.test(d),
    ],
    pathSignals: [
      /\?[a-z]{1,3}=[A-Za-z0-9]{25,}&[a-z]{1,3}=/i,
    ],
    confidence: (matches) => Math.min(matches * 36, 93),
  },

  // ── 51. Gabagool (AiTM PhaaS) ─────────────────────────
  // Documented by: Microsoft Threat Intelligence (2024)
  {
    kitId:       "GABAGOOL_PHAAS",
    kitName:     "Gabagool",
    version:     "2024+",
    targetBrands:["microsoft","google"],
    sophistication:"expert",
    description: "AiTM PhaaS kit documented by Microsoft Threat Intelligence in 2024, part of the broader 'Storm' actor-tracked AiTM ecosystem.",
    urlSignals: [
      /\/(?:gbg|gabagool)\/(?:session|verify)/i,
    ],
    domainSignals: [
      (d) => /^[a-z0-9]{6,10}\.(?:sbs|cyou|cfd)$/.test(d),
    ],
    pathSignals: [
      /\?s=[a-zA-Z0-9]{32,}/,
    ],
    confidence: (matches) => Math.min(matches * 35, 92),
  },

  // ── 52. Dadsec / Phoenix ───────────────────────────────
  // Documented by: Microsoft MSTIC, Trustwave (2023-2024)
  {
    kitId:       "DADSEC_PHOENIX",
    kitName:     "Dadsec / Phoenix",
    version:     "2023+",
    targetBrands:["microsoft"],
    sophistication:"expert",
    description: "AiTM PhaaS platform, predecessor lineage to Rockstar2FA. Documented by Microsoft MSTIC and Trustwave 2023-2024, sold via Telegram subscription.",
    urlSignals: [
      /\/(?:dadsec|phoenix)\/(?:login|auth)/i,
    ],
    domainSignals: [
      (d) => /^[a-z]{5,8}[0-9]{1,3}\.(?:xyz|top|live)$/.test(d),
    ],
    pathSignals: [
      /\?token=[a-zA-Z0-9]{30,}/,
    ],
    confidence: (matches) => Math.min(matches * 35, 91),
  },

  // ── 53. Fake Airline E-Ticket/Refund Kit ──────────────
  // Documented by: TSA, airline fraud advisories
  {
    kitId:       "FAKE_AIRLINE_ETICKET",
    kitName:     "Fake Airline E-Ticket/Refund Kit",
    version:     "various",
    targetBrands:["various airlines"],
    sophistication:"low",
    description: "Airline e-ticket confirmation / flight cancellation refund phishing kit. Recurring category in TSA and airline fraud advisories, spikes around holiday travel seasons.",
    urlSignals: [
      /\/(?:airline|flight)\/(?:eticket|refund|cancel|verify)/i,
    ],
    domainSignals: [
      (d) => /(?:airline|flight|eticket)(?:-?(?:refund|confirm|secure))/i.test(d),
    ],
    pathSignals: [
      /\?(?:pnr|confirmation)=[A-Z0-9]{6}/i,
    ],
    confidence: (matches) => Math.min(matches * 22, 75),
  },

  // ── 54. Fake Airbnb Booking/Host Payout Kit ───────────
  // Documented by: Airbnb trust & safety transparency reports
  {
    kitId:       "FAKE_AIRBNB_BOOKING",
    kitName:     "Fake Airbnb Booking/Host Payout Kit",
    version:     "2022+",
    targetBrands:["airbnb"],
    sophistication:"medium",
    description: "Airbnb fake booking request and host payout phishing kit, targets both guests and hosts with off-platform payment lures. Documented in Airbnb trust & safety transparency reports.",
    urlSignals: [
      /\/airbnb\/(?:booking|payout|verify|host)/i,
    ],
    domainSignals: [
      (d) => /airbnb(?:-?(?:booking|payout|verify|secure|host))/i.test(d),
    ],
    pathSignals: [
      /\?(?:reservation|listing)=[a-zA-Z0-9]{8,}/i,
    ],
    confidence: (matches) => Math.min(matches * 24, 78),
  },

  // ── 55. Fake Booking.com/Hotel Confirmation Kit ───────
  // Documented by: Booking.com security advisories (2023)
  {
    kitId:       "FAKE_BOOKING_HOTEL",
    kitName:     "Fake Booking.com/Hotel Confirmation Kit",
    version:     "2023+",
    targetBrands:["booking.com","various hotels"],
    sophistication:"medium",
    description: "Hotel booking confirmation phishing kit impersonating Booking.com/Expedia messaging systems, often delivered via the platform's own compromised message threads. Documented by Booking.com security advisories 2023.",
    urlSignals: [
      /\/(?:booking|hotel)\/(?:confirm|verify|payment)/i,
    ],
    domainSignals: [
      (d) => /(?:booking|hotels)(?:-?(?:confirm|verify|secure|payment))/i.test(d),
    ],
    pathSignals: [
      /\?(?:reservation|confirmation)=\d{8,12}/i,
    ],
    confidence: (matches) => Math.min(matches * 24, 79),
  },

  // ── 56. Fake Steam Gift/Trade Kit ─────────────────────
  // Documented by: Valve community warnings
  {
    kitId:       "FAKE_STEAM_GIFT",
    kitName:     "Fake Steam Gift/Trade Kit",
    version:     "various",
    targetBrands:["steam","valve"],
    sophistication:"medium",
    description: "Steam account phishing via fake gift offers and trade requests, frequently distributed via Discord and gaming forums. Valve has published repeated community warnings.",
    urlSignals: [
      /\/steam(?:community)?\/(?:gift|trade|login)/i,
    ],
    domainSignals: [
      (d) => /steam(?:community)?(?:-?(?:gift|trade|secure|login))/i.test(d),
    ],
    pathSignals: [
      /\?(?:tradeoffer|partner)=\d{8,}/i,
    ],
    confidence: (matches) => Math.min(matches * 24, 78),
  },

  // ── 57. Fake Discord Nitro Kit ─────────────────────────
  // Documented by: Discord trust & safety team
  {
    kitId:       "FAKE_DISCORD_NITRO",
    kitName:     "Fake Discord Nitro Kit",
    version:     "various",
    targetBrands:["discord"],
    sophistication:"medium",
    description: "Discord Nitro free-gift phishing kit, one of the highest-volume Discord-targeted phishing categories, extensively documented by Discord's own trust & safety team.",
    urlSignals: [
      /\/discord\/(?:nitro|gift|verify)/i,
      /\/dlscord|d1scord/i,
    ],
    domainSignals: [
      (d) => /(?:discord|dlscord|d1scord)(?:-?(?:nitro|gift|secure))/i.test(d),
    ],
    pathSignals: [
      /\?(?:code|gift)=[a-zA-Z0-9]{16,}/i,
    ],
    confidence: (matches) => Math.min(matches * 26, 81),
  },

  // ── 58. Fake Roblox Robux Generator Kit ───────────────
  // Documented by: Roblox parental safety advisories
  {
    kitId:       "FAKE_ROBLOX",
    kitName:     "Fake Roblox Robux Generator Kit",
    version:     "various",
    targetBrands:["roblox"],
    sophistication:"low",
    description: "Roblox 'free Robux generator' credential-harvesting kit, primarily targets minors. Documented extensively in Roblox parental safety advisories.",
    urlSignals: [
      /\/roblox\/(?:robux|generator|free)/i,
    ],
    domainSignals: [
      (d) => /roblox(?:-?(?:robux|free|generator|gen))/i.test(d),
    ],
    pathSignals: [
      /\?(?:user|player)=[a-zA-Z0-9_]{3,20}/i,
    ],
    confidence: (matches) => Math.min(matches * 20, 72),
  },

  // ── 59. Fake Epic Games/Fortnite V-Bucks Kit ──────────
  // Documented by: Epic Games community alerts
  {
    kitId:       "FAKE_EPIC_FORTNITE",
    kitName:     "Fake Epic Games/Fortnite V-Bucks Kit",
    version:     "various",
    targetBrands:["epic games","fortnite"],
    sophistication:"low",
    description: "Fortnite V-Bucks generator and Epic Games account phishing kit. Epic Games has published numerous community alerts on this category.",
    urlSignals: [
      /\/(?:epicgames|fortnite)\/(?:vbucks|generator|login)/i,
    ],
    domainSignals: [
      (d) => /(?:epicgames|fortnite)(?:-?(?:vbucks|free|generator))/i.test(d),
    ],
    pathSignals: [
      /\?(?:account|epicid)=[a-zA-Z0-9_]{3,16}/i,
    ],
    confidence: (matches) => Math.min(matches * 20, 72),
  },

  // ── 60. Fake Slack Workspace Invite Kit ───────────────
  // Documented by: Slack security team
  {
    kitId:       "FAKE_SLACK_WORKSPACE",
    kitName:     "Fake Slack Workspace Invite Kit",
    version:     "2023+",
    targetBrands:["slack"],
    sophistication:"medium",
    description: "Slack workspace invite / admin verification phishing kit targeting enterprise credentials. Documented by Slack security team and used in supply-chain BEC attacks.",
    urlSignals: [
      /\/slack\/(?:workspace|invite|admin|verify)/i,
    ],
    domainSignals: [
      (d) => /slack(?:-?(?:workspace|invite|admin|secure))/i.test(d),
    ],
    pathSignals: [
      /\?(?:team|workspace)=[a-zA-Z0-9-]{4,}/i,
    ],
    confidence: (matches) => Math.min(matches * 26, 81),
  },

  // ── 61. Fake Dropbox Shared File Kit ──────────────────
  // In continuous circulation for over a decade
  {
    kitId:       "FAKE_DROPBOX_SHARE",
    kitName:     "Fake Dropbox Shared File Kit",
    version:     "various",
    targetBrands:["dropbox"],
    sophistication:"medium",
    description: "Dropbox shared-document phishing kit, classic credential harvester via fake 'someone shared a file with you' lure, in continuous circulation for over a decade.",
    urlSignals: [
      /\/dropbox\/(?:share|file|login|verify)/i,
    ],
    domainSignals: [
      (d) => /dropbox(?:-?(?:share|secure|verify|login))/i.test(d),
    ],
    pathSignals: [
      /\?(?:file|doc)=[a-zA-Z0-9_-]{10,}/i,
    ],
    confidence: (matches) => Math.min(matches * 25, 80),
  },

  // ── 62. Fake Google Drive/Docs Share Kit ──────────────
  // Abuses real Google infrastructure — especially evasive
  {
    kitId:       "FAKE_GOOGLE_DRIVE",
    kitName:     "Fake Google Drive/Docs Share Kit",
    version:     "various",
    targetBrands:["google"],
    sophistication:"medium",
    description: "Google Drive/Docs shared-document phishing kit, frequently abuses real Google infrastructure (legitimate docs.google.com links pointing to external phishing redirects) making it especially evasive.",
    urlSignals: [
      /\/(?:drive|docs)\.google\.com.*(?:redirect|continue)=/i,
      /\/google-?drive\/(?:share|verify)/i,
    ],
    domainSignals: [
      (d) => /google-?(?:drive|docs)(?:-?(?:share|secure|verify))/i.test(d),
    ],
    pathSignals: [
      /\?(?:continue|redirect)=https?%3A/i,
    ],
    confidence: (matches) => Math.min(matches * 27, 83),
  },

  // ── 63. Fake Adobe Creative Cloud Kit ─────────────────
  {
    kitId:       "FAKE_ADOBE_CREATIVE",
    kitName:     "Fake Adobe Creative Cloud Kit",
    version:     "2022+",
    targetBrands:["adobe"],
    sophistication:"medium",
    description: "Adobe Creative Cloud subscription/license expiration phishing kit, targets creative professionals and enterprise license admins.",
    urlSignals: [
      /\/adobe\/(?:creativecloud|license|subscription|verify)/i,
    ],
    domainSignals: [
      (d) => /adobe(?:-?(?:creativecloud|license|secure|verify))/i.test(d),
    ],
    pathSignals: [
      /\?(?:license|sub)=[a-zA-Z0-9-]{8,}/i,
    ],
    confidence: (matches) => Math.min(matches * 24, 79),
  },

  // ── 64. Pig Butchering / Investment Scam Kit ──────────
  // Documented by: FBI IC3, UN trafficking reports, FTC
  {
    kitId:       "PIG_BUTCHERING",
    kitName:     "Pig Butchering / Investment Scam Kit",
    version:     "2022+",
    targetBrands:["fake crypto exchanges","fake trading platforms"],
    sophistication:"high",
    description: "Long-con romance/investment scam kit ('Sha Zhu Pan'), combines fake trading platform UI with sustained social engineering. Extensively documented by FBI IC3, UN human trafficking reports (linked to forced-labor scam compounds), and FTC.",
    urlSignals: [
      /\/(?:invest|trading|portfolio)\/(?:deposit|withdraw|verify)/i,
    ],
    domainSignals: [
      (d) => /(?:invest|trading|asset|wealth)(?:-?(?:pro|global|secure|platform))/i.test(d),
    ],
    pathSignals: [
      /\?(?:uid|account)=[a-zA-Z0-9]{10,}/i,
    ],
    confidence: (matches) => Math.min(matches * 30, 86),
  },

  // ── 65. Fake Utility Disconnection Kit ────────────────
  // Documented by: FTC, state utility commissions (seasonal warnings)
  {
    kitId:       "FAKE_UTILITY_DISCONNECT",
    kitName:     "Fake Utility Disconnection Kit",
    version:     "various",
    targetBrands:["various electric/gas utilities"],
    sophistication:"low",
    description: "Utility shutoff threat phishing/vishing kit, extremely common during extreme weather seasons. FTC and state utility commissions issue recurring seasonal warnings.",
    urlSignals: [
      /\/(?:utility|electric|gas)\/(?:pay|disconnect|verify)/i,
    ],
    domainSignals: [
      (d) => /(?:utility|power|electric|energy)(?:-?(?:pay|secure|disconnect))/i.test(d),
    ],
    pathSignals: [
      /\?(?:account|meter)=\d{8,12}/i,
    ],
    confidence: (matches) => Math.min(matches * 22, 75),
  },
];

// ═══════════════════════════════════════════════════════
// KIT IDENTIFICATION ENGINE
// ═══════════════════════════════════════════════════════

function extractDomain(url) {
  try {
    const u = url.startsWith("http") ? url : `https://${url}`;
    return new URL(u).hostname.toLowerCase();
  } catch { return url.toLowerCase(); }
}

function extractPath(url) {
  try {
    const u = url.startsWith("http") ? url : `https://${url}`;
    return new URL(u).pathname + new URL(u).search;
  } catch { return url; }
}

// ── Match a single URL against all kit signatures ──
function identifyKit(url, issues = [], attackTypes = []) {
  if (!url) return null;

  const domain   = extractDomain(url);
  const path     = extractPath(url);
  const fullUrl  = url.toLowerCase();

  const results = [];

  for (const kit of KIT_SIGNATURES) {
    let matchCount = 0;
    const matchedSignals = [];

    // URL pattern signals
    for (const signal of kit.urlSignals || []) {
      if (signal.test(fullUrl)) {
        matchCount++;
        matchedSignals.push("url_pattern");
      }
    }

    // Domain signals
    for (const signal of kit.domainSignals || []) {
      if (typeof signal === "function" ? signal(domain) : signal.test(domain)) {
        matchCount++;
        matchedSignals.push("domain_pattern");
      }
    }

    // Path signals
    for (const signal of kit.pathSignals || []) {
      if (signal.test(path)) {
        matchCount++;
        matchedSignals.push("path_pattern");
      }
    }

    // Boost if attack types match known kit targets
    if (attackTypes.some(a => /brand_impersonation|typosquatting|aitm/i.test(a))) {
      if (kit.sophistication === "expert") matchCount += 0.5;
    }

    if (matchCount >= 1) {
      const confidence = kit.confidence(matchCount);
      if (confidence >= 35) { // minimum confidence threshold
        results.push({
          kitId:       kit.kitId,
          kitName:     kit.kitName,
          version:     kit.version,
          targetBrands:kit.targetBrands,
          sophistication: kit.sophistication,
          description: kit.description,
          confidence,
          matchCount:  Math.floor(matchCount),
          matchedSignals: [...new Set(matchedSignals)],
        });
      }
    }
  }

  if (results.length === 0) return null;

  // Return best match (highest confidence)
  results.sort((a, b) => b.confidence - a.confidence);
  return results[0];
}

// ── Batch: identify kits across all phishing scans ──
async function identifyKitsFromDatabase() {
  const Scan = require("../models/Scan");
  const since30d = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);

  const phishingScans = await Scan.find(
    { status: "phishing", inputType: "url", createdAt: { $gte: since30d } },
    { input:1, issues:1, attackTypes:1, "dna.brand":1, "dna.technique":1, createdAt:1 }
  ).limit(500).lean();

  const kitStats = {};

  for (const scan of phishingScans) {
    const match = identifyKit(scan.input, scan.issues || [], scan.attackTypes || []);
    if (!match) continue;

    if (!kitStats[match.kitId]) {
      kitStats[match.kitId] = {
        ...match,
        detections:     0,
        firstSeen:      scan.createdAt,
        lastSeen:       scan.createdAt,
        targetedBrands: new Set(),
        sampleInputs:   [],
      };
    }
    const stat = kitStats[match.kitId];
    stat.detections++;
    stat.lastSeen  = scan.createdAt;
    if (scan.dna?.brand && scan.dna.brand !== "unknown") stat.targetedBrands.add(scan.dna.brand);
    if (stat.sampleInputs.length < 3) stat.sampleInputs.push(scan.input.substring(0, 80));
  }

  return Object.values(kitStats)
    .map(k => ({
      ...k,
      targetedBrands: [...k.targetedBrands],
    }))
    .sort((a, b) => b.detections - a.detections);
}

// ── Generate kit threat hash ──
function generateKitHash(kitId, domain) {
  return crypto.createHash("sha256")
    .update(`${kitId}::${domain}`)
    .digest("hex").slice(0, 12).toUpperCase();
}

// ── Sophistication label + metadata ──
const SOPHISTICATION_META = {
  low:    { color:"#00ff88", label:"Low",    mitre:"T1566 - Phishing",               riskMod: 0 },
  medium: { color:"#f5a623", label:"Medium", mitre:"T1566.002 - Spearphishing Link", riskMod:10 },
  high:   { color:"#f97316", label:"High",   mitre:"T1566.002 - Spearphishing Link", riskMod:15 },
  expert: { color:"#ff4444", label:"Expert", mitre:"T1557 - Adversary-in-the-Middle",riskMod:20 },
};

// ── Return ALL kit matches above threshold (not just top-1) ──
// Useful when a URL matches multiple kit patterns (e.g. AiTM + PhaaS overlap)
function getAllKitMatches(url, issues = [], attackTypes = []) {
  if (!url) return [];

  const domain  = extractDomain(url);
  const path    = extractPath(url);
  const fullUrl = url.toLowerCase();
  const results = [];

  for (const kit of KIT_SIGNATURES) {
    let matchCount = 0;
    const matchedSignals = [];

    for (const signal of kit.urlSignals || []) {
      if (signal.test(fullUrl)) { matchCount++; matchedSignals.push("url_pattern"); }
    }
    for (const signal of kit.domainSignals || []) {
      if (typeof signal === "function" ? signal(domain) : signal.test(domain)) {
        matchCount++; matchedSignals.push("domain_pattern");
      }
    }
    for (const signal of kit.pathSignals || []) {
      if (signal.test(path)) { matchCount++; matchedSignals.push("path_pattern"); }
    }
    if (attackTypes.some(a => /brand_impersonation|typosquatting|aitm/i.test(a))) {
      if (kit.sophistication === "expert") matchCount += 0.5;
    }

    if (matchCount >= 1) {
      const confidence = kit.confidence(matchCount);
      if (confidence >= 35) {
        results.push({
          kitId:          kit.kitId,
          kitName:        kit.kitName,
          version:        kit.version,
          targetBrands:   kit.targetBrands,
          sophistication: kit.sophistication,
          description:    kit.description,
          confidence,
          matchCount:     Math.floor(matchCount),
          matchedSignals: [...new Set(matchedSignals)],
        });
      }
    }
  }

  return results.sort((a, b) => b.confidence - a.confidence);
}

// ── Enrich a kit match with MITRE sub-techniques, recommended actions, and threat hash ──
function getKitRiskProfile(kitMatch, url = "") {
  if (!kitMatch) return null;

  const sophMeta = SOPHISTICATION_META[kitMatch.sophistication] || SOPHISTICATION_META.low;
  const domain   = url ? extractDomain(url) : "";
  const hash     = domain ? generateKitHash(kitMatch.kitId, domain) : null;

  // MITRE sub-technique mapping per kit
  const MITRE_MAP = {
    EVILPROXY:        { id:"T1557.001", name:"LLMNR/NBT-NS Poisoning and SMB Relay" },
    EVILGINX2:        { id:"T1557",     name:"Adversary-in-the-Middle" },
    MODLISHKA:        { id:"T1557",     name:"Adversary-in-the-Middle" },
    TYCOON_2FA:       { id:"T1557",     name:"Adversary-in-the-Middle" },
    GREATNESS_PHAAS:  { id:"T1557",     name:"Adversary-in-the-Middle" },
    SNEAKY_LOG:       { id:"T1557",     name:"Adversary-in-the-Middle" },
    MAMBA_2FA:        { id:"T1557",     name:"Adversary-in-the-Middle" },
    RUSTY_2FA:        { id:"T1557",     name:"Adversary-in-the-Middle" },
    GABAGOOL_PHAAS:   { id:"T1557",     name:"Adversary-in-the-Middle" },
    DADSEC_PHOENIX:   { id:"T1557",     name:"Adversary-in-the-Middle" },
    W3LL_PANEL:       { id:"T1566.002", name:"Spearphishing Link — BEC" },
    CAFFEINE_PHAAS:   { id:"T1566.002", name:"Spearphishing Link" },
    ROBIN_BANKS:      { id:"T1566.002", name:"Spearphishing Link — Banking" },
    GROZIO_BANKING:   { id:"T1566.002", name:"Spearphishing Link — Banking" },
    DARCULA_PHAAS:    { id:"T1566.003", name:"Spearphishing via Service (SMS/RCS)" },
    KR3PTO:           { id:"T1566.003", name:"Spearphishing via Service (SMS)" },
    SMISHING_DELIVERY:{ id:"T1566.003", name:"Spearphishing via Service (SMS)" },
    FAKE_DMV_VEHICLE: { id:"T1566.003", name:"Spearphishing via Service (SMS)" },
    CRYPTO_DRAINER:   { id:"T1539",     name:"Steal Web Session Cookie / Wallet Drain" },
    FAKE_COINBASE:    { id:"T1539",     name:"Steal Web Session Cookie" },
    GOV_TAX_KIT:      { id:"T1598.003", name:"Spearphishing Link — Gov Impersonation" },
    FAKE_HR_PAYROLL:  { id:"T1598.003", name:"Spearphishing Link — BEC Payroll" },
    FAKE_SOCIAL_SECURITY: { id:"T1598.003", name:"Spearphishing Link — Gov Impersonation" },
    FAKE_UNEMPLOYMENT:    { id:"T1598.003", name:"Spearphishing Link — Gov Impersonation" },
    FAKE_HEALTH_INSURANCE:{ id:"T1598.003", name:"Spearphishing Link — PII Harvest" },
    FAKE_SIM_SWAP:    { id:"T1586.002", name:"Compromise Accounts — Telecom Pretext" },
    QUISHING_KIT:     { id:"T1566.002", name:"Spearphishing Link — QR Code" },
    FAKE_DOCUSIGN:    { id:"T1566.002", name:"Spearphishing Attachment — Lure" },
    FAKE_ZOOM:        { id:"T1566.002", name:"Spearphishing Link — Meeting Lure" },
    FAKE_AWS_CONSOLE: { id:"T1078.004", name:"Valid Accounts — Cloud Accounts" },
    FAKE_TEAMS_O365:  { id:"T1566.002", name:"Spearphishing Link — O365" },
    FAKE_SLACK_WORKSPACE: { id:"T1566.002", name:"Spearphishing Link — SaaS" },
    FAKE_LINKEDIN:    { id:"T1566.002", name:"Spearphishing Link — Social Engineering" },
    PIG_BUTCHERING:   { id:"T1566.002", name:"Spearphishing Link — Investment Fraud" },
  };

  // Recommended analyst actions per sophistication
  const ACTIONS_MAP = {
    expert: [
      "Escalate to Tier-3 analyst immediately",
      "Check for session token exfiltration in proxy logs",
      "Verify MFA bypass indicators in auth logs",
      "Block domain at DNS and proxy layer",
      "Submit to CISA / MS-ISAC for threat sharing",
    ],
    high: [
      "Escalate to Tier-2 analyst",
      "Block domain at perimeter firewall",
      "Check for credential reuse across internal systems",
      "Notify affected brand's abuse team",
      "Submit IOC to threat intel platform",
    ],
    medium: [
      "Block domain at email gateway and proxy",
      "Notify users who may have received related lures",
      "Check email logs for related phishing campaigns",
      "Submit to PhishTank / OpenPhish",
    ],
    low: [
      "Block URL at web proxy",
      "Submit to Google Safe Browsing / PhishTank",
      "Log IOC for future correlation",
    ],
  };

  const mitre   = MITRE_MAP[kitMatch.kitId] || { id: sophMeta.mitre.split(" ")[0], name: sophMeta.mitre };
  const actions = ACTIONS_MAP[kitMatch.sophistication] || ACTIONS_MAP.low;

  return {
    ...kitMatch,
    threatHash:         hash,
    mitre,
    sophMeta,
    recommendedActions: actions,
    iocType:            "url",
    tlp:                kitMatch.sophistication === "expert" ? "TLP:RED" : kitMatch.sophistication === "high" ? "TLP:AMBER" : "TLP:WHITE",
  };
}

// ── Paginated batch kit identification (for large datasets) ──
async function identifyKitsFromDatabasePaged({ page = 1, limit = 20, days = 30 } = {}) {
  const Scan = require("../models/Scan");
  const since = new Date(Date.now() - days * 24 * 60 * 60 * 1000);

  const phishingScans = await Scan.find(
    { status: "phishing", inputType: "url", createdAt: { $gte: since } },
    { input:1, issues:1, attackTypes:1, "dna.brand":1, "dna.technique":1, createdAt:1 }
  ).limit(2000).lean();

  const kitStats = {};

  for (const scan of phishingScans) {
    const match = identifyKit(scan.input, scan.issues || [], scan.attackTypes || []);
    if (!match) continue;

    if (!kitStats[match.kitId]) {
      kitStats[match.kitId] = {
        ...match,
        detections:     0,
        firstSeen:      scan.createdAt,
        lastSeen:       scan.createdAt,
        targetedBrands: new Set(),
        sampleInputs:   [],
      };
    }
    const stat = kitStats[match.kitId];
    stat.detections++;
    stat.lastSeen = scan.createdAt;
    if (scan.dna?.brand && scan.dna.brand !== "unknown") stat.targetedBrands.add(scan.dna.brand);
    if (stat.sampleInputs.length < 3) stat.sampleInputs.push(scan.input.substring(0, 80));
  }

  const all = Object.values(kitStats)
    .map(k => ({ ...k, targetedBrands: [...k.targetedBrands] }))
    .sort((a, b) => b.detections - a.detections);

  const total      = all.length;
  const startIndex = (page - 1) * limit;
  const items      = all.slice(startIndex, startIndex + limit);

  return {
    items,
    total,
    page,
    limit,
    pages:   Math.ceil(total / limit),
    hasMore: startIndex + limit < total,
  };
}

// ── HTML-based kit fingerprinting (from sandbox HTML) ──
// Analyzes HTML structure patterns to identify specific kit versions
// Purely passive — never executes code

const HTML_KIT_SIGNATURES = [
  {
    kitId:   "16SHOP_HTML",
    kitName: "16Shop (HTML Pattern)",
    patterns:[
      /\bgoLogin\s*=\s*function/i,
      /id=["']apple-login["']/i,
      /<title[^>]*>Apple ID</i,
      /class=["'][^"']*apple-form/i,
    ],
    minMatches: 2,
    confidence: 90,
  },
  {
    kitId:   "W3LL_HTML",
    kitName: "W3LL Panel (HTML Pattern)",
    patterns:[
      /msLoginPage|microsoft-login-form/i,
      /<title[^>]*>(?:Sign in|Microsoft)/i,
      /aadcdn\.msauthimages\.net/i,
      /loginPage\.aspx/i,
    ],
    minMatches: 2,
    confidence: 88,
  },
  {
    kitId:   "GENERIC_PAYPAL_HTML",
    kitName: "Generic PayPal Kit (HTML)",
    patterns:[
      /<title[^>]*>PayPal/i,
      /class=["'][^"']*paypal/i,
      /paypal\.com\/signin/i,
      /data-paypal-button/i,
    ],
    minMatches: 2,
    confidence: 82,
  },
  {
    kitId:   "EVILPROXY_HTML",
    kitName: "EvilProxy (HTML Pattern)",
    patterns:[
      /\?a=[a-zA-Z0-9_-]{20,}/,
      /workers\.dev.*login/i,
      /state=[a-zA-Z0-9]{30,}/i,
    ],
    minMatches: 2,
    confidence: 85,
  },
  {
    kitId:   "CRYPTO_DRAINER_HTML",
    kitName: "Crypto Wallet Drainer (HTML)",
    patterns:[
      /connect.*wallet|wallet.*connect/i,
      /metamask|walletconnect|coinbase.*wallet/i,
      /seed.*phrase|recovery.*phrase|private.*key/i,
      /web3|ethers\.js|wagmi/i,
    ],
    minMatches: 2,
    confidence: 88,
  },
];

function identifyKitFromHTML(html) {
  if (!html || html.length < 50) return null;
  const results = [];
  for (const sig of HTML_KIT_SIGNATURES) {
    const matchCount = sig.patterns.filter(p => p.test(html)).length;
    if (matchCount >= sig.minMatches) {
      results.push({
        kitId:      sig.kitId,
        kitName:    sig.kitName,
        confidence: Math.min(sig.confidence + (matchCount - sig.minMatches) * 5, 97),
        matchCount,
        source:     "html_analysis",
      });
    }
  }
  results.sort((a, b) => b.confidence - a.confidence);
  return results[0] || null;
}

module.exports = {
  identifyKit,
  getAllKitMatches,
  identifyKitsFromDatabase,
  identifyKitsFromDatabasePaged,
  identifyKitFromHTML,
  getKitRiskProfile,
  generateKitHash,
  SOPHISTICATION_META,
  KIT_SIGNATURES,
};