// ════════════════════════════════════════════════════════════════
// FILE: backend/services/indiaFraudDetector.js — CREATE NEW
// Indian Language Cyber-Fraud Detection
// Real-world use: Most Indian cybercrime complaints are in Hindi,
// Tamil, Telugu, Bengali, Marathi etc. Standard English NLP misses
// them. This detector handles Hinglish, transliterated text, and
// India-specific fraud patterns (UPI fraud, digital arrest, TRAI
// scam, fake CBI/ED calls, PM Kisan fraud, electricity scam etc.)
// ════════════════════════════════════════════════════════════════
 
const INDIA_FRAUD_PATTERNS = [
  // ── Digital Arrest (2024 major scam) ──────────────────────
  {
    id: "INDIA-001", name: "Digital Arrest Scam", severity: 5,
    risk: 90, mitre: "T1566 - Phishing",
    fraudType: "police_impersonation",
    patterns: [
      /digital\s*arrest/i,
      /aapko\s*arrest\s*kiya\s*jayega/i,
      /cbi|narcotics|customs|trai|cci/i,
      /aadhar.*used.*drug|drug.*parcel.*your\s*name/i,
      /stay.*home.*investigation|ghar.*raho.*jaanch/i,
      /video.*call.*police|police.*verify.*video/i,
    ],
    description: "Digital Arrest scam — fake police/CBI officer demands victim stay on video call under threat of arrest. Major 2024 Indian cybercrime pattern.",
    action: "Report to CyberCrime.gov.in and call 1930. Real police never conduct video call 'digital arrests'.",
  },
 
  // ── UPI Fraud ─────────────────────────────────────────────
  {
    id: "INDIA-002", name: "UPI/QR Code Fraud", severity: 4,
    risk: 75, mitre: "T1566 - Phishing",
    fraudType: "upi_fraud",
    patterns: [
      /upi|gpay|phonepe|paytm|bhim/i,
      /collect.*request|payment.*request.*approve/i,
      /scan.*qr.*pay|qr.*receive.*money/i,
      /refund.*upi|upi.*refund.*process/i,
      /ybl|okaxis|okicici|okhdfcbank|paytm|okbizaxis/i,
      /paise\s*wapas|refund\s*milega|money\s*return/i,
    ],
    description: "UPI fraud — fraudster sends fake collect requests or tricks victim into scanning QR to 'receive' money (which actually debits their account).",
    action: "Never approve UPI collect requests from unknown parties. Scanning QR to receive money is a fraud.",
  },
 
  // ── TRAI/SIM Card Scam ────────────────────────────────────
  {
    id: "INDIA-003", name: "TRAI/SIM Card Scam", severity: 4,
    risk: 72, mitre: "T1566 - Phishing",
    fraudType: "govt_impersonation",
    patterns: [
      /trai|telecom regulatory/i,
      /sim.*disconnect|number.*disconnect.*hours/i,
      /illegal.*activity.*number|number.*misuse|your\s*mobile\s*misused/i,
      /sim.*block.*2\s*hour|aapka\s*number\s*band/i,
    ],
    description: "TRAI scam — fake TRAI officer threatens to disconnect SIM for 'illegal activity'. Redirects to fake police for 'verification'.",
    action: "TRAI never calls individuals. Disconnect immediately and report to 1930.",
  },
 
  // ── FedEx/Courier Drug Parcel Scam ───────────────────────
  {
    id: "INDIA-004", name: "FedEx/Courier Drug Parcel Scam", severity: 5,
    risk: 85, mitre: "T1566 - Phishing",
    fraudType: "courier_scam",
    patterns: [
      /fedex|bluedart|dhl|courier/i,
      /parcel.*drug|drug.*parcel|narcotics.*courier/i,
      /customs.*hold|parcel.*seized|package.*narcotic/i,
      /mumbai\s*airport|delhi\s*customs|intercepted/i,
    ],
    description: "Courier drug scam — fake FedEx/DHL call claims parcel contains drugs/contraband linked to victim's Aadhaar. Demands payment to 'clear' the case.",
    action: "No courier company can arrest you. Report to 1930 immediately.",
  },
 
  // ── Electricity Scam ──────────────────────────────────────
  {
    id: "INDIA-005", name: "Electricity Disconnection Scam", severity: 3,
    risk: 60, mitre: "T1566 - Phishing",
    fraudType: "electricity_scam",
    patterns: [
      /bijli.*kategi|electricity.*disconnect|power.*cut.*tonight/i,
      /bijli\s*bill|electricity\s*bill.*pending|outstanding.*amount/i,
      /lineman.*call|je.*call|meter\s*reader|wapcos|bescom|msedcl|tneb/i,
      /immediately.*pay|abhi.*pay.*karo|2\s*ghante.*mein\s*pay/i,
    ],
    description: "Electricity disconnection scam — fake electricity board employee threatens immediate power cut unless victim pays immediately via UPI.",
    action: "Call your electricity board's official helpline to verify any bill. Never pay through unknown UPI IDs.",
  },
 
  // ── Job/Part-Time Work Scam ───────────────────────────────
  {
    id: "INDIA-006", name: "Fake Job/Task Scam", severity: 4,
    risk: 70, mitre: "T1566 - Phishing",
    fraudType: "job_scam",
    patterns: [
      /work\s*from\s*home.*earn|ghar\s*baithe.*kamao/i,
      /like.*video.*earn|subscribe.*earn|youtube.*task/i,
      /per\s*task.*rs|rs.*per\s*click|rating.*earn/i,
      /telegram.*join.*earn|whatsapp.*task.*money/i,
      /part.*time.*daily.*earning|investment.*double/i,
      /crypto.*task.*earn|nft.*task/i,
    ],
    description: "Task-based job scam — victim paid small amounts initially then asked to 'invest' to unlock larger earnings. Money is never returned.",
    action: "Legitimate jobs never require you to invest money. Report to CyberCrime.gov.in.",
  },
 
  // ── PM Kisan / Govt Scheme Fraud ─────────────────────────
  {
    id: "INDIA-007", name: "Fake Government Scheme Fraud", severity: 4,
    risk: 68, mitre: "T1566 - Phishing",
    fraudType: "govt_impersonation",
    patterns: [
      /pm\s*kisan|pradhan\s*mantri|ayushman|jan\s*dhan/i,
      /subsidy.*release|subsidy.*claim|government.*money.*release/i,
      /aadhar.*update.*scheme|kyc.*scheme.*update/i,
      /free.*laptop|free.*phone.*government|sarkari.*yojana.*apply/i,
    ],
    description: "Fake government scheme — fraudster claims victim is eligible for PM scheme benefits but needs KYC update or registration fee.",
    action: "Government schemes never ask for fees. Verify at official .gov.in websites only.",
  },
 
  // ── Sextortion/Honey Trap ────────────────────────────────
  {
    id: "INDIA-008", name: "Sextortion / Honey Trap", severity: 5,
    risk: 85, mitre: "T1566 - Phishing",
    fraudType: "sextortion",
    patterns: [
      /nude.*video|video.*call.*compromise|morphed.*photo/i,
      /share.*contacts|send.*family|viral.*karo/i,
      /blackmail|pay.*delete.*video|delete\s*karo.*pay/i,
      /screenshot.*video\s*call|recording.*share/i,
    ],
    description: "Sextortion — victim trapped in compromising video call, threatened to pay or have video shared with contacts.",
    action: "Do not pay. Block the number. Report to CyberCrime.gov.in and cybercrime.gov.in/sextortion.",
  },
 
  // ── Hinglish/Hindi urgency patterns ──────────────────────
  {
    id: "INDIA-009", name: "Hindi Urgency Social Engineering", severity: 3,
    risk: 55, mitre: "T1566 - Phishing",
    fraudType: "phishing",
    patterns: [
      /abhi\s*karo|turant\s*karo|jaldi\s*karo/i,
      /aaj\s*hi|aaj\s*raat|kal\s*tak/i,
      /account\s*band\s*ho\s*jayega|account\s*block\s*hoga/i,
      /otp\s*share\s*karo|otp\s*batao|otp\s*send\s*karo/i,
      /aapka\s*account\s*verify|kyc\s*update\s*karo/i,
    ],
    description: "Hindi/Hinglish urgency pattern — social engineering using Hindi language urgency and OTP sharing requests.",
    action: "Never share OTP with anyone. Banks and government agencies never ask for OTP over phone.",
  },
 
  // ── Investment / Stock Tip Scam ───────────────────────────
  {
    id: "INDIA-010", name: "SEBI/Stock Market Investment Scam", severity: 4,
    risk: 78, mitre: "T1566 - Phishing",
    fraudType: "investment_scam",
    patterns: [
      /sebi.*registered|sebi.*advisor|sensex.*tip/i,
      /guaranteed.*profit|sure.*shot.*tip|100.*percent.*return/i,
      /stock.*tip.*telegram|whatsapp.*trading.*group/i,
      /nse.*bse.*insider|insider.*trading.*tip/i,
      /crypto.*10x|bitcoin.*double|nft.*guaranteed/i,
    ],
    description: "Investment scam — fake SEBI-registered advisors promise guaranteed stock market returns. Victims lose money to fake trading platforms.",
    action: "SEBI never guarantees profits. Verify advisor registration at sebi.gov.in/sebiweb/other/OtherAction.do",
  },

  // ── Aadhaar OTP/Biometric Fraud (NEW) ────────────────────
  {
    id: "INDIA-011", name: "Aadhaar OTP / Biometric Fraud", severity: 5,
    risk: 88, mitre: "T1078 - Valid Accounts",
    fraudType: "aadhaar_fraud",
    patterns: [
      /aadhaar.*otp|otp.*aadhaar|uid.*otp/i,
      /biometric.*update|fingerprint.*update|iris.*scan.*aadhaar/i,
      /aadhaar.*link.*bank|bank.*link.*aadhaar|aadhaar.*verify.*bank/i,
      /uid.*authenticate|aadhaar.*authentication.*fail/i,
      /maadhaar.*app.*otp|resident\.uidai/i,
    ],
    description: "Aadhaar OTP fraud — fraudster impersonates UIDAI or bank agent, tricks victim into sharing Aadhaar OTP to link bank account or 'update biometrics', then conducts unauthorized banking transactions.",
    action: "Never share Aadhaar OTP with anyone. UIDAI never calls for OTP. Report to 1947 (UIDAI helpline) and 1930.",
  },

  // ── Fake Bank App / Screen Sharing Fraud (NEW) ───────────
  {
    id: "INDIA-012", name: "Fake Banking App / Screen Sharing Fraud", severity: 5,
    risk: 90, mitre: "T1219 - Remote Access Software",
    fraudType: "bank_fraud",
    patterns: [
      /anydesk|teamviewer|quick support|remote.*access.*app/i,
      /bank.*app.*install|install.*bank.*app.*verify/i,
      /screen.*share.*verify|share.*screen.*bank/i,
      /official.*bank.*app.*link|bank.*apk.*download/i,
      /account.*freeze.*remote|unfreeze.*download.*app/i,
    ],
    description: "Fake banking app fraud — fraudster sends APK link or remote access app (AnyDesk/TeamViewer) claiming to be bank helpdesk to 'resolve account issues', then takes over device to conduct transactions.",
    action: "Never install apps from unknown links. Never share screen with bank 'agents'. Call your bank's official number only.",
  },

  // ── Deepfake/AI Voice Phishing (NEW) ─────────────────────
  {
    id: "INDIA-013", name: "AI Voice / Deepfake Fraud", severity: 5,
    risk: 85, mitre: "T1566.004 - Spearphishing via Voice",
    fraudType: "vishing",
    patterns: [
      /ai.*generated.*voice|deepfake.*call|voice.*clone/i,
      /boss.*call.*transfer|ceo.*call.*payment|md.*call.*urgent/i,
      /familiar.*voice.*help|relative.*voice.*accident/i,
      /emergency.*money.*voice.*call|accident.*hospital.*urgent.*transfer/i,
      /voice.*message.*fraud|whatsapp.*voice.*urgent.*money/i,
    ],
    description: "AI deepfake voice fraud — AI-cloned voice of relative/CEO calls asking for emergency money transfer. Increasingly common with AI tools; hard to detect without callback verification.",
    action: "Always call back on the official/known number of the person. No emergency justifies transferring money without verification.",
  },

  // ── SIM Swap Fraud (NEW) ──────────────────────────────────
  {
    id: "INDIA-014", name: "SIM Swap / Mobile Number Portability Fraud", severity: 5,
    risk: 92, mitre: "T1556 - Modify Authentication",
    fraudType: "sim_swap",
    patterns: [
      /sim.*swap|sim.*port|mnp.*fraud/i,
      /new.*sim.*issued|duplicate.*sim.*issued/i,
      /mobile.*number.*port.*request|mnp.*request.*approve/i,
      /sim.*blocked.*suddenly|network.*gone.*suddenly/i,
      /all.*otp.*started.*coming|otp.*not.*receiving/i,
      /operator.*called.*verify.*port/i,
    ],
    description: "SIM swap fraud — attacker fraudulently ports victim's mobile number to a new SIM using fake documents, then receives all banking OTPs and drains accounts. Often combined with phishing for account details.",
    action: "If your SIM stops working suddenly, call operator immediately. Set port block on your number. File FIR at cybercrime.gov.in.",
  },

  // ── Fake Loan App Fraud (NEW) ────────────────────────────
  {
    id: "INDIA-015", name: "Predatory Loan App / Recovery Agent Fraud", severity: 4,
    risk: 75, mitre: "T1566 - Phishing",
    fraudType: "bank_fraud",
    patterns: [
      /loan.*app.*blackmail|recovery.*agent.*abuse/i,
      /contacts.*access.*loan|gallery.*access.*loan/i,
      /morphed.*photos.*loan|nude.*photos.*contacts.*loan/i,
      /instant.*loan.*app.*harassment|loan.*app.*threat/i,
      /nbfc.*recovery.*agent|chinese.*loan.*app/i,
      /process.*fee.*loan.*disburse|security.*deposit.*loan/i,
    ],
    description: "Predatory loan app fraud — unauthorized loan apps access contacts/gallery, send morphed photos to contacts as threat, demand repayment of inflated amounts. Often operated by Chinese entities via Indian shell companies.",
    action: "Uninstall immediately. File complaint at RBI Sachet portal (sachet.rbi.org.in) and cybercrime.gov.in. Block recovery agent numbers.",
  },
];
 
// ── Main detection function ───────────────────────────────────
function detectIndiaFraud(text) {
  if (!text || typeof text !== "string") return { detected: false, detections: [] };
  const detections = [];
 
  for (const pattern of INDIA_FRAUD_PATTERNS) {
    const hits = pattern.patterns.filter(p => p.test(text));
    if (hits.length > 0) {
      const confidence = Math.min(50 + hits.length * 20, 98);
      detections.push({
        id:          pattern.id,
        name:        pattern.name,
        severity:    pattern.severity,
        risk:        pattern.risk,
        fraudType:   pattern.fraudType,
        confidence,
        hitsCount:   hits.length,
        description: pattern.description,
        action:      pattern.action,
        mitre:       pattern.mitre,
      });
    }
  }
 
  if (!detections.length) return { detected: false, detections: [] };
 
  detections.sort((a,b) => b.confidence - a.confidence);
  const top = detections[0];
 
  return {
    detected:    true,
    topFraud:    top.name,
    topFraudId:  top.id,
    riskBoost:   top.risk,
    fraudType:   top.fraudType,
    severity:    top.severity,
    confidence:  top.confidence,
    action:      top.action,
    mitre:       top.mitre,
    detections,
    helpline:    "1930 (National Cyber Crime Helpline)",
    reportUrl:   "https://cybercrime.gov.in",
  };
}
 
module.exports.detectIndiaFraud = detectIndiaFraud;
module.exports.INDIA_FRAUD_PATTERNS = INDIA_FRAUD_PATTERNS;