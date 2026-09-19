// FILE: src/pages/TrainingMode.tsx — Full Rebuild
// Levelled interactive training: Beginner → Intermediate → Expert
// MCQ with concept-first teaching, real-world scenarios, detailed explanations

import { useState } from "react";
import { motion, AnimatePresence } from "motion/react";
import {
  Brain, Shield, ChevronRight, Award, RefreshCw,
  BookOpen, CheckCircle, XCircle, Lightbulb, Lock,
  Target, Zap, AlertTriangle,
} from "lucide-react";

type Level = "beginner" | "intermediate" | "expert";
type Phase = "level_select" | "concept" | "question" | "complete";

interface Option   { id:string; text:string; }
interface Question {
  id:string; level:Level;
  conceptTitle:string; concept:string;
  scenario:string; question:string;
  options:Option[]; correct:string;
  explanation:string; wrongExplain:string;
  signals:string[]; mitre:string|null; attackType:string;
}

const LEVEL_CFG = {
  beginner:    { color:"#34d399", bg:"rgba(52,211,153,0.08)",  border:"rgba(52,211,153,0.2)",  label:"Beginner",    icon:Shield,       desc:"URL basics, urgency tactics, display name spoofing — 3 scenarios" },
  intermediate:{ color:"#fbbf24", bg:"rgba(251,191,36,0.08)",  border:"rgba(251,191,36,0.2)",  label:"Intermediate",icon:Target,       desc:"Homoglyphs, conversation hijacking, smishing — 3 scenarios" },
  expert:      { color:"#f87171", bg:"rgba(248,113,113,0.08)", border:"rgba(248,113,113,0.2)", label:"Expert",      icon:Zap,          desc:"BEC, AiTM attacks, phishing kit infrastructure — 3 scenarios" },
};

const QUESTIONS: Question[] = [
  // ── BEGINNER ──
  {
    id:"b1", level:"beginner",
    conceptTitle:"What Makes a URL Phishing?",
    concept:"A phishing URL is a web address designed to look legitimate but leads to a fake site. Attackers register domains that visually mimic trusted brands using three main tricks:\n\n1. Subdomain abuse — 'paypal.com.evil.com' (real domain is evil.com)\n2. Typosquatting — 'paypa1.com' (digit substitution)\n3. Free TLDs — '.tk', '.ml', '.ga' (free, easy to discard)\n\nThe rule: look at what comes IMMEDIATELY before the TLD. That is the real domain.\n\npaypal-secure-login.tk → real domain is 'paypal-secure-login.tk', NOT paypal",
    scenario:"http://paypal-secure-login.tk/verify-account",
    question:"Which element definitively identifies this as a phishing URL?",
    options:[
      { id:"a", text:"The path '/verify-account' — legitimate sites never include 'verify' in their URLs" },
      { id:"b", text:"The use of HTTP instead of HTTPS — any HTTP site is automatically a phishing attempt" },
      { id:"c", text:"The domain 'paypal-secure-login.tk' — real PayPal only operates from paypal.com" },
      { id:"d", text:"The hyphen in the domain — hyphens always indicate a fake website" },
    ],
    correct:"c",
    explanation:"The domain is the only reliable signal. Real PayPal exclusively uses 'paypal.com'. The domain 'paypal-secure-login.tk' uses a free .tk TLD and adds words to create false legitimacy — classic brand impersonation. HTTP vs HTTPS is NOT reliable — many phishing sites use HTTPS. Hyphens appear in countless legitimate domains (coca-cola.com, apple-support.com are examples used in legitimate contexts). Only the actual domain registration can't be faked.",
    wrongExplain:"A: Legitimate services like banks use /verify paths constantly. B: Over 85% of phishing sites now use HTTPS — this check is obsolete. D: Many legitimate brands use hyphens in domains.",
    signals:["Free .tk TLD","Brand name not the actual domain","/verify in path (supporting signal)"],
    mitre:"T1583.001 — Acquire Infrastructure: Domains",
    attackType:"Typosquatting",
  },
  {
    id:"b2", level:"beginner",
    conceptTitle:"Urgency — Phishing's Psychological Weapon",
    concept:"Phishing emails weaponize urgency to short-circuit rational thinking. When you feel panicked, you act before you verify. The formula is always:\n\nThreat + Deadline + Action link\n\nExamples:\n• 'Your account closes in 2 hours'\n• 'Suspicious activity detected — act now'\n• 'Final notice before legal action'\n\nLegitimate companies: notify you through your account dashboard, allow reasonable time, and never threaten permanent consequences via unsolicited email alone. The panic feeling is itself a detection signal.",
    scenario:"Subject: URGENT — Your Amazon account has been suspended\n\nDear Customer,\n\nWe detected suspicious activity. Your account will be permanently closed in 2 hours unless you verify immediately.\n\nRestore access: http://amazon-support-verify.ml/restore\n\nAmazon Security Team",
    question:"This email has multiple phishing signals. Which combination is the STRONGEST evidence?",
    options:[
      { id:"a", text:"Generic greeting + .ml domain + 2-hour deadline + amazon not in the actual domain" },
      { id:"b", text:"The 2-hour deadline alone — Amazon always gives at least 48 hours before suspending accounts" },
      { id:"c", text:"The subject line uses all caps URGENT — Amazon's style guide prohibits this" },
      { id:"d", text:"It arrived by email — Amazon only communicates account issues through the mobile app" },
    ],
    correct:"a",
    explanation:"Phishing is reliably identified by converging signals, not a single indicator. Here: (1) 'Dear Customer' instead of your real name, (2) .ml is a free high-abuse TLD, (3) the 2-hour window forces action without thinking, (4) 'amazon-support-verify.ml' — Amazon only uses amazon.com. Each signal alone could occasionally appear in legitimate communications. Together, they form an unambiguous phishing fingerprint.",
    wrongExplain:"B: Amazon does sometimes act quickly on fraud — no 'minimum time' rule exists. C: All-caps subjects are used by many legitimate companies. D: Amazon routinely sends email for account notifications.",
    signals:["Generic greeting 'Dear Customer'","Free .ml TLD","2-hour pressure deadline","Amazon not the registered domain"],
    mitre:"T1566 — Phishing",
    attackType:"Brand Impersonation + Social Engineering",
  },
  {
    id:"b3", level:"beginner",
    conceptTitle:"Display Name Spoofing and Domain Confusion",
    concept:"Email clients show a 'display name' — friendly text that can say anything, regardless of the actual sending address. Attackers set display names to 'Google Security' or 'PayPal Support' while sending from attacker-controlled domains.\n\nDomain confusion goes further: attackers put a real brand domain as a SUBDOMAIN prefix:\n\nsecurity.google.com.attacker.xyz\n\nThe real domain here is 'attacker.xyz'. Browsers and email clients only trust the last two segments before the TLD. Everything before that is just a subdomain the attacker controls.\n\nAlways expand the sender details to see the full email address.",
    scenario:"From: 'Google Security' <security-noreply@accounts.google.com.secure-alert.xyz>\nSubject: Sign-in attempt blocked from new device\n\nWe blocked a sign-in from an unrecognized device in Russia. If this was not you, secure your account now.",
    question:"The sender shows 'Google Security' and the address contains 'accounts.google.com'. Why is this still definitively phishing?",
    options:[
      { id:"a", text:"Google never sends security alerts — they only notify through the Google Security Checkup tool" },
      { id:"b", text:"The actual sending domain is 'secure-alert.xyz' — 'accounts.google.com' is only a subdomain prefix the attacker controls" },
      { id:"c", text:"The message mentions Russia — legitimate Google alerts never reveal the location of blocked attempts" },
      { id:"d", text:"Legitimate Google security emails always include your profile picture in the header" },
    ],
    correct:"b",
    explanation:"Domain parsing: 'accounts.google.com.secure-alert.xyz' → real domain is 'secure-alert.xyz'. The attacker registered 'secure-alert.xyz' and created a subdomain 'accounts.google.com' under it. When email security tools scan the domain, less sophisticated filters may see 'accounts.google.com' and pass it. This is domain confusion — designed to fool both humans and automated security tools. The display name 'Google Security' is meaningless since it can be set to anything.",
    wrongExplain:"A: Google sends security alert emails constantly. C: Google does reveal geolocation in security alerts. D: Google email templates vary and don't always include profile pictures.",
    signals:["Real domain is secure-alert.xyz","accounts.google.com is just a subdomain","Display name is spoofed"],
    mitre:"T1566.002 — Spearphishing Link",
    attackType:"Domain Confusion + Display Name Spoofing",
  },

  // ── INTERMEDIATE ──
  {
    id:"i1", level:"intermediate",
    conceptTitle:"Homoglyph Attacks — Character-Level Deception",
    concept:"Homoglyph attacks substitute visually identical characters to create fake domains that pass casual inspection:\n\n• Capital I (eye) → identical to lowercase l (ell) in most fonts: paypaI.com\n• Digit 0 (zero) → looks like letter O: micr0soft.com  \n• 'rn' sequence → looks like 'm': arnazon.com (amazon)\n• 'vv' sequence → looks like 'w': tvvitter.com\n\nDetecting homoglyphs requires character-by-character analysis. At reading speed, the human brain autocorrects them to the expected word.\n\nMore advanced: Unicode/Punycode attacks use characters from Cyrillic, Greek, or other alphabets that are pixel-identical to Latin characters. These display as legitimate brand names in the browser bar.",
    scenario:"A phishing link directs to: micr0s0ft-account-verify.com",
    question:"Identify the exact homoglyph technique used in this domain:",
    options:[
      { id:"a", text:"Typosquatting — extra characters were inserted into the word 'microsoft'" },
      { id:"b", text:"Homoglyph substitution — the letter 'o' was replaced with digit '0' in two positions (micr[0]s[0]ft)" },
      { id:"c", text:"Subdomain abuse — 'microsoft' is used as a subdomain before the attacker's domain" },
      { id:"d", text:"Keyboard-adjacency substitution — nearby keyboard keys were swapped to create a misspelling" },
    ],
    correct:"b",
    explanation:"Two substitutions: micr[o]s[o]ft → micr[0]s[0]ft. The letter 'o' (ASCII 111) is replaced with digit '0' (ASCII 48). In most sans-serif fonts at body text size these are visually indistinguishable. The '-account-verify' suffix adds plausibility. Unlike typosquatting which adds/removes/swaps letters changing the word structure, homoglyphs preserve the visual word shape while changing specific characters. Character-level string comparison is required for detection — which is exactly what PhishNetra's HOMOGLYPH_URL_PATTERNS_V2 does.",
    wrongExplain:"A: Typosquatting would be 'microsofft' or 'micosoft' — adding or removing characters. No characters were inserted here. C: 'micr0s0ft' is the registered domain itself, not a subdomain. D: Keyboard-adjacency would produce 'nicrosoft' (m→n adjacent) not '0' substitution.",
    signals:["Two '0' digit substitutions for letter 'o'","Visual appearance identical to microsoft","Added -account-verify for plausibility"],
    mitre:"T1583.001 — Acquire Infrastructure: Domains",
    attackType:"Homoglyph Attack",
  },
  {
    id:"i2", level:"intermediate",
    conceptTitle:"Conversation Hijacking — Fake Thread Replies",
    concept:"Conversation hijacking inserts malicious content into what appears to be a real ongoing email thread. Because the victim sees their own previous messages, the credibility is near-absolute.\n\nAttack flow:\n1. Attacker obtains real email thread content (data breach, compromised account, or public sources)\n2. Sends a reply that continues the thread naturally\n3. References real context — names, project names, file names, dates\n4. Embeds malicious link or attachment as an 'updated document'\n\nKey difference from regular phishing: NO urgency language. The message reads as normal business workflow. Detection requires verifying the sender's actual email address and independently confirming via a separate channel that the document request is real.",
    scenario:"Re: Project Atlas — Budget Approval\n\nHi,\n\nFollowing up on what we discussed yesterday. The updated budget document has been finalized with the revisions from the last meeting. Please review and sign off before finance closes the cycle tomorrow.\n\nAccess document: [Review Budget v3.2]\n\nThanks",
    question:"There are no obvious phishing signals — professional tone, no urgency keywords, references to a real-sounding project. What is the key analytical signal?",
    options:[
      { id:"a", text:"The tomorrow deadline — legitimate budget approvals never have next-day deadlines" },
      { id:"b", text:"The reference to 'what we discussed yesterday' contains no specific verifiable detail — false familiarity without checkable context" },
      { id:"c", text:"'Budget v3.2' is a suspicious version number — real documents use date-based naming" },
      { id:"d", text:"Finance deadlines are always communicated by the CFO, not via email thread replies" },
    ],
    correct:"b",
    explanation:"'What we discussed yesterday' — what specifically? No meeting details, no specific revision points, no named attendees, no reference to actual previous email content in the thread. Legitimate follow-ups contain enough specific context that the recipient can independently verify the claim without clicking anything. This vagueness is intentional — the attacker hopes the victim assumes they forgot. The correct response: reply to the sender asking what specifically was discussed, or call them directly. Never click the document link without independent verification.",
    wrongExplain:"A: Next-day budget deadlines are completely normal in business. C: Version numbering conventions vary entirely by organization. D: Finance approvals arrive from many directions in different organizations.",
    signals:["No specific verifiable context in thread reference","Fake familiarity — 'we discussed'","Action link embedded in vague context","No actual previous thread content shown"],
    mitre:"T1534 — Internal Spearphishing",
    attackType:"Conversation Hijacking",
  },
  {
    id:"i3", level:"intermediate",
    conceptTitle:"Smishing — Why SMS Phishing Bypasses Email Security",
    concept:"Smishing succeeds because:\n1. SMS has no spam filters, no sandboxing, no email security gateway\n2. People trust SMS more than email — it feels more personal\n3. Mobile screens hide full URLs — bit.ly/xyz looks safe on a phone\n4. 90%+ SMS open rate vs 20% email open rate\n\nCommon smishing patterns:\n• Delivery scams — fake USPS/FedEx/DHL with small 'redelivery fee'\n• Bank fraud alerts — 'unusual transaction detected'\n• Government — fake IRS/HMRC refund or fine\n• Prize notifications\n\nURL shorteners are almost always present. Never click a link in an SMS from an unknown sender — go directly to the official website and check your account.",
    scenario:"FedEx: Delivery attempt failed for package FX847291055. Customs clearance fee of $3.49 required to release package. Pay: rb.gy/fedex-customs",
    question:"This message uses a convincing tracking number format and a small, believable fee. Which signals most reliably identify it as smishing?",
    options:[
      { id:"a", text:"FedEx never sends SMS — all delivery notifications come via the FedEx app only" },
      { id:"b", text:"URL shortener (rb.gy) hiding destination + FedEx never requests customs payment via SMS link + tracking number format doesn't match real FedEx format" },
      { id:"c", text:"The $3.49 fee amount — real customs fees are always over $20" },
      { id:"d", text:"The message used 'Delivery attempt failed' — FedEx uses 'Delivery unsuccessful' in official communications" },
    ],
    correct:"b",
    explanation:"Three converging signals: (1) rb.gy is a URL shortener — legitimate delivery companies send links to their own tracked domains, never shortened URLs. (2) FedEx, USPS, and DHL do NOT request payment via SMS link — customs fees are handled through official broker processes or at the physical facility. (3) Real FedEx tracking numbers follow a 12-digit or 15-digit pattern beginning with specific prefixes — 'FX847291055' doesn't match. If you're unsure about a delivery, go directly to fedex.com and enter the tracking number manually.",
    wrongExplain:"A: FedEx absolutely sends SMS delivery notifications. C: There's no minimum customs fee — small fees are very common. D: Wording variations don't distinguish phishing from legitimate messages.",
    signals:["URL shortener rb.gy hides real destination","Logistics companies never request payment via SMS link","Tracking number format invalid for FedEx"],
    mitre:"T1660 — Phishing via SMS",
    attackType:"Smishing (Delivery Scam)",
  },

  // ── EXPERT ──
  {
    id:"e1", level:"expert",
    conceptTitle:"Business Email Compromise — Zero Technical Indicators",
    concept:"BEC causes over $50 billion in annual losses (FBI IC3). It has no links, no attachments, no malware — pure social engineering.\n\nThe attack exploits three psychological levers simultaneously:\n• Authority — comes from someone with power (CEO, CFO, legal)\n• Urgency — must happen today, time-sensitive deal/situation  \n• Secrecy — 'do not discuss with others', 'keep confidential'\n\nThe secrecy element is the critical signal — it specifically engineers around an organization's verification controls. Legitimate urgent business requests welcome verification. BEC requests specifically forbid it.\n\nDetection: Any financial or sensitive request that includes a confidentiality demand + bypasses normal process should trigger an out-of-band verification call to the requester's known number.",
    scenario:"From: 'David Park, CEO' <d.park@corporaion-hq.com>\n\nHi Jennifer,\n\nI'm currently in acquisition negotiations and need finance to execute a wire of $67,500 to the target company by 3pm today. This is commercially sensitive — please do not route through standard AP or discuss with the wider team as it could compromise the deal. I'll brief the CFO after signing.\n\nWire details attached.\n\nDavid",
    question:"The CEO's name matches your actual CEO and the request is plausible. What is the PRIMARY signal that should trigger immediate escalation?",
    options:[
      { id:"a", text:"The domain 'corporaion-hq.com' has a typo — 'corporation' is misspelled as 'corporaion'" },
      { id:"b", text:"No legitimate business process requires bypassing AP controls and CFO notification simultaneously — the secrecy demand is engineering around fraud prevention" },
      { id:"c", text:"$67,500 is a suspicious amount — BEC attacks always use round numbers" },
      { id:"d", text:"CEOs don't handle wire transfer requests directly — this would always go through a PA or assistant" },
    ],
    correct:"b",
    explanation:"While the typo (Option A) is a real secondary signal, the PRIMARY indicator is the explicit instruction to bypass AP controls AND withhold from the CFO. These two controls exist specifically to prevent unauthorized wire transfers. Any request that targets both simultaneously — and adds a 'do not discuss' instruction — is definitively engineering around fraud detection. Even if this email came from the real CEO's legitimate account (possible in account compromise scenarios), this instruction alone should trigger a mandatory phone verification to the CEO's known mobile number before any action. The urgency (3pm) prevents this verification from feeling optional — which is intentional.",
    wrongExplain:"A: Real signal, but secondary — attackers sometimes use the real domain. B is the answer because it catches BEC even when the domain is correct. C: BEC amounts are chosen to be plausible, not formulaic. D: Organizational structures vary — CEOs do sometimes handle deals directly.",
    signals:["Bypass AP controls instruction","Withhold from CFO demand","Confidentiality demand prevents verification","Typo in domain (secondary)","3pm deadline prevents out-of-band check"],
    mitre:"T1566 — Phishing / BEC",
    attackType:"Business Email Compromise",
  },
  {
    id:"e2", level:"expert",
    conceptTitle:"AiTM — When MFA Doesn't Stop the Attack",
    concept:"AiTM (Adversary-in-the-Middle) defeats MFA by acting as a real-time relay between the victim and the legitimate service.\n\nStandard phishing: victim enters credentials on a fake page → attacker gets password → MFA blocks attacker login\n\nAiTM: victim connects to attacker's proxy → proxy forwards everything to real Microsoft in real time → victim sees real Microsoft page → completes real MFA → attacker captures the authenticated session cookie → uses cookie directly, bypassing MFA forever\n\nTools: Evilginx2, EvilProxy, Modlishka\nTargets: Microsoft 365, Google Workspace (high-value accounts)\nDetection signal: The URL domain is wrong. The page content is perfectly real.\n\nMFA remains essential — AiTM is complex, expensive to operate, and only used against high-value targets. But Passkeys/FIDO2 hardware tokens DO defeat AiTM.",
    scenario:"You receive: 'Shared file notification from Microsoft Teams'. Link goes to:\nhxxps://login.microsoftonline.com.ms365-secure.net/oauth2/v2.0/authorize?client_id=4765445b...\n\nThe page that loads is the pixel-perfect real Microsoft login page. You complete MFA successfully. Three hours later your account shows unauthorized access.",
    question:"You completed MFA successfully and saw the real Microsoft page. Explain exactly why MFA failed to protect you.",
    options:[
      { id:"a", text:"Your MFA app was compromised — attackers installed spyware that captured the TOTP secret" },
      { id:"b", text:"The proxy at 'ms365-secure.net' relayed your MFA code to Microsoft in real time, received an authenticated session cookie, and stored it — the cookie grants access without future MFA requirements" },
      { id:"c", text:"Microsoft's session tokens don't expire — once generated they grant permanent access regardless of MFA" },
      { id:"d", text:"The attacker used pass-the-hash to bypass MFA after obtaining your NTLM hash from a previous breach" },
    ],
    correct:"b",
    explanation:"The real domain is 'ms365-secure.net' — 'login.microsoftonline.com' is just a subdomain. When you typed your password, the AiTM proxy (Evilginx2/EvilProxy) forwarded it to Microsoft instantly. When you completed MFA (app push or TOTP code), the proxy relayed it to Microsoft within the ~30-second validity window. Microsoft responded with a valid session cookie. The proxy captured this cookie and discarded the connection. The attacker now uses this cookie directly in their browser — no password, no MFA challenge required, because the cookie proves authentication already occurred. Defeat: FIDO2/Passkeys bind authentication to the specific domain — a proxy can't relay these because the cryptographic challenge includes the legitimate domain.",
    wrongExplain:"A: TOTP secrets are stored in the authenticator app, not intercepted this way. C: Microsoft sessions do expire (hours to days depending on policy). D: Pass-the-hash is an Active Directory attack, unrelated to AiTM.",
    signals:["Real domain is ms365-secure.net","Session cookie captured post-MFA","Real-time relay defeats time-based OTP","FIDO2 would have blocked this"],
    mitre:"T1557 — Adversary-in-the-Middle / T1111 — MFA Interception",
    attackType:"AiTM Proxy Attack",
  },
  {
    id:"e3", level:"expert",
    conceptTitle:"Phishing Kit Fingerprinting — Attributing Attacks to Infrastructure",
    concept:"Professional phishing operations use packaged kits — W3LL Panel, 16Shop, Caffeine PhaaS. Each kit has fingerprints:\n\nURL patterns:\n• '?a=' parameter with base64-encoded victim email (W3LL/EvilProxy)\n• '/admin/login.php' or '/panel/' paths (generic kits)\n• Multiple redirects through Cloudflare Workers or legitimate CDNs\n\nBehavior patterns:\n• Pre-filled email on fake login page (proves targeted list)\n• Telegram bot exfiltration (kit-specific)\n• Geographic filtering (serves decoy to security researchers)\n\nFingerprinting kits lets security teams:\n• Track campaigns across multiple domains\n• Predict next targets based on kit's historical focus\n• Identify Phishing-as-a-Service operators selling access",
    scenario:"Observed redirect chain:\n1. bit.ly/3xK9mPp\n2. → redirect.cloudflareapp.workers.dev/?a=am9obi5zbWl0aEBhY21lY29ycC5jb20=&t=MjAyNi0wNi0xNA==\n3. → microsoft365-webmail.top/login\n\nNote: Base64 'am9obi5zbWl0aEBhY21lY29ycC5jb20=' decodes to 'john.smith@acmecorp.com'",
    question:"What does the '?a=' base64 parameter in the redirect chain reveal about this attack's sophistication level?",
    options:[
      { id:"a", text:"It is a session tracking cookie for analytics — all redirect chains include encoded parameters" },
      { id:"b", text:"It encodes the specific victim's email address, proving the attacker had a targeted list before launching and that the kit pre-fills the email on the fake login page to increase conversion rate" },
      { id:"c", text:"It is an anti-bot fingerprint that blocks security scanners from accessing the phishing page" },
      { id:"d", text:"It encodes the attacker's Telegram chat ID for credential exfiltration routing" },
    ],
    correct:"b",
    explanation:"'?a=am9obi5zbWl0aEBhY21lY29ycC5jb20=' decodes to john.smith@acmecorp.com — the specific target's email. This reveals: (1) This is NOT spray-and-pray phishing — attacker had a validated list of real corporate emails before launching. (2) The W3LL Panel / EvilProxy kit decodes this parameter and pre-populates it on the Microsoft login page — victims see their real email already entered, massively increasing the believability and click-through-to-credential rate. (3) The '?t=' parameter decodes to the date '2026-06-14' — likely the campaign launch date for correlation. The Cloudflare Workers middle hop serves as a URL reputation laundering layer — security tools see a cloudflare.com domain initially. This is a high-sophistication, targeted, commercially-operated PhaaS campaign.",
    wrongExplain:"A: Analytics tracking doesn't encode target email addresses. C: Anti-bot fingerprinting is done separately (usually via JavaScript challenges), not in the redirect parameter. D: Telegram exfiltration IDs are in the kit's server-side config, not in URL parameters.",
    signals:["Base64 victim email proves targeted list","Kit pre-fills email for higher conversion","Cloudflare Workers launders URL reputation","Date parameter enables campaign correlation"],
    mitre:"T1566.002 — Spearphishing Link / T1027 — Obfuscated Files",
    attackType:"PhaaS Kit (W3LL/EvilProxy pattern)",
  },
];

const LEVEL_ORDER: Level[] = ["beginner","intermediate","expert"];

// ── Score rating ──
function getRank(score:number, total:number) {
  const pct = (score/total)*100;
  if (pct === 100) return { label:"Perfect",      emoji:"🏆", color:"#34d399" };
  if (pct >= 75)   return { label:"Sharp Eye",    emoji:"🎯", color:"var(--color-info)" };
  if (pct >= 50)   return { label:"Learning",     emoji:"📚", color:"#fbbf24" };
  return               { label:"Keep Practicing",emoji:"💪", color:"#fb923c" };
}

export default function TrainingMode() {
  const [phase,      setPhase]      = useState<Phase>("level_select");
  const [level,      setLevel]      = useState<Level>("beginner");
  const [qIdx,       setQIdx]       = useState(0);
  const [answered,   setAnswered]   = useState(false);
  const [selected,   setSelected]   = useState<string|null>(null);
  const [score,      setScore]      = useState(0);
  const [answers,    setAnswers]    = useState<boolean[]>([]);
  const [showHint,   setShowHint]   = useState(false);

  const levelQs  = QUESTIONS.filter(q => q.level === level);
  const q        = levelQs[qIdx];
  const isLast   = qIdx === levelQs.length - 1;
  const isCorrect= selected === q?.correct;
  const cfg      = LEVEL_CFG[level];

  const handleAnswer = (optId:string) => {
    if (answered) return;
    const correct = optId === q.correct;
    setSelected(optId);
    setAnswered(true);
    if (correct) setScore(s => s + 1);
    setAnswers(prev => [...prev, correct]);
  };

  const handleNext = () => {
    if (isLast) { setPhase("complete"); return; }
    setQIdx(i => i + 1);
    setAnswered(false);
    setSelected(null);
    setShowHint(false);
  };

  const restart = (newLevel?: Level) => {
    setQIdx(0); setScore(0); setAnswers([]);
    setAnswered(false); setSelected(null); setShowHint(false);
    if (newLevel) setLevel(newLevel);
    setPhase(newLevel ? "concept" : "level_select");
  };

  // ── LEVEL SELECT ──
  if (phase === "level_select") return (
    <div className="min-h-full py-12 px-6" style={{ background:"var(--bg-base)" }}>
      <div className="max-w-2xl mx-auto">
        <motion.div initial={{ opacity:0, y:16 }} animate={{ opacity:1, y:0 }} className="text-center mb-12">
          <div className="tag-green inline-flex mb-5"><Brain className="size-3" /> TRAINING MODE</div>
          <h1 className="font-display text-4xl mb-3" style={{ color:"var(--text-primary)" }}>
            Phishing Detection Quiz
          </h1>
          <p className="text-sm max-w-md mx-auto" style={{ color:"var(--text-secondary)" }}>
            Real-world attack scenarios with concept-first teaching. Each level covers 3 scenarios with detailed explanations.
          </p>
        </motion.div>

        <div className="space-y-3">
          {LEVEL_ORDER.map((lv, i) => {
            const c = LEVEL_CFG[lv];
            const Icon = c.icon;
            return (
              <motion.button key={lv}
                initial={{ opacity:0, y:12 }} animate={{ opacity:1, y:0 }}
                transition={{ delay:i*0.1 }}
                onClick={() => { setLevel(lv); setPhase("concept"); }}
                className="w-full card p-5 text-left flex items-center gap-4 stat-card group"
                style={{ background:"var(--bg-card)" }}>
                <div className="w-12 h-12 rounded-xl flex items-center justify-center flex-shrink-0"
                     style={{ background:c.bg, border:`1px solid ${c.border}` }}>
                  <Icon className="size-6" style={{ color:c.color }} />
                </div>
                <div className="flex-1">
                  <div className="flex items-center gap-2 mb-0.5">
                    <span className="text-base font-semibold" style={{ color:c.color }}>
                      {c.label}
                    </span>
                    <span className="text-xs px-2 py-0.5 rounded"
                          style={{ color:c.color, background:c.bg, border:`1px solid ${c.border}`,
                                   fontFamily:"var(--font-mono)" }}>
                      {QUESTIONS.filter(q=>q.level===lv).length} scenarios
                    </span>
                  </div>
                  <p className="text-xs" style={{ color:"var(--text-muted)" }}>{c.desc}</p>
                </div>
                <ChevronRight className="size-5 flex-shrink-0 transition-transform group-hover:translate-x-0.5"
                              style={{ color:"var(--text-muted)" }} />
              </motion.button>
            );
          })}
        </div>
      </div>
    </div>
  );

  // ── CONCEPT PHASE ──
  if (phase === "concept" && q) return (
    <div className="min-h-full py-12 px-6" style={{ background:"var(--bg-base)" }}>
      <div className="max-w-2xl mx-auto">
        <AnimatePresence mode="wait">
          <motion.div key={`concept-${qIdx}`}
            initial={{ opacity:0, y:16 }} animate={{ opacity:1, y:0 }}
            exit={{ opacity:0, y:-8 }}>

            {/* Header */}
            <div className="flex items-center gap-3 mb-8">
              <button onClick={() => restart()} className="text-xs"
                      style={{ color:"var(--text-muted)", fontFamily:"var(--font-mono)" }}>
                ← Levels
              </button>
              <span className="text-xs" style={{ color:"var(--text-dim)" }}>·</span>
              <span className="text-xs" style={{ color:cfg.color, fontFamily:"var(--font-mono)" }}>
                {cfg.label} · Scenario {qIdx+1}/{levelQs.length}
              </span>
            </div>

            {/* Concept card */}
            <div className="card overflow-hidden mb-4"
                 style={{ background:"var(--bg-card)", borderColor:`${cfg.color}22` }}>
              <div className="h-0.5" style={{ background:`linear-gradient(90deg, ${cfg.color}, transparent)` }} />
              <div className="p-6">
                <div className="flex items-center gap-2 mb-4">
                  <BookOpen className="size-4 flex-shrink-0" style={{ color:cfg.color }} />
                  <span className="text-xs font-semibold uppercase tracking-widest"
                        style={{ color:cfg.color, fontFamily:"var(--font-mono)" }}>
                    Concept
                  </span>
                </div>
                <h2 className="text-xl font-bold mb-4" style={{ color:"var(--text-primary)",
                               fontFamily:"var(--font-sans)", letterSpacing:"-0.02em" }}>
                  {q.conceptTitle}
                </h2>
                <div className="space-y-1">
                  {q.concept.split("\n").map((line, i) => (
                    line.trim() === "" ? <div key={i} className="h-2" /> :
                    <p key={i} className="text-sm leading-relaxed"
                       style={{ color: line.startsWith("•") || line.match(/^\d\./) ? "var(--text-primary)" : "var(--text-secondary)" }}>
                      {line}
                    </p>
                  ))}
                </div>
              </div>
            </div>

            <motion.button
              whileHover={{ scale:1.01 }} whileTap={{ scale:0.99 }}
              onClick={() => setPhase("question")}
              className="btn-primary w-full flex items-center justify-center gap-2 py-4 text-sm">
              I understand — Show the scenario
              <ChevronRight className="size-4" />
            </motion.button>
          </motion.div>
        </AnimatePresence>
      </div>
    </div>
  );

  // ── QUESTION PHASE ──
  if (phase === "question" && q) return (
    <div className="min-h-full py-12 px-6" style={{ background:"var(--bg-base)" }}>
      <div className="max-w-2xl mx-auto">

        {/* Progress */}
        <div className="flex items-center gap-2 mb-6">
          <button onClick={() => restart()} className="text-xs flex-shrink-0"
                  style={{ color:"var(--text-muted)", fontFamily:"var(--font-mono)" }}>
            ← Levels
          </button>
          <div className="flex-1 flex items-center gap-1">
            {levelQs.map((_,i) => (
              <div key={i} className="flex-1 h-1.5 rounded-full transition-all"
                   style={{ background: i < answers.length ? (answers[i] ? "#34d399" : "#f87171") :
                                        i === qIdx ? cfg.color : "var(--bg-border)" }} />
            ))}
          </div>
          <span className="text-xs flex-shrink-0 font-bold"
                style={{ color:cfg.color, fontFamily:"var(--font-mono)" }}>
            {score}/{levelQs.length}
          </span>
        </div>

        <AnimatePresence mode="wait">
          <motion.div key={`q-${qIdx}`}
            initial={{ opacity:0, x:20 }} animate={{ opacity:1, x:0 }}
            exit={{ opacity:0, x:-20 }} transition={{ duration:0.2 }}>

            {/* Attack type tag */}
            <div className="flex items-center gap-2 mb-4">
              <span className="tag" style={{ color:cfg.color, background:cfg.bg, border:`1px solid ${cfg.border}` }}>
                {q.attackType}
              </span>
              <span className="text-xs" style={{ color:"var(--text-muted)", fontFamily:"var(--font-mono)" }}>
                Scenario {qIdx+1} of {levelQs.length}
              </span>
            </div>

            {/* Scenario */}
            <div className="card overflow-hidden mb-4" style={{ background:"var(--bg-card)" }}>
              <div className="terminal-chrome py-2">
                <div className="terminal-dot" style={{ background:"#ff5f57" }} />
                <div className="terminal-dot" style={{ background:"#febc2e" }} />
                <div className="terminal-dot" style={{ background:"#28c840" }} />
                <span className="ml-3 text-xs" style={{ color:"var(--text-muted)", fontFamily:"var(--font-mono)" }}>
                  scenario.txt
                </span>
              </div>
              <div className="p-5">
                <pre className="text-sm whitespace-pre-wrap break-all leading-relaxed"
                     style={{ color:"var(--text-primary)", fontFamily:"var(--font-mono)", fontSize:12 }}>
                  {q.scenario}
                </pre>
              </div>
            </div>

            {/* Question */}
            <p className="text-base font-semibold mb-5 leading-snug"
               style={{ color:"var(--text-primary)", letterSpacing:"-0.01em" }}>
              {q.question}
            </p>

            {/* MCQ Options */}
            {!answered && (
              <div className="space-y-2.5 mb-4">
                {q.options.map(opt => (
                  <motion.button key={opt.id}
                    whileHover={{ scale:1.005 }} whileTap={{ scale:0.995 }}
                    onClick={() => handleAnswer(opt.id)}
                    className="w-full text-left p-4 rounded-xl transition-all text-sm leading-relaxed"
                    style={{ background:"var(--bg-elevated)", border:"1px solid var(--bg-border)",
                             color:"var(--text-secondary)" }}
                    onMouseEnter={e => {
                      (e.currentTarget as HTMLButtonElement).style.borderColor = cfg.color + "44";
                      (e.currentTarget as HTMLButtonElement).style.color = "var(--text-primary)";
                    }}
                    onMouseLeave={e => {
                      (e.currentTarget as HTMLButtonElement).style.borderColor = "var(--bg-border)";
                      (e.currentTarget as HTMLButtonElement).style.color = "var(--text-secondary)";
                    }}>
                    <span className="font-bold mr-2"
                          style={{ color:cfg.color, fontFamily:"var(--font-mono)" }}>
                      {opt.id.toUpperCase()}.
                    </span>
                    {opt.text}
                  </motion.button>
                ))}
              </div>
            )}

            {/* Answered state — show all options with color coding */}
            {answered && (
              <motion.div initial={{ opacity:0, y:6 }} animate={{ opacity:1, y:0 }}
                          className="space-y-2 mb-4">
                {q.options.map(opt => {
                  const isCorrectOpt = opt.id === q.correct;
                  const isSelectedOpt= opt.id === selected;
                  const borderColor  = isCorrectOpt ? "rgba(52,211,153,0.4)" :
                                       isSelectedOpt && !isCorrectOpt ? "rgba(248,113,113,0.35)" :
                                       "var(--bg-border)";
                  const bgColor      = isCorrectOpt ? "rgba(52,211,153,0.07)" :
                                       isSelectedOpt && !isCorrectOpt ? "rgba(248,113,113,0.07)" :
                                       "var(--bg-elevated)";
                  const textColor    = isCorrectOpt ? "#34d399" :
                                       isSelectedOpt && !isCorrectOpt ? "#f87171" : "var(--text-muted)";
                  return (
                    <div key={opt.id} className="p-4 rounded-xl text-sm flex items-start gap-3"
                         style={{ background:bgColor, border:`1px solid ${borderColor}` }}>
                      <span className="flex-shrink-0 mt-0.5">
                        {isCorrectOpt ? <CheckCircle className="size-4" style={{ color:"#34d399" }} /> :
                         isSelectedOpt ? <XCircle className="size-4" style={{ color:"#f87171" }} /> :
                         <div className="w-4 h-4" />}
                      </span>
                      <span style={{ color:textColor }}>
                        <span className="font-bold mr-1.5"
                              style={{ fontFamily:"var(--font-mono)" }}>
                          {opt.id.toUpperCase()}.
                        </span>
                        {opt.text}
                      </span>
                    </div>
                  );
                })}
              </motion.div>
            )}

            {/* Hint (before answering) */}
            {!answered && (
              <div className="mb-5">
                {!showHint ? (
                  <button onClick={() => setShowHint(true)}
                          className="flex items-center gap-1.5 text-xs transition-colors"
                          style={{ color:"var(--text-muted)" }}>
                    <Lightbulb className="size-3.5" /> Show hint
                  </button>
                ) : (
                  <div className="px-4 py-3 rounded-xl"
                       style={{ background:"rgba(96,165,250,0.07)", border:"1px solid rgba(96,165,250,0.2)" }}>
                    <div className="flex items-start gap-2">
                      <Lightbulb className="size-3.5 flex-shrink-0 mt-0.5" style={{ color:"var(--color-info)" }} />
                      <p className="text-xs leading-relaxed"
                         style={{ color:"var(--color-info)" }}>
                        Focus on the signals from the concept section. Look for what is technically impossible for a legitimate service to produce.
                      </p>
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* Explanation (after answering) */}
            {answered && (
              <motion.div initial={{ opacity:0, y:6 }} animate={{ opacity:1, y:0 }} transition={{ delay:0.1 }}>

                {/* Result banner */}
                <div className="flex items-center gap-3 px-4 py-3.5 rounded-xl mb-4"
                     style={{
                       background: isCorrect ? "rgba(52,211,153,0.07)" : "rgba(248,113,113,0.07)",
                       border:`1px solid ${isCorrect ? "rgba(52,211,153,0.25)" : "rgba(248,113,113,0.25)"}`,
                     }}>
                  {isCorrect
                    ? <CheckCircle className="size-5 flex-shrink-0" style={{ color:"#34d399" }} />
                    : <XCircle    className="size-5 flex-shrink-0" style={{ color:"#f87171" }} />}
                  <div>
                    <p className="text-sm font-bold"
                       style={{ color:isCorrect ? "#34d399" : "#f87171" }}>
                      {isCorrect ? "Correct." : `Incorrect — the answer was ${q.correct.toUpperCase()}.`}
                    </p>
                    <p className="text-xs mt-0.5" style={{ color:"var(--text-muted)" }}>
                      {q.attackType}
                    </p>
                  </div>
                </div>

                {/* Explanation */}
                <div className="card p-5 mb-4" style={{ background:"var(--bg-elevated)" }}>
                  <div className="label-caps mb-3">Why this is the correct answer</div>
                  <p className="text-sm leading-relaxed mb-4" style={{ color:"var(--text-secondary)" }}>
                    {q.explanation}
                  </p>

                  {!isCorrect && (
                    <div className="mb-4 pt-3 border-t" style={{ borderColor:"var(--bg-border)" }}>
                      <div className="label-caps mb-2">Why the other options are wrong</div>
                      <p className="text-xs leading-relaxed"
                         style={{ color:"var(--text-muted)" }}>
                        {q.wrongExplain}
                      </p>
                    </div>
                  )}

                  {/* Signals */}
                  <div className="pt-3 border-t" style={{ borderColor:"var(--bg-border)" }}>
                    <div className="label-caps mb-2.5">Detection signals</div>
                    <div className="flex flex-wrap gap-1.5">
                      {q.signals.map((sig,i) => (
                        <span key={i} className="text-[10px] px-2 py-1 rounded"
                              style={{ color:cfg.color, background:cfg.bg,
                                       border:`1px solid ${cfg.border}`,
                                       fontFamily:"var(--font-mono)" }}>
                          {sig}
                        </span>
                      ))}
                    </div>
                  </div>

                  {/* MITRE */}
                  {q.mitre && (
                    <div className="mt-3 pt-3 border-t" style={{ borderColor:"var(--bg-border)" }}>
                      <div className="text-xs px-3 py-2 rounded-lg"
                           style={{ color:"#a78bfa", background:"rgba(167,139,250,0.07)",
                                    border:"1px solid rgba(167,139,250,0.18)",
                                    fontFamily:"var(--font-mono)" }}>
                        🎯 {q.mitre}
                      </div>
                    </div>
                  )}
                </div>

                {/* Next button */}
                <motion.button whileHover={{ scale:1.01 }} whileTap={{ scale:0.99 }}
                  onClick={handleNext}
                  className="btn-primary w-full flex items-center justify-center gap-2 py-4 text-sm">
                  {isLast ? <><Award className="size-4" /> See Results</> :
                            <>Next Scenario <ChevronRight className="size-4" /></>}
                </motion.button>
              </motion.div>
            )}
          </motion.div>
        </AnimatePresence>
      </div>
    </div>
  );

  // ── COMPLETE ──
  const rank = getRank(score, levelQs.length);
  const nextLevel = LEVEL_ORDER[LEVEL_ORDER.indexOf(level) + 1] as Level | undefined;

  return (
    <div className="min-h-full py-16 px-6 flex items-center justify-center"
         style={{ background:"var(--bg-base)" }}>
      <motion.div initial={{ opacity:0, scale:0.97 }} animate={{ opacity:1, scale:1 }}
                  transition={{ duration:0.4, ease:[0.23,1,0.32,1] }}
                  className="max-w-md w-full">
        <div className="card overflow-hidden" style={{ background:"var(--bg-card)" }}>
          <div className="h-0.5" style={{ background:`linear-gradient(90deg, ${rank.color}, transparent)` }} />
          <div className="p-8 text-center">
            <div className="text-5xl mb-4">{rank.emoji}</div>
            <h2 className="font-display text-3xl mb-2"
                style={{ color:rank.color }}>
              {rank.label}
            </h2>
            <p className="text-sm mb-1" style={{ color:"var(--text-muted)" }}>
              {cfg.label} Level · {score}/{levelQs.length} correct
            </p>

            {/* Per-question dots */}
            <div className="flex items-center justify-center gap-2 my-6">
              {answers.map((correct,i) => (
                <div key={i} className="flex flex-col items-center gap-1">
                  {correct
                    ? <CheckCircle className="size-5" style={{ color:"#34d399" }} />
                    : <XCircle    className="size-5" style={{ color:"#f87171" }} />}
                  <span className="text-[9px]"
                        style={{ color:"var(--text-muted)", fontFamily:"var(--font-mono)" }}>
                    S{i+1}
                  </span>
                </div>
              ))}
            </div>

            <div className="space-y-2.5">
              {/* Retry same level */}
              <button onClick={() => restart(level)}
                      className="btn-ghost w-full flex items-center justify-center gap-2 py-3 text-sm">
                <RefreshCw className="size-4" /> Retry {cfg.label}
              </button>

              {/* Next level */}
              {nextLevel && (
                <button onClick={() => restart(nextLevel)}
                        className="btn-primary w-full flex items-center justify-center gap-2 py-3.5 text-sm">
                  <ChevronRight className="size-4" />
                  Next: {LEVEL_CFG[nextLevel].label}
                </button>
              )}

              {/* All levels done */}
              {!nextLevel && (
                <button onClick={() => restart()}
                        className="btn-primary w-full flex items-center justify-center gap-2 py-3.5 text-sm">
                  <Brain className="size-4" /> All Levels Complete — Restart
                </button>
              )}
            </div>
          </div>
        </div>
      </motion.div>
    </div>
  );
}