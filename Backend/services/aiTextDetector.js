"use strict";

// ── AI fingerprint phrases (ChatGPT/Claude signatures) ───────
// These phrases appear disproportionately in AI-generated text
const AI_FINGERPRINT_PHRASES = [
  // Over-formal openers
  "i hope this message finds you well",
  "i hope this email finds you well",
  "i trust this finds you well",
  "i hope you are doing well",
  "i am writing to",
  "i wanted to reach out",
  "i am reaching out regarding",
  "please don't hesitate to reach out",
  // Excessive politeness closers
  "please feel free to contact",
  "do not hesitate to contact",
  "please do not hesitate",
  "should you require any further",
  "if you have any questions or concerns",
  "i appreciate your understanding",
  "thank you for your understanding",
  "thank you for your prompt attention",
  "looking forward to your prompt",
  "i look forward to hearing from you",
  "at your earliest convenience",
  "as soon as possible",
  "kindly note that",
  "kindly be informed",
  "please be informed",
  "please be advised",
  "please take note",
  "please find attached",
  "pursuant to",
  "as per our records",
  "as per our conversation",
  // Filler phrases AI overuses
  "it is important to note",
  "it is worth noting",
  "it should be noted",
  "in this regard",
  "in this context",
  "in order to",
  "with regard to",
  "with respect to",
  "going forward",
  "rest assured",
  "needless to say",
  "as you are aware",
  "as you may be aware",
  "as previously mentioned",
  "first and foremost",
  "last but not least",
  "on a different note",
  "in light of",
  "take note of",
  "in the meantime",
  // AI BEC-specific phrases
  "due to the sensitive nature",
  "for security purposes",
  "your immediate attention is required",
  "this is an automated notification",
  "please verify your information",
  "to ensure the security of your account",
  "for your security and convenience",
  "we have detected unusual activity",
  "your account has been flagged",
  "your account requires verification",
];

// ── Phrases that indicate HUMAN writing (lower AI score) ─────
const HUMAN_SIGNALS = [
  /\b(lol|haha|btw|fyi|omg|tbh|ngl|imo|idk)\b/i,
  /\b(gonna|wanna|kinda|sorta|dunno|gotta)\b/i,
  /\b(hey|hi there|hello there|yo)\b/i,
  /[!]{2,}/, // multiple exclamation marks (emotional)
  /\.\.\./, // ellipsis (hesitation — human)
  /[a-z]{1}[A-Z]/, // camelCase mid-sentence (typing casualness)
];

// ── Compute Shannon entropy of a string ──────────────────────
function shannonEntropy(text) {
  if (!text || text.length < 10) return 0;
  const freq = {};
  for (const ch of text) {
    freq[ch] = (freq[ch] || 0) + 1;
  }
  const len = text.length;
  let entropy = 0;
  for (const count of Object.values(freq)) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return Math.round(entropy * 100) / 100;
}

// ── Sentence length analysis ──────────────────────────────────
function analyzeSentenceLengths(text) {
  const sentences = text
    .split(/[.!?]+/)
    .map((s) => s.trim())
    .filter((s) => s.length > 5);

  if (sentences.length < 3) return { avg: 0, variance: 0, stddev: 0 };

  const lengths = sentences.map((s) => s.split(/\s+/).length);
  const avg = lengths.reduce((a, b) => a + b, 0) / lengths.length;
  const variance =
    lengths.reduce((a, b) => a + Math.pow(b - avg, 2), 0) / lengths.length;
  const stddev = Math.sqrt(variance);

  return {
    avg: Math.round(avg * 10) / 10,
    variance: Math.round(variance * 10) / 10,
    stddev: Math.round(stddev * 10) / 10,
    count: sentences.length,
  };
}

// ── Punctuation density ───────────────────────────────────────
function punctuationDensity(text) {
  if (!text.length) return 0;
  const puncts = (text.match(/[,;:!?.'"()\-–—]/g) || []).length;
  return Math.round((puncts / text.split(/\s+/).length) * 100) / 100;
}

// ── Vocabulary richness (type-token ratio) ────────────────────
function vocabularyRichness(text) {
  const words = text.toLowerCase().match(/\b[a-z]{3,}\b/g) || [];
  if (!words.length) return 0;
  const unique = new Set(words).size;
  return Math.round((unique / words.length) * 100) / 100;
}

// ── Detect copy-paste phishing template markers ───────────────
const TEMPLATE_MARKERS = [
  /\[your name\]|\[name\]|\[username\]|\[account\]/i,
  /\{name\}|\{user\}|\{account\}|\{email\}/i,
  /dear \[|hello \[|hi \[/i,
  /ACCOUNT_NUMBER|TRANSACTION_ID|ORDER_ID/,
  /%%[A-Z_]+%%/,
  /\{\{[a-z_]+\}\}/,
];

// ── Main detection function ───────────────────────────────────
function detectAIGeneratedText(text) {
  if (!text || text.length < 80) {
    return {
      aiProbability: 0,
      verdict: "unclear",
      signals: [],
      riskBoost: 0,
      linguisticProfile: {},
    };
  }

  const lower = text.toLowerCase();
  const signals = [];
  let aiScore = 0;

  // ── 1. AI fingerprint phrases ──────────────────────────────
  const fingerprintHits = AI_FINGERPRINT_PHRASES.filter((p) =>
    lower.includes(p),
  );
  if (fingerprintHits.length >= 4) {
    aiScore += 40;
    signals.push({
      id: "ai_phrases",
      label: "AI Fingerprint Phrases",
      weight: 40,
      detail: `${fingerprintHits.length} AI-characteristic phrases detected: "${fingerprintHits.slice(0, 3).join('", "')}"`,
      finding:
        "LLM models consistently produce these over-formal phrases that rarely appear together in natural human email.",
    });
  } else if (fingerprintHits.length >= 2) {
    aiScore += 20;
    signals.push({
      id: "ai_phrases_low",
      label: "AI Fingerprint Phrases (low)",
      weight: 20,
      detail: `${fingerprintHits.length} AI-characteristic phrases: "${fingerprintHits.slice(0, 2).join('", "')}"`,
      finding:
        "Possible AI-generated content — over-formal phrasing common in LLM output.",
    });
  }

  // ── 2. Sentence length uniformity ─────────────────────────
  const sentStats = analyzeSentenceLengths(text);
  if (sentStats.count >= 3) {
    if (sentStats.stddev < 4 && sentStats.avg > 8) {
      aiScore += 25;
      signals.push({
        id: "uniform_sentences",
        label: "Unnaturally Uniform Sentences",
        weight: 25,
        detail: `Sentence length std dev: ${sentStats.stddev} words (avg: ${sentStats.avg}). AI produces sentences of similar length; human text has high length variance.`,
        finding:
          "Statistical signature of AI generation — sentence lengths are too consistent for natural human writing.",
      });
    }
  }

  // ── 3. Zero typos + perfect grammar indicator ──────────────
  const wordCount = (text.match(/\b\w+\b/g) || []).length;
  const humanHits = HUMAN_SIGNALS.filter((p) => p.test(text)).length;
  if (wordCount >= 100 && humanHits === 0) {
    aiScore += 15;
    signals.push({
      id: "zero_casual",
      label: "Zero Casual Language Markers",
      weight: 15,
      detail: `${wordCount}-word email with no informal language, contractions, or casual expressions — statistically unusual for authentic human email.`,
      finding:
        "Natural human email (especially urgent requests) contains informal markers. Zero casual language in a long email suggests AI generation.",
    });
  }

  // ── 4. Vocabulary richness anomaly ─────────────────────────
  const ttr = vocabularyRichness(text);
  if (ttr > 0.75 && wordCount > 80) {
    aiScore += 15;
    signals.push({
      id: "high_vocabulary",
      label: "Unusually High Vocabulary Diversity",
      weight: 15,
      detail: `Type-token ratio: ${ttr} (${wordCount} words) — AI models use a broader vocabulary than typical phishing templates or human informal email.`,
      finding:
        "LLM-generated text has higher lexical diversity than template phishing. Combined with other signals, suggests AI authorship.",
    });
  }

  // ── 5. Punctuation consistency ─────────────────────────────
  const pDensity = punctuationDensity(text);
  if (pDensity > 0.4 && wordCount > 50) {
    aiScore += 10;
    signals.push({
      id: "perfect_punctuation",
      label: "Perfect Punctuation Consistency",
      weight: 10,
      detail: `Punctuation density: ${pDensity} per word — unusually consistent for a long email. Human casual email has irregular punctuation.`,
      finding:
        "AI models produce grammatically perfect text. Consistent punctuation across a long suspicious email is a weak AI indicator.",
    });
  }

  // ── 6. Template markers (NEGATIVE signal — human template) ─
  const templateHits = TEMPLATE_MARKERS.filter((p) => p.test(text)).length;
  if (templateHits > 0) {
    aiScore -= 20;
    signals.push({
      id: "template_markers",
      label: "Template Variable Markers Detected",
      weight: -20,
      detail: `Found ${templateHits} template placeholder(s) — this is a phishing TEMPLATE, not AI-generated text. Different attack vector.`,
      finding:
        "Template-based phishing (not AI-generated). Reduce AI probability but maintain high phishing risk.",
    });
  }

  // ── 7. Entropy analysis ────────────────────────────────────
  const entropy = shannonEntropy(text);
  if (entropy < 3.8) {
    aiScore -= 10;
    signals.push({
      id: "low_entropy",
      label: "Low Character Entropy",
      weight: -10,
      detail: `Shannon entropy: ${entropy} bits — low entropy indicates repetitive/template content rather than AI generation.`,
      finding: "Repetitive phishing template detected by entropy analysis.",
    });
  }

  // ── 8. Human writing signals (REDUCE AI score) ─────────────
  if (humanHits >= 2) {
    aiScore -= 15;
    signals.push({
      id: "human_markers",
      label: "Human Writing Markers Present",
      weight: -15,
      detail: `${humanHits} human-style markers found (informal language, emoticons, casual phrasing) — reduces AI generation probability.`,
      finding: "Text contains markers inconsistent with AI generation.",
    });
  }

  // ── 9. Long formal email + suspicious request combination ──
  const BEC_REQUESTS = [
    /wire transfer|wiring|bank transfer/i,
    /gift card|itunes|amazon gift|google play card/i,
    /cryptocurrency|bitcoin|crypto wallet/i,
    /invoice.*pay|pay.*invoice/i,
    /urgent.*payment|payment.*urgent/i,
    /confidential.*transfer|transfer.*confidential/i,
  ];
  const becHits = BEC_REQUESTS.filter((p) => p.test(text)).length;
  if (becHits > 0 && wordCount > 150 && aiScore >= 20) {
    aiScore += 20;
    signals.push({
      id: "ai_bec",
      label: "AI-Generated BEC Pattern",
      weight: 20,
      detail: `Long professional email (${wordCount} words) combined with ${becHits} financial request signal(s). This is the primary use case for AI-generated phishing — bypassing BEC detection that relies on typos.`,
      finding:
        "AI-generated Business Email Compromise — the most dangerous phishing variant. No typos, professional tone, legitimate-sounding request.",
    });
  }

  // Clamp aiScore to 0-100
  const aiProbability = Math.max(0, Math.min(100, aiScore));

  // Determine verdict
  const verdict =
    aiProbability >= 60
      ? "likely_ai"
      : aiProbability >= 35
        ? "possibly_ai"
        : aiProbability >= 15
          ? "unclear"
          : "likely_human";

  // Risk boost: AI + phishing signals combined = dangerous
  const riskBoost = aiProbability >= 60 ? 20 : aiProbability >= 35 ? 10 : 0;

  return {
    aiProbability,
    verdict,
    verdictLabel: {
      likely_ai: "Likely AI-Generated",
      possibly_ai: "Possibly AI-Generated",
      unclear: "Uncertain",
      likely_human: "Likely Human-Written",
    }[verdict],
    signals: signals.filter((s) => s.weight !== 0),
    riskBoost,
    fingerprintPhrases: fingerprintHits.slice(0, 5),
    linguisticProfile: {
      charEntropy: entropy,
      avgSentenceLength: sentStats.avg,
      sentenceLengthStdDev: sentStats.stddev,
      vocabularyRichness: ttr,
      punctuationDensity: pDensity,
      wordCount,
      humanMarkers: humanHits,
      templateMarkers: templateHits,
    },
  };
}

module.exports = { detectAIGeneratedText };
