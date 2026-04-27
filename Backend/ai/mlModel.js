// ============================================================
// FILE: backend/ai/mlModel.js  (NEW FILE — create this)
// Neural Network wrapper using synaptic.js
// Architecture: 18 inputs → 14 hidden → 8 hidden → 1 output
// ============================================================

const path   = require("path");
const synaptic = require("synaptic");

let model      = null;
let modelReady = false;

// 18 feature names — order must match extractFeatureVector()
const FEATURE_NAMES = [
  "inputLength", "urlCount", "hasHttps", "hasHttp",
  "issueCount", "urgencyWordCount", "credentialWordCount", "financialWordCount",
  "hasBrandSpoof", "hasOtpRequest", "hasUrgency", "hasSocialEngineering",
  "hasFinancialLure", "hasAttachment", "hasSuspiciousTLD", "hasIPAddress",
  "isURL", "isText",
];

// ─── Load trained model from JSON on startup ───
function loadModel() {
  try {
    const modelData = require(path.join(__dirname, "phishing_model.json"));
    model      = synaptic.Network.fromJSON(modelData);
    modelReady = true;
    console.log("🧠 ML Model loaded — 18→14→8→1 neural network ready");
  } catch (err) {
    console.warn("⚠️  ML Model failed to load:", err.message);
    console.warn("   Detection will use rule-based engine only");
    modelReady = false;
  }
}

// ─── Run feature vector through neural network ───
// Returns 0.0 (safe) → 1.0 (phishing), or null if model not ready
function mlPredict(featureVector) {
  if (!modelReady || !model) return null;
  try {
    const inputArray = FEATURE_NAMES.map((name) => {
      const val = featureVector[name];
      return typeof val === "number" ? Math.max(0, Math.min(1, val)) : 0;
    });
    return model.activate(inputArray)[0];
  } catch (err) {
    console.error("ML prediction error:", err.message);
    return null;
  }
}

// ─── Hybrid Score: ML (45%) + Rules (55%) ───
// If ML unavailable → rule score used directly (graceful fallback)
function hybridScore(ruleScore, featureVector) {
  const mlRaw = mlPredict(featureVector);

  if (mlRaw === null) {
    return { finalScore: ruleScore, mlScore: null, ruleScore, hybridMode: false };
  }

  const mlScore = Math.round(mlRaw * 100);
  const blended = Math.round(mlScore * 0.45 + ruleScore * 0.55);

  // Agreement bonuses
  let finalScore = blended;
  if (mlScore >= 70 && ruleScore >= 70) finalScore = Math.min(blended + 8, 100); // both agree: phishing
  else if (mlScore <= 20 && ruleScore <= 20) finalScore = Math.max(blended - 5, 0); // both agree: safe
  else if (Math.abs(mlScore - ruleScore) > 35) finalScore = Math.round(mlScore * 0.3 + ruleScore * 0.7); // disagree: trust rules more

  return {
    finalScore: Math.min(finalScore, 100),
    mlScore,
    ruleScore,
    hybridMode: true,
  };
}

loadModel();

module.exports = { mlPredict, hybridScore, isModelReady: () => modelReady };