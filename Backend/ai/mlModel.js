// ================================================================
// FILE: Backend/ai/mlModel.js — FULL REPLACE
//
// Loads phishing_model_v4.json (custom layer format — NOT synaptic)
// Architecture: 15 inputs -> 32 -> 16 -> 1
// Xavier-initialized, balanced 1:1, Accuracy 85.4% F1 84.7%
//
// WHY v4 replaces v3:
//   v3 stuck at constant ~77% output (dead network bug).
//   v4 fixes: Xavier init + balanced 1:1 data + trusted-domain
//   feature + 15-feature vector + synthetic safe URLs injected.
// ================================================================

"use strict";

const fs   = require("fs");
const path = require("path");

const V4_PATH = path.join(__dirname, "phishing_model_v4.json");
const V3_PATH = path.join(__dirname, "phishing_model_v3.json");

let W1, b1, W2, b2, W3, b3;
let modelReady  = false;
let modelMeta   = {};
let useV4       = false;
let synapticNet = null;

function sigmoid(x) {
  return 1 / (1 + Math.exp(-Math.max(-15, Math.min(15, x))));
}

function layerFwd(x, W, b) {
  return W.map((row, i) =>
    sigmoid(b[i] + row.reduce((s, w, j) => s + w * x[j], 0))
  );
}

function v4Forward(features) {
  const h1  = layerFwd(features, W1, b1);
  const h2  = layerFwd(h1,       W2, b2);
  return layerFwd(h2, W3, b3)[0];
}

// ── Feature extractor — matches Python training exactly ──
const HIGH_ABUSE = new Set([
  ".tk",".ml",".ga",".cf",".gq",".top",".xyz",
  ".icu",".sbs",".cfd",".click",".vip",".fun",
]);
const TRUSTED = new Set([
  "google.com","gmail.com","youtube.com","microsoft.com","github.com",
  "stackoverflow.com","amazon.com","linkedin.com","twitter.com","facebook.com",
  "apple.com","netflix.com","reddit.com","wikipedia.org","paypal.com",
  "dropbox.com","slack.com","zoom.us","instagram.com","spotify.com",
  "adobe.com","oracle.com","ibm.com","cloudflare.com","npmjs.com",
]);
const PHISH_KW = [
  "login","verify","secure","account","update","confirm","paypal",
  "google","apple","amazon","microsoft","bank","signin","password","credential",
];

function extractFeatures(url) {
  const u = url.toLowerCase();
  let domain = u;
  try { domain = u.split("//")[1].split("/")[0].replace(/^www\./, ""); } catch {}
  const tld     = domain.includes(".") ? "." + domain.split(".").pop() : "";
  const trusted = [...TRUSTED].some(d => domain === d || domain.endsWith("." + d)) ? 1 : 0;
  return [
    Math.min(url.length / 200, 1),
    Math.min((url.match(/\./g) || []).length / 10, 1),
    Math.min((url.match(/-/g)  || []).length / 10, 1),
    HIGH_ABUSE.has(tld) ? 1 : 0,
    url.startsWith("https") ? 1 : 0,
    Math.min(PHISH_KW.filter(k => u.includes(k)).length / 5, 1),
    url.includes("@") ? 1 : 0,
    /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(domain) ? 1 : 0,
    Math.min(Math.max(domain.split(".").length - 2, 0), 5) / 5,
    ["-secure-","-login-","-verify-","-update-"].some(p => url.includes(p)) ? 1 : 0,
    trusted,
    url.startsWith("https") && trusted ? 1 : 0,
    url.length < 40 && url.startsWith("https") ? 1 : 0,
    Math.min((url.match(/\//g) || []).length / 8, 1),
    /\.(exe|bat|sh|zip|js)$/i.test(url) ? 1 : 0,
  ];
}

// ── Load v4 ──
function loadV4() {
  try {
    const data = JSON.parse(fs.readFileSync(V4_PATH, "utf8"));
    const L    = data.layers;
    W1 = L.L1.W; b1 = L.L1.b;
    W2 = L.L2.W; b2 = L.L2.b;
    W3 = L.L3.W; b3 = L.L3.b;
    modelMeta  = data._meta || {};
    modelReady = true;
    useV4      = true;
    console.log(
      `\u{1F9E0} ML Model v4 loaded — ` +
      `acc:${modelMeta.accuracy}% f1:${modelMeta.f1}% ` +
      `prec:${modelMeta.precision}% recall:${modelMeta.recall}%`
    );
    console.log(
      `   Arch: ${modelMeta.architecture} | ` +
      `Samples: ${(modelMeta.samples||0).toLocaleString()} | ` +
      `MSE: ${(modelMeta.finalMSE||0).toFixed(5)} | ` +
      `Live test: ${modelMeta.liveTestAccuracy}%`
    );
    return true;
  } catch (err) {
    console.warn("\u26A0\uFE0F  phishing_model_v4.json not found:", err.message);
    return false;
  }
}

// ── Load v3 synaptic fallback ──
function loadV3Synaptic() {
  try {
    const synaptic = require("synaptic");
    const data     = JSON.parse(fs.readFileSync(V3_PATH, "utf8"));
    synapticNet    = synaptic.Network.fromJSON(data);
    modelMeta      = data._meta || {};
    modelReady     = true;
    useV4          = false;
    console.log("\u{1F9E0} ML Model v3 loaded (synaptic fallback)");
    console.log("   \u26A0\uFE0F v3 has dead-network bug (outputs constant ~77%)");
    console.log("   \u{1F449} Copy phishing_model_v4.json to Backend/ai/ to fix this");
    return true;
  } catch (err) {
    console.warn("\u26A0\uFE0F v3 fallback failed:", err.message);
    return false;
  }
}

// ── Predict ──
function mlPredict(urlOrFeatures) {
  if (!modelReady) return null;
  try {
    if (useV4) {
      const features = typeof urlOrFeatures === "string"
        ? extractFeatures(urlOrFeatures)
        : urlOrFeatures.slice(0, 15).concat(
            Array(Math.max(0, 15 - urlOrFeatures.length)).fill(0)
          );
      return v4Forward(features);
    } else {
      const features = Array.isArray(urlOrFeatures)
        ? urlOrFeatures
        : extractFeatures(urlOrFeatures);
      return synapticNet.activate(features.slice(0, 64))[0];
    }
  } catch (err) {
    console.error("ML predict error:", err.message);
    return null;
  }
}

// ── Hybrid score: ML 45% + Rules 55% ──
function hybridScore(ruleScore, featureVectorOrUrl) {
  const mlRaw = mlPredict(featureVectorOrUrl);
  if (mlRaw === null)
    return { finalScore: ruleScore, mlScore: null, ruleScore, hybridMode: false };

  const mlScore = Math.round(mlRaw * 100);

  // Dead-network guard: if ML stuck near 77% and rules say safe, trust rules
  if (mlScore >= 75 && mlScore <= 79 && ruleScore < 20) {
    console.warn("\u26A0\uFE0F ML score may be stuck — trusting rule score");
    return { finalScore: ruleScore, mlScore, ruleScore, hybridMode: false };
  }

  let blended = Math.round(mlScore * 0.45 + ruleScore * 0.55);

  // Confidence boosters
  if (mlScore >= 70 && ruleScore >= 70)
    blended = Math.min(blended + 8, 100);
  else if (mlScore <= 20 && ruleScore <= 20)
    blended = Math.max(blended - 5, 0);
  else if (Math.abs(mlScore - ruleScore) > 35)
    blended = Math.round(mlScore * 0.3 + ruleScore * 0.7);

  return {
    finalScore: Math.min(blended, 100),
    mlScore,
    ruleScore,
    hybridMode: true,
  };
}

// ── Hot-swap after retraining ──
function hotSwapModel() {
  console.log("\u{1F504} Hot-swapping ML model...");
  loadV4();
}

// Initialise on require()
if (!loadV4()) loadV3Synaptic();

module.exports = {
  mlPredict,
  hybridScore,
  hotSwapModel,
  extractFeatures,
  isModelReady: () => modelReady,
  getModelMeta: () => modelMeta,
  isV4: () => useV4,
};