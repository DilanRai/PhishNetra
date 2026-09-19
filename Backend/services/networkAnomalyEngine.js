// ════════════════════════════════════════════════════════════════
// FILE: backend/services/networkAnomalyEngine.js
// Thin re-export shim — the actual implementation lives inside
// govtPortalDetector.js (both engines share one file).
// routes/features.js calls getEngine("networkAnomalyEngine") so
// this shim bridges the name mismatch without moving any logic.
// ════════════════════════════════════════════════════════════════
"use strict";
const { NetworkAnomaly, detectAnomaly, getAnomalyStats } = require("./govtPortalDetector");
module.exports = { NetworkAnomaly, detectAnomaly, getAnomalyStats };
