// FILE: backend/routes/bulk.js
// Bulk scan — accepts array of inputs, scans all, returns results

const express          = require("express");
const router           = express.Router();
const { analyzeInput } = require("../ai/phishingDetector");
const { generateDNA }  = require("../ai/threatDNA");
const Scan             = require("../models/Scan");

// POST /api/bulk/scan — scan array of inputs
router.post("/scan", async (req, res) => {
  try {
    const { inputs } = req.body;
    if (!Array.isArray(inputs) || inputs.length === 0) {
      return res.status(400).json({ error: "inputs array required" });
    }
    if (inputs.length > 500) {
      return res.status(400).json({ error: "Max 500 inputs per bulk scan" });
    }

    const results = [];
    for (const input of inputs) {
      const trimmed = String(input || "").trim();
      if (!trimmed) { results.push({ input: trimmed, skipped: true }); continue; }

      try {
        const result = await analyzeInput(trimmed);
        const dna    = result.status !== "safe" ? generateDNA(trimmed, result) : null;

        // Save to DB (non-blocking batch)
        new Scan({
          input:      trimmed, status:    result.status,
          riskScore:  result.riskScore, issues:    result.issues,
          inputType:  result.inputType, confidence:result.confidence,
          mlEnabled:  result.mlEnabled, mlScore:   result.mlScore,
          ruleScore:  result.ruleScore, dna,
          detectionVersion: result.detectionVersion,
          createdAt:  new Date(),
        }).save().catch(() => {});

        results.push({
          input:       trimmed,
          status:      result.status,
          riskScore:   result.riskScore,
          confidence:  result.confidence,
          inputType:   result.inputType,
          issues:      result.issues.slice(0, 3),
          attackTypes: result.attackTypes || [],
          fingerprint: dna?.fingerprint || null,
          technique:   dna?.technique   || null,
          mlEnabled:   result.mlEnabled,
          mlScore:     result.mlScore,
          ruleScore:   result.ruleScore,
        });
      } catch {
        results.push({ input: trimmed, status: "error", riskScore: 0, issues: ["Analysis failed"] });
      }
    }

    // Summary stats
    const summary = {
      total:      results.length,
      phishing:   results.filter(r => r.status === "phishing").length,
      suspicious: results.filter(r => r.status === "suspicious").length,
      safe:       results.filter(r => r.status === "safe").length,
      errors:     results.filter(r => r.status === "error").length,
      skipped:    results.filter(r => r.skipped).length,
    };
    summary.threatRate = summary.total > 0
      ? Math.round((summary.phishing / summary.total) * 100) : 0;

    res.json({ summary, results });
  } catch (err) {
    console.error("Bulk scan error:", err.message);
    res.status(500).json({ error: "Bulk scan failed" });
  }
});

module.exports = router;