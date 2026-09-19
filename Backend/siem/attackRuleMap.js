// ================================================================
// FILE: Backend/siem/attackRuleMap.js — CREATE NEW
//
// Loads attack_rule_map.json and provides lookup functions
// used by ruleEngine.js and the SIEM alert expansion panel.
//
// The dataset maps MITRE ATT&CK technique IDs to:
//   - Sigma detection rules (with GitHub links)
//   - Splunk ESCU detection rules (with links)
//
// Usage:
//   const { getSigmaRules, getSplunkRules, getAttackEntry } = require("./attackRuleMap");
//   const sigmaRules = getSigmaRules("T1566.002");
//   // → [{ rule_name: "...", rule_link: "..." }, ...]
// ================================================================

"use strict";

const fs   = require("fs");
const path = require("path");

const DATA_PATH = path.join(__dirname, "../data/attack_rule_map.json");

// ── Load and index the dataset at startup ──
let INDEX_BY_TECH_ID = {};  // { "T1566.002": [entries...] }
let ALL_ENTRIES      = [];
let LOADED           = false;

function load() {
  if (LOADED) return;
  try {
    const raw     = fs.readFileSync(DATA_PATH, "utf8");
    const entries = JSON.parse(raw);

    // Build index by tech_id — one tech_id can have multiple entries
    // (different atomic attack names / platforms for same technique)
    for (const entry of entries) {
      const tid = entry.tech_id?.trim();
      if (!tid) continue;
      if (!INDEX_BY_TECH_ID[tid]) INDEX_BY_TECH_ID[tid] = [];
      INDEX_BY_TECH_ID[tid].push(entry);
    }

    ALL_ENTRIES = entries;
    LOADED      = true;
    const techCount  = Object.keys(INDEX_BY_TECH_ID).length;
    const sigmaTotal = entries.reduce((s, e) => s + (e.sigma_rules?.length  || 0), 0);
    const splkTotal  = entries.reduce((s, e) => s + (e.splunk_rules?.length || 0), 0);
    console.log(`📋 Attack Rule Map loaded: ${techCount} techniques | ${sigmaTotal} Sigma rules | ${splkTotal} Splunk rules`);
  } catch (err) {
    console.warn(`⚠️  attack_rule_map.json not found or invalid: ${err.message}`);
    console.warn(`   Expected at: ${DATA_PATH}`);
  }
}

// ── Normalize tech_id for lookup ──
// Handles: "T1566.002", "T1566/002", "T1566", "t1566.002"
function normalizeTechId(techId) {
  if (!techId) return null;
  return techId.trim().toUpperCase().replace("/", ".");
}

// ── Get all dataset entries for a technique ──
function getAttackEntries(techId) {
  load();
  const tid = normalizeTechId(techId);
  if (!tid) return [];

  // Exact match first
  const exact = INDEX_BY_TECH_ID[tid] || [];
  if (exact.length > 0) return exact;

  // Parent technique fallback: T1566.002 → try T1566
  const parent = tid.split(".")[0];
  return INDEX_BY_TECH_ID[parent] || [];
}

// ── Get Sigma rules for a technique ──
// Returns deduplicated list of { rule_name, rule_link }
function getSigmaRules(techId) {
  const entries = getAttackEntries(techId);
  const seen    = new Set();
  const rules   = [];

  for (const entry of entries) {
    for (const rule of (entry.sigma_rules || [])) {
      if (!seen.has(rule.rule_name)) {
        seen.add(rule.rule_name);
        rules.push({
          rule_name: rule.rule_name,
          rule_link: rule.rule_link,
          platform:  entry.platform || "Any",
          tech_id:   entry.tech_id,
        });
      }
    }
  }
  return rules;
}

// ── Get Splunk ESCU rules for a technique ──
function getSplunkRules(techId) {
  const entries = getAttackEntries(techId);
  const seen    = new Set();
  const rules   = [];

  for (const entry of entries) {
    for (const rule of (entry.splunk_rules || [])) {
      if (!seen.has(rule.rule_name)) {
        seen.add(rule.rule_name);
        rules.push({
          rule_name: rule.rule_name,
          rule_link: rule.rule_link,
          platform:  entry.platform || "Any",
          tech_id:   entry.tech_id,
        });
      }
    }
  }
  return rules;
}

// ── Enrich a MITRE array (from phishingDetector output) with rules ──
// Input:  [{ id: "T1566.002", tactic: "...", technique: "..." }]
// Output: same array but each item gets sigmaRules + splunkRules added
function enrichMitreWithRules(mitreAttack) {
  if (!mitreAttack || !Array.isArray(mitreAttack)) return [];
  return mitreAttack.map(item => ({
    ...item,
    sigmaRules:  getSigmaRules(item.id),
    splunkRules: getSplunkRules(item.id),
  }));
}

// ── Get all techniques covered by the dataset ──
function getAllCoveredTechniques() {
  load();
  return Object.keys(INDEX_BY_TECH_ID).map(tid => ({
    tech_id:      tid,
    entry_count:  INDEX_BY_TECH_ID[tid].length,
    sigma_count:  INDEX_BY_TECH_ID[tid].reduce((s, e) => s + (e.sigma_rules?.length  || 0), 0),
    splunk_count: INDEX_BY_TECH_ID[tid].reduce((s, e) => s + (e.splunk_rules?.length || 0), 0),
    platforms:    [...new Set(INDEX_BY_TECH_ID[tid].map(e => e.platform))].join(", "),
  }));
}

// ── Get full stats ──
function getStats() {
  load();
  const techs = Object.keys(INDEX_BY_TECH_ID);
  return {
    loaded:         LOADED,
    totalEntries:   ALL_ENTRIES.length,
    uniqueTechniques: techs.length,
    sigmaRulesTotal:  ALL_ENTRIES.reduce((s, e) => s + (e.sigma_rules?.length  || 0), 0),
    splunkRulesTotal: ALL_ENTRIES.reduce((s, e) => s + (e.splunk_rules?.length || 0), 0),
    platforms:        [...new Set(ALL_ENTRIES.map(e => e.platform))],
    dataPath:         DATA_PATH,
  };
}

module.exports = {
  getSigmaRules,
  getSplunkRules,
  getAttackEntries,
  enrichMitreWithRules,
  getAllCoveredTechniques,
  getStats,
  load,
};