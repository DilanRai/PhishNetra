"use strict";

// ════════════════════════════════════════════════════════════════
// FILE: backend/utils/forensicId.js — PHISHNETRA FORENSIC ID SYSTEM
//
// ID FORMAT: {PREFIX}-{YYYYMMDD}-{HHMM}-{4HEX}
// Example:   ALT-20240115-0923-A3F9
//
// Prefixes:
//   ALT-  → SIEM Alert
//   EVT-  → SIEM Event
//   LOG-  → Endpoint Log Event
//   SHN-  → Shift Handover Note
// ════════════════════════════════════════════════════════════════

const crypto = require("crypto");

/**
 * generateForensicId(prefix)
 * Returns a structured forensic ID for chain of custody use.
 *
 * Format: {PREFIX}-{YYYYMMDD}-{HHMM}-{4HEX}
 * Example: ALT-20240115-0923-A3F9
 *          LOG-20240115-0923-B7C2
 *          SHN-20240115-1430-F1E8
 *
 * The 4-hex suffix is derived from crypto.randomBytes for
 * collision resistance — not sequential, not predictable.
 */
function generateForensicId(prefix) {
  const now  = new Date();
  const yyyy = now.getUTCFullYear();
  const mm   = String(now.getUTCMonth() + 1).padStart(2, "0");
  const dd   = String(now.getUTCDate()).padStart(2, "0");
  const hh   = String(now.getUTCHours()).padStart(2, "0");
  const min  = String(now.getUTCMinutes()).padStart(2, "0");
  const hex  = crypto.randomBytes(2).toString("hex").toUpperCase();

  return `${prefix}-${yyyy}${mm}${dd}-${hh}${min}-${hex}`;
}

/**
 * parseForensicId(id)
 * Decodes a forensic ID back into its components.
 * Useful for displaying in reports or chain-of-custody documents.
 *
 * Returns: { prefix, date, time, suffix, issuedAt: Date, raw: string }
 */
function parseForensicId(id) {
  if (!id || typeof id !== "string") return null;

  const match = id.match(/^([A-Z]+)-(\d{4})(\d{2})(\d{2})-(\d{2})(\d{2})-([A-F0-9]{4})$/);
  if (!match) return null;

  const [, prefix, yyyy, mm, dd, hh, min, suffix] = match;

  return {
    prefix,
    date:     `${dd}/${mm}/${yyyy}`,
    time:     `${hh}:${min} UTC`,
    suffix,
    issuedAt: new Date(`${yyyy}-${mm}-${dd}T${hh}:${min}:00Z`),
    raw:      id,
  };
}

/**
 * formatIdForReport(id)
 * Returns a human-readable string for chain-of-custody reports.
 * Example: "ALT-20240115-0923-A3F9 (issued 15 Jan 2024 at 09:23 UTC)"
 */
function formatIdForReport(id) {
  const parsed = parseForensicId(id);
  if (!parsed) return id;

  const months = ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"];
  const d      = parsed.issuedAt;
  const dateStr= `${d.getUTCDate()} ${months[d.getUTCMonth()]} ${d.getUTCFullYear()}`;

  return `${id} (issued ${dateStr} at ${parsed.time})`;
}

module.exports = { generateForensicId, parseForensicId, formatIdForReport };
