// FILE: backend/models/ShiftNote.js

const mongoose = require("mongoose");
const { generateForensicId } = require("../utils/forensicId");

const shiftNoteSchema = new mongoose.Schema({
  noteId: {
    type: String,
    default: () => generateForensicId("SHN"),
    unique: true,
    index: true,
  },

  content: { type: String, required: true, trim: true, maxlength: 2000 },
  author: { type: String, required: true },
  pinned: { type: Boolean, default: false },
  priority: {
    type: String,
    enum: ["normal", "high", "critical"],
    default: "normal",
  },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
  expiresAt: {
    type: Date,
    default: () => new Date(Date.now() + 24 * 60 * 60 * 1000),
  },

  // ── Cross-reference IDs ────────────────────────────────────
  referencedAlertIds: { type: [String], default: [] }, // ALT- IDs mentioned in note
  referencedLogIds: { type: [String], default: [] }, // LOG- IDs mentioned
  referencedCaseId: { type: String, default: null }, // CASE- ID if related to a case

  // ── Evidence metadata ─────────────────────────────────────
  shiftStart: { type: Date, default: null }, // shift period this note covers
  shiftEnd: { type: Date, default: null },
  signedBy: { type: String, default: null }, // analyst who authored (for legal)
  isHandover: { type: Boolean, default: false }, // true = formal shift handover
});

shiftNoteSchema.index({ createdAt: -1 });
shiftNoteSchema.index({ pinned: -1, createdAt: -1 });

module.exports = mongoose.model("ShiftNote", shiftNoteSchema);
