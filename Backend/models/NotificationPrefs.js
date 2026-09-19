// FILE: backend/models/NotificationPrefs.js

const mongoose = require("mongoose");

const prefsSchema = new mongoose.Schema({
  userId:   { type: String, required: true, unique: true },
  channels: {
    email:   { enabled: { type: Boolean, default: true  }, minSeverity: { type: Number, default: 4 } },
    slack:   { enabled: { type: Boolean, default: true  }, minSeverity: { type: Number, default: 4 } },
    discord: { enabled: { type: Boolean, default: true  }, minSeverity: { type: Number, default: 4 } },
  },
  quietHours: {
    enabled: { type: Boolean, default: false },
    start:   { type: Number, default: 23 }, // 11pm
    end:     { type: Number, default: 7  }, // 7am
  },
  digestMode: { type: Boolean, default: false }, // false = instant, true = digest
  updatedAt:  { type: Date, default: Date.now },
});

module.exports = mongoose.model("NotificationPrefs", prefsSchema);