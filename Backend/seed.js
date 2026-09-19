// ================================================================
// FILE: Backend/seed.js — CREATE NEW — RUN ONCE BEFORE FIRST START
//
// This script creates the default admin user so you can actually
// log in. Without this, the database has no users, login always
// fails with "Invalid credentials", and nothing works.
//
// RUN: node seed.js
// THEN: node server.js
// ================================================================

require("dotenv").config();
const mongoose = require("mongoose");
const bcrypt   = require("bcryptjs");

const MONGODB_URI = process.env.MONGODB_URI || "mongodb://127.0.0.1:27017/phishnetra";

const userSchema = new mongoose.Schema({
  username:  { type: String, required: true, unique: true, trim: true },
  password:  { type: String, required: true },
  role:      { type: String, enum: ["admin","analyst","viewer"], default: "analyst" },
  createdAt: { type: Date, default: Date.now },
  lastLogin: { type: Date, default: null },
});

userSchema.pre("save", async function(next) {
  if (!this.isModified("password")) return next();
  this.password = await bcrypt.hash(this.password, 12);
  next();
});

const User = mongoose.model("User", userSchema);

const DEFAULT_USERS = [
  { username: "admin",    password: "Admin@123",    role: "admin"   },
  { username: "analyst",  password: "Analyst@123",  role: "analyst" },
  { username: "viewer",   password: "Viewer@123",   role: "viewer"  },
];

async function seed() {
  console.log("─────────────────────────────────────");
  console.log("  PhishNetra — Database Seeder");
  console.log("─────────────────────────────────────");

  try {
    await mongoose.connect(MONGODB_URI);
    console.log("✅ Connected to MongoDB:", MONGODB_URI);

    let created = 0;
    let skipped = 0;

    for (const u of DEFAULT_USERS) {
      const exists = await User.findOne({ username: u.username });
      if (exists) {
        console.log(`⏩ Skipped: ${u.username} (already exists, role: ${exists.role})`);
        skipped++;
        continue;
      }
      const user = new User(u);
      await user.save();
      console.log(`✅ Created: ${u.username} / ${u.password} (role: ${u.role})`);
      created++;
    }

    console.log("─────────────────────────────────────");
    console.log(`Done. Created: ${created}, Skipped: ${skipped}`);
    console.log("");
    console.log("LOGIN CREDENTIALS:");
    console.log("  Admin:   admin / Admin@123");
    console.log("  Analyst: analyst / Analyst@123");
    console.log("  Viewer:  viewer / Viewer@123");
    console.log("");
    console.log("⚠️  Change these passwords after first login!");
    console.log("─────────────────────────────────────");

  } catch (err) {
    console.error("❌ Seed failed:", err.message);
    process.exit(1);
  } finally {
    await mongoose.disconnect();
  }
}

seed();