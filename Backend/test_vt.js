"use strict";
// Quick VirusTotal API key test — uses the EICAR test file hash
// EICAR is the industry-standard AV test string, universally known by VT
// SHA-256: 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
require("dotenv").config();

const https = require("https");

const VT_API_KEY = process.env.VIRUSTOTAL_API_KEY;
const EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";

if (!VT_API_KEY || VT_API_KEY === "your_free_key_here") {
  console.error("❌  VIRUSTOTAL_API_KEY not set in .env");
  process.exit(1);
}

console.log(`🔑  Key loaded: ${VT_API_KEY.slice(0, 8)}...${VT_API_KEY.slice(-4)}`);
console.log(`📡  Querying VT for EICAR test hash...`);
console.log(`    Hash: ${EICAR_SHA256}\n`);

const options = {
  hostname: "www.virustotal.com",
  path:     `/api/v3/files/${EICAR_SHA256}`,
  method:   "GET",
  headers:  {
    "x-apikey": VT_API_KEY,
    "Accept":   "application/json",
  },
};

const req = https.request(options, (res) => {
  let body = "";
  res.on("data", c => body += c);
  res.on("end", () => {
    if (res.statusCode === 401) {
      console.error("❌  401 Unauthorized — API key is invalid or not yet activated.");
      console.error("    VT keys can take a few minutes to activate after registration.");
      return;
    }
    if (res.statusCode === 429) {
      console.error("❌  429 Rate limit — too many requests. Wait 60 seconds and retry.");
      return;
    }
    if (res.statusCode !== 200) {
      console.error(`❌  Unexpected HTTP ${res.statusCode}`);
      console.error(body.slice(0, 300));
      return;
    }

    try {
      const d = JSON.parse(body);
      const attrs  = d?.data?.attributes;
      const stats  = attrs?.last_analysis_stats || {};
      const det    = (stats.malicious || 0) + (stats.suspicious || 0);
      const total  = Object.values(stats).reduce((a, b) => a + b, 0);

      console.log("✅  VT API is working!\n");
      console.log(`    File name  : ${attrs?.meaningful_name || "eicar.com"}`);
      console.log(`    Detections : ${det} / ${total} engines flagged this file`);
      console.log(`    Type       : ${attrs?.type_description || "—"}`);
      console.log(`    VT Link    : https://www.virustotal.com/gui/file/${EICAR_SHA256}`);

      if (det >= 5) {
        console.log("\n    ✅ Detection count looks correct for EICAR (most engines flag it).");
      } else {
        console.log("\n    ⚠️  Low detection count for EICAR — unexpected, but API is responding.");
      }
    } catch (e) {
      console.error("❌  Failed to parse VT response:", e.message);
      console.error(body.slice(0, 300));
    }
  });
});

req.setTimeout(8000, () => {
  req.destroy();
  console.error("❌  Request timed out after 8 seconds — check your internet connection.");
});

req.on("error", (e) => {
  console.error("❌  Network error:", e.message);
});

req.end();
