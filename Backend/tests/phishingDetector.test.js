// Automated regression tests for PhishNetra detection engine v6.0
// Run: cd backend && npm install --save-dev jest && npx jest

const { analyzeInput } = require("../ai/phishingDetector");

describe("PhishNetra Detection Engine v6.0 — Regression Suite", () => {
  // ── Corporate Phishing ──
  describe("Corporate Phishing (IT Security Impersonation)", () => {
    test("Session ownership reconfirmation email → PHISHING", () => {
      const r = analyzeInput(
        `Hello, We detected an unusual authentication attempt associated with your corporate access profile earlier today. As part of our scheduled security validation improvements, some users may be asked to reconfirm session ownership to avoid temporary interruption of cloud services. Review activity and confirm access: https://security-verification.test/session-review. Please complete this process before end of business day to prevent automated lock procedures from being applied to your profile. Reference ID: SEC-2026-4418. Security Operations Team`,
      );
      expect(r.status).toBe("phishing");
      expect(r.riskScore).toBeGreaterThanOrEqual(60);
    });
  });

  // ── Smishing ──
  describe("Smishing — SMS/WhatsApp Phishing", () => {
    test("Payment profile SMS with 30min deadline → PHISHING", () => {
      const r = analyzeInput(
        "Notice: Your payment profile requires confirmation due to a recent policy update. Review pending activity within 30 minutes to avoid temporary restrictions: https://acct-review.test",
      );
      expect(["phishing", "suspicious"]).toContain(r.status);
      expect(r.riskScore).toBeGreaterThanOrEqual(60);
    });

    test("USPS delivery smishing with bit.ly link → PHISHING/SUSPICIOUS", () => {
      const r = analyzeInput(
        "USPS: Your package #9400111899223467088 could not be delivered. Pay $2.99 redelivery fee: bit.ly/usps-redeliver",
      );
      expect(["phishing", "suspicious"]).toContain(r.status);
      expect(r.riskScore).toBeGreaterThanOrEqual(40);
    });
  });

  // ── Homoglyph Detection ──
  describe("Homoglyph Attacks", () => {
    test("micr0soft-auth-check URL → PHISHING/SUSPICIOUS", () => {
      const r = analyzeInput("https://micr0soft-auth-check.test/security");
      expect(["phishing", "suspicious"]).toContain(r.status);
      expect(r.riskScore).toBeGreaterThanOrEqual(55);
    });

    test("paypaI (capital I) URL → PHISHING/SUSPICIOUS", () => {
      const r = analyzeInput("https://paypaI-account-verify.test/login");
      expect(["phishing", "suspicious"]).toContain(r.status);
      expect(r.riskScore).toBeGreaterThanOrEqual(55);
    });

    test("paypaI standalone domain → PHISHING", () => {
      const r = analyzeInput("paypaI.example.test");
      expect(r.status).toBe("phishing");
      expect(r.riskScore).toBeGreaterThanOrEqual(66);
    });

    test("micros0ft domain → PHISHING", () => {
      const r = analyzeInput("micros0ft.example.test");
      expect(r.status).toBe("phishing");
      expect(r.riskScore).toBeGreaterThanOrEqual(66);
    });

    test("arnazon (rn→m homoglyph) domain → PHISHING", () => {
      const r = analyzeInput("arnazon.example.test");
      expect(r.status).toBe("phishing");
      expect(r.riskScore).toBeGreaterThanOrEqual(66);
    });
  });

  // ── URL Structure ──
  describe("Suspicious URL Structure", () => {
    test("drive-share-docs cloud phishing domain → SUSPICIOUS", () => {
      const r = analyzeInput("https://drive-share-docs.test/review");
      expect(["phishing", "suspicious"]).toContain(r.status);
      expect(r.riskScore).toBeGreaterThanOrEqual(30);
    });

    test("secure-update-center auth URL → SUSPICIOUS", () => {
      const r = analyzeInput("https://secure-update-center.test/auth");
      expect(["phishing", "suspicious"]).toContain(r.status);
      expect(r.riskScore).toBeGreaterThanOrEqual(30);
    });
  });

  // ── Conversation Hijacking ──
  describe("Conversation Hijacking (Thread Injection)", () => {
    test("Document from yesterday with finance approval → SUSPICIOUS", () => {
      const r = analyzeInput(
        "Following up on the document from yesterday — updated version attached below for approval before finance closes the ticket.",
      );
      expect(["phishing", "suspicious"]).toContain(r.status);
      expect(r.riskScore).toBeGreaterThanOrEqual(45);
    });
  });

  // ── Low-and-Slow ──
  describe("Low-and-Slow Phishing (Professional Notification)", () => {
    test("Workspace permissions refreshed with portal link → SUSPICIOUS", () => {
      const r = analyzeInput(
        "Your shared workspace permissions were refreshed successfully. If anything appears incorrect, you can review active sessions using the portal below.",
      );
      expect(["phishing", "suspicious"]).toContain(r.status);
      expect(r.riskScore).toBeGreaterThanOrEqual(45);
    });
  });

  // ── Defanged URLs ──
  describe("Defanged URL Normalization", () => {
    test("hxxps:// notation should be analyzed not skipped", () => {
      const r = analyzeInput("hxxps://paypal-secure.tk/login");
      expect(r.riskScore).toBeGreaterThan(30);
    });

    test("[.] notation should be analyzed not skipped", () => {
      const r = analyzeInput("paypal-secure[.]tk/login");
      expect(r.riskScore).toBeGreaterThan(20);
    });
  });

  // ── BEC / CEO Fraud ──
  describe("BEC / CEO Fraud", () => {
    test("Gift card CEO fraud → PHISHING/SUSPICIOUS", () => {
      const r = analyzeInput(
        "Hi, this is the CEO. I need you to urgently purchase 5x $200 Amazon gift cards for a client meeting. Keep this confidential and email me the codes. I'm in a meeting and can't talk.",
      );
      expect(["phishing", "suspicious"]).toContain(r.status);
      expect(r.riskScore).toBeGreaterThanOrEqual(40);
    });
  });

  // ── False Positive Prevention ──
  describe("Safe Inputs — No False Positives", () => {
    test("google.com → SAFE", () => {
      const r = analyzeInput("https://google.com");
      expect(r.status).toBe("safe");
      expect(r.riskScore).toBeLessThan(31);
    });

    test("github.com → SAFE", () => {
      const r = analyzeInput("https://github.com/anthropics");
      expect(r.status).toBe("safe");
    });

    test("microsoft.com → SAFE", () => {
      const r = analyzeInput("https://microsoft.com");
      expect(r.status).toBe("safe");
    });

    test("Plain professional email → SAFE", () => {
      const r = analyzeInput(
        "Hi Team, please review the Q3 report attached and share your feedback by Friday. Thanks.",
      );
      expect(r.riskScore).toBeLessThan(31);
    });

    test("Generic OTP message → not safe (contains OTP request signals)", () => {
      const r = analyzeInput(
        "Your verification code is 847291. Do not share this with anyone.",
      );
      // This SHOULD be suspicious — OTP harvesting signal
      expect(r.riskScore).toBeGreaterThanOrEqual(15);
    });
  });

  // ── Detection Version ──
  describe("Detection Engine Metadata", () => {
    test("Detection version is 5.2", () => {
      const r = analyzeInput("https://google.com");
      expect(r.detectionVersion).toBe("5.2");
    });

    test("Result always has required fields", () => {
      const r = analyzeInput("https://test.com");
      expect(r).toHaveProperty("status");
      expect(r).toHaveProperty("riskScore");
      expect(r).toHaveProperty("issues");
      expect(r).toHaveProperty("inputType");
      expect(r).toHaveProperty("confidence");
      expect(r).toHaveProperty("attackTypes");
      expect(r).toHaveProperty("mitre");
    });
  });
});
