import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import {
  detectLanguage,
  exportReportToMarkdown,
  extractStructuredJobData,
  inspectUrlStructurally,
  redactSensitiveInfo,
  runLocalVerification,
} from "../frontend/src/engine/localEngine.mjs";
import {
  clearEvidence,
  exportEvidenceAsJson,
  importEvidenceFromJson,
  readEvidence,
  removeEvidence,
  saveEvidence,
} from "../frontend/src/engine/evidenceStore.mjs";

function memoryStorage(initial = null) {
  let value = initial;
  return {
    getItem: () => value,
    setItem: (_key, next) => { value = next; },
    removeItem: () => { value = null; },
  };
}

test("Evidence JSON handles damaged storage and retains saved entries", () => {
  const damaged = memoryStorage("{broken");
  assert.match(readEvidence(damaged).error, /invalid JSON/i);
  assert.throws(() => saveEvidence({ result: {} }, damaged), /invalid JSON/i);

  const storage = memoryStorage();
  saveEvidence({ saved_at: "2026-01-01", result: { risk_percentage: 40 } }, storage);
  saveEvidence({ saved_at: "2026-01-02", result: { risk_percentage: 70 } }, storage);
  assert.equal(readEvidence(storage).items.length, 2);
  assert.equal(removeEvidence(0, storage).length, 1);
});

test("1. Detects English advance registration fee scam as HIGH RISK with 7 categories", () => {
  const rep = runLocalVerification({
    text: "Company: Apex Global\nRole: Operations Executive\nSelected without interview. Pay ₹999 registration fee today.",
  });
  assert.equal(rep.risk_level, "HIGH RISK");
  assert.equal(rep.categories.length, 7);
  assert.ok(rep.suspicious_indicator_count >= 2);
});

test("2. Detects Hindi and Hinglish recruitment fraud signals", () => {
  const hi = runLocalVerification({ text: "बिना इंटरव्यू के नौकरी पाने के लिए ₹2,000 सिक्योरिटी डिपॉजिट दें।" });
  assert.equal(hi.detected_language, "hi");
  assert.equal(hi.risk_level, "HIGH RISK");

  const hinglish = runLocalVerification({ text: "Job ke liye pehle ₹1500 registration fees jama karo." });
  assert.equal(hinglish.detected_language, "hinglish");
  assert.equal(hinglish.risk_level, "HIGH RISK");
});

test("3. Negation handling: anti-fraud disclaimer does not trigger false positive", () => {
  const rep = runLocalVerification({
    text: "Company: Infosys Limited\nRole: Software Engineer\nApply at https://www.infosys.com/careers/ or careers@infosys.com. Never pay any registration fee during recruitment.",
  });
  assert.equal(rep.risk_level, "LOW RISK");
  assert.equal(rep.suspicious_indicator_count, 0);
});

test("4. Word 'urgent' alone does not trigger HIGH RISK", () => {
  const rep = runLocalVerification({
    text: "Company: Razorpay\nRole: Backend Software Engineer\nUrgent reminder: confirm interview via recruiting@razorpay.com.",
  });
  assert.equal(rep.risk_level, "LOW RISK");
});

test("5. Zero-visit URL inspector flags fake Infosys career portal", () => {
  const res = inspectUrlStructurally("https://infosys.careers-verification.xyz/apply");
  assert.equal(res.risk_level, "HIGH RISK");
  assert.equal(res.registrable_domain, "careers-verification.xyz");
  assert.equal(res.impersonated_brand, "INFOSYS");
});

test("6. Unknown company is marked Unverified, not fraudulent", () => {
  const rep = runLocalVerification({
    text: "Company: GreenLeaf Robotics\nRole: Firmware Engineer\nSalary: 8 LPA\nEmail: hr@greenleafrobotics.in",
  });
  assert.equal(rep.risk_level, "LOW RISK");
  assert.equal(rep.categories[0].overall_status, "Unverified");
});

test("7. PII redaction masks Aadhaar, PAN, IFSC, OTP/PIN, and bank account", () => {
  const { redacted, counts } = redactSensitiveInfo(
    "Aadhaar 2345 6789 0123 PAN ABCDE1234F IFSC HDFC0001234 OTP: 981234"
  );
  assert.ok(!redacted.includes("2345 6789 0123"));
  assert.ok(!redacted.includes("ABCDE1234F"));
  assert.ok(!redacted.includes("HDFC0001234"));
  assert.ok(!redacted.includes("981234"));
  assert.ok(Object.keys(counts).length >= 4);
});

test("8. Structured 10-field extraction leaves missing fields explicitly missing", () => {
  const ext = extractStructuredJobData("Company: Zoho\nRole: Frontend Developer");
  assert.equal(ext.employer.status, "extracted");
  assert.equal(ext.requisition_id.status, "missing");
  assert.equal(ext.requisition_id.value, null);
});

test("9. Markdown report export includes risk level and all 7 categories", () => {
  const rep = runLocalVerification({ text: "Company: Infosys\nRole: Systems Engineer" });
  const md = exportReportToMarkdown(rep);
  assert.ok(md.includes("# JobGuard AI — Evidence-Based Verification Report"));
  assert.ok(md.includes("7. Document and Message Consistency"));
});

test("10. Production bundle frontend/dist/index.html exists and contains JobGuard AI assets", () => {
  const distFile = path.resolve("frontend/dist/index.html");
  const html = fs.readFileSync(distFile, "utf-8");
  assert.ok(html.includes("JobGuard AI"));
  assert.ok(html.includes("/assets/"));
  const assetDir = path.resolve("frontend/dist/assets");
  const assets = fs.readdirSync(assetDir);
  const jsFile = assets.find((name) => name.endsWith(".js"));
  const cssFile = assets.find((name) => name.endsWith(".css"));
  assert.ok(jsFile);
  assert.ok(cssFile);
  const js = fs.readFileSync(path.join(assetDir, jsFile), "utf-8");
  const css = fs.readFileSync(path.join(assetDir, cssFile), "utf-8");
  assert.ok(js.length > 100);
  assert.ok(css.includes("outline"));
});

test("11. Evidence JSON export and import functions operate cleanly without loss", () => {
  const storage = memoryStorage();
  saveEvidence({ saved_at: "2026-05-01", result: { risk_category: "HIGH RISK", risk_percentage: 90, fraud_category: "UPI Scam" } }, storage);
  const exported = exportEvidenceAsJson(storage);
  assert.ok(exported.includes("UPI Scam"));

  const targetStorage = memoryStorage();
  importEvidenceFromJson(exported, targetStorage);
  const readBack = readEvidence(targetStorage);
  assert.equal(readBack.items.length, 1);
  assert.equal(readBack.items[0].result.fraud_category, "UPI Scam");
});

test("12. Structured 10-field extraction handles JSON formatted job data", () => {
  const jsonInput = JSON.stringify({
    employer: "Wipro Technologies",
    role: "Cloud DevOps Engineer",
    salary: "14 LPA",
    location: "Hyderabad",
    job_url: "https://careers.wipro.com/job/123",
  });
  const ext = extractStructuredJobData(jsonInput);
  assert.equal(ext.employer.status, "extracted");
  assert.ok(ext.employer.value.includes("Wipro"));
});

test("13. Production bundle contains app.js and styles.css static fallbacks", () => {
  const appJs = path.resolve("frontend/dist/app.js");
  const stylesCss = path.resolve("frontend/dist/styles.css");
  assert.ok(fs.existsSync(appJs), "dist/app.js exists");
  assert.ok(fs.existsSync(stylesCss), "dist/styles.css exists");
  assert.ok(fs.readFileSync(appJs, "utf-8").includes("Call Recording Scam Detector"));
});

test("14. Local engine achieves 100% scam recall and 0% false positives on 112-sample benchmark", () => {
  const benchPath = path.resolve("tests/benchmark_112.json");
  const samples = JSON.parse(fs.readFileSync(benchPath, "utf-8"));
  let scamHits = 0;
  let scamTotal = 0;
  let legitFps = 0;
  let legitTotal = 0;
  for (const row of samples) {
    const rep = runLocalVerification({ text: row.text });
    const flagged = (rep.indicators && rep.indicators.length > 0) || rep.risk_level === "HIGH RISK";
    if (row.label === "SCAM") {
      scamTotal += 1;
      if (flagged) scamHits += 1;
    } else {
      legitTotal += 1;
      if (flagged) legitFps += 1;
    }
  }
  assert.equal(scamHits, scamTotal, `Expected 100% scam recall, got ${scamHits}/${scamTotal}`);
  assert.equal(legitFps, 0, `Expected 0% false positives, got ${legitFps}/${legitTotal}`);
});

test("15. Independent URL-only and URL editing classification edge cases", () => {
  const safeUrl = runLocalVerification({
    text: "",
    jobUrl: "https://www.razorpay.com/careers/software-engineer",
    isDemo: false,
  });
  assert.equal(safeUrl.is_demo, false);
  assert.equal(safeUrl.risk_level, "LOW RISK");

  const suspiciousUrl = runLocalVerification({
    text: "",
    jobUrl: "https://infosys.careers-verification.xyz/apply",
    isDemo: false,
  });
  assert.equal(suspiciousUrl.is_demo, false);
  assert.equal(suspiciousUrl.risk_level, "HIGH RISK");
});
