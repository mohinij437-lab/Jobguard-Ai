interface BarcodeDetectorLike {
  detect: (source: ImageBitmapSource) => Promise<Array<{ rawValue?: string }>>;
}
interface EvidenceFinding {
  category?: string;
  matched_text?: string;
  severity?: string;
  explanation?: string;
}
interface FraudResult {
  [key: string]: unknown;
  risk_category: string;
  risk_percentage: number;
  fraud_category: string;
  explanation: string;
  evidence: EvidenceFinding[];
  recommended_next_steps: string[];
}
interface CommunityReport {
  fingerprint?: string;
  verification_status?: string;
  indicator: string;
  report_type: string;
  description: string;
  reports: number;
}
type BarcodeWindow = Window & {
  BarcodeDetector?: new (opts: { formats: string[] }) => BarcodeDetectorLike;
};

import React, { useMemo, useState } from "react";
import {
  clearEvidence,
  readEvidence,
  removeEvidence,
  saveEvidence as saveEvidenceRecord,
  exportEvidenceAsJson,
  importEvidenceFromJson,
} from "../engine/evidenceStore.mjs";
import { Download, Upload, Trash2, ShieldAlert, CheckCircle, AlertTriangle, FileCode } from "lucide-react";

type Mode = "guardian" | "payment" | "screenshot" | "qr" | "assistant" | "community" | "evidence" | "deepfake";

interface Props {
  mode: Mode;
}

export const AdvancedProtectionPanel: React.FC<Props> = ({ mode }) => {
  const [text, setText] = useState("");
  const [result, setResult] = useState<FraudResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [communityQuery, setCommunityQuery] = useState("");
  const [communityReports, setCommunityReports] = useState<CommunityReport[]>([]);
  const [chatReply, setChatReply] = useState("");
  const [actionError, setActionError] = useState("");
  const [saveSuccess, setSaveSuccess] = useState(false);
  const [savedEvidence, setSavedEvidence] = useState(() => readEvidence());

  const title = useMemo(() => ({
    guardian: "🔗 Link Guardian — Zero-Visit Phishing URL Inspector",
    payment: "💳 UPI & Payment Fraud Analyzer",
    screenshot: "🖼️ Screenshot Scam Detector",
    qr: "▣ QR Code Scam Scanner",
    assistant: "🤖 AI Cyber Safety Assistant",
    community: "🌐 Community Scam Intelligence",
    evidence: "📁 Evidence Locker — Secure Scam Chain-of-Custody",
    deepfake: "🎙️ Deepfake Voice & Audio Assessment",
  }[mode]), [mode]);

  const analyzeText = async (overrideText?: string) => {
    const targetText = (overrideText !== undefined ? overrideText : text).trim();
    if (!targetText) return;
    setLoading(true);
    setActionError("");
    setSaveSuccess(false);
    try {
      const res = await fetch("/api/fraud/intelligence", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text: targetText, input_type: mode }),
      });
      if (res.ok) {
        setResult(await res.json());
      } else {
        const err = await res.json().catch(() => ({}));
        setActionError(err.detail || "Analysis request failed.");
      }
    } catch {
      setActionError("Unable to reach backend service. Verify server is running.");
    } finally {
      setLoading(false);
    }
  };

  const handleAudioAssessment = async (file?: File) => {
    if (!file) return;
    setLoading(true);
    setActionError("");
    try {
      const fd = new FormData();
      fd.append("file", file);
      const res = await fetch("/api/fraud/audio-assessment", { method: "POST", body: fd });
      if (res.ok) {
        const data = await res.json();
        setResult({
          risk_category: data.status === "UNVERIFIED" ? "UNVERIFIED" : "ASSESSED",
          risk_percentage: data.synthetic_voice_confidence || 0,
          fraud_category: data.assessment,
          explanation: data.assessment,
          recommended_next_steps: data.limitations || [],
          evidence: data.manipulation_indicators || [],
        });
      } else {
        const err = await res.json().catch(() => ({}));
        setActionError(err.detail || "Audio assessment failed.");
      }
    } catch {
      setActionError("Unable to reach audio assessment endpoint.");
    } finally {
      setLoading(false);
    }
  };

  const handleImage = async (file?: File) => {
    if (!file) return;
    setLoading(true);
    setActionError("");
    setSaveSuccess(false);

    if (mode === "qr" && "BarcodeDetector" in window) {
      try {
        const DetectorCtor = (window as BarcodeWindow).BarcodeDetector;
        if (!DetectorCtor) throw new Error("BarcodeDetector unavailable");
        const detector = new DetectorCtor({ formats: ["qr_code"] });
        const bitmap = await createImageBitmap(file);
        const codes = await detector.detect(bitmap);
        bitmap.close?.();
        if (codes?.[0]?.rawValue) {
          const raw = codes[0].rawValue;
          setText(raw);
          setLoading(false);
          await analyzeText(raw);
          return;
        }
      } catch {
        // Fallback to OCR
      }
    }

    try {
      const Tesseract = await import("tesseract.js");
      const ocr = await Tesseract.recognize(file, "eng");
      const extracted = ocr?.data?.text?.trim() || "";
      setText(extracted);
      if (extracted) {
        await analyzeText(extracted);
      } else {
        setActionError("No readable text detected in uploaded image.");
      }
    } catch {
      setActionError("OCR processing failed on this image.");
    } finally {
      setLoading(false);
    }
  };

  const searchCommunity = async () => {
    try {
      const res = await fetch(`/api/community/search?q=${encodeURIComponent(communityQuery)}`);
      if (res.ok) setCommunityReports((await res.json()).reports || []);
    } catch {
      setActionError("Failed to search community reports.");
    }
  };

  const submitCommunity = async () => {
    if (!text.trim()) return;
    try {
      const res = await fetch("/api/community/report", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ indicator: text.trim(), report_type: mode, description: "User-submitted suspicious indicator" }),
      });
      if (res.ok) {
        setText("");
        await searchCommunity();
      }
    } catch {
      setActionError("Failed to submit community report.");
    }
  };

  const answerAssistant = () => {
    const lower = text.toLowerCase();
    if (/1930|lost|money|debited|stolen|scammed/.test(lower)) {
      setChatReply("🚨 EMERGENCY PROTOCOL: If money was debited, call 1930 immediately (National Cyber Crime Helpline). File a complaint at cybercrime.gov.in within 24 hours. Contact your bank immediately to freeze the beneficiary account / reverse the UPI transaction with the UTR number.");
    } else if (/otp|upi pin|mpin|cvv|password/.test(lower)) {
      setChatReply("⚠️ CRITICAL SECURITY WARNING: Never share your OTP, UPI PIN, ATM PIN, or CVV. Legitimate recruiters, banks, and payment gateways NEVER ask for your UPI PIN to credit money to your account. Remember: Entering your UPI PIN always DEBITS money from your account.");
    } else if (/job|recruit|offer|wfh|work from home|telegram/.test(lower)) {
      setChatReply("🛡️ RECRUITMENT SAFETY RULE: Legitimate companies (Infosys, TCS, Wipro, Razorpay, etc.) NEVER charge registration, security deposit, laptop, or processing fees. Verify any job opening on the company's official career portal typed manually in your browser.");
    } else if (/anydesk|teamviewer|quicksupport|rustdesk/.test(lower)) {
      setChatReply("🚫 REMOTE ACCESS SCAM ALERT: Never install AnyDesk, TeamViewer, QuickSupport or allow screen sharing during an interview or banking call. Scammers use remote access to capture OTPs and drain bank accounts.");
    } else {
      setChatReply("JobGuard AI Safety Advice: Carefully inspect any recruiter message or payment request. Check if they ask for upfront fees, urgency/isolation pressure, or unverified links. Feel free to paste the exact message above to run a multi-signal fraud scan.");
    }
  };

  const saveEvidence = () => {
    if (!result) return;
    try {
      const items = saveEvidenceRecord({ saved_at: new Date().toISOString(), result });
      setSavedEvidence({ items, error: null });
      setActionError("");
      setSaveSuccess(true);
      setTimeout(() => setSaveSuccess(false), 3000);
    } catch (error) {
      setActionError(error instanceof Error ? error.message : "Unable to save evidence.");
    }
  };

  const deleteEvidence = (index: number) => {
    try {
      setSavedEvidence({ items: removeEvidence(index), error: null });
      setActionError("");
    } catch (error) {
      setActionError(error instanceof Error ? error.message : "Unable to delete evidence.");
    }
  };

  const exportSingleEvidence = (item: unknown, index: number) => {
    const jsonStr = JSON.stringify(item, null, 2);
    const blob = new Blob([jsonStr], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `jobguard-evidence-record-${index + 1}.json`;
    anchor.click();
    setTimeout(() => URL.revokeObjectURL(url), 1500);
  };

  const exportAllEvidence = () => {
    try {
      const jsonStr = exportEvidenceAsJson();
      const blob = new Blob([jsonStr], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = `jobguard-evidence-locker-export-${Date.now()}.json`;
      anchor.click();
      setTimeout(() => URL.revokeObjectURL(url), 1500);
    } catch (e) {
      setActionError(e instanceof Error ? e.message : "Failed to export evidence.");
    }
  };

  const handleImportEvidence = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (event) => {
      try {
        const textContent = String(event.target?.result || "");
        const updated = importEvidenceFromJson(textContent);
        setSavedEvidence({ items: updated, error: null });
        setActionError("");
      } catch (err) {
        setActionError(err instanceof Error ? err.message : "Invalid JSON file for evidence import.");
      }
    };
    reader.readAsText(file);
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <span className="text-xs font-bold uppercase tracking-wider text-blue-600 dark:text-blue-400">
            JobGuard AI Specialized Defense Module
          </span>
          <h1 className="text-2xl font-extrabold mt-1 text-slate-900 dark:text-white">{title}</h1>
        </div>
      </div>

      {actionError && (
        <div role="alert" className="rounded-xl border border-rose-200 bg-rose-50 p-3.5 text-xs font-medium text-rose-700 dark:border-rose-900 dark:bg-rose-950/40 dark:text-rose-300">
          {actionError}
        </div>
      )}

      {mode === "evidence" ? (
        <section className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm dark:border-slate-800 dark:bg-[#111C32]">
          <div className="mb-6 flex flex-wrap items-center justify-between gap-4 pb-5 border-b border-slate-200 dark:border-slate-800">
            <div>
              <h2 className="text-base font-bold text-slate-900 dark:text-white">Evidence Locker Chain-of-Custody</h2>
              <p className="mt-1 text-xs text-slate-500">
                Preserved locally on your device for cybercrime reporting (1930 / cybercrime.gov.in). Records are never transmitted to external third parties.
              </p>
            </div>
            <div className="flex flex-wrap gap-2">
              <button
                type="button"
                onClick={exportAllEvidence}
                disabled={savedEvidence.items.length === 0}
                className="flex items-center gap-1.5 rounded-xl border border-slate-200 bg-slate-50 px-3.5 py-2 text-xs font-bold hover:bg-slate-100 disabled:opacity-40 dark:border-slate-700 dark:bg-slate-900 dark:hover:bg-slate-800 transition"
              >
                <Download size={14} /> Export All JSON
              </button>
              <label className="flex items-center gap-1.5 rounded-xl border border-slate-200 bg-slate-50 px-3.5 py-2 text-xs font-bold hover:bg-slate-100 cursor-pointer dark:border-slate-700 dark:bg-slate-900 dark:hover:bg-slate-800 transition">
                <Upload size={14} /> Import Evidence JSON
                <input type="file" accept=".json,application/json" onChange={handleImportEvidence} className="hidden" />
              </label>
              {savedEvidence.error ? (
                <button
                  type="button"
                  onClick={() => { clearEvidence(); setSavedEvidence({ items: [], error: null }); }}
                  className="rounded-xl border border-rose-300 bg-rose-50 px-3.5 py-2 text-xs font-bold text-rose-700 dark:border-rose-900 dark:bg-rose-950/40"
                >
                  Clear Damaged Data
                </button>
              ) : savedEvidence.items.length > 0 ? (
                <button
                  type="button"
                  onClick={() => {
                    if (window.confirm("Clear all saved evidence records from this device?")) {
                      clearEvidence();
                      setSavedEvidence({ items: [], error: null });
                    }
                  }}
                  className="rounded-xl border border-rose-200 px-3.5 py-2 text-xs font-bold text-rose-600 hover:bg-rose-50 dark:border-rose-900/60 dark:hover:bg-rose-950/30 transition"
                >
                  Clear All
                </button>
              ) : null}
            </div>
          </div>

          {savedEvidence.error ? (
            <div role="alert" className="rounded-xl border border-rose-200 bg-rose-50 p-4 text-sm text-rose-700 dark:border-rose-900 dark:bg-rose-950/40">
              {savedEvidence.error}
            </div>
          ) : savedEvidence.items.length === 0 ? (
            <div className="rounded-2xl border border-dashed border-slate-200 p-8 text-center dark:border-slate-800">
              <FileCode className="mx-auto text-slate-400" size={32} />
              <p className="mt-3 text-sm font-bold text-slate-800 dark:text-slate-200">No Evidence Records Saved Yet</p>
              <p className="mt-1 text-xs text-slate-500 max-w-md mx-auto">
                Scan suspicious messages, links, screenshots, or payment demands. When suspicious patterns are detected, click "Save to Evidence Locker" to build your scam chain-of-custody.
              </p>
            </div>
          ) : (
            <div className="space-y-3">
              {savedEvidence.items.map((item, index) => (
                <article
                  key={`${item.saved_at || "saved"}-${index}`}
                  className="flex flex-wrap items-center justify-between gap-4 rounded-xl border border-slate-200 p-4 dark:border-slate-800 dark:bg-slate-900/50 hover:border-blue-400 transition"
                >
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <span className={`px-2.5 py-0.5 rounded-full text-[11px] font-extrabold ${
                        item.result?.risk_category === "CRITICAL" || item.result?.risk_category === "HIGH RISK"
                          ? "bg-rose-100 text-rose-700 dark:bg-rose-950/60 dark:text-rose-300"
                          : item.result?.risk_category === "SUSPICIOUS"
                          ? "bg-amber-100 text-amber-800 dark:bg-amber-950/60 dark:text-amber-300"
                          : "bg-emerald-100 text-emerald-800 dark:bg-emerald-950/60 dark:text-emerald-300"
                      }`}>
                        {item.result?.risk_category || "EVIDENCE"} • {item.result?.risk_percentage ?? 0}% Risk
                      </span>
                      <span className="text-xs font-bold text-slate-800 dark:text-slate-200">
                        {item.result?.fraud_category || "Detected Scam Pattern"}
                      </span>
                    </div>
                    <p className="text-xs text-slate-500">
                      Timestamp: {item.saved_at ? new Date(item.saved_at).toLocaleString() : "Preserved"}
                    </p>
                    {Array.isArray((item.result as { evidence?: EvidenceFinding[] })?.evidence) && ((item.result as { evidence?: EvidenceFinding[] }).evidence?.length ?? 0) > 0 && (
                      <p className="text-[11px] text-slate-600 dark:text-slate-400">
                        Signal: "{(item.result as { evidence?: EvidenceFinding[] }).evidence?.[0]?.matched_text || (item.result as { evidence?: EvidenceFinding[] }).evidence?.[0]?.category}"
                      </p>
                    )}
                  </div>
                  <div className="flex gap-2">
                    <button
                      type="button"
                      onClick={() => exportSingleEvidence(item, index)}
                      className="rounded-lg border border-slate-200 px-3 py-1.5 text-xs font-bold hover:bg-slate-100 dark:border-slate-700 dark:hover:bg-slate-800 transition"
                    >
                      Export JSON
                    </button>
                    <button
                      type="button"
                      onClick={() => deleteEvidence(index)}
                      className="rounded-lg border border-rose-200 px-3 py-1.5 text-xs font-bold text-rose-600 hover:bg-rose-50 dark:border-rose-900/60 dark:hover:bg-rose-950/40 transition"
                    >
                      Delete
                    </button>
                  </div>
                </article>
              ))}
            </div>
          )}
        </section>
      ) : mode === "community" ? (
        <div className="grid md:grid-cols-2 gap-5">
          <div className="rounded-2xl border border-slate-200 bg-white dark:border-slate-800 dark:bg-[#111C32] p-5 space-y-4">
            <h2 className="font-bold text-sm">Submit Anonymous Scam Indicator</h2>
            <textarea
              rows={4}
              value={text}
              onChange={(e) => setText(e.target.value)}
              placeholder="UPI ID, suspicious recruiter phone number, Telegram task group handle, or phishing URL..."
              className="w-full rounded-xl border border-slate-200 dark:border-slate-700 p-3 text-xs dark:bg-slate-900 focus-visible:ring-2 focus-visible:ring-blue-500"
            />
            <button
              onClick={submitCommunity}
              className="px-5 py-2.5 rounded-xl bg-blue-600 hover:bg-blue-500 text-white text-xs font-bold shadow-md shadow-blue-600/20 transition"
            >
              Submit Anonymously
            </button>
            <p className="text-[11px] text-amber-700 dark:text-amber-400">
              Community reports are flagged as unverified community intelligence until corroborated. Do not submit passwords or sensitive personal data.
            </p>
          </div>
          <div className="rounded-2xl border border-slate-200 bg-white dark:border-slate-800 dark:bg-[#111C32] p-5 space-y-4">
            <h2 className="font-bold text-sm">Search Community Intelligence Registry</h2>
            <div className="flex gap-2">
              <input
                value={communityQuery}
                onChange={(e) => setCommunityQuery(e.target.value)}
                placeholder="Search phone, UPI handle, or domain..."
                className="flex-1 rounded-xl border border-slate-200 dark:border-slate-700 px-3 py-2 text-xs dark:bg-slate-900"
              />
              <button
                onClick={searchCommunity}
                className="px-4 rounded-xl bg-slate-900 text-white text-xs font-bold dark:bg-slate-700"
              >
                Search
              </button>
            </div>
            {communityReports.length === 0 ? (
              <p className="text-xs text-slate-500">No community reports matching query. Type a keyword and click Search.</p>
            ) : (
              <div className="space-y-2">
                {communityReports.map((r) => (
                  <div key={r.fingerprint || r.indicator} className="p-3 rounded-xl bg-slate-50 dark:bg-slate-900 text-xs border border-slate-200 dark:border-slate-800">
                    <b className="font-mono text-blue-600 dark:text-blue-400">{r.indicator}</b>
                    <div className="text-slate-600 dark:text-slate-400 mt-1">
                      {r.reports} report(s) • Type: {r.report_type} • Status: {r.verification_status}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      ) : mode === "assistant" ? (
        <div className="rounded-2xl border border-slate-200 bg-white dark:border-slate-800 dark:bg-[#111C32] p-6 space-y-4">
          <label className="block text-xs font-bold text-slate-700 dark:text-slate-300">
            Ask Cyber Safety Assistant (English, Hindi, or Hinglish)
          </label>
          <textarea
            rows={4}
            value={text}
            onChange={(e) => setText(e.target.value)}
            placeholder="E.g., Recruiter asked me to pay ₹1,500 registration fee on UPI; What should I do if money was debited?; Caller claims I am in digital arrest..."
            className="w-full rounded-xl border border-slate-200 dark:border-slate-700 p-3.5 text-sm dark:bg-slate-900 focus-visible:ring-2 focus-visible:ring-blue-500"
          />
          <div className="flex flex-wrap gap-2">
            <button
              onClick={answerAssistant}
              className="px-5 py-2.5 rounded-xl bg-blue-600 hover:bg-blue-500 text-white text-xs font-bold shadow-md shadow-blue-600/20 transition"
            >
              Get Instant Safety Guidance
            </button>
            <button
              type="button"
              onClick={() => { setText("Money was debited from my account after clicking a link"); }}
              className="px-3 py-1.5 rounded-lg bg-slate-100 dark:bg-slate-800 text-xs"
            >
              Money debited?
            </button>
            <button
              type="button"
              onClick={() => { setText("Recruiter asked for ₹999 security deposit before interview"); }}
              className="px-3 py-1.5 rounded-lg bg-slate-100 dark:bg-slate-800 text-xs"
            >
              Registration fee?
            </button>
            <button
              type="button"
              onClick={() => { setText("Caller asks me to install AnyDesk for verification"); }}
              className="px-3 py-1.5 rounded-lg bg-slate-100 dark:bg-slate-800 text-xs"
            >
              Remote access app?
            </button>
          </div>
          {chatReply && (
            <div className="mt-4 p-5 rounded-2xl bg-blue-50/80 border border-blue-200 dark:border-blue-900/60 dark:bg-blue-950/40 text-sm leading-relaxed text-slate-900 dark:text-slate-100">
              {chatReply}
            </div>
          )}
        </div>
      ) : (
        <div className="space-y-5">
          {/* Quick Demo Pre-sets for Evaluators */}
          <div className="rounded-2xl border border-slate-200 bg-white p-4 dark:border-slate-800 dark:bg-[#111C32] space-y-2">
            <span className="text-[11px] font-bold uppercase text-slate-500">Evaluation Demonstration Scenarios</span>
            <div className="flex flex-wrap gap-2">
              {mode === "payment" && (
                <>
                  <button
                    type="button"
                    onClick={() => {
                      const sample = "Selected for Data Entry role! Pay ₹1,500 refundable security deposit to upi:hr.security@ybl to activate offer.";
                      setText(sample);
                      analyzeText(sample);
                    }}
                    className="px-3 py-1.5 rounded-lg bg-slate-100 dark:bg-slate-800 text-xs font-semibold hover:bg-blue-600 hover:text-white transition"
                  >
                    Demo 1: Registration Fee UPI Scam
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      const sample = "Approve UPI Collect request of ₹3,999 on PhonePe for laptop delivery charges.";
                      setText(sample);
                      analyzeText(sample);
                    }}
                    className="px-3 py-1.5 rounded-lg bg-slate-100 dark:bg-slate-800 text-xs font-semibold hover:bg-blue-600 hover:text-white transition"
                  >
                    Demo 2: UPI Collect Request Fraud
                  </button>
                </>
              )}
              {mode === "qr" && (
                <>
                  <button
                    type="button"
                    onClick={() => {
                      const sample = "upi://pay?pa=recruiter.scam@ybl&pn=Infosys%20HR&am=1200&cu=INR&tn=JobRegistration";
                      setText(sample);
                      analyzeText(sample);
                    }}
                    className="px-3 py-1.5 rounded-lg bg-slate-100 dark:bg-slate-800 text-xs font-semibold hover:bg-blue-600 hover:text-white transition"
                  >
                    Demo 1: QR Payment VPA Extraction
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      const sample = "https://infosys.careers-verification.xyz/apply?candidate=qr901";
                      setText(sample);
                      analyzeText(sample);
                    }}
                    className="px-3 py-1.5 rounded-lg bg-slate-100 dark:bg-slate-800 text-xs font-semibold hover:bg-blue-600 hover:text-white transition"
                  >
                    Demo 2: Phishing Portal QR Link
                  </button>
                </>
              )}
              {mode === "guardian" && (
                <>
                  <button
                    type="button"
                    onClick={() => {
                      const sample = "https://infosys.careers-verification.xyz/apply";
                      setText(sample);
                      analyzeText(sample);
                    }}
                    className="px-3 py-1.5 rounded-lg bg-slate-100 dark:bg-slate-800 text-xs font-semibold hover:bg-blue-600 hover:text-white transition"
                  >
                    Demo 1: Impersonated Brand Domain
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      const sample = "http://192.168.1.100/hr-portal/apply";
                      setText(sample);
                      analyzeText(sample);
                    }}
                    className="px-3 py-1.5 rounded-lg bg-slate-100 dark:bg-slate-800 text-xs font-semibold hover:bg-blue-600 hover:text-white transition"
                  >
                    Demo 2: Raw IP Recruitment Host
                  </button>
                </>
              )}
            </div>
          </div>

          <div className="grid lg:grid-cols-2 gap-5">
            <div className="rounded-2xl border border-slate-200 bg-white dark:border-slate-800 dark:bg-[#111C32] p-5 space-y-4">
              <label className="block text-xs font-bold text-slate-700 dark:text-slate-300">
                {mode === "qr" ? "Scan or Upload QR Code" :
                 mode === "screenshot" ? "Upload Screenshot Image" :
                 mode === "deepfake" ? "Upload Audio for Deepfake Analysis" :
                 mode === "payment" ? "Paste UPI Message, VPA, or Payment Demand" :
                 "Enter URL or Message to Inspect"}
              </label>

              {mode === "screenshot" || mode === "qr" ? (
                <div className="space-y-2">
                  <input
                    type="file"
                    accept="image/*"
                    onChange={(e) => handleImage(e.target.files?.[0])}
                    className="block w-full text-xs text-slate-500 file:mr-4 file:py-2 file:px-4 file:rounded-xl file:border-0 file:text-xs file:font-semibold file:bg-blue-50 file:text-blue-700 hover:file:bg-blue-100 dark:file:bg-slate-800 dark:file:text-slate-300"
                  />
                  <p className="text-[11px] text-slate-500">Supports PNG, JPEG, WEBP. On-device BarcodeDetector or Tesseract.js OCR extract codes and text.</p>
                </div>
              ) : mode === "deepfake" ? (
                <div className="space-y-2">
                  <input
                    type="file"
                    accept="audio/*"
                    onChange={(e) => handleAudioAssessment(e.target.files?.[0])}
                    className="block w-full text-xs text-slate-500 file:mr-4 file:py-2 file:px-4 file:rounded-xl file:border-0 file:text-xs file:font-semibold file:bg-blue-50 file:text-blue-700 hover:file:bg-blue-100 dark:file:bg-slate-800 dark:file:text-slate-300"
                  />
                  <p className="text-[11px] text-slate-500">Supports WAV, MP3, M4A, OGG. Evaluates format, stream integrity, and acoustic anomalies.</p>
                </div>
              ) : (
                <textarea
                  rows={6}
                  value={text}
                  onChange={(e) => setText(e.target.value)}
                  placeholder={
                    mode === "payment" ? "Paste UPI payment request, transaction SMS, or fee demand..." :
                    mode === "guardian" ? "https://company.careers-portal.xyz/apply" :
                    "Paste suspicious message or content..."
                  }
                  className="w-full rounded-xl border border-slate-200 dark:border-slate-700 p-3.5 text-xs font-mono dark:bg-slate-900 focus-visible:ring-2 focus-visible:ring-blue-500"
                />
              )}

              {mode !== "deepfake" && (
                <button
                  disabled={loading || !text.trim()}
                  onClick={() => analyzeText()}
                  className="px-6 py-2.5 rounded-xl bg-blue-600 hover:bg-blue-500 text-white text-xs font-bold shadow-md shadow-blue-600/20 disabled:opacity-50 transition"
                >
                  {loading ? "Analyzing..." : "Run AI Fraud Intelligence Scan →"}
                </button>
              )}
            </div>

            {result ? (
              <div className="rounded-2xl border border-slate-200 bg-white dark:border-slate-800 dark:bg-[#111C32] p-5 space-y-4">
                <div className="flex items-center justify-between pb-3 border-b border-slate-200 dark:border-slate-800">
                  <span className={`px-3 py-1 rounded-full text-xs font-black ${
                    result.risk_category === "CRITICAL" || result.risk_category === "HIGH RISK"
                      ? "bg-rose-100 text-rose-700 dark:bg-rose-950 dark:text-rose-300"
                      : result.risk_category === "SUSPICIOUS"
                      ? "bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-300"
                      : "bg-emerald-100 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-300"
                  }`}>
                    {result.risk_category}
                  </span>
                  <span className="text-xl font-black text-slate-900 dark:text-white">
                    {result.risk_percentage}% Risk Score
                  </span>
                </div>

                <div>
                  <h3 className="text-sm font-bold text-slate-800 dark:text-slate-100">{result.fraud_category}</h3>
                  <p className="mt-1 text-xs text-slate-500 leading-relaxed">{result.explanation}</p>
                </div>

                {result.evidence?.length > 0 && (
                  <div className="space-y-2">
                    <span className="text-xs font-bold text-slate-700 dark:text-slate-300">Detected Warning Indicators:</span>
                    <div className="space-y-1.5">
                      {result.evidence.map((ev: EvidenceFinding, idx: number) => (
                        <div key={idx} className="p-2.5 rounded-lg bg-rose-50/70 border border-rose-200 dark:bg-rose-950/30 dark:border-rose-900/40 text-xs">
                          <b className="text-rose-700 dark:text-rose-300 capitalize">{ev.category?.replace(/_/g, " ")}:</b>{" "}
                          <span className="font-mono">"{ev.matched_text}"</span>
                          <div className="mt-0.5 text-slate-600 dark:text-slate-400">{ev.explanation}</div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {result.recommended_next_steps?.length > 0 && (
                  <div className="space-y-1.5">
                    <span className="text-xs font-bold text-slate-700 dark:text-slate-300">Recommended Next Steps:</span>
                    <ul className="text-xs list-disc pl-4 space-y-1 text-slate-600 dark:text-slate-300">
                      {result.recommended_next_steps.map((x: string, i: number) => (
                        <li key={i}>{x}</li>
                      ))}
                    </ul>
                  </div>
                )}

                <div className="pt-2 flex items-center gap-3">
                  <button
                    onClick={saveEvidence}
                    className="px-4 py-2 rounded-xl bg-slate-900 text-white text-xs font-bold hover:bg-slate-800 dark:bg-slate-100 dark:text-slate-900 dark:hover:bg-white transition"
                  >
                    Save to Evidence Locker
                  </button>
                  {saveSuccess && (
                    <span className="flex items-center gap-1 text-xs font-bold text-emerald-600 dark:text-emerald-400">
                      <CheckCircle size={14} /> Saved successfully!
                    </span>
                  )}
                </div>
              </div>
            ) : (
              <div className="rounded-2xl border border-dashed border-slate-200 p-8 text-center flex flex-col items-center justify-center dark:border-slate-800 text-slate-400">
                <ShieldAlert size={36} />
                <p className="mt-2 text-xs font-medium">Scan results and risk assessment will appear here.</p>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
