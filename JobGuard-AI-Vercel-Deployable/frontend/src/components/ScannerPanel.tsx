import React, { useState } from "react";
import { inspectUrlStructurally } from "../engine/localEngine.mjs";
import type { URLInspectionResult } from "../types";

interface Props {
  onSendTextToVerify: (text: string, isDemo?: boolean) => void;
}

export const ScannerPanel: React.FC<Props> = ({ onSendTextToVerify }) => {
  const [imageUrl, setImageUrl] = useState<string | null>(null);
  const [ocrStatus, setOcrStatus] = useState("");
  const [ocrProgress, setOcrProgress] = useState(0);
  const [extractedText, setExtractedText] = useState("");
  const [docWarning, setDocWarning] = useState("");
  const [urlInput, setUrlInput] = useState("https://infosys.careers-verification.xyz/apply");
  const [urlResult, setUrlResult] = useState<URLInspectionResult | null>(null);
  const [ocrIsDemo, setOcrIsDemo] = useState(false);

  const runOcr = async (src: string, isDemo = false) => {
    setOcrProgress(15);
    setOcrStatus("Running local browser OCR (Tesseract.js)...");
    try {
      const Tesseract = await import("tesseract.js");
      const res = await Tesseract.recognize(src, "eng", {
        logger: (m: { progress?: number }) => {
          if (m && typeof m.progress === "number") {
            setOcrProgress(Math.max(15, Math.round(m.progress * 100)));
          }
        },
      });
      if (res?.data?.text?.trim()) {
        setExtractedText(res.data.text.trim());
        setOcrIsDemo(isDemo);
        setOcrProgress(100);
        setOcrStatus("OCR complete! Edit text below if needed and send to Verification.");
        return;
      }
    } catch (err) { console.debug("Scanner fallback active:", err); }
    setOcrProgress(100);
    if (isDemo) {
      setExtractedText(
        "Company: Infosys Hiring Desk\nRole: Junior Software Associate (WFH)\nSelected without interview! Salary: Rs 48,000/month\nPay Rs 999 refundable registration fee today at: https://infosys.careers-verification.xyz/apply"
      );
      setOcrStatus("Extracted text from demo screenshot. Ready to verify.");
      setOcrIsDemo(true);
    } else {
      setOcrStatus("OCR worker unavailable offline; paste or type the visible text below.");
      setOcrIsDemo(false);
    }
  };

  const handleImageUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const f = e.target.files?.[0];
    if (!f) return;
    const reader = new FileReader();
    reader.onload = (ev) => {
      const src = String(ev.target?.result || "");
      setImageUrl(src);
      setOcrIsDemo(false);
      runOcr(src, false);
    };
    reader.readAsDataURL(f);
  };

  const generateDemoScreenshot = () => {
    const c = document.createElement("canvas");
    c.width = 760;
    c.height = 300;
    const ctx = c.getContext("2d");
    if (!ctx) return;
    ctx.fillStyle = "#FFFFFF";
    ctx.fillRect(0, 0, 760, 300);
    ctx.fillStyle = "#4F46E5";
    ctx.fillRect(0, 0, 760, 46);
    ctx.fillStyle = "#FFFFFF";
    ctx.font = "bold 16px Arial";
    ctx.fillText("WHATSAPP RECRUITER SCREENSHOT (DEMO)", 20, 29);
    ctx.fillStyle = "#14131B";
    ctx.font = "bold 19px Arial";
    [
      "Company: Infosys Hiring Desk",
      "Role: Junior Software Associate (WFH)",
      "Selected without interview! Salary: Rs 48,000/month",
      "Pay Rs 999 refundable registration fee today at:",
      "https://infosys.careers-verification.xyz/apply",
    ].forEach((line, i) => ctx.fillText(line, 24, 88 + i * 40));
    const src = c.toDataURL("image/png");
    setImageUrl(src);
    runOcr(src, true);
  };

  const handleDocUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const f = e.target.files?.[0];
    if (!f) return;
    setDocWarning("");
    try {
      const fd = new FormData();
      fd.append("file", f);
      const r = await fetch("/api/extract/document", { method: "POST", body: fd });
      if (r.ok) {
        const data = await r.json();
        setExtractedText(data.extracted_text || "");
        setOcrIsDemo(false);
        if (data.warnings?.length) setDocWarning(data.warnings.join(" "));
        return;
      }
    } catch (err) { console.debug("Scanner fallback active:", err); }
    if (f.name.toLowerCase().endsWith(".txt")) {
      setExtractedText(await f.text());
      setOcrIsDemo(false);
    } else {
      setDocWarning("Start the FastAPI backend (uvicorn backend.main:app --port 8000) to parse PDF/DOCX files in dev mode.");
    }
  };

  const handleInspectUrl = async (target?: string) => {
    const u = (target || urlInput).trim();
    if (!u) return;
    setUrlInput(u);
    try {
      const r = await fetch("/api/inspect-url", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: u }),
      });
      if (r.ok) {
        setUrlResult(await r.json());
        return;
      }
    } catch (err) { console.debug("Scanner fallback active:", err); }
    setUrlResult(inspectUrlStructurally(u) as URLInspectionResult);
  };

  return (
    <section aria-label="Document and Screenshot Scanner" aria-live="polite" className="space-y-6">
      <div>
        <span className="text-xs font-bold uppercase tracking-wider text-indigo-600 dark:text-indigo-300">
          Multi-Format Inspection Suite
        </span>
        <h1 className="text-2xl font-extrabold mt-1">📷 Screenshot OCR, PDF/DOCX & URL Inspector</h1>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        <div className="rounded-2xl bg-white dark:bg-[#161822] border border-slate-200 dark:border-slate-700 p-5 space-y-4">
          <h2 className="font-bold text-sm">1. Screenshot OCR (Tesseract.js)</h2>
          <input type="file" accept="image/jpeg,image/png,image/webp" onChange={handleImageUpload} className="block w-full text-xs" />
          <button
            type="button"
            onClick={generateDemoScreenshot}
            className="px-3.5 py-2 rounded-xl text-xs font-bold bg-slate-100 dark:bg-slate-800 hover:bg-indigo-600 hover:text-white transition"
          >
            🎨 Generate Demo Job Scam Screenshot
          </button>
          {imageUrl && (
            <div className="space-y-2">
              <img src={imageUrl} alt="Screenshot preview" className="max-h-48 rounded-xl border border-slate-200" />
              <div className="w-full h-1.5 rounded-full bg-slate-200 overflow-hidden">
                <div className="h-full bg-indigo-600" style={{ width: `${ocrProgress}%` }} />
              </div>
              <div className="text-xs text-slate-500">{ocrStatus}</div>
            </div>
          )}

          <div className="pt-3 border-t border-slate-200 dark:border-slate-700 space-y-2">
            <h2 className="font-bold text-sm">2. Offer Letter / Document Upload (PDF, DOCX, TXT)</h2>
            <input type="file" accept=".pdf,.docx,.txt" onChange={handleDocUpload} className="block w-full text-xs" />
            {docWarning && <div className="p-2.5 rounded-xl bg-amber-50 text-amber-800 text-xs">{docWarning}</div>}
          </div>
        </div>

        <div className="rounded-2xl bg-white dark:bg-[#161822] border border-slate-200 dark:border-slate-700 p-5 flex flex-col justify-between space-y-4">
          <div className="space-y-2">
            <h2 className="font-bold text-sm">Extracted Text (Editable Before Verification)</h2>
            <textarea
              rows={9}
              value={extractedText}
              onChange={(e) => {
                setExtractedText(e.target.value);
                setOcrIsDemo(false);
              }}
              placeholder="Extracted screenshot or document text appears here..."
              className="w-full rounded-xl border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-slate-900 p-3 text-xs font-mono"
            />
          </div>
          <button
            type="button"
            disabled={!extractedText.trim()}
            onClick={() => onSendTextToVerify(extractedText, ocrIsDemo)}
            className="w-full py-3 rounded-full bg-indigo-600 hover:bg-indigo-700 text-white text-xs font-bold disabled:opacity-50"
          >
            ⚡ Send Extracted Text to 7-Category Verification →
          </button>
        </div>
      </div>

      {/* Zero-Visit URL Inspector */}
      <div className="rounded-2xl bg-white dark:bg-[#161822] border border-slate-200 dark:border-slate-700 p-5 space-y-4">
        <h2 className="font-bold text-sm">🔗 Zero-Visit Career Portal & Domain Safety Inspector</h2>
        <div className="flex flex-col sm:flex-row gap-2.5">
          <input
            type="text"
            value={urlInput}
            onChange={(e) => setUrlInput(e.target.value)}
            className="flex-1 rounded-xl border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-slate-900 px-3.5 py-2.5 text-xs font-mono"
          />
          <button
            type="button"
            onClick={() => handleInspectUrl()}
            className="px-5 py-2.5 rounded-xl bg-indigo-600 text-white text-xs font-bold"
          >
            Inspect Structurally
          </button>
        </div>
        {urlResult && (
          <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-700 space-y-2 text-xs">
            <div className="flex flex-wrap justify-between gap-2">
              <span className="font-extrabold">
                {urlResult.risk_level} ({urlResult.risk_index}%)
              </span>
              <span className="font-mono">True Domain: {urlResult.registrable_domain || "N/A"}</span>
            </div>
            <p>{urlResult.summary}</p>
          </div>
        )}
      </div>
    </section>
  );
};
