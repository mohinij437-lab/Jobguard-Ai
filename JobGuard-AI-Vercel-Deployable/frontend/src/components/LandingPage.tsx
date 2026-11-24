import React, { useState } from "react";
import { ArrowRight, CheckCircle2, Link2, MessageSquareWarning, Mic2, ShieldCheck, UploadCloud } from "lucide-react";

interface Props {
  onNavigate: (view: string) => void;
}

export const LandingPage: React.FC<Props> = React.memo(({ onNavigate }) => {
  const [previewText, setPreviewText] = useState("");
  const [previewResult, setPreviewResult] = useState<string | null>(null);

  const runPreview = () => {
    const value = previewText.toLowerCase();
    const suspicious = /(otp|upi pin|registration fee|digital arrest|anydesk|telegram|security deposit)/.test(value);
    setPreviewResult(
      suspicious
        ? "DEMO PATTERN: Suspicious scam indicators detected. Do not pay or share secrets."
        : "DEMO: No strong keyword pattern detected. Verification is not guaranteed."
    );
  };

  const features = [
    { icon: ShieldCheck, title: "Job Verification", text: "Check recruiter claims and evidence.", view: "verify", color: "text-blue-600" },
    { icon: Mic2, title: "Call Guard", text: "Analyze calls and multilingual transcripts.", view: "call-guard", color: "text-cyan-600" },
    { icon: UploadCloud, title: "Document Scanner", text: "OCR screenshots, PDFs and documents.", view: "scanner", color: "text-violet-600" },
    { icon: Link2, title: "Link Guardian", text: "Inspect domains without opening links.", view: "link-guardian", color: "text-emerald-600" },
  ];

  return (
    <div className="space-y-16 pb-12">
      <section className="relative overflow-hidden rounded-[28px] bg-[#0B1220] px-6 py-10 sm:px-10 sm:py-14 text-white">
        <div className="absolute -right-24 -top-24 h-72 w-72 rounded-full bg-blue-600/20 blur-3xl" />
        <div className="relative grid items-center gap-10 lg:grid-cols-[1.12fr_.88fr]">
          <div className="max-w-2xl space-y-6">
            <div className="inline-flex items-center gap-2 rounded-full border border-white/10 bg-white/5 px-3 py-1.5 text-xs font-semibold text-cyan-300">
              <span className="h-2 w-2 rounded-full bg-cyan-400" /> AI-powered fraud protection
            </div>
            <h1 className="text-4xl sm:text-5xl font-extrabold tracking-tight leading-[1.08]">
              Don&apos;t Trust Blindly.<br /><span className="text-cyan-400">Verify with AI.</span>
            </h1>
            <p className="max-w-xl text-base leading-7 text-slate-300">
              Your intelligent shield against fake jobs, phishing links, scam calls and digital fraud.
            </p>
            <div className="flex flex-wrap gap-3">
              <button onClick={() => onNavigate("verify")} className="inline-flex items-center gap-2 rounded-xl bg-blue-600 px-5 py-3 text-sm font-bold shadow-lg shadow-blue-950/30 transition hover:bg-blue-500">
                Scan for Scams <ArrowRight size={16} />
              </button>
              <button onClick={() => onNavigate("scanner")} className="rounded-xl border border-white/15 bg-white/5 px-5 py-3 text-sm font-bold transition hover:bg-white/10">
                Explore Protection
              </button>
            </div>
          </div>

          <div className="rounded-2xl border border-white/10 bg-white/[0.055] p-5 backdrop-blur">
            <div className="mb-4 flex items-center justify-between">
              <span className="text-sm font-bold">Live protection preview</span>
              <span className="rounded-full bg-emerald-400/10 px-2.5 py-1 text-[10px] font-bold text-emerald-300">DEMO</span>
            </div>
            <label className="mb-2 block text-xs text-slate-400">Suspicious message</label>
            <textarea
              value={previewText}
              onChange={(e) => setPreviewText(e.target.value)}
              rows={5}
              placeholder="Paste a message or enter a URL..."
              className="w-full resize-none rounded-xl border border-white/10 bg-[#111C32] p-3 text-sm text-white placeholder:text-slate-500"
            />
            <button onClick={runPreview} disabled={!previewText.trim()} className="mt-3 w-full rounded-xl bg-cyan-500 px-4 py-2.5 text-sm font-bold text-[#0B1220] disabled:opacity-50">
              Analyze Demo
            </button>
            {previewResult && (
              <div className="mt-3 rounded-xl border border-white/10 bg-black/15 p-3 text-xs leading-5 text-slate-200">
                {previewResult}
              </div>
            )}
          </div>
        </div>
      </section>

      <section className="space-y-5">
        <div>
          <p className="text-xs font-bold uppercase tracking-[0.18em] text-blue-600">Protection suite</p>
          <h2 className="mt-1 text-2xl font-extrabold text-slate-950 dark:text-white">One platform. Every fraud scenario.</h2>
        </div>
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          {features.map((feature) => (
            <button
              key={feature.title}
              onClick={() => onNavigate(feature.view)}
              className="group rounded-2xl border border-slate-200 bg-white p-5 text-left shadow-sm transition duration-200 hover:-translate-y-1 hover:border-blue-200 hover:shadow-lg dark:border-slate-800 dark:bg-[#111C32]"
            >
              <feature.icon className={`mb-5 ${feature.color}`} size={24} />
              <h3 className="font-bold text-slate-950 dark:text-white">{feature.title}</h3>
              <p className="mt-2 text-xs leading-5 text-slate-500">{feature.text}</p>
              <span className="mt-4 inline-flex items-center gap-1 text-xs font-bold text-blue-600">Learn more <ArrowRight size={13} className="transition group-hover:translate-x-1" /></span>
            </button>
          ))}
        </div>
      </section>

      <section className="grid gap-4 md:grid-cols-3">
        {[
          ["11+ languages", "Browser speech-to-text and multilingual analysis"],
          ["Privacy-first", "Local processing and redaction where available"],
          ["1930 emergency help", "Clear India-specific incident response guidance"],
        ].map(([title, text]) => (
          <div key={title} className="flex gap-3 rounded-2xl border border-slate-200 bg-white p-5 dark:border-slate-800 dark:bg-[#111C32]">
            <CheckCircle2 size={18} className="shrink-0 text-emerald-500" />
            <div><h3 className="text-sm font-bold">{title}</h3><p className="mt-1 text-xs text-slate-500">{text}</p></div>
          </div>
        ))}
      </section>
    </div>
  );
});
