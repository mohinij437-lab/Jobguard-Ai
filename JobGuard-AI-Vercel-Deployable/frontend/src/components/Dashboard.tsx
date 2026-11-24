import React from "react";
import type { VerificationReport } from "../types";
import { Download, Upload, Trash2, ShieldCheck, ArrowRight } from "lucide-react";

interface Props {
  history: VerificationReport[];
  onStartVerify: () => void;
  onOpenReport: (reportId: string) => void;
  onExportHistory?: () => void;
  onImportReport?: (report: VerificationReport) => void;
  onClearHistory?: () => void;
}

export const Dashboard: React.FC<Props> = React.memo(({
  history,
  onStartVerify,
  onOpenReport,
  onExportHistory,
  onImportReport,
  onClearHistory,
}) => {
  const high = history.filter((r) => r.risk_level === "HIGH RISK").length;
  const med = history.filter((r) => r.risk_level === "MEDIUM RISK").length;
  const low = history.filter((r) => r.risk_level === "LOW RISK").length;

  const handleFileImport = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file || !onImportReport) return;
    const reader = new FileReader();
    reader.onload = (event) => {
      try {
        const text = String(event.target?.result || "");
        const parsed = JSON.parse(text);
        if (parsed && typeof parsed === "object" && parsed.report_id && parsed.risk_level) {
          onImportReport(parsed as VerificationReport);
        } else {
          alert("The selected JSON file is not a valid JobGuard AI verification report.");
        }
      } catch {
        alert("Failed to parse JSON file.");
      }
    };
    reader.readAsText(file);
  };

  return (
    <section aria-label="Verification Dashboard" className="space-y-6">
      <div className="rounded-3xl bg-[#091426] text-white p-6 sm:p-8 flex flex-wrap items-center justify-between gap-6 shadow-xl shadow-slate-900/10">
        <div className="space-y-2 max-w-2xl">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-teal-500/20 text-teal-300 text-xs font-bold uppercase tracking-wider">
            <ShieldCheck size={14} /> JobGuard AI Security Operations Center
          </div>
          <h1 className="text-2xl sm:text-3xl font-extrabold leading-tight">
            Before You Trust the Offer, Verify the Evidence.
          </h1>
          <p className="text-xs sm:text-sm text-slate-300">
            All analytics and metrics reflect your actual local verification records and verified indicators — never fabricated telemetry.
          </p>
        </div>
        <div className="flex flex-wrap gap-3">
          <button
            type="button"
            onClick={onStartVerify}
            className="px-6 py-3 rounded-xl font-bold text-sm bg-[#167D82] hover:bg-[#1A9399] text-white shadow-lg shadow-teal-900/30 transition focus-visible:ring-2 focus-visible:ring-teal-400"
          >
            + Start New Verification
          </button>
        </div>
      </div>

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="p-5 rounded-2xl bg-white dark:bg-[#111F36] border border-slate-200 dark:border-slate-800 shadow-sm">
          <div className="text-xs font-bold text-slate-500 uppercase tracking-wider">Total Verifications</div>
          <div className="text-3xl font-black mt-2 text-slate-900 dark:text-white">{history.length}</div>
        </div>
        <div className="p-5 rounded-2xl bg-red-50/80 dark:bg-red-950/30 border border-red-200 dark:border-red-900 shadow-sm">
          <div className="text-xs font-bold text-red-700 dark:text-red-300 uppercase tracking-wider">High-Risk Fraud</div>
          <div className="text-3xl font-black text-red-600 mt-2">{high}</div>
        </div>
        <div className="p-5 rounded-2xl bg-amber-50/80 dark:bg-amber-950/30 border border-amber-200 dark:border-amber-900 shadow-sm">
          <div className="text-xs font-bold text-amber-800 dark:text-amber-300 uppercase tracking-wider">Unverified / Medium</div>
          <div className="text-3xl font-black text-amber-600 mt-2">{med}</div>
        </div>
        <div className="p-5 rounded-2xl bg-emerald-50/80 dark:bg-emerald-950/30 border border-emerald-200 dark:border-emerald-900 shadow-sm">
          <div className="text-xs font-bold text-emerald-800 dark:text-emerald-300 uppercase tracking-wider">Low-Risk Clean</div>
          <div className="text-3xl font-black text-emerald-600 mt-2">{low}</div>
        </div>
      </div>

      <div className="rounded-2xl bg-white dark:bg-[#111F36] border border-slate-200 dark:border-slate-800 p-6 shadow-sm space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3 pb-3 border-b border-slate-100 dark:border-slate-800">
          <h2 className="text-base font-bold text-slate-900 dark:text-white">Recently Analyzed Opportunities</h2>
          <div className="flex flex-wrap items-center gap-2">
            {onExportHistory && (
              <button
                type="button"
                onClick={onExportHistory}
                disabled={history.length === 0}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-200 dark:border-slate-700 text-xs font-bold text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-800 disabled:opacity-40 transition"
              >
                <Download size={13} /> Export All JSON
              </button>
            )}
            {onImportReport && (
              <label className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-200 dark:border-slate-700 text-xs font-bold text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-800 cursor-pointer transition">
                <Upload size={13} /> Import Report JSON
                <input type="file" accept=".json,application/json" onChange={handleFileImport} className="hidden" />
              </label>
            )}
            {onClearHistory && history.length > 0 && (
              <button
                type="button"
                onClick={onClearHistory}
                className="flex items-center gap-1 px-3 py-1.5 rounded-lg border border-rose-200 dark:border-rose-900/60 text-xs font-bold text-rose-600 hover:bg-rose-50 dark:hover:bg-rose-950/30 transition"
              >
                <Trash2 size={13} /> Clear
              </button>
            )}
          </div>
        </div>

        {history.length === 0 ? (
          <div className="py-10 text-center">
            <p className="text-sm font-semibold text-slate-600 dark:text-slate-400">No verifications recorded yet.</p>
            <p className="text-xs text-slate-500 mt-1">Submit a job advertisement, message, or load a labeled demonstration scenario.</p>
            <button
              type="button"
              onClick={onStartVerify}
              className="mt-4 inline-flex items-center gap-1.5 px-5 py-2.5 rounded-xl bg-blue-600 text-white text-xs font-bold hover:bg-blue-500 transition"
            >
              Start First Verification <ArrowRight size={14} />
            </button>
          </div>
        ) : (
          <div className="space-y-2.5">
            {history.slice(0, 10).map((item) => (
              <div
                key={item.report_id}
                className="p-4 rounded-xl bg-[#F4F7FB] dark:bg-slate-900/60 border border-slate-200 dark:border-slate-800/80 flex flex-wrap items-center justify-between gap-4 hover:border-blue-400 transition"
              >
                <div className="min-w-0 space-y-1">
                  <div className="flex items-center gap-2">
                    <span className={`px-2.5 py-0.5 rounded-full text-[10px] font-extrabold uppercase ${
                      item.risk_level === "HIGH RISK"
                        ? "bg-rose-100 text-rose-700 dark:bg-rose-950/60 dark:text-rose-300"
                        : item.risk_level === "MEDIUM RISK"
                        ? "bg-amber-100 text-amber-800 dark:bg-amber-950/60 dark:text-amber-300"
                        : "bg-emerald-100 text-emerald-800 dark:bg-emerald-950/60 dark:text-emerald-300"
                    }`}>
                      {item.risk_level} ({item.risk_index}/100)
                    </span>
                    <span className="text-xs font-bold text-slate-900 dark:text-slate-100 truncate">
                      {item.extracted_data.employer.value || "Unidentified Employer"} — {item.extracted_data.role.value || "Role Unspecified"}
                    </span>
                  </div>
                  <div className="text-[11px] text-slate-500">
                    Report ID: <span className="font-mono">{item.report_id}</span> • Evidence Coverage: {item.evidence_coverage_percent}% • Time: {new Date(item.timestamp).toLocaleString()}
                  </div>
                </div>
                <button
                  type="button"
                  onClick={() => onOpenReport(item.report_id)}
                  className="px-4 py-2 rounded-xl text-xs font-bold bg-[#167D82] hover:bg-[#12686D] text-white shadow-sm shrink-0 transition"
                >
                  Open Report →
                </button>
              </div>
            ))}
          </div>
        )}
      </div>
    </section>
  );
});
