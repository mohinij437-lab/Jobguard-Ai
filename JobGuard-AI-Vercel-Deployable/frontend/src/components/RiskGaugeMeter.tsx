import React from "react";

interface RiskGaugeMeterProps {
  score: number;
  riskLevel: string;
  confidenceLabel?: string;
}

const ARC_LENGTH = 251.2;

export const RiskGaugeMeter: React.FC<RiskGaugeMeterProps> = React.memo(({
  score,
  riskLevel,
  confidenceLabel,
}) => {
  const clamped = Math.max(0, Math.min(100, Math.round(score)));
  const upper = riskLevel.toUpperCase();
  const strokeColor = upper.includes("HIGH")
    ? "#EF4444"
    : upper.includes("MEDIUM") || upper.includes("SUSPICIOUS")
    ? "#F59E0B"
    : "#10B981";
  const dashOffset = ARC_LENGTH - (ARC_LENGTH * clamped) / 100;

  return (
    <div className="bg-white/95 dark:bg-slate-900/95 px-5 py-4 rounded-2xl border border-slate-200 dark:border-slate-800 text-center min-w-[210px] shadow-sm">
      <svg
        viewBox="0 0 200 115"
        className="w-44 h-24 mx-auto overflow-visible"
        role="img"
        aria-label={`Scam Risk Meter: ${clamped} out of 100, ${riskLevel}`}
      >
        <path
          d="M 20 100 A 80 80 0 0 1 180 100"
          fill="none"
          stroke="currentColor"
          className="text-slate-200 dark:text-slate-700"
          strokeWidth="15"
          strokeLinecap="round"
        />
        <path
          d="M 20 100 A 80 80 0 0 1 180 100"
          fill="none"
          stroke={strokeColor}
          strokeWidth="15"
          strokeLinecap="round"
          strokeDasharray={ARC_LENGTH}
          strokeDashoffset={dashOffset}
        />
        <text
          x="100"
          y="78"
          textAnchor="middle"
          className="fill-slate-900 dark:fill-white font-extrabold"
          fontSize="32"
        >
          {clamped}
          <tspan fontSize="13" className="fill-slate-400" fontWeight="700">
            /100
          </tspan>
        </text>
        <text
          x="100"
          y="98"
          textAnchor="middle"
          className="fill-slate-500 dark:fill-slate-400 font-bold"
          fontSize="10"
          letterSpacing="1.2"
        >
          SCAM RISK METER
        </text>
      </svg>

      <div className="relative h-2.5 w-full rounded-full bg-gradient-to-r from-emerald-500 via-amber-500 to-red-500 mt-2 mb-1">
        <span
          aria-hidden="true"
          className="absolute top-1/2 -translate-y-1/2 -translate-x-1/2 h-4 w-4 rounded-full bg-white dark:bg-slate-950 border-[3px] border-slate-900 dark:border-white shadow"
          style={{ left: `${clamped}%` }}
        />
      </div>
      <div className="flex justify-between text-[10px] font-bold text-slate-500 dark:text-slate-400">
        <span>0 Safe</span>
        <span>50 Caution</span>
        <span>100 High</span>
      </div>
      {confidenceLabel && (
        <div className="text-[11px] font-semibold text-slate-500 dark:text-slate-400 mt-1.5">
          {confidenceLabel}
        </div>
      )}
    </div>
  );
});
