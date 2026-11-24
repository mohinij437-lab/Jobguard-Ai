import React, { useState } from "react";
import { ACADEMY_MODULES } from "../data/academy";
import { QUIZ_SETS } from "../data/quiz";

export const LearnAndHelpPanel: React.FC<{ mode: "learn" | "help" }> = React.memo(({ mode }) => {
  const [tab, setTab] = useState<"academy" | "quiz">("academy");
  const questions = QUIZ_SETS.set1.questions;
  const [qIdx, setQIdx] = useState(0);
  const [choice, setChoice] = useState<"scam" | "legitimate" | null>(null);
  const [score, setScore] = useState(0);
  const [done, setDone] = useState(false);

  if (mode === "help") {
    return (
      <div className="space-y-6">
        <h1 className="text-2xl font-extrabold">🚨 Report Recruitment Fraud & Emergency Help (India)</h1>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="rounded-2xl bg-white dark:bg-[#161822] border border-rose-300 dark:border-rose-800 p-6 space-y-2">
            <span className="text-xs font-extrabold uppercase text-rose-600">Financial Cyber Fraud Helpline</span>
            <div className="text-4xl font-extrabold">Dial 1930</div>
            <p className="text-xs text-slate-600 dark:text-slate-300">
              If you transferred money to a fake recruiter via UPI, NEFT/IMPS, or card, dial 1930 immediately for bank-level lien/freeze.
            </p>
            <a href="tel:1930" className="inline-block px-5 py-2 rounded-full bg-rose-600 text-white text-xs font-bold">
              📞 Call 1930 Now
            </a>
          </div>
          <div className="rounded-2xl bg-white dark:bg-[#161822] border border-slate-200 dark:border-slate-700 p-6 space-y-2">
            <span className="text-xs font-extrabold uppercase text-indigo-600">National Cyber Crime Reporting Portal</span>
            <div className="text-2xl font-extrabold">cybercrime.gov.in</div>
            <p className="text-xs text-slate-600 dark:text-slate-300">
              File an official complaint with screenshots of the job post, recruiter phone/email, fake offer letter, and 12-digit UTR numbers.
            </p>
            <a
              href="https://cybercrime.gov.in/"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-block px-5 py-2 rounded-full bg-indigo-600 text-white text-xs font-bold"
            >
              🌐 Open cybercrime.gov.in ↗
            </a>
          </div>
        </div>
      </div>
    );
  }

  const q = questions[qIdx];
  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h1 className="text-2xl font-extrabold">🎓 Recruitment Scam Academy & Quiz</h1>
        <div className="flex gap-2">
          <button
            type="button"
            onClick={() => setTab("academy")}
            className={`px-4 py-1.5 rounded-full text-xs font-bold ${tab === "academy" ? "bg-indigo-600 text-white" : "bg-slate-200 dark:bg-slate-800"}`}
          >
            10 Modules
          </button>
          <button
            type="button"
            onClick={() => setTab("quiz")}
            className={`px-4 py-1.5 rounded-full text-xs font-bold ${tab === "quiz" ? "bg-indigo-600 text-white" : "bg-slate-200 dark:bg-slate-800"}`}
          >
            Fraud Quiz
          </button>
        </div>
      </div>

      {tab === "academy" ? (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {ACADEMY_MODULES.map((m) => (
            <div key={m.slug} className="rounded-2xl bg-white dark:bg-[#161822] border border-slate-200 dark:border-slate-700 p-5 space-y-2 text-xs">
              <span className="px-2.5 py-0.5 rounded-full font-bold bg-indigo-50 dark:bg-indigo-950 text-indigo-700 dark:text-indigo-300">
                Module {m.number} • {m.category}
              </span>
              <h2 className="text-base font-bold">{m.title}</h2>
              <p className="text-slate-600 dark:text-slate-300">{m.summary}</p>
              <ul className="list-disc pl-4 text-rose-700 dark:text-rose-300 space-y-0.5">
                {m.redFlags.map((f, i) => <li key={i}>{f}</li>)}
              </ul>
            </div>
          ))}
        </div>
      ) : done ? (
        <div className="rounded-2xl bg-white dark:bg-[#161822] border border-slate-200 p-8 text-center space-y-4">
          <h2 className="text-2xl font-extrabold">Quiz Complete: {score} / {questions.length}</h2>
          <button
            type="button"
            onClick={() => { setQIdx(0); setChoice(null); setScore(0); setDone(false); }}
            className="px-5 py-2.5 rounded-full bg-indigo-600 text-white text-xs font-bold"
          >
            Play Again
          </button>
        </div>
      ) : (
        <div className="rounded-2xl bg-white dark:bg-[#161822] border border-slate-200 dark:border-slate-700 p-6 space-y-4">
          <div className="text-xs font-bold text-slate-500">
            Question {qIdx + 1} of {questions.length} • Sender: {q.sender}
          </div>
          <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-900 font-mono text-xs">{q.message}</div>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            {(["scam", "legitimate"] as const).map((opt) => (
              <button
                key={opt}
                type="button"
                disabled={choice !== null}
                onClick={() => {
                  setChoice(opt);
                  if (opt === q.correctChoice) setScore((s) => s + 1);
                }}
                className={`p-4 rounded-xl border-2 text-left text-xs font-bold ${
                  choice === opt ? "border-indigo-600" : "border-slate-200 dark:border-slate-700"
                }`}
              >
                {opt === "scam" ? "🚨 Fraudulent Recruitment Scam" : "✅ Legitimate Recruitment Message"}
              </button>
            ))}
          </div>
          {choice && (
            <div className="p-4 rounded-xl bg-slate-100 dark:bg-slate-900 text-xs space-y-2">
              <div className="font-bold">{choice === q.correctChoice ? "✅ Correct!" : "❌ Incorrect"}</div>
              <div>{q.explanation}</div>
              <button
                type="button"
                onClick={() => {
                  if (qIdx + 1 < questions.length) {
                    setQIdx((i) => i + 1);
                    setChoice(null);
                  } else {
                    setDone(true);
                  }
                }}
                className="px-4 py-2 rounded-full bg-indigo-600 text-white text-xs font-bold"
              >
                {qIdx + 1 < questions.length ? "Next Question →" : "See Final Score →"}
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  );
});
