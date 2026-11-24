interface SpeechRecognitionEventLike {
  resultIndex: number;
  results: ArrayLike<{ isFinal: boolean; 0: { transcript: string } }>;
}
interface SpeechRecognitionLike {
  lang: string;
  continuous: boolean;
  onresult: ((ev: SpeechRecognitionEventLike) => void) | null;
  onend: (() => void) | null;
  start: () => void;
  stop: () => void;
}
type SpeechWindow = Window & {
  SpeechRecognition?: new () => SpeechRecognitionLike;
  webkitSpeechRecognition?: new () => SpeechRecognitionLike;
};

import React, { useRef, useState } from "react";

interface CallIndicator {
  id: string;
  category: string;
  matched_text: string;
  severity: string;
  explanation: string;
  suggested_action: string;
}

interface CallReport {
  call_report_id: string;
  detected_language_code: string;
  detected_language_label: string;
  risk_index: number;
  risk_level: string;
  verdict_headline: string;
  risk_index_disclaimer: string;
  transcription_status: string;
  extracted_entities: {
    claimed_organization: string | null;
    payment_amounts_mentioned: string[];
    upi_ids_mentioned: string[];
    phone_numbers_mentioned: string[];
  };
  indicator_count: number;
  indicators: CallIndicator[];
  redacted_transcript: string;
  recommended_actions: string[];
}

const CALL_DEMOS = [
  {
    id: "call-en-hr",
    short: "English Fake HR Fee",
    lang: "English",
    transcript:
      "Hello, I am calling from Infosys HR Recruitment Desk. Congratulations, you are selected without interview for Junior Software Engineer at ₹48,000 per month. Please stay on the line and pay ₹1,500 refundable registration fee to hr.verify@ybl right now. Do not hang up or tell anyone.",
  },
  {
    id: "call-hi-arrest",
    short: "Hindi Digital Arrest + OTP",
    lang: "Hindi",
    transcript:
      "नमस्ते, मैं सीबीआई अधिकारी बोल रहा हूँ। आपके आधार नंबर पर एक अवैध पार्सल पकड़ा गया है। अभी आप डिजिटल अरेस्ट में हैं। फोन मत काटना और किसी को मत बताना। वेरिफिकेशन के लिए ₹25,000 ट्रांसफर करें और मोबाइल पर आया ओटीपी बताइए।",
  },
  {
    id: "call-hinglish-anydesk",
    short: "Hinglish AnyDesk Trap",
    lang: "Hinglish",
    transcript:
      "Hello sir, main TCS onboarding team se bol raha hoon. Laptop kit ke liye pehle ₹2,000 security deposit jama karo aur Play Store se AnyDesk install karke 9-digit code batao. Phone mat katna.",
  },
  {
    id: "call-ta-fee",
    short: "Tamil Job Fee Call",
    lang: "Tamil",
    transcript:
      "வணக்கம், உங்களுக்கு வேலை உறுதியாகிவிட்டது. ₹1,500 ரெஜிஸ்ட்ரேஷன் கட்டணம் செலுத்தவும் மற்றும் உங்கள் மொபைலில் வந்த ஓடிபி சொல்லுங்கள்.",
  },
  {
    id: "call-es-deposit",
    short: "Spanish Fake Job Call",
    lang: "Spanish",
    transcript:
      "Hola, felicidades por tu trabajo sin entrevista. Paga una tarifa de registro de $150 y dame el código OTP de tu banco. No cuelgues.",
  },
  {
    id: "call-legit-hr",
    short: "Legitimate HR Call",
    lang: "English (Legit)",
    transcript:
      "Hi Priya, calling from Razorpay Recruiting regarding your Backend Engineer interview on Thursday at 3 PM. Reminder: we do not charge any fee and never share your OTP or UPI PIN.",
  },
];

function localAnalyzeCall(transcript: string): CallReport {
  const clean = transcript.trim();
  const isHi = /[\u0900-\u097F]{4,}/.test(clean);
  const isTa = /[\u0B80-\u0BFF]{4,}/.test(clean);
  const isEs = /\b(hola|tarifa\s+de\s+registro|c[oó]digo\s+otp|no\s+cuelgues)\b/i.test(clean);
  const isHinglish = /\b(batao|jama\s+karo|phone\s+mat\s+katna|se\s+bol\s+raha|rupaye|bhej)\b/i.test(clean);
  const langCode = isTa ? "ta" : isHi ? "hi" : isEs ? "es" : isHinglish ? "hinglish" : "en";
  const langMap: Record<string, string> = {
    en: "English",
    hi: "Hindi (हिंदी)",
    hinglish: "Hinglish",
    ta: "Tamil (தமிழ்)",
    es: "Spanish (Español)",
  };
  const hasDisc = /(never\s+(?:share|pay)|we\s+do\s+not\s+charge\s+any\s+fee)/i.test(clean);
  const rules: Array<[string, string, RegExp, string]> = [
    ["Live Call OTP / UPI PIN Theft", "critical", /(?:(?:read|tell|share|batao|dame)\s+(?:me\s+)?(?:the\s+|your\s+|el\s+)?(?:otp|upi\s+pin|c[oó]digo\s+otp)|ओटीपी|ஓடிபி)/i, "Caller asks for an OTP or UPI PIN over the call."],
    ["Advance Job Fee / Deposit on Call", "critical", /(?:registration\s+fee|security\s+deposit|tarifa\s+de\s+registro|रजिस्ट्रेशन\s+फीस|सिक्योरिटी\s+डिपॉजिट|ரெஜிஸ்ட்ரேஷன்\s*கட்டணம்)/i, "Caller demands an advance registration fee or security deposit."],
    ["Remote-Access Takeover (AnyDesk/TeamViewer)", "critical", /(?:anydesk|teamviewer|quicksupport|rustdesk)/i, "Caller instructs installing remote-access software."],
    ["Authority Impersonation / Digital Arrest", "critical", /(?:digital\s+arrest|डिजिटल\s+अरेस्ट|सीबीआई\s+अधिकारी|अवैध\s+पार्सल)/i, "Caller threatens 'Digital Arrest' or impersonates CBI/Police."],
    ["Call Isolation Pressure", "high", /(?:do\s+not\s+hang\s+up|phone\s+mat\s+katna|फोन\s+मत\s+काटना|no\s+cuelgues)/i, "Caller pressures you not to hang up or consult anyone."],
  ];
  const indicators: CallIndicator[] = [];
  for (const [cat, sev, rx, exp] of rules) {
    const m = clean.match(rx);
    if (m) {
      const pref = clean.slice(Math.max(0, (m.index || 0) - 45), m.index || 0);
      if (/\b(never|do\s+not|does\s+not)\b/i.test(pref)) continue;
      indicators.push({
        id: `c-${indicators.length}`,
        category: cat,
        matched_text: m[0],
        severity: sev,
        explanation: exp,
        suggested_action: "Hang up immediately and never pay or share OTP/UPI PIN.",
      });
    }
  }
  const crit = indicators.filter((i) => i.severity === "critical").length;
  const hi = indicators.filter((i) => i.severity === "high").length;
  const riskLevel = crit >= 1 || hi >= 2 ? "HIGH RISK" : hi >= 1 ? "MEDIUM RISK" : "LOW RISK";
  const riskIndex =
    riskLevel === "HIGH RISK"
      ? Math.min(98, Math.max(76, crit * 44 + hi * 28))
      : riskLevel === "MEDIUM RISK"
      ? 48
      : hasDisc
      ? 5
      : 10;

  return {
    call_report_id: `jg-call-${Date.now().toString(36)}`,
    detected_language_code: langCode,
    detected_language_label: langMap[langCode] || "English",
    risk_index: riskIndex,
    risk_level: riskLevel,
    verdict_headline:
      riskLevel === "HIGH RISK"
        ? "HIGH RISK CALL SCAM — Live-call fraud tactics detected."
        : riskLevel === "MEDIUM RISK"
        ? "MEDIUM RISK — Suspicious call pressure detected."
        : "LOW RISK — No strong phone-scam indicators found.",
    risk_index_disclaimer: "Heuristic 0–100% Call Risk Score based on multilingual voice-scam rules.",
    transcription_status: "User / Browser Provided",
    extracted_entities: {
      claimed_organization: (clean.match(/(?:calling\s+from|from)\s+([A-Z][A-Za-z0-9 ]{2,30})/) || [])[1] || null,
      payment_amounts_mentioned: [...new Set(clean.match(/(?:₹|Rs\.?|\$|€)\s*\d[\d,]*/gi) || [])],
      upi_ids_mentioned: [...new Set(clean.match(/\b[a-zA-Z0-9._-]+@(?:upi|ybl|okaxis|okicici|oksbi|paytm)\b/gi) || [])],
      phone_numbers_mentioned: [...new Set(clean.match(/(?:\+91[\s-]?)?[6-9]\d{4}[\s-]?\d{5}\b/g) || [])],
    },
    indicator_count: indicators.length,
    indicators,
    redacted_transcript: clean,
    recommended_actions:
      riskLevel === "HIGH RISK"
        ? ["Hang up immediately and block the caller.", "Never transfer money or share OTP/UPI PIN.", "In India, dial 1930 immediately if money was debited (cybercrime.gov.in)."]
        : ["Verify the caller via the company's official published number."],
  };
}

export const CallGuardPanel: React.FC = () => {
  const [audioFile, setAudioFile] = useState<File | null>(null);
  const [audioUrl, setAudioUrl] = useState<string | null>(null);
  const [transcript, setTranscript] = useState("");
  const [speechLang, setSpeechLang] = useState("en-IN");
  const [listening, setListening] = useState(false);
  const [report, setReport] = useState<CallReport | null>(null);
  const [loading, setLoading] = useState(false);
  const recRef = useRef<SpeechRecognitionLike | null>(null);

  const handleAudioChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const f = e.target.files?.[0];
    if (!f) return;
    if (audioUrl) URL.revokeObjectURL(audioUrl);
    setAudioFile(f);
    setAudioUrl(URL.createObjectURL(f));
  };

  const toggleSpeech = () => {
    const speechWin = window as SpeechWindow;
    const SR = speechWin.SpeechRecognition || speechWin.webkitSpeechRecognition;
    if (!SR) {
      alert("Live browser Speech-to-Text requires Chrome or Edge. You can paste/edit the transcript directly.");
      return;
    }
    if (listening && recRef.current) {
      recRef.current.stop();
      setListening(false);
      return;
    }
    const rec = new SR();
    rec.lang = speechLang;
    rec.continuous = true;
    rec.onresult = (ev: SpeechRecognitionEventLike) => {
      let chunk = "";
      for (let i = ev.resultIndex; i < ev.results.length; i++) {
        if (ev.results[i].isFinal) chunk += " " + ev.results[i][0].transcript;
      }
      if (chunk.trim()) setTranscript((prev) => (prev ? `${prev} ${chunk.trim()}` : chunk.trim()));
    };
    rec.onend = () => setListening(false);
    recRef.current = rec;
    setListening(true);
    rec.start();
  };

  const analyzeCall = async (explicitText?: string) => {
    const textToUse = (explicitText !== undefined ? explicitText : transcript).trim();
    if (!audioFile && !textToUse) return;
    setLoading(true);
    try {
      if (audioFile) {
        const fd = new FormData();
        fd.append("file", audioFile);
        if (textToUse) fd.append("transcript", textToUse);
        const r = await fetch("/api/call/analyze", { method: "POST", body: fd });
        if (r.ok) {
          setReport(await r.json());
          setLoading(false);
          return;
        }
      } else {
        const r = await fetch("/api/call/analyze-transcript", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ transcript: textToUse }),
        });
        if (r.ok) {
          setReport(await r.json());
          setLoading(false);
          return;
        }
      }
    } catch (err) { console.debug("Call API fallback to local engine:", err); }
    setReport(localAnalyzeCall(textToUse));
    setLoading(false);
  };

  return (
    <section aria-label="Call Guard Analyzer" aria-live="polite" className="space-y-6">
      <div>
        <span className="text-xs font-bold uppercase tracking-wider text-indigo-600 dark:text-indigo-300">
          Multilingual Voice & Vishing Protection (11+ Languages)
        </span>
        <h1 className="text-2xl font-extrabold mt-1">📞 Call Recording Scam Detector</h1>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        <div className="lg:col-span-5 rounded-2xl bg-white dark:bg-[#161822] border border-slate-200 dark:border-slate-700 p-5 space-y-4">
          <h2 className="font-bold text-sm">1. Upload Call Recording (MP3, WAV, M4A, OGG, WEBM)</h2>
          <input type="file" accept="audio/*" onChange={handleAudioChange} className="block w-full text-xs" />
          {audioUrl && <audio controls src={audioUrl} className="w-full h-9" />}
          <div className="pt-3 border-t border-slate-200 dark:border-slate-700 space-y-2">
            <div className="text-xs font-bold">Live Browser Speech-to-Text</div>
            <div className="flex gap-2">
              <select
                value={speechLang}
                onChange={(e) => setSpeechLang(e.target.value)}
                className="flex-1 rounded-xl border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-slate-900 px-3 py-2 text-xs"
              >
                <option value="en-IN">English (India)</option>
                <option value="hi-IN">Hindi (हिंदी)</option>
                <option value="ta-IN">Tamil (தமிழ்)</option>
                <option value="te-IN">Telugu (తెలుగు)</option>
                <option value="bn-IN">Bengali (বাংলা)</option>
                <option value="mr-IN">Marathi (मराठी)</option>
                <option value="es-ES">Spanish (Español)</option>
                <option value="fr-FR">French (Français)</option>
              </select>
              <button
                type="button"
                onClick={toggleSpeech}
                className={`px-4 py-2 rounded-xl text-xs font-bold text-white ${listening ? "bg-rose-600 animate-pulse" : "bg-indigo-600"}`}
              >
                {listening ? "⏹ Stop" : "🎙️ Listen"}
              </button>
            </div>
          </div>
        </div>

        <div className="lg:col-span-7 rounded-2xl bg-white dark:bg-[#161822] border border-slate-200 dark:border-slate-700 p-5 space-y-4">
          <h2 className="font-bold text-sm">2. Call Transcript (Editable • Auto-Detects 11+ Languages)</h2>
          <textarea
            rows={7}
            value={transcript}
            onChange={(e) => setTranscript(e.target.value)}
            placeholder="Transcribed speech appears here, or paste what the caller said in English, Hindi, Hinglish, Tamil, Spanish..."
            className="w-full rounded-xl border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-slate-900 p-3 text-xs"
          />
          <div className="flex justify-end">
            <button
              type="button"
              disabled={loading}
              onClick={() => analyzeCall()}
              className="px-6 py-2.5 rounded-full bg-indigo-600 hover:bg-indigo-700 text-white text-xs font-bold"
            >
              {loading ? "Analyzing Call..." : "🔍 Analyze Call Recording →"}
            </button>
          </div>
        </div>
      </div>

      <div className="rounded-2xl bg-white dark:bg-[#161822] border border-slate-200 dark:border-slate-700 p-5 space-y-2.5">
        <div className="text-xs font-bold uppercase text-slate-500">Multilingual Demo Call Scenarios</div>
        <div className="flex flex-wrap gap-2">
          {CALL_DEMOS.map((d) => (
            <button
              key={d.id}
              type="button"
              onClick={() => {
                setTranscript(d.transcript);
                analyzeCall(d.transcript);
              }}
              className="px-3 py-1.5 rounded-full text-xs font-semibold bg-slate-100 dark:bg-slate-800 hover:bg-indigo-600 hover:text-white transition"
            >
              📞 {d.short} ({d.lang})
            </button>
          ))}
        </div>
      </div>

      {report && (
        <div
          className={`rounded-2xl p-6 border-2 space-y-4 ${
            report.risk_level === "HIGH RISK"
              ? "border-rose-300 bg-rose-50/70 dark:bg-rose-950/30"
              : report.risk_level === "MEDIUM RISK"
              ? "border-amber-300 bg-amber-50/70 dark:bg-amber-950/30"
              : "border-emerald-300 bg-emerald-50/70 dark:bg-emerald-950/30"
          }`}
        >
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <span className="px-3 py-1 rounded-full text-xs font-extrabold bg-slate-900 text-white">
                {report.risk_level} • {report.risk_index}%
              </span>
              <span className="ml-2 px-2.5 py-1 rounded-full text-xs font-bold bg-white dark:bg-slate-900">
                🌐 {report.detected_language_label}
              </span>
              <h3 className="text-lg font-extrabold mt-2">{report.verdict_headline}</h3>
            </div>
          </div>
          {report.indicators.length > 0 && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
              {report.indicators.map((ind) => (
                <div key={ind.id} className="p-3.5 rounded-xl bg-white dark:bg-slate-900 border border-rose-200 dark:border-rose-900">
                  <div className="font-bold text-rose-700 dark:text-rose-300">{ind.category}</div>
                  <div className="font-mono mt-1">"{ind.matched_text}"</div>
                  <div className="text-slate-600 dark:text-slate-300 mt-1">{ind.explanation}</div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </section>
  );
};
