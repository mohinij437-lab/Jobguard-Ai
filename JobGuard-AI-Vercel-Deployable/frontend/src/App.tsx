import React, { Suspense, lazy, useCallback, useEffect, useMemo, useState } from "react";
import { Bell, ChevronDown, Menu, Moon, Search, Sun, X, Shield, Sparkles } from "lucide-react";
import { AnalysisForm } from "./components/AnalysisForm";
import { DEMO_SCENARIOS } from "./data/samples";
import {
  exportReportToMarkdown,
  extractStructuredJobData,
  runLocalVerification,
} from "./engine/localEngine.mjs";
import type { ExtractedJobData, VerificationReport } from "./types";
import { useAuth } from "./components/AuthContext";
import type { AuthMode, AuthUser } from "./components/AuthPanel";

const LandingPage = lazy(() => import("./components/LandingPage").then((m) => ({ default: m.LandingPage })));
const AnalysisResultView = lazy(() => import("./components/AnalysisResultView").then((m) => ({ default: m.AnalysisResultView })));
const CallGuardPanel = lazy(() => import("./components/CallGuardPanel").then((m) => ({ default: m.CallGuardPanel })));
const Dashboard = lazy(() => import("./components/Dashboard").then((m) => ({ default: m.Dashboard })));
const ExtractionReview = lazy(() => import("./components/ExtractionReview").then((m) => ({ default: m.ExtractionReview })));
const LearnAndHelpPanel = lazy(() => import("./components/LearnAndHelpPanel").then((m) => ({ default: m.LearnAndHelpPanel })));
const ScannerPanel = lazy(() => import("./components/ScannerPanel").then((m) => ({ default: m.ScannerPanel })));
const AdvancedProtectionPanel = lazy(() => import("./components/AdvancedProtectionPanel").then((m) => ({ default: m.AdvancedProtectionPanel })));
const AuthPanel = lazy(() => import("./components/AuthPanel").then((m) => ({ default: m.AuthPanel })));

type ViewId =
  | "home"
  | "verify"
  | "call-guard"
  | "scanner"
  | "dashboard"
  | "review"
  | "report"
  | "learn"
  | "help"
  | "link-guardian"
  | "payment"
  | "screenshot"
  | "qr"
  | "deepfake"
  | "assistant"
  | "community"
  | "evidence"
  | "auth";

export const App: React.FC = () => {
  const { user: currentUser, setUser, logout, loading: authLoading } = useAuth();
  const [view, setView] = useState<ViewId>("home");
  const [dark, setDark] = useState(() => {
    const saved = localStorage.getItem("jobguard-theme");
    return saved ? saved === "dark" : window.matchMedia("(prefers-color-scheme: dark)").matches;
  });
  const [mobileOpen, setMobileOpen] = useState(false);
  const [notificationsOpen, setNotificationsOpen] = useState(false);
  const [profileOpen, setProfileOpen] = useState(false);
  const [globalQuery, setGlobalQuery] = useState("");
  const [text, setText] = useState("");
  const [secondaryText, setSecondaryText] = useState("");
  const [jobUrl, setJobUrl] = useState("");
  const [isDemo, setIsDemo] = useState(false);
  const [authMode, setAuthMode] = useState<AuthMode>("signin");
  const [extracted, setExtracted] = useState<ExtractedJobData | null>(null);
  const [edits, setEdits] = useState<Record<string, string>>({});
  const [currentReport, setCurrentReport] = useState<VerificationReport | null>(null);
  const [history, setHistory] = useState<VerificationReport[]>(() => {
    try {
      const raw = localStorage.getItem("jobguard-history");
      if (raw) {
        const parsed = JSON.parse(raw);
        if (Array.isArray(parsed)) return parsed;
      }
    } catch (err) { console.debug("Local fallback active:", err); }
    return [];
  });
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    document.documentElement.classList.toggle("dark", dark);
  }, [dark]);

  useEffect(() => {
    try {
      localStorage.setItem("jobguard-history", JSON.stringify(history.slice(0, 50)));
    } catch (err) { console.debug("Local fallback active:", err); }
  }, [history]);

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    if (params.has("reset_password")) {
      setAuthMode("reset");
      setView("auth");
    } else if (params.has("verify_email")) {
      setAuthMode("verify_email");
      setView("auth");
    }
  }, []);

  useEffect(() => {
    if (!currentUser) {
      setHistory((prev) => prev.filter((report) => report.is_demo || !("saved_owner" in report)));
      return;
    }
    const controller = new AbortController();
    fetch("/api/reports", { credentials: "include", signal: controller.signal })
      .then((res) => (res.ok ? res.json() : null))
      .then((repData: { reports?: Array<{ report?: VerificationReport }> } | null) => {
        const reports = repData?.reports;
        if (Array.isArray(reports)) {
          setHistory((prev) => {
            const existingIds = new Set(prev.map((h) => h.report_id));
            const fromBackend = reports
              .map((item: { report?: VerificationReport }) => item.report)
              .filter((rep): rep is VerificationReport => Boolean(rep && rep.report_id && !existingIds.has(rep.report_id)));
            return fromBackend.length ? [...fromBackend, ...prev] : prev;
          });
        }
      })
      .catch(() => undefined);
    return () => controller.abort();
  }, [currentUser]);

  const historyById = useMemo(
    () => new Map(history.map((item) => [item.report_id, item])),
    [history]
  );

  const toggleTheme = useCallback(() => {
    setDark((prev) => {
      const next = !prev;
      localStorage.setItem("jobguard-theme", next ? "dark" : "light");
      document.documentElement.classList.toggle("dark", next);
      return next;
    });
  }, []);

  const handleExtract = async (overrideText?: string) => {
    const srcText = overrideText !== undefined ? overrideText : text;
    if (!srcText.trim() && !jobUrl.trim()) return;
    setLoading(true);
    try {
      const resp = await fetch("/api/extract", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text: srcText, job_url: jobUrl || null }),
      });
      const data = resp.ok ? await resp.json() : extractStructuredJobData(srcText, jobUrl);
      setExtracted(data);
      setEdits({});
      setView("review");
    } catch {
      setExtracted(extractStructuredJobData(srcText, jobUrl) as ExtractedJobData);
      setEdits({});
      setView("review");
    } finally {
      setLoading(false);
    }
  };

  const handleVerify = async () => {
    setLoading(true);
    try {
      const resp = await fetch("/api/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          text,
          secondary_text: secondaryText || null,
          job_url: jobUrl || null,
          edited_fields: edits,
          is_demo: isDemo,
        }),
      });
      const rep: VerificationReport = resp.ok
        ? await resp.json()
        : (runLocalVerification({ text, secondaryText, jobUrl, editedFields: edits, isDemo }) as VerificationReport);
      setCurrentReport(rep);
      setHistory((prev) => [rep, ...prev]);

      // Save to backend isolated storage if endpoint is accessible
      if (currentUser) {
        fetch("/api/reports/save", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ report: rep, report_id: rep.report_id }),
          credentials: "include",
        }).catch(() => undefined);
      }

      setView("report");
    } catch {
      const rep = runLocalVerification({ text, secondaryText, jobUrl, editedFields: edits, isDemo }) as VerificationReport;
      setCurrentReport(rep);
      setHistory((prev) => [rep, ...prev]);
      setView("report");
    } finally {
      setLoading(false);
    }
  };

  const handleLoadDemo = (id: string) => {
    const sc = DEMO_SCENARIOS.find((s) => s.id === id);
    if (!sc) return;
    setText(sc.text);
    setSecondaryText(sc.secondaryText || "");
    setJobUrl(sc.jobUrl || "");
    setIsDemo(true);
  };

  const downloadFile = (content: string, filename: string, mime: string) => {
    const blob = new Blob([content], { type: mime });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1500);
  };

  const navItems: Array<[ViewId, string]> = [
    ["verify", "✨ Verify Job"],
    ["call-guard", "📞 Call Guard"],
    ["scanner", "📷 OCR / PDF / URL"],
    ["link-guardian", "🔗 Link Guardian"],
    ["payment", "💳 Payment Check"],
    ["deepfake", "🎙️ Deepfake Voice"],
    ["assistant", "🤖 AI Assistant"],
    ["community", "🌐 Scam Reports"],
    ["dashboard", "📊 Dashboard"],
    ["evidence", "📁 Evidence Locker"],
    ["learn", "🎓 Academy & Quiz"],
    ["help", "🚨 1930 Help"],
  ];

  const navigate = useCallback((id: ViewId) => {
    setView(id);
    setMobileOpen(false);
    setNotificationsOpen(false);
    setProfileOpen(false);
  }, []);

  const exportHistoryJson = () => {
    downloadFile(JSON.stringify(history, null, 2), `jobguard-history-export-${Date.now()}.json`, "application/json");
  };

  const importReportJson = (rep: VerificationReport) => {
    setCurrentReport(rep);
    setHistory((prev) => [rep, ...prev.filter((h) => h.report_id !== rep.report_id)]);
    setView("report");
  };

  const clearHistory = () => {
    if (window.confirm("Clear all locally recorded verification reports from Dashboard?")) {
      if (currentUser) {
        void Promise.all(
          history
            .filter((report) => !report.is_demo)
            .map((report) =>
              fetch(`/api/reports/${encodeURIComponent(report.report_id)}`, {
                method: "DELETE",
                credentials: "include",
              }).catch(() => undefined)
            )
        );
      }
      setHistory([]);
      localStorage.removeItem("jobguard-history");
    }
  };

  return (
    <div className="min-h-screen bg-[#F5F7FB] text-slate-900 transition-colors dark:bg-[#090F1E] dark:text-slate-100">
      <a
        href="#main-content"
        className="sr-only focus:not-sr-only focus:fixed focus:left-4 focus:top-4 focus:z-50 focus:rounded-lg focus:bg-blue-600 focus:px-4 focus:py-2 focus:text-sm focus:font-bold focus:text-white"
      >
        Skip to main content
      </a>
      <header className="sticky top-0 z-40 border-b border-slate-200/90 bg-white/95 backdrop-blur-xl dark:border-slate-800 dark:bg-[#0B1220]/95">
        <div className="mx-auto flex h-16 max-w-7xl items-center gap-3 px-4 sm:px-6">
          <button
            type="button"
            onClick={() => navigate("home")}
            className="flex shrink-0 items-center gap-2 focus-visible:ring-2 focus-visible:ring-blue-500 rounded-xl"
            aria-label="JobGuard AI Home"
          >
            <span className="grid h-9 w-9 place-items-center rounded-xl bg-[#2563EB] text-xs font-black text-white shadow-md shadow-blue-600/20">
              JG
            </span>
            <span className="hidden font-extrabold sm:inline">
              JobGuard <span className="text-blue-600">AI</span>
            </span>
          </button>

          <nav aria-label="Primary Navigation" className="hidden items-center gap-0.5 xl:flex">
            {navItems.slice(0, 8).map(([id, label]) => (
              <button
                key={id}
                type="button"
                aria-current={view === id ? "page" : undefined}
                onClick={() => navigate(id)}
                className={`relative px-2.5 py-2 text-xs font-bold transition rounded-lg focus-visible:ring-2 focus-visible:ring-blue-500 ${
                  view === id
                    ? "text-blue-600 dark:text-blue-400"
                    : "text-slate-600 hover:text-slate-950 dark:text-slate-300 dark:hover:text-white"
                }`}
              >
                {label.replace(/^[^ ]+ /, "")}
                {view === id && <span className="absolute inset-x-2 -bottom-[15px] h-0.5 rounded-full bg-blue-600" />}
              </button>
            ))}
          </nav>

          <div className="ml-auto flex items-center gap-2">
            <label className="hidden lg:flex items-center gap-2 rounded-xl border border-slate-200 bg-slate-50 px-3 py-1.5 dark:border-slate-700 dark:bg-slate-900 focus-within:ring-2 focus-within:ring-blue-500">
              <Search size={14} aria-hidden="true" className="text-slate-400" />
              <input
                value={globalQuery}
                onChange={(e) => setGlobalQuery(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") {
                    const q = globalQuery.toLowerCase();
                    if (q.includes("call") || q.includes("audio") || q.includes("voice")) navigate("call-guard");
                    else if (q.includes("url") || q.includes("link")) navigate("link-guardian");
                    else if (q.includes("pay") || q.includes("upi")) navigate("payment");
                    else if (q.includes("deepfake")) navigate("deepfake");
                    else if (q.includes("qr")) navigate("qr");
                    else if (q.includes("evidence") || q.includes("locker")) navigate("evidence");
                    else navigate("verify");
                  }
                }}
                aria-label="Search JobGuard modules"
                placeholder="Search modules..."
                className="w-28 xl:w-36 bg-transparent text-xs outline-none"
              />
            </label>

            {/* Account Status */}
            <button
              type="button"
              onClick={() => setProfileOpen((v) => !v)}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl border border-emerald-300/80 bg-emerald-50 dark:border-emerald-800 dark:bg-emerald-950/40 text-emerald-800 dark:text-emerald-300 text-xs font-bold hover:bg-emerald-100 dark:hover:bg-emerald-950/60 transition focus-visible:ring-2 focus-visible:ring-emerald-500"
              aria-label={currentUser ? "Open account menu" : "Open sign in menu"}
              aria-expanded={profileOpen}
              aria-haspopup="menu"
            >
              <span className="h-2 w-2 rounded-full bg-emerald-500 animate-pulse" />
              <span className="hidden sm:inline">{authLoading ? "Checking..." : currentUser ? currentUser.full_name || currentUser.email : "Sign in"}</span>
              <span className="sm:hidden">{currentUser ? "Account" : "Sign in"}</span>
              <ChevronDown size={12} className="text-emerald-600 dark:text-emerald-400" />
            </button>

            <button
              type="button"
              aria-label="Notifications"
              aria-expanded={notificationsOpen}
              aria-haspopup="menu"
              onClick={() => setNotificationsOpen((v) => !v)}
              className="relative grid h-9 w-9 place-items-center rounded-xl border border-slate-200 dark:border-slate-700 hover:bg-slate-100 dark:hover:bg-slate-800 focus-visible:ring-2 focus-visible:ring-blue-500 transition"
            >
              <Bell size={16} />
              {history.length > 0 && (
                <span className="absolute right-1.5 top-1.5 h-2 w-2 rounded-full border border-white bg-rose-500 dark:border-[#0B1220]" />
              )}
            </button>

            <button
              type="button"
              aria-label="Toggle theme"
              aria-pressed={dark}
              onClick={toggleTheme}
              className="grid h-9 w-9 place-items-center rounded-xl border border-slate-200 dark:border-slate-700 hover:bg-slate-100 dark:hover:bg-slate-800 focus-visible:ring-2 focus-visible:ring-blue-500 transition"
            >
              {dark ? <Sun size={16} /> : <Moon size={16} />}
            </button>

            <button
              type="button"
              aria-label="Open navigation menu"
              aria-expanded={mobileOpen}
              onClick={() => setMobileOpen(true)}
              className="grid h-9 w-9 place-items-center rounded-xl border border-slate-200 lg:hidden dark:border-slate-700 focus-visible:ring-2 focus-visible:ring-blue-500"
            >
              <Menu size={18} />
            </button>
          </div>
        </div>
      </header>

      {/* Notifications Popover */}
      {notificationsOpen && (
        <div className="fixed right-4 top-16 z-50 w-80 rounded-2xl border border-slate-200 bg-white p-5 shadow-2xl dark:border-slate-800 dark:bg-[#111C32]">
          <div className="flex items-center justify-between pb-3 border-b border-slate-100 dark:border-slate-800">
            <b className="text-sm">Security Notifications</b>
            <button type="button" onClick={() => setNotificationsOpen(false)} aria-label="Close notifications">
              <X size={16} />
            </button>
          </div>
          <p className="mt-3 text-xs text-slate-500">
            {history.length
              ? `${history.length} verified report(s) available in your Dashboard.`
              : "No unread alerts. Your JobGuard AI protection center is active and up to date."}
          </p>
          {history.length > 0 && (
            <button
              type="button"
              onClick={() => navigate("dashboard")}
              className="mt-4 w-full rounded-xl bg-blue-600 py-2 text-xs font-bold text-white hover:bg-blue-500 transition"
            >
              Open Dashboard
            </button>
          )}
        </div>
      )}

      {/* Account Popover */}
      {profileOpen && (
        <div className="fixed right-4 top-16 z-50 w-80 rounded-2xl border border-slate-200 bg-white p-5 shadow-2xl dark:border-slate-800 dark:bg-[#111C32]">
          <div className="flex items-center justify-between pb-3 border-b border-slate-100 dark:border-slate-800">
            <div className="flex items-center gap-2">
              <span className="h-2.5 w-2.5 rounded-full bg-emerald-500 animate-pulse" />
              <b className="text-sm text-slate-900 dark:text-white">{currentUser ? "Your Account" : "Guest Mode"}</b>
            </div>
            <button type="button" onClick={() => setProfileOpen(false)} aria-label="Close demo details">
              <X size={16} />
            </button>
          </div>
          <div className="mt-3 space-y-3">
            {currentUser ? (
              <p className="text-xs text-slate-600 dark:text-slate-300 leading-relaxed">
                Signed in as <strong>{currentUser.full_name || currentUser.email}</strong>. Saved reports are private to this account.
              </p>
            ) : (
              <p className="text-xs text-slate-600 dark:text-slate-300 leading-relaxed">
                Local verification remains available without registration. Sign in to save reports to a private evidence locker.
              </p>
            )}
            <div className="rounded-xl bg-slate-50 dark:bg-slate-900/80 p-3 space-y-1.5 border border-slate-100 dark:border-slate-800 text-xs">
              <div className="flex justify-between">
                <span className="text-slate-500">Session:</span>
                <span className="font-bold text-emerald-600 dark:text-emerald-400">{currentUser ? "Authenticated" : "Guest"}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-500">Modules:</span>
                <span className="font-bold text-blue-600 dark:text-blue-400">25 / 25 Available</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-500">Storage:</span>
                <span className="font-bold text-slate-700 dark:text-slate-300">Local Evidence Locker</span>
              </div>
            </div>
            {currentUser ? (
              <div className="grid grid-cols-2 gap-2">
                <button type="button" onClick={() => { setAuthMode("profile"); setProfileOpen(false); navigate("auth"); }} className="rounded-xl bg-blue-600 py-2.5 text-xs font-bold text-white">Profile</button>
                <button type="button" onClick={() => { setAuthMode("settings"); setProfileOpen(false); navigate("auth"); }} className="rounded-xl border border-slate-200 py-2.5 text-xs font-bold dark:border-slate-700">Settings</button>
                <button type="button" onClick={async () => { await logout(); setProfileOpen(false); navigate("home"); }} className="col-span-2 rounded-xl border border-rose-200 py-2.5 text-xs font-bold text-rose-600 dark:border-rose-900">Logout</button>
              </div>
            ) : (
              <div className="grid grid-cols-2 gap-2">
                <button type="button" onClick={() => { setAuthMode("signin"); setProfileOpen(false); navigate("auth"); }} className="rounded-xl bg-blue-600 py-2.5 text-xs font-bold text-white">Sign in</button>
                <button type="button" onClick={() => { setAuthMode("register"); setProfileOpen(false); navigate("auth"); }} className="rounded-xl border border-slate-200 py-2.5 text-xs font-bold dark:border-slate-700">Register</button>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Mobile Menu */}
      {mobileOpen && (
        <div className="fixed inset-0 z-50 lg:hidden">
          <button aria-label="Close menu" className="absolute inset-0 bg-slate-950/50 backdrop-blur-sm" onClick={() => setMobileOpen(false)} />
          <aside className="absolute right-0 top-0 h-full w-[85%] max-w-sm bg-white p-6 shadow-2xl dark:bg-[#0B1220] overflow-y-auto">
            <div className="mb-6 flex items-center justify-between pb-3 border-b border-slate-100 dark:border-slate-800">
              <div className="flex items-center gap-2">
                <span className="grid h-7 w-7 place-items-center rounded-lg bg-blue-600 text-[10px] font-black text-white">JG</span>
                <span className="font-extrabold text-sm">JobGuard AI (Demo)</span>
              </div>
              <button aria-label="Close" onClick={() => setMobileOpen(false)} className="p-1 rounded-lg">
                <X size={20} />
              </button>
            </div>
            <nav className="space-y-1">
              {[
                ["home", "🏠 Home"],
                ...navItems,
                ["screenshot", "🖼️ Screenshot Scanner"],
                ["qr", "▣ QR Code Scanner"],
                ["auth", currentUser ? "👤 Account" : "🔐 Sign in / Register"],
              ].map(([id, label]) => (
                <button
                  key={id}
                  onClick={() => navigate(id as ViewId)}
                  className={`w-full rounded-xl px-4 py-3 text-left text-sm font-bold transition ${
                    view === id
                      ? "bg-blue-50 text-blue-600 dark:bg-blue-950/40 dark:text-blue-400"
                      : "hover:bg-slate-100 dark:hover:bg-slate-800"
                  }`}
                >
                  {label}
                </button>
              ))}
            </nav>
          </aside>
        </div>
      )}

      <main id="main-content" tabIndex={-1} className="mx-auto max-w-7xl px-4 py-6 sm:px-6 sm:py-8 focus:outline-none">
        <Suspense fallback={<div role="status" aria-live="polite" className="py-12 text-center text-sm text-slate-500">Loading workspace module...</div>}>
        {view === "home" && <LandingPage onNavigate={(id) => navigate(id as ViewId)} />}
        {view === "dashboard" && (
          <Dashboard
            history={history}
            onStartVerify={() => setView("verify")}
            onOpenReport={(id) => {
              const found = historyById.get(id);
              if (found) {
                setCurrentReport(found);
                setView("report");
              }
            }}
            onExportHistory={exportHistoryJson}
            onImportReport={importReportJson}
            onClearHistory={clearHistory}
          />
        )}
        {view === "verify" && (
          <AnalysisForm
            text={text}
            secondaryText={secondaryText}
            jobUrl={jobUrl}
            onTextChange={(v) => {
              setText(v);
              setIsDemo(false);
            }}
            onSecondaryTextChange={(v) => {
              setSecondaryText(v);
              setIsDemo(false);
            }}
            onJobUrlChange={(v) => {
              setJobUrl(v);
              setIsDemo(false);
            }}
            onExtract={() => handleExtract()}
            onLoadDemo={handleLoadDemo}
            isLoading={loading}
          />
        )}
        {view === "call-guard" && <CallGuardPanel />}
        {view === "scanner" && (
          <ScannerPanel
            onSendTextToVerify={(extractedTxt, demoFlag) => {
              setText(extractedTxt);
              setIsDemo(Boolean(demoFlag));
              handleExtract(extractedTxt);
            }}
          />
        )}
        {view === "link-guardian" && <AdvancedProtectionPanel mode="guardian" />}
        {view === "payment" && <AdvancedProtectionPanel mode="payment" />}
        {view === "screenshot" && <AdvancedProtectionPanel mode="screenshot" />}
        {view === "qr" && <AdvancedProtectionPanel mode="qr" />}
        {view === "deepfake" && <AdvancedProtectionPanel mode="deepfake" />}
        {view === "assistant" && <AdvancedProtectionPanel mode="assistant" />}
        {view === "community" && <AdvancedProtectionPanel mode="community" />}
        {view === "evidence" && <AdvancedProtectionPanel mode="evidence" />}
        {view === "auth" && (
          <AuthPanel
            mode={authMode}
            onModeChange={(mode) => setAuthMode(mode)}
            onAuthenticated={(nextUser: AuthUser | null) => setUser(nextUser)}
            currentUser={currentUser}
          />
        )}
        {view === "review" && extracted && (
          <ExtractionReview
            extracted={extracted}
            edits={edits}
            onEditChange={(k, v) => setEdits((prev) => ({ ...prev, [k]: v }))}
            onConfirmVerify={handleVerify}
            onBack={() => setView("verify")}
            isVerifying={loading}
          />
        )}
        {view === "report" && currentReport && (
          <AnalysisResultView
            report={currentReport}
            onExportMarkdown={() =>
              downloadFile(exportReportToMarkdown(currentReport), `${currentReport.report_id}.md`, "text/markdown")
            }
            onExportJson={() =>
              downloadFile(JSON.stringify(currentReport, null, 2), `${currentReport.report_id}.json`, "application/json")
            }
            onNewVerification={() => setView("verify")}
          />
        )}
        {view === "learn" && <LearnAndHelpPanel mode="learn" />}
        {view === "help" && <LearnAndHelpPanel mode="help" />}
        </Suspense>
      </main>
    </div>
  );
};

export default App;
