export interface AuthUser {
  id?: string;
  email?: string;
  name?: string;
  full_name?: string;
  mobile?: string;
  notifications?: boolean;
  email_verified?: boolean;
  created_at?: number;
}

import React, { useState, useEffect } from "react";
import { Eye, EyeOff, ShieldCheck, UserCheck, KeyRound, MailCheck, Settings, Trash2 } from "lucide-react";

export type AuthMode = "signin" | "register" | "forgot" | "reset" | "verify_email" | "profile" | "settings";

interface Props {
  mode: AuthMode;
  onModeChange: (mode: AuthMode) => void;
  onAuthenticated: (user: AuthUser | null) => void;
  currentUser?: AuthUser | null;
}

export const AuthPanel: React.FC<Props> = ({ mode, onModeChange, onAuthenticated, currentUser }) => {
  const [fullName, setFullName] = useState(currentUser?.full_name || "");
  const [email, setEmail] = useState(currentUser?.email || "");
  const [mobile, setMobile] = useState(currentUser?.mobile || "");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [token, setToken] = useState("");
  const [notifications, setNotifications] = useState(currentUser?.notifications ?? true);
  const [terms, setTerms] = useState(false);
  const [remember, setRemember] = useState(true);
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");

  useEffect(() => {
    if (currentUser) {
      setFullName(currentUser.full_name || "");
      setEmail(currentUser.email || "");
      setMobile(currentUser.mobile || "");
      setNotifications(currentUser.notifications ?? true);
    }
  }, [currentUser]);

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const linkToken = params.get("reset_password") || params.get("verify_email");
    if (linkToken) setToken(linkToken);
  }, []);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setMessage("");

    if (mode === "register" && password !== confirmPassword) {
      setError("Passwords do not match.");
      return;
    }

    setLoading(true);
    try {
      if (mode === "signin" || mode === "register" || mode === "forgot") {
        const endpoint =
          mode === "register" ? "/api/auth/register" :
          mode === "forgot" ? "/api/auth/forgot-password" : "/api/auth/login";
        const body = mode === "forgot" ? { email } :
          mode === "register" ? { full_name: fullName, email, mobile, password, terms_accepted: terms } :
          { email, password, remember_me: remember };
        const response = await fetch(endpoint, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(body),
          credentials: "include",
        });
        const data = await response.json();
        if (!response.ok) throw new Error(data.detail || "Request failed.");
        if (mode === "forgot") {
          setMessage(data.message || "If your account is eligible, reset instructions have been requested.");
        } else if (mode === "register") {
          setMessage("Account created successfully!");
          onAuthenticated(data.user);
        } else {
          onAuthenticated(data.user);
        }
      } else if (mode === "reset") {
        if (newPassword !== confirmPassword) {
          setError("New passwords do not match.");
          setLoading(false);
          return;
        }
        const res = await fetch("/api/auth/reset-password", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ token: token.trim(), new_password: newPassword }),
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || "Password reset failed.");
        setMessage("Password reset successfully! You can now sign in with your new password.");
        setTimeout(() => onModeChange("signin"), 1500);
      } else if (mode === "verify_email") {
        const res = await fetch("/api/auth/verify-email", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ token: token.trim() }),
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || "Email verification failed.");
        setMessage("Email address verified successfully!");
      } else if (mode === "profile") {
        const res = await fetch("/api/auth/profile", {
          method: "PATCH",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ full_name: fullName, mobile, notifications }),
          credentials: "include",
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || "Profile update failed.");
        setMessage("Profile updated successfully!");
        onAuthenticated(data.user);
      } else if (mode === "settings") {
        if (!currentPassword || !newPassword) {
          setError("Please provide current and new password.");
          setLoading(false);
          return;
        }
        const res = await fetch("/api/auth/password", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ current_password: currentPassword, new_password: newPassword }),
          credentials: "include",
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || "Failed to update password.");
        setMessage("Password changed successfully!");
        setCurrentPassword("");
        setNewPassword("");
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to complete the request.");
    } finally {
      setLoading(false);
    }
  };

  const handleDeleteAccount = async () => {
    if (!window.confirm("Are you sure you want to permanently delete your account and all saved data? This action cannot be undone.")) return;
    setLoading(true);
    try {
      const res = await fetch("/api/auth/account", { method: "DELETE", credentials: "include" });
      if (res.ok) {
        onAuthenticated(null);
        onModeChange("signin");
      }
    } catch {
      setError("Failed to delete account.");
    } finally {
      setLoading(false);
    }
  };

  const title = {
    signin: "Welcome back",
    register: "Create your account",
    forgot: "Reset your password",
    reset: "Confirm new password",
    verify_email: "Verify your email",
    profile: "User profile & preferences",
    settings: "Account security settings",
  }[mode];

  const icon = {
    signin: <ShieldCheck size={22} />,
    register: <ShieldCheck size={22} />,
    forgot: <KeyRound size={22} />,
    reset: <KeyRound size={22} />,
    verify_email: <MailCheck size={22} />,
    profile: <UserCheck size={22} />,
    settings: <Settings size={22} />,
  }[mode];

  return (
    <div className="mx-auto max-w-md">
      <form onSubmit={submit} className="rounded-3xl border border-slate-200 bg-white p-6 shadow-xl shadow-slate-200/40 dark:border-slate-800 dark:bg-[#111C32] dark:shadow-none sm:p-8">
        <div className="mb-6 flex items-center justify-between">
          <div className="grid h-11 w-11 place-items-center rounded-xl bg-blue-600 text-white shadow-md shadow-blue-600/20">{icon}</div>
          <div className="flex gap-1.5 text-xs font-bold">
            {currentUser && (
              <>
                <button type="button" onClick={() => onModeChange("profile")} className={`px-2.5 py-1 rounded-lg ${mode === "profile" ? "bg-blue-600 text-white" : "text-slate-600 dark:text-slate-300"}`}>Profile</button>
                <button type="button" onClick={() => onModeChange("settings")} className={`px-2.5 py-1 rounded-lg ${mode === "settings" ? "bg-blue-600 text-white" : "text-slate-600 dark:text-slate-300"}`}>Settings</button>
              </>
            )}
          </div>
        </div>
        <h1 className="text-2xl font-extrabold">{title}</h1>
        <p className="mt-2 text-sm text-slate-500">
          {mode === "register" ? "Protect your account and save scam reports to your personal evidence locker." :
           mode === "forgot" ? "Enter your registered email address to receive secure reset instructions." :
           mode === "reset" ? "Enter your reset token and your new strong password." :
           mode === "verify_email" ? "Enter your email verification token to confirm account ownership." :
           mode === "profile" ? "Update your personal details and security alert notifications." :
           mode === "settings" ? "Manage your password and permanent account deletion." :
           "Sign in to access your saved verification reports and security dashboard."}
        </p>

        {error && <div role="alert" className="mt-5 rounded-xl border border-rose-200 bg-rose-50 p-3 text-xs text-rose-700 dark:border-rose-900 dark:bg-rose-950/30">{error}</div>}
        {message && <div role="status" className="mt-5 rounded-xl border border-emerald-200 bg-emerald-50 p-3 text-xs text-emerald-700 dark:border-emerald-900 dark:bg-emerald-950/30">{message}</div>}

        <div className="mt-6 space-y-4">
          {(mode === "register" || mode === "profile") && (
            <>
              <label className="block text-xs font-bold">Full name
                <input value={fullName} onChange={(e) => setFullName(e.target.value)} required className="mt-1.5 w-full rounded-xl border border-slate-200 px-3.5 py-3 text-sm dark:border-slate-700 dark:bg-slate-900 focus-visible:ring-2 focus-visible:ring-blue-500" />
              </label>
              <label className="block text-xs font-bold">Mobile number <span className="font-normal text-slate-400">(optional)</span>
                <input value={mobile} onChange={(e) => setMobile(e.target.value)} className="mt-1.5 w-full rounded-xl border border-slate-200 px-3.5 py-3 text-sm dark:border-slate-700 dark:bg-slate-900 focus-visible:ring-2 focus-visible:ring-blue-500" />
              </label>
            </>
          )}

          {mode === "profile" && (
            <label className="flex items-center gap-2 text-xs font-bold text-slate-700 dark:text-slate-300">
              <input type="checkbox" checked={notifications} onChange={(e) => setNotifications(e.target.checked)} className="rounded" />
              <span>Receive security alerts and suspicious recruitment warnings</span>
            </label>
          )}

          {(mode === "signin" || mode === "register" || mode === "forgot") && (
            <label className="block text-xs font-bold">Email address
              <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} required autoComplete="email" className="mt-1.5 w-full rounded-xl border border-slate-200 px-3.5 py-3 text-sm dark:border-slate-700 dark:bg-slate-900 focus-visible:ring-2 focus-visible:ring-blue-500" />
            </label>
          )}

          {(mode === "reset" || mode === "verify_email") && (
            <label className="block text-xs font-bold">Security Token
              <input value={token} onChange={(e) => setToken(e.target.value)} placeholder="Paste verification or reset token..." required className="mt-1.5 w-full rounded-xl border border-slate-200 px-3.5 py-3 text-sm font-mono dark:border-slate-700 dark:bg-slate-900 focus-visible:ring-2 focus-visible:ring-blue-500" />
            </label>
          )}

          {(mode === "signin" || mode === "register") && (
            <label className="block text-xs font-bold">Password
              <div className="mt-1.5 flex rounded-xl border border-slate-200 dark:border-slate-700 focus-within:ring-2 focus-within:ring-blue-500">
                <input type={showPassword ? "text" : "password"} value={password} onChange={(e) => setPassword(e.target.value)} required minLength={mode === "register" ? 10 : 1} autoComplete={mode === "register" ? "new-password" : "current-password"} className="min-w-0 flex-1 rounded-l-xl px-3.5 py-3 text-sm dark:bg-slate-900 outline-none" />
                <button type="button" aria-label={showPassword ? "Hide password" : "Show password"} onClick={() => setShowPassword((v) => !v)} className="px-3 text-slate-400 hover:text-slate-600">{showPassword ? <EyeOff size={16} /> : <Eye size={16} />}</button>
              </div>
            </label>
          )}

          {mode === "settings" && (
            <>
              <label className="block text-xs font-bold">Current Password
                <input type="password" value={currentPassword} onChange={(e) => setCurrentPassword(e.target.value)} required className="mt-1.5 w-full rounded-xl border border-slate-200 px-3.5 py-3 text-sm dark:border-slate-700 dark:bg-slate-900 focus-visible:ring-2 focus-visible:ring-blue-500" />
              </label>
              <label className="block text-xs font-bold">New Password (min 10 characters, mixed case & numbers)
                <input type="password" value={newPassword} onChange={(e) => setNewPassword(e.target.value)} required minLength={10} className="mt-1.5 w-full rounded-xl border border-slate-200 px-3.5 py-3 text-sm dark:border-slate-700 dark:bg-slate-900 focus-visible:ring-2 focus-visible:ring-blue-500" />
              </label>
            </>
          )}

          {mode === "reset" && (
            <>
              <label className="block text-xs font-bold">New Password (min 10 characters, mixed case & numbers)
                <input type="password" value={newPassword} onChange={(e) => setNewPassword(e.target.value)} required minLength={10} className="mt-1.5 w-full rounded-xl border border-slate-200 px-3.5 py-3 text-sm dark:border-slate-700 dark:bg-slate-900 focus-visible:ring-2 focus-visible:ring-blue-500" />
              </label>
              <label className="block text-xs font-bold">Confirm New Password
                <input type="password" value={confirmPassword} onChange={(e) => setConfirmPassword(e.target.value)} required minLength={10} className="mt-1.5 w-full rounded-xl border border-slate-200 px-3.5 py-3 text-sm dark:border-slate-700 dark:bg-slate-900 focus-visible:ring-2 focus-visible:ring-blue-500" />
              </label>
            </>
          )}

          {mode === "register" && (
            <>
              <label className="block text-xs font-bold">Confirm password
                <input type={showPassword ? "text" : "password"} value={confirmPassword} onChange={(e) => setConfirmPassword(e.target.value)} required minLength={10} className="mt-1.5 w-full rounded-xl border border-slate-200 px-3.5 py-3 text-sm dark:border-slate-700 dark:bg-slate-900 focus-visible:ring-2 focus-visible:ring-blue-500" />
              </label>
              <label className="flex items-start gap-2 text-xs text-slate-600 dark:text-slate-300">
                <input type="checkbox" checked={terms} onChange={(e) => setTerms(e.target.checked)} required className="mt-0.5 rounded" />
                <span>I accept the Terms and Privacy Policy (zero data selling, local PII protection).</span>
              </label>
            </>
          )}

          {mode === "signin" && (
            <div className="flex items-center justify-between text-xs">
              <label className="flex items-center gap-2">
                <input type="checkbox" checked={remember} onChange={(e) => setRemember(e.target.checked)} className="rounded" />
                <span>Remember me</span>
              </label>
              <button type="button" onClick={() => onModeChange("forgot")} className="font-bold text-blue-600 hover:underline">Forgot password?</button>
            </div>
          )}
        </div>

        <button disabled={loading} className="mt-6 w-full rounded-xl bg-blue-600 py-3 text-sm font-bold text-white shadow-lg shadow-blue-600/20 hover:bg-blue-500 disabled:opacity-50 transition focus-visible:ring-2 focus-visible:ring-blue-500">
          {loading ? "Please wait..." :
           mode === "register" ? "Create account" :
           mode === "forgot" ? "Send reset instructions" :
           mode === "reset" ? "Reset password" :
           mode === "verify_email" ? "Verify email address" :
           mode === "profile" ? "Save profile changes" :
           mode === "settings" ? "Update password" : "Sign in"}
        </button>

        {mode === "settings" && (
          <div className="mt-6 pt-5 border-t border-slate-200 dark:border-slate-800">
            <h3 className="text-xs font-bold text-rose-600 dark:text-rose-400">Danger Zone</h3>
            <p className="mt-1 text-[11px] text-slate-500">Permanently delete your account and all stored evidence.</p>
            <button type="button" onClick={handleDeleteAccount} className="mt-3 flex items-center gap-2 rounded-xl border border-rose-300 bg-rose-50 px-3.5 py-2 text-xs font-bold text-rose-700 hover:bg-rose-100 dark:border-rose-900 dark:bg-rose-950/40 dark:text-rose-300 transition">
              <Trash2 size={14} /> Delete account permanently
            </button>
          </div>
        )}

        <div className="mt-5 flex flex-wrap items-center justify-center gap-3 text-center text-xs text-slate-500">
          {mode === "signin" ? (
            <>
              <span>New to JobGuard?</span>
              <button type="button" onClick={() => onModeChange("register")} className="font-bold text-blue-600 hover:underline">Create account</button>
              <span>•</span>
              <button type="button" onClick={() => onModeChange("verify_email")} className="font-bold text-slate-600 dark:text-slate-400 hover:underline">Verify email</button>
            </>
          ) : mode === "profile" || mode === "settings" ? null : (
            <>
              <button type="button" onClick={() => onModeChange("signin")} className="font-bold text-blue-600 hover:underline">Back to sign in</button>
              <span>•</span>
              <button type="button" onClick={() => onModeChange("reset")} className="font-bold text-slate-600 dark:text-slate-400 hover:underline">Have a reset token?</button>
            </>
          )}
        </div>
      </form>
    </div>
  );
};
