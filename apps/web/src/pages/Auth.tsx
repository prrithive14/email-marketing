import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Eye, EyeOff } from "lucide-react";
import { useEffect, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { api, ApiError } from "../api";
import { GoogleMark, MicrosoftMark } from "../marks";
import { Logo } from "../Shell";
import { cx } from "../ui";

export function AuthPage({ mode }: { mode: "login" | "signup" }) {
  const [form, setForm] = useState({ name: "", company: "", email: "", password: "", confirm: "" });
  // A failed Google/Microsoft login comes back to this page as ?error=…
  const [params] = useSearchParams();
  const [error, setError] = useState<string | null>(params.get("error"));
  // Only providers the server is configured for are offered, so every button leads somewhere.
  const providers = useQuery({ queryKey: ["auth-providers"], queryFn: () => api<{ google: boolean; microsoft: boolean }>("/v1/auth/providers"), staleTime: 60_000 });
  const [busy, setBusy] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  // After the details are accepted, a 6-digit code is emailed and must be entered before the account exists.
  const [codeFor, setCodeFor] = useState<string | null>(null);
  const [code, setCode] = useState("");
  const [cooldown, setCooldown] = useState(0);
  useEffect(() => {
    if (cooldown <= 0) return;
    const t = setTimeout(() => setCooldown((c) => c - 1), 1000);
    return () => clearTimeout(t);
  }, [cooldown]);
  const nav = useNavigate();
  const qc = useQueryClient();

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      if (mode === "signup") {
        if (form.password !== form.confirm) { setError("The two passwords do not match."); return; }
        await api("/v1/auth/signup", { body: { name: form.name, email: form.email, password: form.password, confirmPassword: form.confirm, company: form.company || undefined } });
        await qc.invalidateQueries({ queryKey: ["me"] });
        nav("/");
        return;
      }
      await api("/v1/auth/login", { body: { email: form.email, password: form.password } });
      await qc.invalidateQueries({ queryKey: ["me"] });
      nav("/");
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Something went wrong");
    } finally {
      setBusy(false);
    }
  };

  const verify = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!codeFor) return;
    setError(null);
    setBusy(true);
    try {
      await api("/v1/auth/signup/verify", { body: { email: codeFor, code } });
      await qc.invalidateQueries({ queryKey: ["me"] });
      nav("/");
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Something went wrong");
    } finally {
      setBusy(false);
    }
  };
  const resend = async () => {
    if (!codeFor || cooldown > 0) return;
    setError(null);
    try {
      await api("/v1/auth/signup/resend", { body: { email: codeFor } });
      setCode("");
      setCooldown(30);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Something went wrong");
    }
  };

  const set = (k: keyof typeof form) => (e: React.ChangeEvent<HTMLInputElement>) => setForm({ ...form, [k]: e.target.value });

  return (
    <div className="min-h-full flex">
      <div className="flex flex-1 flex-col justify-center px-4 py-12 sm:px-12">
        <div className="w-full max-w-sm mx-auto">
          <Logo />
          {codeFor ? (
            <>
              <h1 className="text-2xl font-semibold text-ink-900 mt-8">Verify your email</h1>
              <p className="text-sm text-ink-500 mt-1">We sent a 6-digit code to <b className="text-ink-800">{codeFor}</b>. Enter it below to finish creating your account. It expires in 10 minutes.</p>
              <form onSubmit={verify} className="mt-8 space-y-4">
                <div>
                  <label className="label" htmlFor="auth-code">Verification code</label>
                  <input id="auth-code" className="input !h-12 text-center text-2xl tracking-[0.5em] font-semibold" inputMode="numeric" autoComplete="one-time-code" maxLength={6} autoFocus
                    placeholder="••••••" value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, "").slice(0, 6))} />
                </div>
                {error && <div className="rounded-lg bg-red-50 text-red-700 text-sm px-3 py-2">{error}</div>}
                <button className="btn-primary w-full h-10" disabled={busy || code.length !== 6}>{busy ? "Verifying…" : "Verify and create account"}</button>
              </form>
              <div className="mt-5 flex items-center justify-between text-sm">
                <button className="text-brand-700 font-medium disabled:text-ink-400" disabled={cooldown > 0} onClick={resend}>{cooldown > 0 ? `Resend code in ${cooldown}s` : "Resend code"}</button>
                <button className="text-ink-500 hover:text-ink-800" onClick={() => { setCodeFor(null); setCode(""); setError(null); }}>Change email</button>
              </div>
            </>
          ) : (
          <>
          <h1 className="text-2xl font-semibold text-ink-900 mt-8">{mode === "login" ? "Log in to your account" : "Create your account"}</h1>
          <p className="text-sm text-ink-500 mt-1">{mode === "login" ? "Welcome back." : "Start sending cold email that lands in the inbox."}</p>
          <form onSubmit={submit} className="mt-8 space-y-4">
            {mode === "signup" && (
              <>
                <div><label className="label">Full name</label><input className="input" value={form.name} onChange={set("name")} required autoFocus /></div>
                <div><label className="label">Company <span className="text-ink-400 font-normal">(optional)</span></label><input className="input" value={form.company} onChange={set("company")} /></div>
              </>
            )}
            <div><label className="label">Username</label><input className="input" type="text" autoComplete="username" value={form.email} onChange={set("email")} required autoFocus={mode === "login"} /></div>
            <div>
              <label className="label" htmlFor="auth-password">Password</label>
              <div className="relative">
                <input id="auth-password" className="input pr-11" type={showPassword ? "text" : "password"} value={form.password} onChange={set("password")} required minLength={mode === "signup" ? 8 : 1}
                  autoComplete={mode === "signup" ? "new-password" : "current-password"} />
                <button type="button" className="absolute right-1.5 top-1/2 -translate-y-1/2 grid place-items-center w-8 h-8 rounded-md text-ink-500 hover:bg-ink-100 hover:text-ink-800"
                  aria-label={showPassword ? "Hide password" : "Show password"} aria-pressed={showPassword} title={showPassword ? "Hide password" : "Show password"}
                  onClick={() => setShowPassword((s) => !s)}>
                  {showPassword ? <EyeOff size={17} /> : <Eye size={17} />}
                </button>
              </div>
            </div>
            {mode === "signup" && (
              <div>
                <label className="label" htmlFor="auth-confirm">Confirm password</label>
                <input id="auth-confirm" className={cx("input", form.confirm && form.confirm !== form.password && "border-red-500")} type={showPassword ? "text" : "password"} value={form.confirm} onChange={set("confirm")} required autoComplete="new-password" />
                {form.confirm && (form.confirm === form.password
                  ? <p className="text-xs text-emerald-700 mt-1">Passwords match</p>
                  : <p className="text-xs text-red-600 mt-1">Passwords do not match</p>)}
              </div>
            )}
            {error && <div className="rounded-lg bg-red-50 text-red-700 text-sm px-3 py-2">{error}</div>}
            <button className="btn-primary w-full h-10" disabled={busy || (mode === "signup" && form.password !== form.confirm)}>{busy ? "Please wait…" : mode === "login" ? "Log in" : "Create account"}</button>
          </form>
          {(providers.data?.google || providers.data?.microsoft) && (
            <>
              <div className="flex items-center gap-3 my-6 text-xs text-ink-400"><span className="h-px flex-1 bg-ink-200" />or<span className="h-px flex-1 bg-ink-200" /></div>
              <div className="space-y-3">
                {providers.data.google && <a className="btn-secondary w-full h-10" href="/v1/auth/oauth/google/start"><GoogleMark /> Continue with Google</a>}
                {providers.data.microsoft && <a className="btn-secondary w-full h-10" href="/v1/auth/oauth/microsoft/start"><MicrosoftMark /> Continue with Microsoft</a>}
              </div>
            </>
          )}
          <p className="text-sm text-ink-500 mt-6 text-center">
            {mode === "login" ? <>Don't have an account? <Link className="text-brand-700 font-medium" to="/signup">Sign up</Link></> : <>Already have an account? <Link className="text-brand-700 font-medium" to="/login">Log in</Link></>}
          </p>
          </>
          )}
        </div>
      </div>
    </div>
  );
}
