import { useEffect, useRef, useState, type FormEvent } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiError, cancelSessionRequests, SESSION_INVALIDATED, type Session } from "./api";
import { MockTag, Spinner } from "./bits";
import Overview from "./pages/Overview";
import Alerts from "./pages/Alerts";
import Incidents from "./pages/Incidents";
import Hunt from "./pages/Hunt";
import Metrics from "./pages/Metrics";

const TABS = ["Overview", "Alerts", "Incidents", "Hunt", "Metrics"] as const;
type Tab = (typeof TABS)[number];

function Dashboard({ session, onSignOut }: { session: Session; onSignOut: () => void }) {
  const [tab, setTab] = useState<Tab>("Overview");
  const health = useQuery({ queryKey: ["health"], queryFn: api.health });

  return (
    <div className="mx-auto min-h-screen max-w-7xl px-4 pb-16">
      <header className="flex flex-wrap items-center justify-between gap-3 py-4">
        <div className="flex items-center gap-3">
          <span className="text-xl font-semibold tracking-tight">
            <span style={{ color: "var(--series-1)" }}>Security</span>Lens
          </span>
          <span className="text-xs" style={{ color: "var(--ink-muted)" }}>
            detection · triage · correlation · hunt
          </span>
        </div>
        <div className="flex flex-wrap items-center gap-3 text-xs" style={{ color: "var(--ink-2)" }}>
          <span className="rounded border px-2 py-1" style={{ borderColor: "var(--ring)" }}>
            {session.role}
          </span>
          <button onClick={onSignOut} className="rounded border px-2 py-1" style={{ borderColor: "var(--ring)" }}>
            Sign out
          </button>
          {health.data && (
            <>
              <span className="tabular">{health.data.logs.toLocaleString()} logs</span>
              <span
                className="inline-flex items-center gap-1.5"
                style={{ color: health.data.ok ? "var(--status-good)" : "var(--status-critical)" }}
              >
                ● {health.data.ok ? "healthy" : "degraded"}
              </span>
              <MockTag mock={health.data.llm_mode !== "live"} model={health.data.llm_model} />
            </>
          )}
        </div>
      </header>

      {session.role === "viewer" && (
        <p className="mb-4 text-sm" style={{ color: "var(--ink-2)" }}>
          Read-only access. An operator can change alert status, run AI analysis, and generate rule drafts.
        </p>
      )}
      <nav className="mb-6 flex gap-1 overflow-x-auto border-b" style={{ borderColor: "var(--ring)" }}>
        {TABS.map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className="px-4 py-2 text-sm"
            style={{
              color: tab === t ? "var(--ink)" : "var(--ink-muted)",
              borderBottom: tab === t ? "2px solid var(--series-1)" : "2px solid transparent",
            }}
          >
            {t}
          </button>
        ))}
      </nav>

      {tab === "Overview" && <Overview />}
      {tab === "Alerts" && <Alerts canOperate={session.role === "operator"} />}
      {tab === "Incidents" && <Incidents />}
      {tab === "Hunt" && <Hunt canOperate={session.role === "operator"} />}
      {tab === "Metrics" && <Metrics />}
    </div>
  );
}

type AuthState =
  | { status: "checking" | "anonymous" | "unavailable" | "signing-out" | "signout-error" }
  | { status: "authenticated"; session: Session };

function SignIn({ onSignIn }: { onSignIn: (session: Session) => void }) {
  const [token, setToken] = useState("");
  const [pending, setPending] = useState(false);
  const [error, setError] = useState("");

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!token.trim() || pending) return;
    setPending(true);
    setError("");
    const signIn = api.signIn(token.trim());
    setToken("");
    try {
      onSignIn(await signIn);
    } catch (err) {
      // Never show a server response that might echo a submitted credential.
      setError(err instanceof ApiError && err.status === 401
        ? "The access token was not accepted. Try again."
        : "Unable to sign in. Check the connection and try again.");
    } finally {
      setPending(false);
    }
  }

  return (
    <form onSubmit={submit} className="card w-full max-w-md p-6" aria-labelledby="sign-in-title">
      <h1 id="sign-in-title" className="text-xl font-semibold">
        <span style={{ color: "var(--series-1)" }}>Security</span>Lens
      </h1>
      <p className="mt-2 text-sm" style={{ color: "var(--ink-2)" }}>Sign in to your private pilot.</p>
      <label htmlFor="access-token" className="mt-6 block text-sm font-medium">Access token</label>
      <input
        id="access-token"
        name="access-token"
        type="password"
        autoComplete="off"
        autoCapitalize="none"
        spellCheck={false}
        value={token}
        onChange={(event) => setToken(event.target.value)}
        disabled={pending}
        required
        aria-describedby="token-help sign-in-error"
        className="mt-2 w-full rounded border bg-transparent p-3 text-sm focus:outline-2 focus:outline-offset-2"
        style={{ borderColor: "var(--ring)" }}
      />
      <p id="token-help" className="mt-2 text-xs" style={{ color: "var(--ink-muted)" }}>
        Use the pilot access token provided by your administrator.
      </p>
      <p id="sign-in-error" role="alert" className="mt-3 text-sm" style={{ color: "var(--status-serious)" }}>{error}</p>
      <button
        type="submit"
        disabled={pending || !token.trim()}
        className="mt-3 w-full rounded px-4 py-2 text-sm font-medium disabled:opacity-50"
        style={{ background: "var(--series-1)", color: "#fff" }}
      >
        {pending ? "Signing in…" : "Sign in"}
      </button>
    </form>
  );
}

export default function App() {
  const qc = useQueryClient();
  const [auth, setAuth] = useState<AuthState>({ status: "checking" });
  const generation = useRef(0);

  function clearSession() {
    generation.current++;
    cancelSessionRequests();
    void qc.cancelQueries();
    qc.clear();
  }

  async function checkSession() {
    const current = ++generation.current;
    setAuth({ status: "checking" });
    try {
      const session = await api.session();
      if (current === generation.current) setAuth({ status: "authenticated", session });
    } catch (err) {
      if (current === generation.current) {
        setAuth({ status: err instanceof ApiError && err.status === 401 ? "anonymous" : "unavailable" });
      }
    }
  }

  useEffect(() => {
    const invalidate = () => {
      clearSession();
      setAuth({ status: "anonymous" });
    };
    window.addEventListener(SESSION_INVALIDATED, invalidate);
    void checkSession();
    return () => {
      window.removeEventListener(SESSION_INVALIDATED, invalidate);
      clearSession();
    };
  }, [qc]);

  async function signOut() {
    clearSession();
    setAuth({ status: "signing-out" });
    try {
      await api.signOut();
      setAuth({ status: "anonymous" });
    } catch (err) {
      setAuth({ status: err instanceof ApiError && err.status === 401 ? "anonymous" : "signout-error" });
    }
  }

  if (auth.status === "authenticated") {
    return <Dashboard session={auth.session} onSignOut={() => void signOut()} />;
  }

  return (
    <main className="flex min-h-screen items-center justify-center px-4 py-8">
      {auth.status === "anonymous" ? (
        <SignIn onSignIn={(session) => {
          clearSession();
          setAuth({ status: "authenticated", session });
        }} />
      ) : (
        <div className="card w-full max-w-md p-6 text-center" role="status">
          {auth.status === "checking" || auth.status === "signing-out" ? (
            <p className="flex items-center justify-center gap-3 text-sm">
              <Spinner /> {auth.status === "checking" ? "Checking your session…" : "Signing out…"}
            </p>
          ) : (
            <>
              <p className="text-sm" style={{ color: "var(--ink-2)" }}>
                {auth.status === "signout-error"
                  ? "Sign-out could not be confirmed. Your session may still be active. Retry to end it."
                  : "Unable to check your session. Check the connection and try again."}
              </p>
              <button
                onClick={() => void (auth.status === "signout-error" ? signOut() : checkSession())}
                className="mt-4 rounded px-4 py-2 text-sm font-medium"
                style={{ background: "var(--series-1)", color: "#fff" }}
              >Retry</button>
            </>
          )}
        </div>
      )}
    </main>
  );
}
