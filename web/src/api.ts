// API types and fetch helpers. Types mirror the Go model structs.

export interface LogEvent {
  id: number;
  ts: string;
  source: string;
  event_type: string;
  username?: string;
  src_ip?: string;
  dst_host?: string;
  status?: string;
  bytes_out?: number;
  message?: string;
}

export interface Evidence {
  counts?: Record<string, number>;
  notes?: string[];
  samples?: LogEvent[];
}

export interface Triage {
  verdict: string;
  confidence: number;
  reasoning: string;
  next_steps: string[];
  model: string;
  mock: boolean;
  cached: boolean;
  at: string;
}

export interface Alert {
  id: string;
  created_at: string;
  alert_type: string;
  severity: string;
  entity: string;
  username?: string;
  src_ip?: string;
  title: string;
  status: string;
  count: number;
  window_start: string;
  window_end: string;
  evidence?: Evidence;
  triage?: Triage;
  incident_id?: string;
}

export interface Incident {
  id: string;
  created_at: string;
  entity: string;
  title: string;
  severity: string;
  status: string;
  alert_count: number;
  first_seen: string;
  last_seen: string;
  alerts?: Alert[];
}

export interface Runbook {
  alert_type: string;
  title: string;
  summary: string;
  steps: string[];
  escalate_when: string[];
}

export interface Investigation {
  hypothesis: string;
  benign_explanations: string[];
  pivot_queries: string[];
  context_events: number;
  model: string;
  mock: boolean;
}

export interface TimelinePoint {
  bucket: string;
  logs: number;
  alerts: number;
}

export interface EvalTypeScore {
  attacks: number;
  detected: number;
  recall: number;
  alerts: number;
  tp: number;
  fp: number;
  cross_tp: number;
}

export interface EvalResult {
  dataset: string;
  logs: number;
  drain_seconds: number;
  per_type: Record<string, EvalTypeScore>;
  overall: EvalTypeScore;
  type_exact_precision: number;
  operational_precision: number;
  benign_fp: number;
}

export interface Health {
  ok: boolean;
  db: boolean;
  redis: boolean;
  llm_mode: string;
  llm_model: string;
  logs: number;
}

export interface Session {
  role: "operator" | "viewer";
}

export class ApiError extends Error {
  constructor(public readonly status: number, message: string) {
    super(message);
    this.name = "ApiError";
  }
}

export const SESSION_INVALIDATED = "securitylens:session-invalidated";
const pendingRequests = new Set<AbortController>();

// A session change must discard in-flight reads as well as cached results.
export function cancelSessionRequests() {
  for (const controller of pendingRequests) controller.abort();
  pendingRequests.clear();
}

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const controller = new AbortController();
  pendingRequests.add(controller);
  const headers = new Headers(options.headers);
  if (options.method && options.method !== "GET") {
    headers.set("X-SecurityLens-Request", "1");
  }
  try {
    const res = await fetch(path, {
      ...options,
      headers,
      credentials: "same-origin",
      cache: "no-store",
      signal: controller.signal,
    });
    if (res.status === 401) {
      window.dispatchEvent(new Event(SESSION_INVALIDATED));
      throw new ApiError(401, "Your session has ended. Sign in to continue.");
    }
    if (res.status === 403) {
      throw new ApiError(403, "Your role does not allow this action.");
    }
    if (!res.ok) {
      const body = await res.text();
      throw new ApiError(res.status, `${res.status}: ${body.slice(0, 300)}`);
    }
    if (res.status === 204) return undefined as T;
    return await res.json() as T;
  } finally {
    pendingRequests.delete(controller);
  }
}

export const api = {
  session: () => request<Session>("/api/session"),
  signIn: (token: string) => request<Session>("/api/session", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ token }),
  }),
  signOut: () => request<void>("/api/session", { method: "DELETE" }),
  health: () => request<Health>("/api/health"),
  logs: async (limit = 100) => {
    const result = await request<{ logs: LogEvent[] | null }>(`/api/logs?limit=${limit}`);
    return { logs: result.logs ?? [] };
  },
  alerts: (params = "") => request<{ alerts: Alert[] }>(`/api/alerts?limit=300${params}`),
  alert: (id: string) => request<{ alert: Alert; runbook: Runbook }>(`/api/alerts/${id}`),
  triage: (id: string) => request<{ triage: Triage }>(`/api/alerts/${id}/triage`, { method: "POST" }),
  investigate: (id: string) => request<{ investigation: Investigation }>(`/api/alerts/${id}/investigate`, { method: "POST" }),
  setStatus: (id: string, status: string) => request<{ ok: boolean }>(`/api/alerts/${id}/status`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ status }),
  }),
  incidents: () => request<{ incidents: Incident[] }>("/api/incidents"),
  incident: (id: string) => request<{ incident: Incident }>(`/api/incidents/${id}`),
  timeline: async () => {
    const result = await request<{ points: TimelinePoint[] | null }>("/api/timeline");
    return { points: result.points ?? [] };
  },
  metrics: () => request<Record<string, any>>("/api/metrics"),
  evalRuns: () => request<{ runs: { id: number; ts: string; dataset: string; result: EvalResult }[] }>("/api/eval"),
  generateRule: (description: string) => request<{
    code: string; compile_ok: boolean; compiler_output: string; mock: boolean; model: string;
  }>("/api/rules/generate", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ description }),
  }),
};

export const TYPE_COLORS: Record<string, string> = {
  credential_stuffing: "var(--series-1)",
  privilege_escalation: "var(--series-6)",
  sensitive_data_exposure: "var(--series-3)",
  identity_anomaly: "var(--series-5)",
  lateral_movement: "var(--series-7)",
  off_hours_access: "var(--series-2)",
  data_exfiltration: "var(--series-4)",
};

export const SEV_COLORS: Record<string, string> = {
  critical: "var(--status-critical)",
  high: "var(--status-serious)",
  medium: "var(--status-warning)",
  low: "var(--status-good)",
};

export function fmtTime(ts: string): string {
  return new Date(ts).toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function fmtBytes(n: number): string {
  if (n >= 1e9) return (n / 1e9).toFixed(1) + " GB";
  if (n >= 1e6) return (n / 1e6).toFixed(1) + " MB";
  if (n >= 1e3) return (n / 1e3).toFixed(1) + " kB";
  return n + " B";
}
