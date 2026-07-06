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

async function j<T>(res: Response): Promise<T> {
  if (!res.ok) {
    const body = await res.text();
    throw new Error(`${res.status}: ${body.slice(0, 300)}`);
  }
  return res.json() as Promise<T>;
}

export const api = {
  health: () => fetch("/api/health").then((r) => j<Health>(r)),
  logs: (limit = 100) =>
    fetch(`/api/logs?limit=${limit}`).then((r) => j<{ logs: LogEvent[] }>(r)),
  alerts: (params = "") =>
    fetch(`/api/alerts?limit=300${params}`).then((r) => j<{ alerts: Alert[] }>(r)),
  alert: (id: string) =>
    fetch(`/api/alerts/${id}`).then((r) => j<{ alert: Alert; runbook: Runbook }>(r)),
  triage: (id: string) =>
    fetch(`/api/alerts/${id}/triage`, { method: "POST" }).then((r) =>
      j<{ triage: Triage }>(r),
    ),
  investigate: (id: string) =>
    fetch(`/api/alerts/${id}/investigate`, { method: "POST" }).then((r) =>
      j<{ investigation: Investigation }>(r),
    ),
  setStatus: (id: string, status: string) =>
    fetch(`/api/alerts/${id}/status`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ status }),
    }).then((r) => j<{ ok: boolean }>(r)),
  incidents: () =>
    fetch("/api/incidents").then((r) => j<{ incidents: Incident[] }>(r)),
  incident: (id: string) =>
    fetch(`/api/incidents/${id}`).then((r) => j<{ incident: Incident }>(r)),
  timeline: () =>
    fetch("/api/timeline").then((r) => j<{ points: TimelinePoint[] }>(r)),
  metrics: () => fetch("/api/metrics").then((r) => j<Record<string, any>>(r)),
  evalRuns: () =>
    fetch("/api/eval").then((r) =>
      j<{ runs: { id: number; ts: string; dataset: string; result: EvalResult }[] }>(r),
    ),
  generateRule: (description: string) =>
    fetch("/api/rules/generate", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ description }),
    }).then((r) =>
      j<{ code: string; compile_ok: boolean; compiler_output: string; mock: boolean; model: string }>(r),
    ),
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
