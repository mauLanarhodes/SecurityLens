import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, fmtTime, type Investigation } from "../api";
import { Empty, MockTag, SevBadge, Spinner, TypeChip } from "../bits";

function AlertDetail({ id, onClose }: { id: string; onClose: () => void }) {
  const qc = useQueryClient();
  const detail = useQuery({ queryKey: ["alert", id], queryFn: () => api.alert(id) });
  const [inv, setInv] = useState<Investigation | null>(null);

  const triage = useMutation({
    mutationFn: () => api.triage(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["alert", id] });
      qc.invalidateQueries({ queryKey: ["alerts"] });
    },
  });
  const investigate = useMutation({
    mutationFn: () => api.investigate(id),
    onSuccess: (d) => setInv(d.investigation),
  });
  const setStatus = useMutation({
    mutationFn: (status: string) => api.setStatus(id, status),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["alert", id] });
      qc.invalidateQueries({ queryKey: ["alerts"] });
    },
  });

  if (!detail.data) return <div className="card p-8 text-center"><Spinner /></div>;
  const { alert: a, runbook: rb } = detail.data;

  return (
    <div className="card max-h-[80vh] overflow-y-auto p-5">
      <div className="flex items-start justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <SevBadge sev={a.severity} />
            <TypeChip type={a.alert_type} />
            <span className="text-xs" style={{ color: "var(--ink-muted)" }}>{a.status}</span>
          </div>
          <h2 className="mt-2 text-lg font-semibold">{a.title}</h2>
          <div className="mt-1 text-xs" style={{ color: "var(--ink-2)" }}>
            entity <b>{a.entity}</b> · window {fmtTime(a.window_start)} → {fmtTime(a.window_end)} · merged firings ×{a.count}
          </div>
        </div>
        <button onClick={onClose} className="text-sm" style={{ color: "var(--ink-muted)" }}>✕ close</button>
      </div>

      <div className="mt-4 flex flex-wrap gap-2">
        <button
          onClick={() => triage.mutate()}
          disabled={triage.isPending}
          className="rounded px-3 py-1.5 text-sm font-medium"
          style={{ background: "var(--series-1)", color: "#fff" }}
        >
          {triage.isPending ? "triaging…" : a.triage ? "re-run LLM triage" : "run LLM triage"}
        </button>
        <button
          onClick={() => investigate.mutate()}
          disabled={investigate.isPending}
          className="rounded px-3 py-1.5 text-sm font-medium"
          style={{ background: "var(--series-5)", color: "#fff" }}
        >
          {investigate.isPending ? "investigating…" : "investigate"}
        </button>
        {["acknowledged", "resolved", "dismissed"].map((s) => (
          <button
            key={s}
            onClick={() => setStatus.mutate(s)}
            className="rounded border px-3 py-1.5 text-sm"
            style={{ borderColor: "var(--ring)", color: "var(--ink-2)" }}
          >
            {s === "dismissed" ? "dismiss (FP)" : s}
          </button>
        ))}
      </div>

      {(triage.error || investigate.error) && (
        <div className="mt-3 text-sm" style={{ color: "var(--status-critical)" }}>
          {String(triage.error ?? investigate.error)}
        </div>
      )}

      {a.triage && (
        <section className="mt-5">
          <div className="mb-1 flex items-center gap-2 text-sm font-medium">
            LLM triage <MockTag mock={a.triage.mock} model={a.triage.model} />
            {a.triage.cached && <span className="text-[10px]" style={{ color: "var(--ink-muted)" }}>cached</span>}
          </div>
          <div className="rounded border p-3 text-sm" style={{ borderColor: "var(--ring)" }}>
            <div className="flex items-center gap-3">
              <span
                className="font-semibold"
                style={{
                  color:
                    a.triage.verdict === "likely_true_positive"
                      ? "var(--status-critical)"
                      : a.triage.verdict === "likely_false_positive"
                        ? "var(--status-good)"
                        : "var(--status-warning)",
                }}
              >
                {a.triage.verdict.replaceAll("_", " ")}
              </span>
              <span className="tabular text-xs" style={{ color: "var(--ink-2)" }}>
                confidence {(a.triage.confidence * 100).toFixed(0)}%
              </span>
            </div>
            <p className="mt-2" style={{ color: "var(--ink-2)" }}>{a.triage.reasoning}</p>
            <ul className="mt-2 list-inside list-decimal text-sm" style={{ color: "var(--ink-2)" }}>
              {a.triage.next_steps?.map((s, i) => <li key={i}>{s}</li>)}
            </ul>
          </div>
        </section>
      )}

      {inv && (
        <section className="mt-5">
          <div className="mb-1 flex items-center gap-2 text-sm font-medium">
            Investigation <MockTag mock={inv.mock} model={inv.model} />
            <span className="text-[10px]" style={{ color: "var(--ink-muted)" }}>
              over {inv.context_events} surrounding events
            </span>
          </div>
          <div className="rounded border p-3 text-sm" style={{ borderColor: "var(--ring)" }}>
            <div className="font-medium">Hypothesis</div>
            <p style={{ color: "var(--ink-2)" }}>{inv.hypothesis}</p>
            <div className="mt-2 font-medium">Benign explanations to rule out</div>
            <ul className="list-inside list-disc" style={{ color: "var(--ink-2)" }}>
              {inv.benign_explanations?.map((b, i) => <li key={i}>{b}</li>)}
            </ul>
            <div className="mt-2 font-medium">Pivot queries</div>
            {inv.pivot_queries?.map((q, i) => (
              <pre key={i} className="mt-1 overflow-x-auto rounded p-2 font-mono text-xs" style={{ background: "var(--page)" }}>{q}</pre>
            ))}
          </div>
        </section>
      )}

      <section className="mt-5">
        <div className="mb-1 text-sm font-medium">Evidence</div>
        <div className="rounded border p-3 text-sm" style={{ borderColor: "var(--ring)" }}>
          {a.evidence?.counts && (
            <div className="flex flex-wrap gap-4">
              {Object.entries(a.evidence.counts).map(([k, v]) => (
                <div key={k}>
                  <span className="tabular text-base font-semibold">{v.toLocaleString()}</span>{" "}
                  <span className="text-xs" style={{ color: "var(--ink-muted)" }}>{k.replaceAll("_", " ")}</span>
                </div>
              ))}
            </div>
          )}
          {a.evidence?.notes?.map((n, i) => (
            <p key={i} className="mt-2 text-xs" style={{ color: "var(--ink-2)" }}>▸ {n}</p>
          ))}
          {a.evidence?.samples && (
            <div className="mt-2 overflow-x-auto">
              <table className="w-full text-left font-mono text-[11px]">
                <tbody>
                  {a.evidence.samples.map((s, i) => (
                    <tr key={i} style={{ color: "var(--ink-2)" }}>
                      <td className="pr-3" style={{ color: "var(--ink-muted)" }}>{fmtTime(s.ts)}</td>
                      <td className="pr-3">{s.event_type}</td>
                      <td className="pr-3">{s.username}</td>
                      <td className="pr-3">{s.src_ip}{s.dst_host ? `→${s.dst_host}` : ""}</td>
                      <td className="max-w-[280px] truncate">{s.message}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </section>

      {rb?.title && (
        <section className="mt-5">
          <div className="mb-1 text-sm font-medium">Runbook — {rb.title}</div>
          <div className="rounded border p-3 text-sm" style={{ borderColor: "var(--ring)" }}>
            <p className="text-xs" style={{ color: "var(--ink-muted)" }}>{rb.summary}</p>
            <ol className="mt-2 list-inside list-decimal" style={{ color: "var(--ink-2)" }}>
              {rb.steps.map((s, i) => <li key={i}>{s}</li>)}
            </ol>
            <div className="mt-2 text-xs font-medium" style={{ color: "var(--status-serious)" }}>
              Escalate when: <span style={{ color: "var(--ink-2)" }}>{rb.escalate_when.join(" · ")}</span>
            </div>
          </div>
        </section>
      )}
    </div>
  );
}

export default function Alerts() {
  const [status, setStatus] = useState("");
  const [selected, setSelected] = useState<string | null>(null);
  const alerts = useQuery({
    queryKey: ["alerts", status],
    queryFn: () => api.alerts(status ? `&status=${status}` : ""),
  });

  return (
    <div className="grid gap-4 xl:grid-cols-2">
      <div className="card overflow-hidden">
        <div className="flex items-center gap-2 border-b px-4 py-2" style={{ borderColor: "var(--ring)" }}>
          <span className="text-sm font-medium">Alerts</span>
          {["", "open", "acknowledged", "resolved", "dismissed"].map((s) => (
            <button
              key={s}
              onClick={() => setStatus(s)}
              className="rounded px-2 py-0.5 text-xs"
              style={{
                color: status === s ? "var(--ink)" : "var(--ink-muted)",
                background: status === s ? "var(--baseline)" : "transparent",
              }}
            >
              {s || "all"}
            </button>
          ))}
        </div>
        <div className="max-h-[75vh] overflow-y-auto">
          {alerts.data?.alerts?.length ? (
            alerts.data.alerts.map((a) => (
              <button
                key={a.id}
                onClick={() => setSelected(a.id)}
                className="block w-full border-b px-4 py-2.5 text-left hover:bg-white/5"
                style={{
                  borderColor: "var(--ring)",
                  background: selected === a.id ? "rgba(57,135,229,0.08)" : undefined,
                }}
              >
                <div className="flex items-center gap-2">
                  <SevBadge sev={a.severity} />
                  <TypeChip type={a.alert_type} />
                  <span className="ml-auto text-xs" style={{ color: "var(--ink-muted)" }}>{fmtTime(a.window_start)}</span>
                </div>
                <div className="mt-1 truncate text-sm" style={{ color: "var(--ink-2)" }}>{a.title}</div>
                <div className="mt-0.5 flex items-center gap-2 text-xs" style={{ color: "var(--ink-muted)" }}>
                  {a.status !== "open" && <span>[{a.status}]</span>}
                  {a.triage && <span>triaged: {a.triage.verdict.replaceAll("_", " ")}</span>}
                </div>
              </button>
            ))
          ) : (
            <Empty text={alerts.isLoading ? "loading…" : "no alerts match"} />
          )}
        </div>
      </div>
      <div>
        {selected ? (
          <AlertDetail id={selected} onClose={() => setSelected(null)} />
        ) : (
          <div className="card"><Empty text="select an alert to see evidence, LLM triage, investigation, and the runbook" /></div>
        )}
      </div>
    </div>
  );
}
