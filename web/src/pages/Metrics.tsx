import { useQuery } from "@tanstack/react-query";
import { api, type EvalResult } from "../api";
import { Empty, StatTile } from "../bits";

function pct(x: number) {
  return `${Math.round(x * 100)}%`;
}

function EvalPanel({ result, dataset, ts }: { result: EvalResult; dataset: string; ts: string }) {
  const types = Object.entries(result.per_type).sort(([a], [b]) => a.localeCompare(b));
  return (
    <div className="card p-5">
      <div className="flex items-baseline justify-between">
        <div className="text-sm font-medium">
          Accuracy vs labelled ground truth
          <span className="ml-2 text-xs font-normal" style={{ color: "var(--ink-muted)" }}>
            dataset {dataset} · {new Date(ts).toLocaleString()} · drain {result.drain_seconds.toFixed(1)}s
          </span>
        </div>
      </div>

      <div className="mt-4 grid grid-cols-2 gap-4 md:grid-cols-4">
        <StatTile label="Recall" value={pct(result.overall.recall)} accent="var(--status-good)"
          sub={`${result.overall.detected}/${result.overall.attacks} attacks detected`} />
        <StatTile label="Operational precision" value={pct(result.operational_precision)} accent="var(--status-good)"
          sub="alerts overlapping real attacks" />
        <StatTile label="Type-exact precision" value={pct(result.type_exact_precision)}
          sub="detector label matches ground truth" />
        <StatTile label="Benign false positives" value={result.benign_fp}
          accent={result.benign_fp === 0 ? "var(--status-good)" : "var(--status-critical)"}
          sub={`across ${result.overall.alerts} alerts`} />
      </div>

      <div className="mt-4 overflow-x-auto">
        <table className="w-full text-left text-sm">
          <thead>
            <tr className="text-xs uppercase tracking-wide" style={{ color: "var(--ink-muted)" }}>
              <th className="py-1.5 pr-3 font-medium">alert type</th>
              <th className="px-2 py-1.5 text-right font-medium">attacks</th>
              <th className="px-2 py-1.5 text-right font-medium">detected</th>
              <th className="px-2 py-1.5 text-right font-medium">recall</th>
              <th className="px-2 py-1.5 text-right font-medium">alerts</th>
              <th className="px-2 py-1.5 text-right font-medium">exact TP</th>
              <th className="px-2 py-1.5 text-right font-medium">cross TP</th>
              <th className="px-2 py-1.5 text-right font-medium">benign FP</th>
            </tr>
          </thead>
          <tbody className="tabular">
            {types.map(([t, s]) => (
              <tr key={t} className="border-t" style={{ borderColor: "var(--ring)" }}>
                <td className="py-1.5 pr-3" style={{ color: "var(--ink-2)" }}>{t.replaceAll("_", " ")}</td>
                <td className="px-2 py-1.5 text-right">{s.attacks}</td>
                <td className="px-2 py-1.5 text-right">{s.detected}</td>
                <td className="px-2 py-1.5 text-right" style={{ color: s.attacks > 0 && s.detected === s.attacks ? "var(--status-good)" : "var(--ink)" }}>
                  {s.attacks ? pct(s.detected / s.attacks) : "—"}
                </td>
                <td className="px-2 py-1.5 text-right">{s.alerts}</td>
                <td className="px-2 py-1.5 text-right">{s.tp}</td>
                <td className="px-2 py-1.5 text-right" style={{ color: "var(--ink-muted)" }}>{s.cross_tp}</td>
                <td className="px-2 py-1.5 text-right" style={{ color: s.fp > 0 ? "var(--status-critical)" : "var(--ink-muted)" }}>{s.fp}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="mt-3 text-xs leading-5" style={{ color: "var(--ink-muted)" }}>
        Cross TP = an alert that flags real attack activity under a different detector's label (e.g. a
        credential-stuffing breakthrough also tripping identity-anomaly). These cost type-exact precision but
        not operational precision — they are overlapping true detections, not false alarms. Benign FP = alerts
        on activity with no attack anywhere near it.
      </p>
    </div>
  );
}

export default function Metrics() {
  const evalRuns = useQuery({ queryKey: ["eval"], queryFn: api.evalRuns, refetchInterval: 60000 });
  const metrics = useQuery({ queryKey: ["metrics"], queryFn: api.metrics });

  const latest = evalRuns.data?.runs?.[0];
  const m = metrics.data;
  const llmFeatures = (m?.llm?.features ?? []) as {
    feature: string; calls: number; cached: number; mock: number;
    input_tokens: number; output_tokens: number; avg_latency_ms: number;
  }[];

  return (
    <div className="space-y-4">
      {latest ? (
        <EvalPanel result={latest.result} dataset={latest.dataset} ts={latest.ts} />
      ) : (
        <div className="card">
          <Empty text="no evaluation run recorded yet — run `make eval` (or `docker compose run --rm backend /app/eval`) to score the detectors against ground truth" />
        </div>
      )}

      <div className="grid gap-4 md:grid-cols-2">
        <div className="card p-5">
          <div className="text-sm font-medium">Operational</div>
          <div className="mt-3 grid grid-cols-2 gap-4">
            <StatTile label="Analyst FP rate" value={m ? pct(m.fp_rate ?? 0) : "…"} sub="alerts dismissed by analysts" />
            <StatTile label="Detection latency bound" value={m ? `${m.detection_latency_bound_seconds}s` : "…"} sub="sweep interval + settle lag" />
          </div>
        </div>
        <div className="card p-5">
          <div className="text-sm font-medium">LLM usage</div>
          <div className="mt-2 overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead>
                <tr className="text-xs uppercase" style={{ color: "var(--ink-muted)" }}>
                  <th className="py-1 pr-2 font-medium">feature</th>
                  <th className="px-2 py-1 text-right font-medium">calls</th>
                  <th className="px-2 py-1 text-right font-medium">cached</th>
                  <th className="px-2 py-1 text-right font-medium">mock</th>
                  <th className="px-2 py-1 text-right font-medium">avg ms</th>
                </tr>
              </thead>
              <tbody className="tabular">
                {llmFeatures.length ? llmFeatures.map((f) => (
                  <tr key={f.feature} className="border-t" style={{ borderColor: "var(--ring)" }}>
                    <td className="py-1 pr-2" style={{ color: "var(--ink-2)" }}>{f.feature}</td>
                    <td className="px-2 py-1 text-right">{f.calls}</td>
                    <td className="px-2 py-1 text-right">{f.cached}</td>
                    <td className="px-2 py-1 text-right">{f.mock}</td>
                    <td className="px-2 py-1 text-right">{Math.round(f.avg_latency_ms)}</td>
                  </tr>
                )) : (
                  <tr><td colSpan={5} className="py-3 text-center text-xs" style={{ color: "var(--ink-muted)" }}>no LLM calls yet — triage an alert</td></tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
}
