import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { api } from "../api";
import { MockTag } from "../bits";

const EXAMPLES = [
  "flag users with more than 5 denied api calls in a window",
  "detect ssh logins to db- hosts outside of cloudtrail-visible sessions",
  "alert when one IP touches more than 10 distinct URL paths with 404s",
];

// Hunt: English → Go detection rule. Generated code is compiled in an
// isolated module (never executed) before an analyst sees it.
export default function Hunt() {
  const [description, setDescription] = useState("");
  const gen = useMutation({ mutationFn: (d: string) => api.generateRule(d) });

  return (
    <div className="mx-auto max-w-4xl space-y-4">
      <div className="card p-5">
        <h2 className="text-lg font-semibold">Rule generator</h2>
        <p className="mt-1 text-sm" style={{ color: "var(--ink-2)" }}>
          Describe a detection in English. The LLM writes a Go rule against the log schema; the code is
          compiled in an isolated throwaway module with an import allowlist and is <b>never executed</b> —
          you review it before it goes anywhere near the pipeline.
        </p>
        <textarea
          value={description}
          onChange={(e) => setDescription(e.target.value)}
          rows={3}
          placeholder="e.g. flag users with more than 5 denied api calls in a window"
          className="mt-3 w-full rounded border bg-transparent p-3 text-sm outline-none"
          style={{ borderColor: "var(--ring)", color: "var(--ink)" }}
        />
        <div className="mt-2 flex flex-wrap items-center gap-2">
          <button
            onClick={() => description.trim() && gen.mutate(description)}
            disabled={gen.isPending || !description.trim()}
            className="rounded px-4 py-2 text-sm font-medium disabled:opacity-50"
            style={{ background: "var(--series-1)", color: "#fff" }}
          >
            {gen.isPending ? "generating…" : "generate rule"}
          </button>
          {EXAMPLES.map((ex) => (
            <button
              key={ex}
              onClick={() => setDescription(ex)}
              className="rounded border px-2 py-1 text-xs"
              style={{ borderColor: "var(--ring)", color: "var(--ink-muted)" }}
            >
              {ex.slice(0, 44)}…
            </button>
          ))}
        </div>
      </div>

      {gen.error && (
        <div className="card p-4 text-sm" style={{ color: "var(--status-critical)" }}>{String(gen.error)}</div>
      )}

      {gen.data && (
        <div className="card p-5">
          <div className="flex items-center gap-3">
            <span
              className="rounded px-2 py-0.5 text-xs font-semibold uppercase"
              style={{
                color: gen.data.compile_ok ? "var(--status-good)" : "var(--status-critical)",
                border: "1px solid var(--ring)",
              }}
            >
              {gen.data.compile_ok ? "✓ compiles in isolation" : "✗ rejected"}
            </span>
            <MockTag mock={gen.data.mock} model={gen.data.model} />
          </div>
          {!gen.data.compile_ok && (
            <pre className="mt-3 overflow-x-auto rounded p-3 font-mono text-xs" style={{ background: "var(--page)", color: "var(--status-serious)" }}>
              {gen.data.compiler_output}
            </pre>
          )}
          <pre className="mt-3 overflow-x-auto rounded p-3 font-mono text-xs leading-5" style={{ background: "var(--page)", color: "var(--ink-2)" }}>
            {gen.data.code}
          </pre>
        </div>
      )}
    </div>
  );
}
