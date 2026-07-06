// Small shared UI atoms.
import { SEV_COLORS, TYPE_COLORS } from "./api";

export function SevBadge({ sev }: { sev: string }) {
  return (
    <span
      className="inline-flex items-center gap-1.5 rounded px-1.5 py-0.5 text-xs font-medium uppercase tracking-wide"
      style={{ color: SEV_COLORS[sev] ?? "var(--ink-2)", border: `1px solid ${SEV_COLORS[sev] ?? "var(--ring)"}` }}
    >
      {sev === "critical" ? "▲" : sev === "high" ? "●" : sev === "medium" ? "◆" : "○"} {sev}
    </span>
  );
}

export function TypeChip({ type }: { type: string }) {
  return (
    <span className="inline-flex items-center gap-1.5 text-xs" style={{ color: "var(--ink-2)" }}>
      <span
        className="inline-block h-2.5 w-2.5 rounded-sm"
        style={{ background: TYPE_COLORS[type] ?? "var(--ink-muted)" }}
      />
      {type.replaceAll("_", " ")}
    </span>
  );
}

export function StatTile({
  label,
  value,
  sub,
  accent,
}: {
  label: string;
  value: string | number;
  sub?: string;
  accent?: string;
}) {
  return (
    <div className="card p-4">
      <div className="text-xs uppercase tracking-wide" style={{ color: "var(--ink-muted)" }}>
        {label}
      </div>
      <div className="mt-1 text-3xl font-semibold" style={{ color: accent ?? "var(--ink)" }}>
        {value}
      </div>
      {sub && (
        <div className="mt-1 text-xs" style={{ color: "var(--ink-2)" }}>
          {sub}
        </div>
      )}
    </div>
  );
}

export function MockTag({ mock, model }: { mock: boolean; model?: string }) {
  return (
    <span
      className="rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wider"
      style={{
        color: mock ? "var(--status-warning)" : "var(--status-good)",
        border: "1px solid var(--ring)",
      }}
      title={model}
    >
      {mock ? "mock llm" : `live · ${model}`}
    </span>
  );
}

export function Spinner() {
  return (
    <span
      className="inline-block h-4 w-4 animate-spin rounded-full border-2 border-t-transparent align-middle"
      style={{ borderColor: "var(--ink-muted)", borderTopColor: "transparent" }}
    />
  );
}

export function Empty({ text }: { text: string }) {
  return (
    <div className="p-8 text-center text-sm" style={{ color: "var(--ink-muted)" }}>
      {text}
    </div>
  );
}
