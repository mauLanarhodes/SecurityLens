import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api, fmtTime } from "../api";
import { Empty, SevBadge, TypeChip } from "../bits";

export default function Incidents() {
  const [selected, setSelected] = useState<string | null>(null);
  const incidents = useQuery({ queryKey: ["incidents"], queryFn: api.incidents });
  const detail = useQuery({
    queryKey: ["incident", selected],
    queryFn: () => api.incident(selected!),
    enabled: !!selected,
  });

  return (
    <div className="grid gap-4 xl:grid-cols-2">
      <div className="card overflow-hidden">
        <div className="border-b px-4 py-2 text-sm font-medium" style={{ borderColor: "var(--ring)" }}>
          Incidents <span className="text-xs font-normal" style={{ color: "var(--ink-muted)" }}>— alerts correlated by entity</span>
        </div>
        <div className="max-h-[75vh] overflow-y-auto">
          {incidents.data?.incidents?.length ? (
            incidents.data.incidents.map((i) => (
              <button
                key={i.id}
                onClick={() => setSelected(i.id)}
                className="block w-full border-b px-4 py-2.5 text-left hover:bg-white/5"
                style={{
                  borderColor: "var(--ring)",
                  background: selected === i.id ? "rgba(57,135,229,0.08)" : undefined,
                }}
              >
                <div className="flex items-center gap-2">
                  <SevBadge sev={i.severity} />
                  <span className="text-xs" style={{ color: "var(--ink-muted)" }}>
                    {i.alert_count} alert{i.alert_count === 1 ? "" : "s"}
                  </span>
                  <span className="ml-auto text-xs" style={{ color: "var(--ink-muted)" }}>{fmtTime(i.first_seen)}</span>
                </div>
                <div className="mt-1 truncate text-sm" style={{ color: "var(--ink-2)" }}>{i.title}</div>
                <div className="mt-0.5 text-xs" style={{ color: "var(--ink-muted)" }}>entity {i.entity}</div>
              </button>
            ))
          ) : (
            <Empty text={incidents.isLoading ? "loading…" : "no incidents"} />
          )}
        </div>
      </div>

      <div className="card p-5">
        {detail.data ? (
          <>
            <div className="flex items-center gap-2">
              <SevBadge sev={detail.data.incident.severity} />
              <span className="text-xs" style={{ color: "var(--ink-muted)" }}>
                {fmtTime(detail.data.incident.first_seen)} → {fmtTime(detail.data.incident.last_seen)}
              </span>
            </div>
            <h2 className="mt-2 text-lg font-semibold">{detail.data.incident.title}</h2>
            <div className="mt-1 text-xs" style={{ color: "var(--ink-2)" }}>entity {detail.data.incident.entity}</div>

            {/* mini-timeline of the incident's alerts */}
            <div className="mt-5 space-y-0">
              {detail.data.incident.alerts?.map((a, idx) => (
                <div key={a.id} className="relative flex gap-3 pb-5">
                  <div className="flex flex-col items-center">
                    <span className="mt-1 h-2.5 w-2.5 rounded-full" style={{ background: "var(--series-1)" }} />
                    {idx < (detail.data!.incident.alerts!.length - 1) && (
                      <span className="w-px flex-1" style={{ background: "var(--baseline)" }} />
                    )}
                  </div>
                  <div>
                    <div className="flex items-center gap-2 text-xs" style={{ color: "var(--ink-muted)" }}>
                      {fmtTime(a.window_start)} <TypeChip type={a.alert_type} /> <SevBadge sev={a.severity} />
                    </div>
                    <div className="text-sm" style={{ color: "var(--ink-2)" }}>{a.title}</div>
                  </div>
                </div>
              ))}
            </div>
          </>
        ) : (
          <Empty text="select an incident to see its correlated alert timeline" />
        )}
      </div>
    </div>
  );
}
