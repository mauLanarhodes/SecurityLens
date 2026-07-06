import { useEffect, useRef, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { api, fmtBytes, type Alert, type LogEvent } from "../api";
import { ActivityTimeline, AlertsByType } from "../charts";
import { Empty, SevBadge, StatTile } from "../bits";

const SOURCE_COLOR: Record<string, string> = {
  cloudtrail: "var(--series-3)",
  ssh: "var(--series-2)",
  nginx: "var(--series-1)",
  app: "var(--series-5)",
};

// LiveFeed subscribes to the SSE stream; new logs tail in as their event time
// passes, and alert events surface immediately.
function LiveFeed() {
  const [rows, setRows] = useState<LogEvent[]>([]);
  const [liveAlerts, setLiveAlerts] = useState<Alert[]>([]);
  const [connected, setConnected] = useState(false);
  const boot = useRef(false);
  const qc = useQueryClient();

  useEffect(() => {
    if (!boot.current) {
      boot.current = true;
      api.logs(40).then((d) => setRows(d.logs.slice(-40)));
    }
    const es = new EventSource("/api/stream");
    es.onopen = () => setConnected(true);
    es.onerror = () => setConnected(false);
    es.addEventListener("log", (e) => {
      const ev = JSON.parse((e as MessageEvent).data) as LogEvent;
      setRows((r) => [...r.slice(-79), ev]);
    });
    es.addEventListener("alert", (e) => {
      const payload = JSON.parse((e as MessageEvent).data) as { kind: string; alert: Alert };
      if (payload.kind === "alert_created") {
        setLiveAlerts((a) => [payload.alert, ...a.slice(0, 4)]);
        qc.invalidateQueries({ queryKey: ["alerts"] });
      }
    });
    return () => es.close();
  }, [qc]);

  return (
    <div className="card flex h-[420px] flex-col">
      <div className="flex items-center justify-between border-b px-4 py-2" style={{ borderColor: "var(--ring)" }}>
        <span className="text-sm font-medium">Live feed</span>
        <span className="text-xs" style={{ color: connected ? "var(--status-good)" : "var(--status-critical)" }}>
          ● {connected ? "streaming" : "reconnecting"}
        </span>
      </div>
      {liveAlerts.length > 0 && (
        <div className="border-b px-4 py-2" style={{ borderColor: "var(--ring)" }}>
          {liveAlerts.map((a) => (
            <div key={a.id} className="flex items-center gap-2 py-0.5 text-xs">
              <SevBadge sev={a.severity} />
              <span className="truncate" style={{ color: "var(--ink-2)" }}>{a.title}</span>
            </div>
          ))}
        </div>
      )}
      <div className="flex-1 overflow-y-auto px-4 py-2 font-mono text-[11px] leading-5">
        {rows.length === 0 && <Empty text="waiting for events…" />}
        {rows.map((r) => (
          <div key={`${r.id}`} className="flex gap-2 whitespace-nowrap">
            <span style={{ color: "var(--ink-muted)" }}>
              {new Date(r.ts).toLocaleTimeString(undefined, { hour12: false })}
            </span>
            <span style={{ color: SOURCE_COLOR[r.source] ?? "var(--ink-2)", minWidth: 74 }}>{r.source}</span>
            <span style={{ color: r.status === "failure" || r.status === "denied" ? "var(--status-serious)" : "var(--ink-2)" }}>
              {r.event_type}
            </span>
            <span style={{ color: "var(--ink-muted)" }}>
              {r.username && `${r.username}@`}
              {r.src_ip}
              {r.dst_host && ` → ${r.dst_host}`}
              {r.bytes_out ? ` (${fmtBytes(r.bytes_out)})` : ""}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

export default function Overview() {
  const timeline = useQuery({ queryKey: ["timeline"], queryFn: api.timeline, refetchInterval: 60000 });
  const metrics = useQuery({ queryKey: ["metrics"], queryFn: api.metrics });

  const m = metrics.data;
  const byType = (m?.alerts?.by_type ?? {}) as Record<string, number>;
  const bySev = (m?.alerts?.by_severity ?? {}) as Record<string, number>;

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
        <StatTile label="Open alerts" value={m?.alerts?.open ?? "…"} accent="var(--status-serious)"
          sub={`${m?.alerts?.total ?? 0} total`} />
        <StatTile label="Incidents" value={m?.alerts?.incidents ?? "…"} sub="entity-correlated" />
        <StatTile label="Critical / High" value={`${bySev.critical ?? 0} / ${bySev.high ?? 0}`} accent="var(--status-critical)"
          sub="by severity" />
        <StatTile label="Logs indexed" value={(m?.logs ?? 0).toLocaleString()}
          sub={`detection latency ≤ ${m?.detection_latency_bound_seconds ?? "—"}s`} />
      </div>

      <div className="grid gap-4 lg:grid-cols-5">
        <div className="card p-4 lg:col-span-3">
          <div className="mb-2 text-sm font-medium">Activity timeline</div>
          {timeline.data ? <ActivityTimeline points={timeline.data.points} /> : <Empty text="loading…" />}
        </div>
        <div className="lg:col-span-2">
          <LiveFeed />
        </div>
      </div>

      <div className="card p-4">
        <div className="mb-2 text-sm font-medium">Alert volume by type</div>
        {Object.keys(byType).length ? <AlertsByType byType={byType} /> : <Empty text="no alerts yet" />}
      </div>
    </div>
  );
}
