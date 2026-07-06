import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "./api";
import { MockTag } from "./bits";
import Overview from "./pages/Overview";
import Alerts from "./pages/Alerts";
import Incidents from "./pages/Incidents";
import Hunt from "./pages/Hunt";
import Metrics from "./pages/Metrics";

const TABS = ["Overview", "Alerts", "Incidents", "Hunt", "Metrics"] as const;
type Tab = (typeof TABS)[number];

export default function App() {
  const [tab, setTab] = useState<Tab>("Overview");
  const health = useQuery({ queryKey: ["health"], queryFn: api.health });

  return (
    <div className="mx-auto min-h-screen max-w-7xl px-4 pb-16">
      <header className="flex items-center justify-between py-4">
        <div className="flex items-center gap-3">
          <span className="text-xl font-semibold tracking-tight">
            <span style={{ color: "var(--series-1)" }}>Security</span>Lens
          </span>
          <span className="text-xs" style={{ color: "var(--ink-muted)" }}>
            detection · triage · correlation · hunt
          </span>
        </div>
        <div className="flex items-center gap-3 text-xs" style={{ color: "var(--ink-2)" }}>
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

      <nav className="mb-6 flex gap-1 border-b" style={{ borderColor: "var(--ring)" }}>
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
      {tab === "Alerts" && <Alerts />}
      {tab === "Incidents" && <Incidents />}
      {tab === "Hunt" && <Hunt />}
      {tab === "Metrics" && <Metrics />}
    </div>
  );
}
