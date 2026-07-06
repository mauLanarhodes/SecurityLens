// Chart components. Palette: validated dark-mode steps (see index.css).
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Cell,
} from "recharts";
import type { TimelinePoint } from "./api";

// Recharts renders marks into SVG fill attributes, where CSS var() does not
// resolve — so charts use resolved hex here (the validated dark-mode steps),
// while the surrounding React UI uses the CSS custom properties.
const TYPE_HEX: Record<string, string> = {
  credential_stuffing: "#3987e5",
  privilege_escalation: "#e66767",
  sensitive_data_exposure: "#c98500",
  identity_anomaly: "#9085e9",
  lateral_movement: "#d55181",
  off_hours_access: "#199e70",
  data_exfiltration: "#008300",
};

const ink2 = "#c3c2b7";
const muted = "#898781";
const grid = "#2c2c2a";
const blue = "#3987e5";
const red = "#e66767";

const tooltipStyle = {
  backgroundColor: "#1a1a19",
  border: "1px solid rgba(255,255,255,0.1)",
  borderRadius: 6,
  color: ink2,
  fontSize: 12,
};

// Logs and alerts live on wildly different scales, so they get two stacked
// charts sharing one time domain (never a dual-axis chart).
export function ActivityTimeline({ points }: { points: TimelinePoint[] }) {
  const data = points.map((p) => ({
    t: new Date(p.bucket).toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit" }),
    logs: p.logs,
    alerts: p.alerts,
  }));
  return (
    <div>
      <div className="px-1 text-xs" style={{ color: ink2 }}>
        logs / hour
      </div>
      <ResponsiveContainer width="100%" height={160}>
        <AreaChart data={data} syncId="tl" margin={{ top: 8, right: 8, left: 0, bottom: 0 }}>
          <CartesianGrid stroke={grid} vertical={false} />
          <XAxis dataKey="t" hide />
          <YAxis tick={{ fill: muted, fontSize: 11 }} tickLine={false} axisLine={false} width={44} />
          <Tooltip contentStyle={tooltipStyle} />
          <Area type="monotone" dataKey="logs" stroke={blue} strokeWidth={2} fill={blue} fillOpacity={0.12} name="logs/hour" />
        </AreaChart>
      </ResponsiveContainer>
      <div className="px-1 text-xs" style={{ color: red }}>
        alerts (window start)
      </div>
      <ResponsiveContainer width="100%" height={80}>
        <BarChart data={data} syncId="tl" margin={{ top: 4, right: 8, left: 0, bottom: 0 }}>
          <XAxis dataKey="t" tick={{ fill: muted, fontSize: 11 }} tickLine={false} minTickGap={60} />
          <YAxis tick={{ fill: muted, fontSize: 11 }} tickLine={false} axisLine={false} width={44} allowDecimals={false} />
          <Tooltip contentStyle={tooltipStyle} cursor={{ fill: "rgba(255,255,255,0.04)" }} />
          <Bar dataKey="alerts" fill={red} name="alerts" radius={[2, 2, 0, 0]} />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

export function AlertsByType({ byType }: { byType: Record<string, number> }) {
  const data = Object.entries(byType)
    .sort((a, b) => b[1] - a[1])
    .map(([type, n]) => ({ type: type.replaceAll("_", " "), raw: type, n }));
  return (
    <ResponsiveContainer width="100%" height={Math.max(180, data.length * 34)}>
      <BarChart data={data} layout="vertical" margin={{ top: 4, right: 32, left: 8, bottom: 4 }}>
        <CartesianGrid stroke={grid} horizontal={false} />
        <XAxis type="number" tick={{ fill: muted, fontSize: 11 }} tickLine={false} allowDecimals={false} />
        <YAxis type="category" dataKey="type" width={160} tick={{ fill: ink2, fontSize: 12 }} tickLine={false} axisLine={false} />
        <Tooltip contentStyle={tooltipStyle} cursor={{ fill: "rgba(255,255,255,0.04)" }} />
        <Bar dataKey="n" name="alerts" radius={[0, 4, 4, 0]} barSize={14} label={{ position: "right", fill: ink2, fontSize: 12 }}>
          {data.map((d) => (
            <Cell key={d.raw} fill={TYPE_HEX[d.raw] ?? blue} />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}
