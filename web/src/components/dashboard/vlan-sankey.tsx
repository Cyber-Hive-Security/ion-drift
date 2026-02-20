import { useMemo } from "react";
import { formatBytes } from "@/lib/format";
import { useInterfaces } from "@/api/queries";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
} from "recharts";

export function VlanTrafficBreakdown() {
  const interfaces = useInterfaces();
  const data = interfaces.data ?? [];

  const vlanData = useMemo(() => {
    return data
      .filter(
        (iface) =>
          iface.type === "vlan" &&
          ((iface["rx-byte"] ?? 0) > 0 || (iface["tx-byte"] ?? 0) > 0),
      )
      .map((iface) => ({
        name: iface.name,
        rx: iface["rx-byte"] ?? 0,
        tx: iface["tx-byte"] ?? 0,
        total: (iface["rx-byte"] ?? 0) + (iface["tx-byte"] ?? 0),
      }))
      .sort((a, b) => b.total - a.total);
  }, [data]);

  if (vlanData.length === 0) {
    return (
      <div className="rounded-lg border border-border bg-card p-4">
        <h3 className="mb-3 text-sm font-medium text-muted-foreground">
          VLAN Traffic Breakdown
        </h3>
        <p className="text-sm text-muted-foreground">
          No VLAN interfaces with traffic counters found.
        </p>
      </div>
    );
  }

  return (
    <div className="rounded-lg border border-border bg-card p-4">
      <h3 className="mb-3 text-sm font-medium text-muted-foreground">
        VLAN Traffic Breakdown
      </h3>
      <ResponsiveContainer width="100%" height={Math.max(200, vlanData.length * 40 + 40)}>
        <BarChart data={vlanData} layout="vertical" margin={{ left: 10, right: 20 }}>
          <XAxis
            type="number"
            tick={{ fill: "oklch(0.65 0.01 285)", fontSize: 11 }}
            tickFormatter={(v: number) => formatBytes(v, 1)}
          />
          <YAxis
            type="category"
            dataKey="name"
            tick={{ fill: "oklch(0.65 0.01 285)", fontSize: 11 }}
            width={100}
          />
          <Tooltip
            contentStyle={{
              backgroundColor: "oklch(0.175 0.015 285)",
              border: "1px solid oklch(0.3 0.015 285)",
              borderRadius: "6px",
              color: "oklch(0.95 0.01 285)",
              fontSize: "12px",
            }}
            formatter={(value: number, name: string) => [
              formatBytes(value),
              name === "rx" ? "Download" : "Upload",
            ]}
          />
          <Bar
            dataKey="rx"
            stackId="traffic"
            fill="oklch(0.65 0.2 145)"
            name="rx"
          />
          <Bar
            dataKey="tx"
            stackId="traffic"
            fill="oklch(0.65 0.18 250)"
            name="tx"
            radius={[0, 4, 4, 0]}
          />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
