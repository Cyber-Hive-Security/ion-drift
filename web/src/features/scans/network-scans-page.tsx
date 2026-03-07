import { useState } from "react";
import {
  Radar,
  Play,
  Loader2,
  AlertTriangle,
  Shield,
  Trash2,
  Plus,
  ChevronDown,
  ChevronRight,
  Clock,
  CheckCircle2,
  XCircle,
} from "lucide-react";
import { PageShell } from "@/components/layout/page-shell";
import { DataTable, type Column } from "@/components/data-table";
import {
  useScanStatus,
  useScans,
  useScanResults,
  useStartScan,
  useScanExclusions,
  useAddExclusion,
  useRemoveExclusion,
} from "@/api/queries";
import type { NmapScan, NmapResult, ScanExclusion } from "@/api/types";
import { useVlanLookup } from "@/hooks/use-vlan-lookup";

// ── Helpers ─────────────────────────────────────────────────────

const PROFILES = [
  {
    value: "quick" as const,
    label: "Quick Scan",
    description: "Ping sweep only — discovers live hosts (~30s)",
    icon: "zap",
  },
  {
    value: "standard" as const,
    label: "Standard Scan",
    description: "Service detection + OS fingerprint, top 100 ports (~5min)",
    icon: "shield",
  },
  {
    value: "deep" as const,
    label: "Deep Scan",
    description: "Full port scan + scripts + OS detection (~20min)",
    icon: "search",
  },
];

function statusBadge(status: string) {
  switch (status) {
    case "running":
      return (
        <span className="inline-flex items-center gap-1 rounded-full border border-primary/30 bg-primary/20 px-2 py-0.5 text-[10px] font-medium text-primary">
          <Loader2 className="h-3 w-3 animate-spin" />
          Running
        </span>
      );
    case "completed":
      return (
        <span className="inline-flex items-center gap-1 rounded-full border border-success/30 bg-success/20 px-2 py-0.5 text-[10px] font-medium text-success">
          <CheckCircle2 className="h-3 w-3" />
          Completed
        </span>
      );
    case "failed":
      return (
        <span className="inline-flex items-center gap-1 rounded-full border border-destructive/30 bg-destructive/20 px-2 py-0.5 text-[10px] font-medium text-destructive">
          <XCircle className="h-3 w-3" />
          Failed
        </span>
      );
    default:
      return (
        <span className="rounded-full border border-border bg-muted px-2 py-0.5 text-[10px] text-muted-foreground">
          {status}
        </span>
      );
  }
}

function formatDuration(start?: string | null, end?: string | null): string {
  if (!start || !end) return "—";
  const s = new Date(start).getTime();
  const e = new Date(end).getTime();
  const diff = Math.floor((e - s) / 1000);
  if (diff < 60) return `${diff}s`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ${diff % 60}s`;
  return `${Math.floor(diff / 3600)}h ${Math.floor((diff % 3600) / 60)}m`;
}

function parseOpenPorts(json: string | null): { port: number; proto: string; service: string; version: string }[] {
  if (!json) return [];
  try {
    return JSON.parse(json);
  } catch {
    return [];
  }
}

// ── Main page ───────────────────────────────────────────────────

export default function NetworkScansPage() {
  const vlan = useVlanLookup();
  const { data: scanStatusData } = useScanStatus();
  const { data: scans = [], refetch: refetchScans } = useScans();
  const { data: exclusions = [] } = useScanExclusions();
  const startScan = useStartScan();
  const addExclusion = useAddExclusion();
  const removeExclusion = useRemoveExclusion();

  const [selectedVlan, setSelectedVlan] = useState<number>(25);
  const [selectedProfile, setSelectedProfile] = useState<"quick" | "standard" | "deep">("standard");
  const [viewingScanId, setViewingScanId] = useState<string | null>(null);
  const [showExclusions, setShowExclusions] = useState(false);
  const [newExclusionIp, setNewExclusionIp] = useState("");
  const [newExclusionReason, setNewExclusionReason] = useState("");

  const { data: scanResults = [] } = useScanResults(viewingScanId || undefined);

  const isScanning = scanStatusData?.scanning ?? false;
  const nmapAvailable = scanStatusData?.nmap_available ?? false;
  const isIoTVlan = selectedVlan === 90 || selectedVlan === 99;

  const handleStartScan = () => {
    startScan.mutate({ vlan_id: selectedVlan, profile: selectedProfile });
  };

  const handleAddExclusion = () => {
    if (!newExclusionIp.trim()) return;
    addExclusion.mutate(
      { ip: newExclusionIp.trim(), reason: newExclusionReason.trim() || "manual" },
      {
        onSuccess: () => {
          setNewExclusionIp("");
          setNewExclusionReason("");
        },
      }
    );
  };

  // Running scan
  const runningScan = scans.find((s) => s.status === "running");

  // Scan history columns
  const scanColumns: Column<NmapScan>[] = [
    {
      key: "vlan",
      header: "VLAN",
      render: (row) => {
        const config = vlan.configs[row.vlan_id];
        return (
          <span className="flex items-center gap-1.5">
            <span
              className="h-2 w-2 rounded-full"
              style={{ backgroundColor: config?.color || "#666" }}
            />
            <span className="text-xs">
              {row.vlan_id} — {config?.name || "Unknown"}
            </span>
          </span>
        );
      },
      sortValue: (row) => row.vlan_id,
    },
    {
      key: "profile",
      header: "Profile",
      render: (row) => (
        <span className="text-xs capitalize">{row.profile}</span>
      ),
      sortValue: (row) => row.profile,
    },
    {
      key: "status",
      header: "Status",
      render: (row) => statusBadge(row.status),
      sortValue: (row) => row.status,
    },
    {
      key: "discovered",
      header: "Discovered",
      render: (row) => (
        <span className="text-xs">
          {row.discovered_count} / {row.target_count}
        </span>
      ),
      sortValue: (row) => row.discovered_count,
    },
    {
      key: "duration",
      header: "Duration",
      render: (row) => (
        <span className="text-xs text-muted-foreground">
          {formatDuration(row.started_at, row.completed_at)}
        </span>
      ),
    },
    {
      key: "started",
      header: "Started",
      render: (row) => (
        <span className="text-xs text-muted-foreground">
          {row.started_at || "—"}
        </span>
      ),
      sortValue: (row) => row.started_at || "",
    },
    {
      key: "actions",
      header: "",
      render: (row) =>
        row.status === "completed" ? (
          <button
            onClick={() => setViewingScanId(viewingScanId === row.id ? null : row.id)}
            className="rounded-md border border-border px-2 py-1 text-xs text-muted-foreground hover:bg-muted"
          >
            {viewingScanId === row.id ? "Hide" : "Results"}
          </button>
        ) : row.error ? (
          <span className="text-xs text-destructive" title={row.error}>
            Error
          </span>
        ) : null,
    },
  ];

  // Scan result columns
  const resultColumns: Column<NmapResult>[] = [
    {
      key: "ip",
      header: "IP Address",
      render: (row) => <span className="font-mono text-xs">{row.ip_address}</span>,
      sortValue: (row) => row.ip_address,
    },
    {
      key: "mac",
      header: "MAC",
      render: (row) => (
        <span className="font-mono text-xs">{row.mac_address || "—"}</span>
      ),
      sortValue: (row) => row.mac_address || "",
    },
    {
      key: "hostname",
      header: "Hostname",
      render: (row) => <span className="text-xs">{row.hostname || "—"}</span>,
      sortValue: (row) => row.hostname || "",
    },
    {
      key: "os",
      header: "OS Guess",
      render: (row) => (
        <span className="max-w-48 truncate text-xs" title={row.os_guess || undefined}>
          {row.os_guess || "—"}
          {row.os_accuracy != null && (
            <span className="ml-1 text-muted-foreground">({row.os_accuracy}%)</span>
          )}
        </span>
      ),
      sortValue: (row) => row.os_guess || "",
    },
    {
      key: "ports",
      header: "Open Ports",
      render: (row) => {
        const ports = parseOpenPorts(row.open_ports);
        if (ports.length === 0) return <span className="text-xs text-muted-foreground">—</span>;
        return (
          <span className="text-xs">
            {ports
              .slice(0, 5)
              .map((p) => `${p.port}/${p.service || p.proto}`)
              .join(", ")}
            {ports.length > 5 && ` +${ports.length - 5}`}
          </span>
        );
      },
    },
    {
      key: "device_type",
      header: "Type",
      render: (row) => (
        <span className="text-xs">{row.device_type || "—"}</span>
      ),
      sortValue: (row) => row.device_type || "",
    },
  ];

  // Exclusion columns
  const exclusionColumns: Column<ScanExclusion>[] = [
    {
      key: "ip",
      header: "IP Address",
      render: (row) => <span className="font-mono text-xs">{row.ip_address}</span>,
      sortValue: (row) => row.ip_address,
    },
    {
      key: "reason",
      header: "Reason",
      render: (row) => <span className="text-xs">{row.reason || "—"}</span>,
      sortValue: (row) => row.reason || "",
    },
    {
      key: "added",
      header: "Added",
      render: (row) => <span className="text-xs text-muted-foreground">{row.created_at}</span>,
    },
    {
      key: "actions",
      header: "",
      render: (row) => (
        <button
          onClick={() => removeExclusion.mutate(row.ip_address)}
          className="rounded p-1 text-muted-foreground hover:bg-destructive/10 hover:text-destructive"
          title="Remove exclusion"
        >
          <Trash2 className="h-3.5 w-3.5" />
        </button>
      ),
    },
  ];

  return (
    <PageShell
      title="Network Scans"
      onRefresh={() => refetchScans()}
    >
      {/* Scan launcher */}
      <div className="mb-6 rounded-lg border border-border bg-card p-5">
        <div className="mb-4 flex items-center gap-2 text-sm font-medium text-muted-foreground">
          <Radar className="h-4 w-4" />
          Launch Scan
        </div>

        {!nmapAvailable && (
          <div className="mb-4 flex items-center gap-2 rounded-md border border-warning/30 bg-warning/10 px-3 py-2 text-sm text-warning">
            <AlertTriangle className="h-4 w-4" />
            nmap is not installed on the server. Scanning is unavailable.
          </div>
        )}

        <div className="flex flex-wrap items-end gap-4">
          {/* VLAN selector */}
          <div className="flex flex-col gap-1">
            <label className="text-[10px] uppercase text-muted-foreground">Target VLAN</label>
            <select
              value={selectedVlan}
              onChange={(e) => setSelectedVlan(Number(e.target.value))}
              className="rounded border border-border bg-background px-3 py-1.5 text-sm"
            >
              {Object.entries(vlan.configs).map(([id, config]) => (
                <option key={id} value={id}>
                  VLAN {id} — {config.name} ({config.subnet})
                </option>
              ))}
            </select>
          </div>

          {/* Profile selector */}
          <div className="flex flex-col gap-1">
            <label className="text-[10px] uppercase text-muted-foreground">Scan Profile</label>
            <select
              value={selectedProfile}
              onChange={(e) => setSelectedProfile(e.target.value as typeof selectedProfile)}
              className="rounded border border-border bg-background px-3 py-1.5 text-sm"
            >
              {PROFILES.map((p) => (
                <option key={p.value} value={p.value}>
                  {p.label}
                </option>
              ))}
            </select>
          </div>

          {/* Start button */}
          <button
            onClick={handleStartScan}
            disabled={isScanning || !nmapAvailable || startScan.isPending}
            className="flex items-center gap-2 rounded-md bg-primary px-4 py-1.5 text-sm font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
          >
            {isScanning ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              <Play className="h-4 w-4" />
            )}
            {isScanning ? "Scanning..." : "Start Scan"}
          </button>
        </div>

        {/* Profile description */}
        <p className="mt-2 text-xs text-muted-foreground">
          {PROFILES.find((p) => p.value === selectedProfile)?.description}
        </p>

        {/* IoT warning */}
        {isIoTVlan && (
          <div className="mt-3 flex items-center gap-2 rounded-md border border-warning/30 bg-warning/10 px-3 py-2 text-xs text-warning">
            <AlertTriangle className="h-4 w-4 shrink-0" />
            IoT VLANs may contain fragile devices. Scanning could disrupt their operation.
            Use Quick scan profile for safer discovery.
          </div>
        )}

        {/* Running scan progress */}
        {runningScan && (
          <div className="mt-4 flex items-center gap-3 rounded-md border border-primary/20 bg-primary/5 px-3 py-2">
            <Loader2 className="h-4 w-4 animate-spin text-primary" />
            <div className="text-sm">
              <span className="font-medium">Scanning VLAN {runningScan.vlan_id}</span>
              <span className="ml-2 text-muted-foreground">
                ({runningScan.profile}) — {runningScan.discovered_count} hosts discovered
              </span>
            </div>
          </div>
        )}
      </div>

      {/* Scan history */}
      <div className="mb-6">
        <h2 className="mb-3 text-sm font-medium text-muted-foreground flex items-center gap-2">
          <Clock className="h-4 w-4" />
          Scan History
        </h2>
        <DataTable
          columns={scanColumns}
          data={scans}
          rowKey={(row) => row.id}
          emptyMessage="No scans yet"
          defaultSort={{ key: "started", asc: false }}
        />
      </div>

      {/* Scan results detail */}
      {viewingScanId && (
        <div className="mb-6">
          <h2 className="mb-3 text-sm font-medium text-muted-foreground flex items-center gap-2">
            <Shield className="h-4 w-4" />
            Scan Results
          </h2>
          <DataTable
            columns={resultColumns}
            data={scanResults}
            rowKey={(row) => String(row.id)}
            emptyMessage="No results"
            searchable
            searchPlaceholder="Search by IP, hostname, OS..."
          />
        </div>
      )}

      {/* Exclusions */}
      <div className="rounded-lg border border-border bg-card">
        <button
          onClick={() => setShowExclusions(!showExclusions)}
          className="flex w-full items-center gap-2 px-4 py-3 text-sm font-medium text-muted-foreground hover:text-foreground"
        >
          {showExclusions ? (
            <ChevronDown className="h-4 w-4" />
          ) : (
            <ChevronRight className="h-4 w-4" />
          )}
          Scan Exclusions ({exclusions.length})
        </button>

        {showExclusions && (
          <div className="border-t border-border px-4 pb-4">
            <div className="my-3 flex items-end gap-2">
              <div className="flex flex-col gap-1">
                <label className="text-[10px] uppercase text-muted-foreground">IP Address</label>
                <input
                  type="text"
                  value={newExclusionIp}
                  onChange={(e) => setNewExclusionIp(e.target.value)}
                  placeholder="192.168.88.1"
                  className="rounded border border-border bg-background px-2 py-1 text-sm"
                />
              </div>
              <div className="flex flex-col gap-1">
                <label className="text-[10px] uppercase text-muted-foreground">Reason</label>
                <input
                  type="text"
                  value={newExclusionReason}
                  onChange={(e) => setNewExclusionReason(e.target.value)}
                  placeholder="Router — do not scan"
                  className="rounded border border-border bg-background px-2 py-1 text-sm"
                />
              </div>
              <button
                onClick={handleAddExclusion}
                disabled={!newExclusionIp.trim() || addExclusion.isPending}
                className="flex items-center gap-1 rounded-md border border-border px-2 py-1 text-xs text-muted-foreground hover:bg-muted disabled:opacity-50"
              >
                <Plus className="h-3.5 w-3.5" />
                Add
              </button>
            </div>
            <DataTable
              columns={exclusionColumns}
              data={exclusions}
              rowKey={(row) => row.ip_address}
              emptyMessage="No exclusions configured"
            />
          </div>
        )}
      </div>
    </PageShell>
  );
}
