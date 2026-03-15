import { useState, useMemo } from "react";
import {
  Fingerprint,
  CheckCircle2,
  AlertCircle,
  Users,
  Check,
  X,
  Filter,
  RotateCcw,
  Microscope,
} from "lucide-react";
import { Link } from "@tanstack/react-router";
import { PageShell } from "@/components/layout/page-shell";
import { IdentityManagerHelp } from "@/components/help-content";
import { StatCard } from "@/components/stat-card";
import { DataTable, type Column } from "@/components/data-table";
import { cn } from "@/lib/utils";
import {
  useNetworkIdentities,
  useIdentityStats,
  useUpdateIdentity,
  useBulkConfirmIdentities,
  useResetIdentityField,
  useObservedServices,
  useSetDisposition,
  useBulkDisposition,
  usePortViolations,
  useDevices,
  useClientBandwidth,
} from "@/api/queries";
import type { NetworkIdentity, ObservedService, DeviceDisposition, ClientBandwidth } from "@/api/types";
import { useVlanLookup } from "@/hooks/use-vlan-lookup";

// ── Device type options ─────────────────────────────────────────

const DEVICE_TYPES = [
  "router",
  "switch",
  "access_point",
  "network_equipment",
  "camera",
  "printer",
  "phone",
  "computer",
  "server",
  "smart_home",
  "media_player",
  "media_server",
  "gaming",
  "storage",
  "iot",
  "unknown",
] as const;

const DEVICE_TYPE_LABELS: Record<string, string> = {
  router: "Router",
  switch: "Switch",
  access_point: "Access Point",
  network_equipment: "Network Equipment",
  camera: "Camera",
  printer: "Printer",
  phone: "Phone",
  computer: "Computer",
  server: "Server",
  smart_home: "Smart Home",
  media_player: "Media Player",
  media_server: "Media Server",
  gaming: "Gaming",
  storage: "Storage",
  iot: "IoT Device",
  unknown: "Unknown",
};

const SOURCE_COLORS: Record<string, string> = {
  human: "bg-success/20 text-success border-success/30",
  lldp: "bg-primary/20 text-primary border-primary/30",
  nmap: "bg-purple-500/20 text-purple-400 border-purple-500/30",
  conntrack: "bg-teal-500/20 text-teal-400 border-teal-500/30",
  traffic_pattern: "bg-warning/20 text-warning border-warning/30",
  oui: "bg-cyan-500/20 text-cyan-400 border-cyan-500/30",
  none: "bg-muted text-muted-foreground border-border",
};

const DISPOSITION_OPTIONS: { value: DeviceDisposition; label: string; color: string }[] = [
  { value: "unknown", label: "Unknown", color: "bg-muted text-muted-foreground border-border" },
  { value: "my_device", label: "My Device", color: "bg-success/20 text-success border-success/30" },
  { value: "external", label: "External", color: "bg-primary/20 text-primary border-primary/30" },
  { value: "ignored", label: "Ignored", color: "bg-muted/50 text-muted-foreground/50 border-border/50" },
  { value: "flagged", label: "Flagged", color: "bg-destructive/20 text-destructive border-destructive/30" },
];

const DISPOSITION_COLORS: Record<string, string> = Object.fromEntries(
  DISPOSITION_OPTIONS.map((d) => [d.value, d.color])
);

const DISPOSITION_LABELS: Record<string, string> = Object.fromEntries(
  DISPOSITION_OPTIONS.map((d) => [d.value, d.label])
);

// ── Helpers ─────────────────────────────────────────────────────

function formatTimeAgo(unixSecs: number): string {
  const diff = Date.now() / 1000 - unixSecs;
  if (diff < 60) return "just now";
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

function formatBytes(bytes: number): string {
  if (bytes === 0) return "—";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1073741824) return `${(bytes / 1048576).toFixed(1)} MB`;
  return `${(bytes / 1073741824).toFixed(1)} GB`;
}

function statusDot(identity: NetworkIdentity): string {
  if (identity.human_confirmed) return "bg-success"; // confirmed
  if (identity.device_type_source === "lldp") return "bg-primary"; // LLDP
  if (identity.device_type && identity.device_type_confidence >= 0.6)
    return "bg-warning"; // automated
  if (identity.device_type) return "bg-orange-500"; // low confidence
  return "bg-muted-foreground/30"; // no type
}

// ── Reset button ────────────────────────────────────────────────

function ResetButton({
  mac,
  field,
  resetField,
}: {
  mac: string;
  field: string;
  resetField: ReturnType<typeof useResetIdentityField>;
}) {
  return (
    <button
      onClick={(e) => {
        e.stopPropagation();
        resetField.mutate({ mac, field });
      }}
      disabled={resetField.isPending}
      className="ml-1 inline-flex rounded p-0.5 text-muted-foreground hover:bg-warning/20 hover:text-warning"
      title="Reset to auto-detected"
    >
      <RotateCcw className="h-3 w-3" />
    </button>
  );
}

// ── Inline edit components ──────────────────────────────────────

function DeviceTypeCell({
  identity,
  onSave,
  resetField,
}: {
  identity: NetworkIdentity;
  onSave: (type: string) => void;
  resetField: ReturnType<typeof useResetIdentityField>;
}) {
  const [editing, setEditing] = useState(false);
  const isHuman = identity.device_type_source === "human";

  if (!editing) {
    return (
      <span className="inline-flex items-center">
        <button
          onClick={() => setEditing(true)}
          className="rounded px-1.5 py-0.5 text-left hover:bg-muted/50"
        >
          {identity.device_type
            ? DEVICE_TYPE_LABELS[identity.device_type] || identity.device_type
            : "—"}
        </button>
        {isHuman && <ResetButton mac={identity.mac_address} field="device_type" resetField={resetField} />}
      </span>
    );
  }

  return (
    <select
      autoFocus
      className="rounded border border-border bg-background px-1.5 py-0.5 text-sm focus:outline-none focus:ring-1 focus:ring-primary"
      defaultValue={identity.device_type || ""}
      onChange={(e) => {
        onSave(e.target.value);
        setEditing(false);
      }}
      onBlur={() => setEditing(false)}
    >
      <option value="">—</option>
      {DEVICE_TYPES.map((t) => (
        <option key={t} value={t}>
          {DEVICE_TYPE_LABELS[t] || t}
        </option>
      ))}
    </select>
  );
}

function LabelCell({
  identity,
  onSave,
  resetField,
}: {
  identity: NetworkIdentity;
  onSave: (label: string) => void;
  resetField: ReturnType<typeof useResetIdentityField>;
}) {
  const [editing, setEditing] = useState(false);
  const [value, setValue] = useState(identity.human_label || "");
  const hasLabel = identity.human_label != null && identity.human_label !== "";

  if (!editing) {
    return (
      <span className="inline-flex items-center">
        <button
          onClick={() => {
            setValue(identity.human_label || "");
            setEditing(true);
          }}
          className="rounded px-1.5 py-0.5 text-left hover:bg-muted/50"
          title="Custom name — overrides hostname in topology map"
        >
          {identity.human_label || "—"}
        </button>
        {hasLabel && <ResetButton mac={identity.mac_address} field="human_label" resetField={resetField} />}
      </span>
    );
  }

  return (
    <input
      autoFocus
      type="text"
      value={value}
      onChange={(e) => setValue(e.target.value)}
      onBlur={() => {
        if (value !== (identity.human_label || "")) {
          onSave(value);
        }
        setEditing(false);
      }}
      onKeyDown={(e) => {
        if (e.key === "Enter") {
          onSave(value);
          setEditing(false);
        }
        if (e.key === "Escape") setEditing(false);
      }}
      className="w-28 rounded border border-border bg-background px-1.5 py-0.5 text-sm focus:outline-none focus:ring-1 focus:ring-primary"
      placeholder="Add label..."
    />
  );
}

function DispositionCell({
  identity,
  onSave,
}: {
  identity: NetworkIdentity;
  onSave: (disposition: DeviceDisposition) => void;
}) {
  const [editing, setEditing] = useState(false);
  const disp = identity.disposition || "unknown";

  if (!editing) {
    return (
      <button
        onClick={() => setEditing(true)}
        className={cn(
          "rounded-full border px-2 py-0.5 text-[10px] font-medium",
          DISPOSITION_COLORS[disp] || DISPOSITION_COLORS.unknown
        )}
      >
        {DISPOSITION_LABELS[disp] || disp}
      </button>
    );
  }

  return (
    <select
      autoFocus
      className="rounded border border-border bg-background px-1.5 py-0.5 text-xs focus:outline-none focus:ring-1 focus:ring-primary"
      defaultValue={disp}
      onChange={(e) => {
        onSave(e.target.value as DeviceDisposition);
        setEditing(false);
      }}
      onBlur={() => setEditing(false)}
    >
      {DISPOSITION_OPTIONS.map((d) => (
        <option key={d.value} value={d.value}>
          {d.label}
        </option>
      ))}
    </select>
  );
}

// ── Switch binding cell ──────────────────────────────────────────

function SwitchBindingCell({
  identity,
  devices,
  onSave,
  resetField,
}: {
  identity: NetworkIdentity;
  devices: { id: string; name: string }[];
  onSave: (switchId: string, port: string) => void;
  resetField: ReturnType<typeof useResetIdentityField>;
}) {
  const [editing, setEditing] = useState(false);
  const [switchId, setSwitchId] = useState(identity.switch_device_id || "");
  const [port, setPort] = useState(identity.switch_port || "");
  const isHuman = identity.switch_binding_source === "human";

  if (!editing) {
    const deviceName = devices.find((d) => d.id === identity.switch_device_id)?.name;
    return (
      <span className="inline-flex items-center">
        <button
          onClick={() => {
            setSwitchId(identity.switch_device_id || "");
            setPort(identity.switch_port || "");
            setEditing(true);
          }}
          className={cn("rounded px-1.5 py-0.5 text-left text-xs hover:bg-muted/50", isHuman && "text-success")}
          title={isHuman ? "Human override" : "Auto-detected"}
        >
          {deviceName || identity.switch_device_id || "—"}
        </button>
        {isHuman && <ResetButton mac={identity.mac_address} field="switch_binding" resetField={resetField} />}
      </span>
    );
  }

  return (
    <div className="flex flex-col gap-1">
      <select
        autoFocus
        className="rounded border border-border bg-background px-1 py-0.5 text-xs focus:outline-none focus:ring-1 focus:ring-primary"
        value={switchId}
        onChange={(e) => setSwitchId(e.target.value)}
      >
        <option value="">— None —</option>
        {devices.map((d) => (
          <option key={d.id} value={d.id}>
            {d.name}
          </option>
        ))}
      </select>
      <div className="flex gap-1">
        <input
          type="text"
          placeholder="Port"
          className="w-20 rounded border border-border bg-background px-1 py-0.5 text-xs focus:outline-none focus:ring-1 focus:ring-primary"
          value={port}
          onChange={(e) => setPort(e.target.value)}
        />
        <button
          onClick={() => { onSave(switchId, port); setEditing(false); }}
          className="rounded bg-primary/20 px-1.5 py-0.5 text-[10px] text-primary hover:bg-primary/30"
        >
          Save
        </button>
        <button
          onClick={() => setEditing(false)}
          className="rounded px-1 py-0.5 text-[10px] text-muted-foreground hover:bg-muted"
        >
          <X className="h-3 w-3" />
        </button>
      </div>
    </div>
  );
}

// ── Infrastructure toggle cell ───────────────────────────────────

function InfrastructureCell({
  identity,
  onSave,
  resetField,
}: {
  identity: NetworkIdentity;
  onSave: (value: boolean | null) => void;
  resetField: ReturnType<typeof useResetIdentityField>;
}) {
  const val = identity.is_infrastructure;
  // Cycle: null (Auto) → true (Yes) → false (No) → null
  const next = val === null ? true : val === true ? false : null;
  const label = val === null ? "Auto" : val ? "Yes" : "No";
  const color = val === null
    ? "bg-muted text-muted-foreground border-border"
    : val
      ? "bg-primary/20 text-primary border-primary/30"
      : "bg-muted/50 text-muted-foreground/50 border-border/50";

  return (
    <span className="inline-flex items-center">
      <button
        onClick={() => onSave(next)}
        className={cn("rounded-full border px-2 py-0.5 text-[10px] font-medium", color)}
        title={`Is infrastructure: ${label}. Click to change.`}
      >
        {label}
      </button>
      {val === true && <ResetButton mac={identity.mac_address} field="is_infrastructure" resetField={resetField} />}
    </span>
  );
}

// ── Main page ───────────────────────────────────────────────────

export default function IdentityManagerPage() {
  const vlan = useVlanLookup();
  const { data: identities = [], isLoading, refetch } = useNetworkIdentities();
  const { data: stats } = useIdentityStats();
  const { data: allServices = [] } = useObservedServices();
  const updateIdentity = useUpdateIdentity();
  const resetField = useResetIdentityField();
  const bulkConfirm = useBulkConfirmIdentities();
  const setDisposition = useSetDisposition();
  const bulkDisposition = useBulkDisposition();
  const { data: violations = [] } = usePortViolations();
  const { data: devices = [] } = useDevices();
  const { data: bandwidthData = [] } = useClientBandwidth();

  // Build MAC → bandwidth lookup
  const bandwidthByMac = useMemo(() => {
    const map = new Map<string, ClientBandwidth>();
    for (const bw of bandwidthData) {
      map.set(bw.mac, bw);
    }
    return map;
  }, [bandwidthData]);

  // Build IP → services lookup for showing ports per identity
  const servicesByIp = useMemo(() => {
    const map = new Map<string, ObservedService[]>();
    for (const svc of allServices) {
      const list = map.get(svc.ip_address) || [];
      list.push(svc);
      map.set(svc.ip_address, list);
    }
    return map;
  }, [allServices]);

  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [filterType, setFilterType] = useState<string>("");
  const [filterSource, setFilterSource] = useState<string>("");
  const [filterConfirmed, setFilterConfirmed] = useState<string>(""); // "" | "confirmed" | "unconfirmed"
  const [filterVlan, setFilterVlan] = useState<string>("");
  const [filterDisposition, setFilterDisposition] = useState<string>("visible"); // "visible" = default (hides ignored)
  const [showFilters, setShowFilters] = useState(false);
  const [bulkDispositionValue, setBulkDispositionValue] = useState<DeviceDisposition>("my_device");

  // Filter identities
  const filtered = useMemo(() => {
    let result = identities;
    if (filterType) {
      result = result.filter(
        (i) => (i.device_type || "unknown") === filterType
      );
    }
    if (filterSource) {
      result = result.filter(
        (i) => (i.device_type_source || "none") === filterSource
      );
    }
    if (filterConfirmed === "confirmed") {
      result = result.filter((i) => i.human_confirmed);
    } else if (filterConfirmed === "unconfirmed") {
      result = result.filter((i) => !i.human_confirmed);
    }
    if (filterVlan) {
      result = result.filter((i) => String(i.vlan_id) === filterVlan);
    }
    // Disposition filter
    if (filterDisposition === "visible") {
      // Default: hide ignored
      result = result.filter((i) => (i.disposition || "unknown") !== "ignored");
    } else if (filterDisposition && filterDisposition !== "all") {
      result = result.filter((i) => (i.disposition || "unknown") === filterDisposition);
    }
    return result;
  }, [identities, filterType, filterSource, filterConfirmed, filterVlan, filterDisposition]);

  const toggleSelect = (mac: string) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(mac)) next.delete(mac);
      else next.add(mac);
      return next;
    });
  };

  const toggleSelectAll = () => {
    if (selected.size === filtered.length) {
      setSelected(new Set());
    } else {
      setSelected(new Set(filtered.map((i) => i.mac_address)));
    }
  };

  const handleSaveType = (mac: string, deviceType: string) => {
    updateIdentity.mutate({ mac, data: { device_type: deviceType || undefined } });
  };

  const handleSaveLabel = (mac: string, label: string) => {
    updateIdentity.mutate({ mac, data: { human_label: label || undefined } });
  };

  const handleConfirm = (mac: string) => {
    bulkConfirm.mutate([mac]);
  };

  const handleBulkConfirm = () => {
    bulkConfirm.mutate(Array.from(selected), {
      onSuccess: () => setSelected(new Set()),
    });
  };

  const handleSetDisposition = (mac: string, disposition: DeviceDisposition) => {
    setDisposition.mutate({ mac, disposition });
  };

  const handleSaveSwitch = (mac: string, switchDeviceId: string, switchPort: string) => {
    updateIdentity.mutate({
      mac,
      data: {
        switch_device_id: switchDeviceId || undefined,
        switch_port: switchPort || undefined,
      },
    });
  };

  const handleSetInfrastructure = (mac: string, value: boolean | null) => {
    updateIdentity.mutate({
      mac,
      data: { is_infrastructure: value },
    });
  };

  const handleBulkDisposition = (disposition: DeviceDisposition) => {
    bulkDisposition.mutate(
      { macs: Array.from(selected), disposition },
      { onSuccess: () => setSelected(new Set()) }
    );
  };

  // Unique values for filter dropdowns
  const uniqueTypes = useMemo(
    () => [...new Set(identities.map((i) => i.device_type || "unknown"))].sort(),
    [identities]
  );
  const uniqueSources = useMemo(
    () => [...new Set(identities.map((i) => i.device_type_source || "none"))].sort(),
    [identities]
  );
  const uniqueVlans = useMemo(
    () =>
      [...new Set(identities.filter((i) => i.vlan_id).map((i) => i.vlan_id!))]
        .sort((a, b) => a - b),
    [identities]
  );

  const columns: Column<NetworkIdentity>[] = [
    {
      key: "select",
      header: "",
      render: (row) => (
        <input
          type="checkbox"
          checked={selected.has(row.mac_address)}
          onChange={() => toggleSelect(row.mac_address)}
          className="h-3.5 w-3.5 rounded border-border"
        />
      ),
    },
    {
      key: "status",
      header: "",
      render: (row) => (
        <div className={cn("h-2.5 w-2.5 rounded-full", statusDot(row))} />
      ),
    },
    {
      key: "disposition",
      header: "Disposition",
      render: (row) => (
        <DispositionCell
          identity={row}
          onSave={(d) => handleSetDisposition(row.mac_address, d)}
        />
      ),
      sortValue: (row) => row.disposition || "unknown",
    },
    {
      key: "mac",
      header: "MAC Address",
      render: (row) => (
        <span className="font-mono text-xs">{row.mac_address}</span>
      ),
      sortValue: (row) => row.mac_address,
    },
    {
      key: "ip",
      header: "IP",
      render: (row) => (
        <span className="font-mono text-xs">{row.best_ip || "—"}</span>
      ),
      sortValue: (row) => row.best_ip || "",
    },
    {
      key: "hostname",
      header: "Hostname",
      render: (row) => row.hostname || "—",
      sortValue: (row) => row.hostname || "",
    },
    {
      key: "manufacturer",
      header: "Manufacturer",
      render: (row) => (
        <span className="max-w-32 truncate" title={row.manufacturer || undefined}>
          {row.manufacturer || "—"}
        </span>
      ),
      sortValue: (row) => row.manufacturer || "",
    },
    {
      key: "device_type",
      header: "Device Type",
      render: (row) => (
        <DeviceTypeCell
          identity={row}
          onSave={(type) => handleSaveType(row.mac_address, type)}
          resetField={resetField}
        />
      ),
      sortValue: (row) => row.device_type || "zzz",
    },
    {
      key: "source",
      header: "Source",
      render: (row) => {
        const src = row.device_type_source || "none";
        return (
          <span
            className={cn(
              "rounded-full border px-2 py-0.5 text-[10px] font-medium uppercase",
              SOURCE_COLORS[src] || SOURCE_COLORS.none
            )}
          >
            {src}
          </span>
        );
      },
      sortValue: (row) => row.device_type_source || "none",
    },
    {
      key: "confidence",
      header: "Conf",
      render: (row) => (
        <div className="flex items-center gap-1.5">
          <div className="h-1.5 w-12 rounded-full bg-muted">
            <div
              className="h-full rounded-full bg-primary"
              style={{ width: `${row.device_type_confidence * 100}%` }}
            />
          </div>
          <span className="text-[10px] text-muted-foreground">
            {(row.device_type_confidence * 100).toFixed(0)}%
          </span>
        </div>
      ),
      sortValue: (row) => row.device_type_confidence,
    },
    {
      key: "label",
      header: "Label",
      headerTitle: "Overrides the auto-discovered hostname in the topology map. Clear with the X button to revert.",
      render: (row) => (
        <LabelCell
          identity={row}
          onSave={(label) => handleSaveLabel(row.mac_address, label)}
          resetField={resetField}
        />
      ),
      sortValue: (row) => row.human_label || "",
    },
    {
      key: "vlan",
      header: "VLAN",
      render: (row) => {
        if (!row.vlan_id) return "—";
        const config = vlan.configs[row.vlan_id];
        return (
          <span className="flex items-center gap-1.5">
            <span
              className="h-2 w-2 rounded-full"
              style={{ backgroundColor: config?.color || "#666" }}
            />
            <span className="text-xs">{row.vlan_id}</span>
          </span>
        );
      },
      sortValue: (row) => row.vlan_id || 0,
    },
    {
      key: "switch",
      header: "Switch",
      render: (row) => (
        <SwitchBindingCell
          identity={row}
          devices={devices}
          onSave={(switchId, port) => handleSaveSwitch(row.mac_address, switchId, port)}
          resetField={resetField}
        />
      ),
      sortValue: (row) => row.switch_device_id || "",
    },
    {
      key: "port",
      header: "Port",
      render: (row) => {
        const isHuman = row.switch_binding_source === "human";
        return (
          <span className={cn("text-xs", isHuman && "text-success")} title={isHuman ? "Human override" : undefined}>
            {row.switch_port || "—"}
          </span>
        );
      },
      sortValue: (row) => row.switch_port || "",
    },
    {
      key: "speed",
      header: "Speed",
      render: (row) => {
        const mbps = row.link_speed_mbps ?? 1000;
        const label =
          mbps >= 1000 ? `${mbps / 1000}G` : `${mbps}M`;
        return (
          <span
            className={cn(
              "text-xs font-mono",
              row.link_speed_mbps == null && "text-muted-foreground"
            )}
            title={row.link_speed_mbps == null ? "Default (no polled speed)" : `${mbps} Mbps`}
          >
            {label}
          </span>
        );
      },
      sortValue: (row) => row.link_speed_mbps ?? 1000,
    },
    {
      key: "traffic_1h",
      header: "Traffic (1h)",
      render: (row) => {
        const bw = bandwidthByMac.get(row.mac_address);
        if (!bw || bw.bytes_1h === 0) return <span className="text-xs text-muted-foreground">—</span>;
        return (
          <span className="text-xs font-mono" title={`${bw.connections_1h} connection${bw.connections_1h !== 1 ? "s" : ""}`}>
            {formatBytes(bw.bytes_1h)}
            <span className="ml-1 text-[10px] text-muted-foreground">({bw.connections_1h})</span>
          </span>
        );
      },
      sortValue: (row) => bandwidthByMac.get(row.mac_address)?.bytes_1h ?? 0,
    },
    {
      key: "baseline",
      header: "Baseline",
      render: (row) => {
        const bw = bandwidthByMac.get(row.mac_address);
        if (!bw || bw.baseline_bytes_per_hour === 0) {
          return <span className="text-xs text-muted-foreground">—</span>;
        }
        const ratio = bw.bytes_1h / bw.baseline_bytes_per_hour;
        const color = ratio > 3
          ? "text-destructive"
          : ratio > 1.5
            ? "text-warning"
            : "text-muted-foreground";
        const indicator = ratio > 3
          ? "!!!"
          : ratio > 1.5
            ? "!"
            : "";
        return (
          <span className={cn("text-xs font-mono", color)} title={`Baseline: ${formatBytes(bw.baseline_bytes_per_hour)}/hr — Current: ${ratio.toFixed(1)}x`}>
            {formatBytes(bw.baseline_bytes_per_hour)}/h
            {indicator && <span className="ml-0.5 font-bold">{indicator}</span>}
          </span>
        );
      },
      sortValue: (row) => bandwidthByMac.get(row.mac_address)?.baseline_bytes_per_hour ?? 0,
    },
    {
      key: "infra",
      header: "Infra",
      render: (row) => (
        <InfrastructureCell
          identity={row}
          onSave={(val) => handleSetInfrastructure(row.mac_address, val)}
          resetField={resetField}
        />
      ),
      sortValue: (row) => row.is_infrastructure === null ? 1 : row.is_infrastructure ? 2 : 0,
    },
    {
      key: "services",
      header: "Services",
      render: (row) => {
        const services = row.best_ip ? servicesByIp.get(row.best_ip) : undefined;
        if (!services || services.length === 0) return <span className="text-xs text-muted-foreground">—</span>;
        // Show up to 4 service badges, then "+N"
        const shown = services.slice(0, 4);
        const remaining = services.length - shown.length;
        return (
          <div className="flex flex-wrap gap-0.5" title={services.map(s => `${s.port}/${s.protocol}${s.service_name ? ` (${s.service_name})` : ""}`).join(", ")}>
            {shown.map((s) => (
              <span
                key={`${s.port}-${s.protocol}`}
                className="rounded bg-muted px-1 py-0.5 text-[10px] font-mono text-muted-foreground"
              >
                {s.service_name || s.port}
              </span>
            ))}
            {remaining > 0 && (
              <span className="rounded bg-muted px-1 py-0.5 text-[10px] text-muted-foreground">
                +{remaining}
              </span>
            )}
          </div>
        );
      },
      sortValue: (row) => {
        const services = row.best_ip ? servicesByIp.get(row.best_ip) : undefined;
        return services?.length ?? 0;
      },
    },
    {
      key: "last_seen",
      header: "Last Seen",
      render: (row) => (
        <span className="text-xs text-muted-foreground">
          {formatTimeAgo(row.last_seen)}
        </span>
      ),
      sortValue: (row) => row.last_seen,
    },
    {
      key: "investigate",
      header: "",
      render: (row) => (
        <Link
          to="/sankey"
          search={{ mac: row.mac_address }}
          className="rounded p-1 text-muted-foreground hover:bg-primary/15 hover:text-primary"
          title="Investigate traffic"
        >
          <Microscope className="h-3.5 w-3.5" />
        </Link>
      ),
    },
    {
      key: "actions",
      header: "",
      render: (row) =>
        !row.human_confirmed ? (
          <button
            onClick={() => handleConfirm(row.mac_address)}
            className="rounded p-1 text-muted-foreground hover:bg-success/10 hover:text-success"
            title="Confirm identity"
          >
            <Check className="h-3.5 w-3.5" />
          </button>
        ) : (
          <CheckCircle2 className="h-3.5 w-3.5 text-success" />
        ),
    },
  ];

  const anyFiltersActive = filterType || filterSource || filterConfirmed || filterVlan || (filterDisposition !== "visible" && filterDisposition !== "");

  return (
    <PageShell
      title="Identity Manager"
      onRefresh={() => refetch()}
      isRefreshing={isLoading}
      help={<IdentityManagerHelp />}
    >
      {/* Port violation banner */}
      {violations.length > 0 && (
        <div className="mb-4 flex items-center gap-2 rounded-lg border border-destructive/30 bg-destructive/10 px-4 py-2">
          <AlertCircle className="h-4 w-4 text-destructive flex-shrink-0" />
          <span className="text-sm font-medium text-destructive">
            {violations.length} port violation{violations.length !== 1 ? "s" : ""} detected
          </span>
          <span className="text-xs text-destructive/70">
            — {violations.filter(v => v.violation_type === "mac_mismatch").length} MAC mismatch, {violations.filter(v => v.violation_type === "device_missing").length} device missing
          </span>
        </div>
      )}

      {/* Stats bar */}
      <div className="mb-6 grid grid-cols-2 gap-4 md:grid-cols-4">
        <StatCard title="Total Identities" icon={<Users className="h-4 w-4" />}>
          <div className="text-2xl font-bold">{stats?.total ?? "—"}</div>
        </StatCard>
        <StatCard
          title="Confirmed"
          icon={<CheckCircle2 className="h-4 w-4 text-success" />}
        >
          <div className="text-2xl font-bold text-success">
            {stats?.confirmed ?? "—"}
            {stats && stats.total > 0 && (
              <span className="ml-1 text-sm font-normal text-muted-foreground">
                ({((stats.confirmed / stats.total) * 100).toFixed(0)}%)
              </span>
            )}
          </div>
        </StatCard>
        <StatCard
          title="Needs Review"
          icon={<AlertCircle className="h-4 w-4 text-warning" />}
        >
          <div className="text-2xl font-bold text-warning">
            {stats?.unconfirmed ?? "—"}
          </div>
        </StatCard>
        <StatCard
          title="By Source"
          icon={<Fingerprint className="h-4 w-4" />}
        >
          <div className="flex flex-wrap gap-1.5">
            {stats?.by_source &&
              Object.entries(stats.by_source)
                .sort(([, a], [, b]) => b - a)
                .map(([source, count]) => (
                  <span
                    key={source}
                    className={cn(
                      "rounded-full border px-2 py-0.5 text-[10px] font-medium",
                      SOURCE_COLORS[source] || SOURCE_COLORS.none
                    )}
                  >
                    {source}: {count}
                  </span>
                ))}
          </div>
        </StatCard>
      </div>

      {/* Filter bar */}
      <div className="mb-4 flex items-center gap-2 flex-wrap">
        <button
          onClick={() => setShowFilters(!showFilters)}
          className={cn(
            "flex items-center gap-1.5 rounded-md border px-3 py-1.5 text-xs transition-colors",
            anyFiltersActive
              ? "border-primary/50 bg-primary/10 text-primary"
              : "border-border text-muted-foreground hover:bg-muted"
          )}
        >
          <Filter className="h-3.5 w-3.5" />
          Filters
          {anyFiltersActive && (
            <span className="rounded-full bg-primary px-1.5 text-[10px] text-primary-foreground">
              {[filterType, filterSource, filterConfirmed, filterVlan].filter(Boolean).length}
            </span>
          )}
        </button>

        <button
          onClick={() => setFilterConfirmed(filterConfirmed === "unconfirmed" ? "" : "unconfirmed")}
          className={cn(
            "rounded-md border px-3 py-1.5 text-xs transition-colors",
            filterConfirmed === "unconfirmed"
              ? "border-amber-500/50 bg-amber-500/10 text-warning"
              : "border-border text-muted-foreground hover:bg-muted"
          )}
        >
          Review Queue
        </button>

        {anyFiltersActive && (
          <button
            onClick={() => {
              setFilterType("");
              setFilterSource("");
              setFilterConfirmed("");
              setFilterVlan("");
              setFilterDisposition("visible");
            }}
            className="flex items-center gap-1 rounded-md border border-border px-2 py-1.5 text-xs text-muted-foreground hover:bg-muted"
          >
            <X className="h-3 w-3" />
            Clear
          </button>
        )}

        <span className="text-xs text-muted-foreground ml-auto">
          {filtered.length} of {identities.length} identities
        </span>
      </div>

      {showFilters && (
        <div className="mb-4 flex flex-wrap gap-3 rounded-lg border border-border bg-muted/30 p-3">
          <div className="flex flex-col gap-1">
            <label className="text-[10px] uppercase text-muted-foreground">Device Type</label>
            <select
              value={filterType}
              onChange={(e) => setFilterType(e.target.value)}
              className="rounded border border-border bg-background px-2 py-1 text-xs"
            >
              <option value="">All</option>
              {uniqueTypes.map((t) => (
                <option key={t} value={t}>
                  {DEVICE_TYPE_LABELS[t] || t}
                </option>
              ))}
            </select>
          </div>
          <div className="flex flex-col gap-1">
            <label className="text-[10px] uppercase text-muted-foreground">Source</label>
            <select
              value={filterSource}
              onChange={(e) => setFilterSource(e.target.value)}
              className="rounded border border-border bg-background px-2 py-1 text-xs"
            >
              <option value="">All</option>
              {uniqueSources.map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </select>
          </div>
          <div className="flex flex-col gap-1">
            <label className="text-[10px] uppercase text-muted-foreground">Status</label>
            <select
              value={filterConfirmed}
              onChange={(e) => setFilterConfirmed(e.target.value)}
              className="rounded border border-border bg-background px-2 py-1 text-xs"
            >
              <option value="">All</option>
              <option value="confirmed">Confirmed</option>
              <option value="unconfirmed">Unconfirmed</option>
            </select>
          </div>
          <div className="flex flex-col gap-1">
            <label className="text-[10px] uppercase text-muted-foreground">VLAN</label>
            <select
              value={filterVlan}
              onChange={(e) => setFilterVlan(e.target.value)}
              className="rounded border border-border bg-background px-2 py-1 text-xs"
            >
              <option value="">All</option>
              {uniqueVlans.map((v) => (
                <option key={v} value={String(v)}>
                  VLAN {v} — {vlan.name(v)}
                </option>
              ))}
            </select>
          </div>
          <div className="flex flex-col gap-1">
            <label className="text-[10px] uppercase text-muted-foreground">Disposition</label>
            <select
              value={filterDisposition}
              onChange={(e) => setFilterDisposition(e.target.value)}
              className="rounded border border-border bg-background px-2 py-1 text-xs"
            >
              <option value="visible">Default (hide ignored)</option>
              <option value="all">All</option>
              {DISPOSITION_OPTIONS.map((d) => (
                <option key={d.value} value={d.value}>
                  {d.label}
                </option>
              ))}
            </select>
          </div>
        </div>
      )}

      {/* Select all checkbox */}
      {filtered.length > 0 && (
        <div className="mb-2 flex items-center gap-2">
          <input
            type="checkbox"
            checked={selected.size === filtered.length && filtered.length > 0}
            onChange={toggleSelectAll}
            className="h-3.5 w-3.5 rounded border-border"
          />
          <span className="text-xs text-muted-foreground">
            Select all ({filtered.length})
          </span>
        </div>
      )}

      {/* Identity table */}
      <DataTable
        columns={columns}
        data={filtered}
        rowKey={(row) => row.mac_address}
        emptyMessage="No identities found"
        defaultSort={{ key: "last_seen", asc: false }}
        searchable
        searchPlaceholder="Search MAC, IP, hostname, manufacturer..."
      />

      {/* Bulk action bar */}
      {selected.size > 0 && (
        <div className="fixed bottom-4 left-1/2 z-50 flex -translate-x-1/2 items-center gap-3 rounded-lg border border-border bg-card px-4 py-3 shadow-lg">
          <span className="text-sm font-medium">
            {selected.size} selected
          </span>
          <button
            onClick={handleBulkConfirm}
            disabled={bulkConfirm.isPending}
            className="rounded-md bg-success px-3 py-1.5 text-xs font-medium text-background hover:bg-success/80 disabled:opacity-50"
          >
            Confirm All
          </button>
          <div className="h-4 w-px bg-border" />
          <select
            value={bulkDispositionValue}
            onChange={(e) => setBulkDispositionValue(e.target.value as DeviceDisposition)}
            className="rounded border border-border bg-background px-2 py-1 text-xs"
          >
            {DISPOSITION_OPTIONS.map((d) => (
              <option key={d.value} value={d.value}>
                {d.label}
              </option>
            ))}
          </select>
          <button
            onClick={() => handleBulkDisposition(bulkDispositionValue)}
            disabled={bulkDisposition.isPending}
            className="rounded-md bg-primary px-3 py-1.5 text-xs font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
          >
            Set Disposition
          </button>
          <div className="h-4 w-px bg-border" />
          <button
            onClick={() => setSelected(new Set())}
            className="rounded-md border border-border px-3 py-1.5 text-xs text-muted-foreground hover:bg-muted"
          >
            Clear
          </button>
        </div>
      )}
    </PageShell>
  );
}
