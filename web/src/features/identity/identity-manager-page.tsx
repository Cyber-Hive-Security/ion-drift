import { useState, useMemo } from "react";
import {
  Fingerprint,
  CheckCircle2,
  AlertCircle,
  Users,
  Check,
  X,
  Filter,
} from "lucide-react";
import { PageShell } from "@/components/layout/page-shell";
import { StatCard } from "@/components/stat-card";
import { DataTable, type Column } from "@/components/data-table";
import { cn } from "@/lib/utils";
import {
  useNetworkIdentities,
  useIdentityStats,
  useUpdateIdentity,
  useBulkConfirmIdentities,
  useObservedServices,
} from "@/api/queries";
import type { NetworkIdentity, ObservedService } from "@/api/types";
import { VLAN_CONFIG } from "@/features/network-map/data";

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
  human: "bg-green-500/20 text-green-400 border-green-500/30",
  lldp: "bg-blue-500/20 text-blue-400 border-blue-500/30",
  nmap: "bg-purple-500/20 text-purple-400 border-purple-500/30",
  conntrack: "bg-teal-500/20 text-teal-400 border-teal-500/30",
  traffic_pattern: "bg-amber-500/20 text-amber-400 border-amber-500/30",
  oui: "bg-cyan-500/20 text-cyan-400 border-cyan-500/30",
  none: "bg-muted text-muted-foreground border-border",
};

// ── Helpers ─────────────────────────────────────────────────────

function formatTimeAgo(unixSecs: number): string {
  const diff = Date.now() / 1000 - unixSecs;
  if (diff < 60) return "just now";
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

function statusDot(identity: NetworkIdentity): string {
  if (identity.human_confirmed) return "bg-green-500"; // confirmed
  if (identity.device_type_source === "lldp") return "bg-blue-500"; // LLDP
  if (identity.device_type && identity.device_type_confidence >= 0.6)
    return "bg-amber-500"; // automated
  if (identity.device_type) return "bg-orange-500"; // low confidence
  return "bg-muted-foreground/30"; // no type
}

// ── Inline edit components ──────────────────────────────────────

function DeviceTypeCell({
  identity,
  onSave,
}: {
  identity: NetworkIdentity;
  onSave: (type: string) => void;
}) {
  const [editing, setEditing] = useState(false);

  if (!editing) {
    return (
      <button
        onClick={() => setEditing(true)}
        className="rounded px-1.5 py-0.5 text-left hover:bg-muted/50"
      >
        {identity.device_type
          ? DEVICE_TYPE_LABELS[identity.device_type] || identity.device_type
          : "—"}
      </button>
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
}: {
  identity: NetworkIdentity;
  onSave: (label: string) => void;
}) {
  const [editing, setEditing] = useState(false);
  const [value, setValue] = useState(identity.human_label || "");

  if (!editing) {
    return (
      <button
        onClick={() => {
          setValue(identity.human_label || "");
          setEditing(true);
        }}
        className="rounded px-1.5 py-0.5 text-left hover:bg-muted/50"
      >
        {identity.human_label || "—"}
      </button>
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

// ── Main page ───────────────────────────────────────────────────

export default function IdentityManagerPage() {
  const { data: identities = [], isLoading, refetch } = useNetworkIdentities();
  const { data: stats } = useIdentityStats();
  const { data: allServices = [] } = useObservedServices();
  const updateIdentity = useUpdateIdentity();
  const bulkConfirm = useBulkConfirmIdentities();

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
  const [showFilters, setShowFilters] = useState(false);

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
    return result;
  }, [identities, filterType, filterSource, filterConfirmed, filterVlan]);

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
      render: (row) => (
        <LabelCell
          identity={row}
          onSave={(label) => handleSaveLabel(row.mac_address, label)}
        />
      ),
      sortValue: (row) => row.human_label || "",
    },
    {
      key: "vlan",
      header: "VLAN",
      render: (row) => {
        if (!row.vlan_id) return "—";
        const config = VLAN_CONFIG[row.vlan_id];
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
      key: "port",
      header: "Port",
      render: (row) => (
        <span className="text-xs">{row.switch_port || "—"}</span>
      ),
      sortValue: (row) => row.switch_port || "",
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
      key: "actions",
      header: "",
      render: (row) =>
        !row.human_confirmed ? (
          <button
            onClick={() => handleConfirm(row.mac_address)}
            className="rounded p-1 text-muted-foreground hover:bg-green-500/10 hover:text-green-500"
            title="Confirm identity"
          >
            <Check className="h-3.5 w-3.5" />
          </button>
        ) : (
          <CheckCircle2 className="h-3.5 w-3.5 text-green-500" />
        ),
    },
  ];

  const anyFiltersActive = filterType || filterSource || filterConfirmed || filterVlan;

  return (
    <PageShell
      title="Identity Manager"
      onRefresh={() => refetch()}
      isRefreshing={isLoading}
    >
      {/* Stats bar */}
      <div className="mb-6 grid grid-cols-2 gap-4 md:grid-cols-4">
        <StatCard title="Total Identities" icon={<Users className="h-4 w-4" />}>
          <div className="text-2xl font-bold">{stats?.total ?? "—"}</div>
        </StatCard>
        <StatCard
          title="Confirmed"
          icon={<CheckCircle2 className="h-4 w-4 text-green-500" />}
        >
          <div className="text-2xl font-bold text-green-500">
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
          icon={<AlertCircle className="h-4 w-4 text-amber-500" />}
        >
          <div className="text-2xl font-bold text-amber-500">
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
              ? "border-amber-500/50 bg-amber-500/10 text-amber-500"
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
                  VLAN {v} — {VLAN_CONFIG[v]?.name || "Unknown"}
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
            className="rounded-md bg-green-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-green-700 disabled:opacity-50"
          >
            Confirm All
          </button>
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
