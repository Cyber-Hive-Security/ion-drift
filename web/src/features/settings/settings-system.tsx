import { useState } from "react";
import { LoadingSpinner } from "@/components/loading-spinner";
import {
  useSyslogStatus,
  useGeoIpStatus,
  useConnectionHistoryStats,
  useMonitoredRegions,
  useUpdateMonitoredRegions,
  useUpdateGeoipDatabases,
  useResetBehavior,
  useResetPreview,
} from "@/api/queries";
import type { BehaviorResetCounts } from "@/api/queries";
import { useQuery } from "@tanstack/react-query";
import { apiFetch } from "@/api/client";
import {
  Radio,
  Globe,
  MapPin,
  Database,
  Check,
  AlertTriangle,
  RefreshCw,
  X,
  Trash2,
  Brain,
  Info,
} from "lucide-react";
import { formatBytes, formatNumber } from "@/lib/format";

// ── About Section ───────────────────────────────────────────────

function AboutSection() {
  const { data } = useQuery({
    queryKey: ["health"],
    queryFn: () => apiFetch<{ status: string; version: string }>("/health"),
    staleTime: Infinity,
  });

  return (
    <div className="rounded-lg border border-border bg-card">
      <div className="flex items-center gap-3 border-b border-border p-4">
        <Info className="h-5 w-5 text-primary" />
        <h2 className="text-lg font-semibold">About Ion Drift</h2>
      </div>
      <div className="p-4 space-y-3">
        <div className="flex items-center justify-between">
          <span className="text-sm text-muted-foreground">Version</span>
          <span className="text-sm font-mono">{data?.version ?? "—"}</span>
        </div>
        <div className="flex items-center justify-between">
          <span className="text-sm text-muted-foreground">License</span>
          <a
            href="https://polyformproject.org/licenses/shield/1.0.0/"
            target="_blank"
            rel="noopener noreferrer"
            className="text-sm text-primary hover:underline"
          >
            PolyForm Shield 1.0.0
          </a>
        </div>
        <div className="flex items-center justify-between">
          <span className="text-sm text-muted-foreground">Publisher</span>
          <a
            href="https://www.mycyberhive.com"
            target="_blank"
            rel="noopener noreferrer"
            className="text-sm text-primary hover:underline"
          >
            Cyber Hive Security LLC
          </a>
        </div>
      </div>
    </div>
  );
}

// ── Syslog Section ──────────────────────────────────────────────

function SyslogSection() {
  const { data, isLoading } = useSyslogStatus();

  if (isLoading) return <LoadingSpinner />;
  if (!data) return null;

  return (
    <div className="rounded-lg border border-border bg-card">
      <div className="flex items-center gap-3 border-b border-border p-4">
        <Radio className="h-5 w-5 text-primary" />
        <h2 className="text-lg font-semibold">Syslog Listener</h2>
      </div>

      <div className="p-4 space-y-3">
        <div className="flex items-center justify-between">
          <span className="text-sm text-muted-foreground">Status</span>
          <div className="flex items-center gap-1.5">
            {data.listening ? (
              <>
                <span className="h-2 w-2 rounded-full bg-success animate-pulse" />
                <span className="text-sm text-success">Listening</span>
              </>
            ) : (
              <>
                <span className="h-2 w-2 rounded-full bg-muted-foreground" />
                <span className="text-sm text-muted-foreground">Stopped</span>
              </>
            )}
          </div>
        </div>
        <div className="flex items-center justify-between">
          <span className="text-sm text-muted-foreground">Port</span>
          <code className="text-sm font-mono">{data.port}</code>
        </div>
        <div className="flex items-center justify-between">
          <span className="text-sm text-muted-foreground">Events Today</span>
          <span className="text-sm">{formatNumber(data.events_today)}</span>
        </div>
        <div className="flex items-center justify-between">
          <span className="text-sm text-muted-foreground">Events This Week</span>
          <span className="text-sm">{formatNumber(data.events_week)}</span>
        </div>

        <div className="mt-4 rounded-md bg-muted/50 p-3">
          <p className="text-xs font-medium text-muted-foreground mb-2">
            RouterOS Configuration
          </p>
          <pre className="text-xs font-mono text-muted-foreground whitespace-pre-wrap select-all">
{`/system logging action
add name=ion-drift target=remote remote=<ion-drift-ip> remote-port=${data.port} bsd-syslog=yes

/system logging
add action=ion-drift topics=firewall`}
          </pre>
        </div>
      </div>
    </div>
  );
}

// ── GeoIP Section ───────────────────────────────────────────────

function GeoIpSection() {
  const { data, isLoading } = useGeoIpStatus();
  const updateMutation = useUpdateGeoipDatabases();

  if (isLoading) return <LoadingSpinner />;
  if (!data) return null;

  return (
    <div className="rounded-lg border border-border bg-card">
      <div className="flex items-center gap-3 border-b border-border p-4">
        <Globe className="h-5 w-5 text-primary" />
        <h2 className="text-lg font-semibold">GeoIP Database</h2>
      </div>

      <div className="p-4 space-y-3">
        <div className="flex items-center justify-between">
          <span className="text-sm text-muted-foreground">Status</span>
          <div className="flex items-center gap-1.5">
            {data.loaded ? (
              <>
                <Check className="h-3.5 w-3.5 text-success" />
                <span className="text-sm text-success">
                  {data.source === "maxmind" ? "MaxMind GeoLite2" : data.source === "dbip" ? "DB-IP Lite" : "Loaded"}
                </span>
              </>
            ) : (
              <>
                <AlertTriangle className="h-3.5 w-3.5 text-warning" />
                <span className="text-sm text-warning">Not loaded</span>
              </>
            )}
          </div>
        </div>
        {data.source === "dbip" && !data.has_credentials && (
          <p className="text-xs text-muted-foreground">
            Using bundled DB-IP Lite databases. For improved city-level accuracy, add MaxMind credentials below.
          </p>
        )}
        <div className="flex items-center justify-between">
          <span className="text-sm text-muted-foreground">MaxMind Credentials</span>
          <div className="flex items-center gap-1.5">
            {data.has_credentials ? (
              <>
                <Check className="h-3.5 w-3.5 text-success" />
                <span className="text-sm text-success">Configured</span>
              </>
            ) : (
              <span className="text-sm text-muted-foreground">Not configured</span>
            )}
          </div>
        </div>
        {data.has_credentials && (
          <div className="flex items-center justify-between pt-1">
            <span className="text-sm text-muted-foreground">
              {data.source === "maxmind" ? "Re-download latest databases" : "Download MaxMind databases"}
            </span>
            <button
              onClick={() => updateMutation.mutate()}
              disabled={updateMutation.isPending}
              className="inline-flex items-center gap-1.5 rounded-md bg-primary px-3 py-1.5 text-xs font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
            >
              <RefreshCw className={`h-3.5 w-3.5 ${updateMutation.isPending ? "animate-spin" : ""}`} />
              {updateMutation.isPending ? "Downloading\u2026" : "Update GeoIP"}
            </button>
          </div>
        )}
        {updateMutation.isSuccess && (
          <p className="text-xs text-success">
            Updated: {updateMutation.data.downloaded.join(", ")}
          </p>
        )}
        {updateMutation.isError && (
          <p className="text-xs text-destructive">
            {(updateMutation.error as Error)?.message || "Download failed"}
          </p>
        )}
        {!data.has_credentials && !data.loaded && (
          <p className="text-xs text-muted-foreground mt-2">
            Add MaxMind Account ID and License Key in the Security tab to enable GeoIP.
            Free account required &mdash;{" "}
            <a
              href="https://www.maxmind.com/en/geolite2/signup"
              target="_blank"
              rel="noopener noreferrer"
              className="text-primary hover:underline"
            >
              sign up at maxmind.com
            </a>
          </p>
        )}
        {data.attribution && (
          <p className="text-[10px] text-muted-foreground/60 mt-3 pt-2 border-t border-border">
            {data.attribution}
          </p>
        )}
      </div>
    </div>
  );
}

// ── Monitored Regions Section ────────────────────────────────────

const COUNTRY_LIST: { code: string; name: string }[] = [
  { code: "AF", name: "Afghanistan" }, { code: "AL", name: "Albania" },
  { code: "DZ", name: "Algeria" }, { code: "AO", name: "Angola" },
  { code: "AR", name: "Argentina" }, { code: "AM", name: "Armenia" },
  { code: "AU", name: "Australia" }, { code: "AT", name: "Austria" },
  { code: "AZ", name: "Azerbaijan" }, { code: "BH", name: "Bahrain" },
  { code: "BD", name: "Bangladesh" }, { code: "BY", name: "Belarus" },
  { code: "BE", name: "Belgium" }, { code: "BJ", name: "Benin" },
  { code: "BO", name: "Bolivia" }, { code: "BA", name: "Bosnia and Herzegovina" },
  { code: "BR", name: "Brazil" }, { code: "BG", name: "Bulgaria" },
  { code: "BF", name: "Burkina Faso" }, { code: "KH", name: "Cambodia" },
  { code: "CM", name: "Cameroon" }, { code: "CA", name: "Canada" },
  { code: "CF", name: "Central African Republic" }, { code: "TD", name: "Chad" },
  { code: "CL", name: "Chile" }, { code: "CN", name: "China" },
  { code: "CO", name: "Colombia" }, { code: "CD", name: "Congo (DRC)" },
  { code: "CR", name: "Costa Rica" }, { code: "HR", name: "Croatia" },
  { code: "CU", name: "Cuba" }, { code: "CY", name: "Cyprus" },
  { code: "CZ", name: "Czechia" }, { code: "DK", name: "Denmark" },
  { code: "DO", name: "Dominican Republic" }, { code: "EC", name: "Ecuador" },
  { code: "EG", name: "Egypt" }, { code: "SV", name: "El Salvador" },
  { code: "EE", name: "Estonia" }, { code: "ET", name: "Ethiopia" },
  { code: "FI", name: "Finland" }, { code: "FR", name: "France" },
  { code: "GE", name: "Georgia" }, { code: "DE", name: "Germany" },
  { code: "GH", name: "Ghana" }, { code: "GR", name: "Greece" },
  { code: "GT", name: "Guatemala" }, { code: "HT", name: "Haiti" },
  { code: "HN", name: "Honduras" }, { code: "HK", name: "Hong Kong" },
  { code: "HU", name: "Hungary" }, { code: "IS", name: "Iceland" },
  { code: "IN", name: "India" }, { code: "ID", name: "Indonesia" },
  { code: "IR", name: "Iran" }, { code: "IQ", name: "Iraq" },
  { code: "IE", name: "Ireland" }, { code: "IL", name: "Israel" },
  { code: "IT", name: "Italy" }, { code: "JM", name: "Jamaica" },
  { code: "JP", name: "Japan" }, { code: "JO", name: "Jordan" },
  { code: "KZ", name: "Kazakhstan" }, { code: "KE", name: "Kenya" },
  { code: "KP", name: "North Korea" }, { code: "KR", name: "South Korea" },
  { code: "KW", name: "Kuwait" }, { code: "KG", name: "Kyrgyzstan" },
  { code: "LA", name: "Laos" }, { code: "LV", name: "Latvia" },
  { code: "LB", name: "Lebanon" }, { code: "LY", name: "Libya" },
  { code: "LT", name: "Lithuania" }, { code: "LU", name: "Luxembourg" },
  { code: "MY", name: "Malaysia" }, { code: "ML", name: "Mali" },
  { code: "MX", name: "Mexico" }, { code: "MD", name: "Moldova" },
  { code: "MN", name: "Mongolia" }, { code: "MA", name: "Morocco" },
  { code: "MZ", name: "Mozambique" }, { code: "MM", name: "Myanmar" },
  { code: "NP", name: "Nepal" }, { code: "NL", name: "Netherlands" },
  { code: "NZ", name: "New Zealand" }, { code: "NI", name: "Nicaragua" },
  { code: "NE", name: "Niger" }, { code: "NG", name: "Nigeria" },
  { code: "NO", name: "Norway" }, { code: "OM", name: "Oman" },
  { code: "PK", name: "Pakistan" }, { code: "PA", name: "Panama" },
  { code: "PY", name: "Paraguay" }, { code: "PE", name: "Peru" },
  { code: "PH", name: "Philippines" }, { code: "PL", name: "Poland" },
  { code: "PT", name: "Portugal" }, { code: "QA", name: "Qatar" },
  { code: "RO", name: "Romania" }, { code: "RU", name: "Russia" },
  { code: "RW", name: "Rwanda" }, { code: "SA", name: "Saudi Arabia" },
  { code: "SN", name: "Senegal" }, { code: "RS", name: "Serbia" },
  { code: "SG", name: "Singapore" }, { code: "SK", name: "Slovakia" },
  { code: "SI", name: "Slovenia" }, { code: "SO", name: "Somalia" },
  { code: "ZA", name: "South Africa" }, { code: "SS", name: "South Sudan" },
  { code: "ES", name: "Spain" }, { code: "LK", name: "Sri Lanka" },
  { code: "SD", name: "Sudan" }, { code: "SE", name: "Sweden" },
  { code: "CH", name: "Switzerland" }, { code: "SY", name: "Syria" },
  { code: "TW", name: "Taiwan" }, { code: "TJ", name: "Tajikistan" },
  { code: "TZ", name: "Tanzania" }, { code: "TH", name: "Thailand" },
  { code: "TN", name: "Tunisia" }, { code: "TR", name: "Turkey" },
  { code: "TM", name: "Turkmenistan" }, { code: "UG", name: "Uganda" },
  { code: "UA", name: "Ukraine" }, { code: "AE", name: "UAE" },
  { code: "GB", name: "United Kingdom" }, { code: "US", name: "United States" },
  { code: "UY", name: "Uruguay" }, { code: "UZ", name: "Uzbekistan" },
  { code: "VE", name: "Venezuela" }, { code: "VN", name: "Vietnam" },
  { code: "YE", name: "Yemen" }, { code: "ZM", name: "Zambia" },
  { code: "ZW", name: "Zimbabwe" },
];

function countryName(code: string): string {
  return COUNTRY_LIST.find((c) => c.code === code)?.name ?? code;
}

function MonitoredRegionsSection() {
  const { data: regions, isLoading } = useMonitoredRegions();
  const updateRegions = useUpdateMonitoredRegions();
  const [search, setSearch] = useState("");
  const [dropdownOpen, setDropdownOpen] = useState(false);

  if (isLoading) return <LoadingSpinner />;

  const currentRegions = regions ?? [];

  const filtered = search.length > 0
    ? COUNTRY_LIST.filter(
        (c) =>
          !currentRegions.includes(c.code) &&
          (c.name.toLowerCase().includes(search.toLowerCase()) ||
            c.code.toLowerCase().includes(search.toLowerCase())),
      ).slice(0, 12)
    : [];

  function addRegion(code: string) {
    if (currentRegions.includes(code)) return;
    updateRegions.mutate([...currentRegions, code]);
    setSearch("");
    setDropdownOpen(false);
  }

  function removeRegion(code: string) {
    updateRegions.mutate(currentRegions.filter((c) => c !== code));
  }

  return (
    <div className="rounded-lg border border-border bg-card">
      <div className="flex items-center gap-3 border-b border-border p-4">
        <MapPin className="h-5 w-5 text-primary" />
        <h2 className="text-lg font-semibold">Monitored Regions</h2>
      </div>

      <div className="p-4 space-y-3">
        <p className="text-sm text-muted-foreground">
          Connections to these countries are highlighted in red on the world map and flagged in connection tables.
        </p>

        {currentRegions.length > 0 && (
          <div className="flex flex-wrap gap-2">
            {currentRegions.sort().map((code) => (
              <span
                key={code}
                className="inline-flex items-center gap-1.5 rounded-md bg-destructive/10 px-2.5 py-1 text-sm text-destructive"
              >
                <span className="font-mono font-medium">{code}</span>
                <span className="text-destructive/70">{countryName(code)}</span>
                <button
                  onClick={() => removeRegion(code)}
                  className="ml-0.5 rounded-sm p-0.5 hover:bg-destructive/20"
                  title={`Remove ${countryName(code)}`}
                >
                  <X className="h-3 w-3" />
                </button>
              </span>
            ))}
          </div>
        )}

        <div className="relative">
          <input
            type="text"
            value={search}
            onChange={(e) => {
              setSearch(e.target.value);
              setDropdownOpen(true);
            }}
            onFocus={() => setDropdownOpen(true)}
            onBlur={() => setTimeout(() => setDropdownOpen(false), 150)}
            onKeyDown={(e) => {
              if (e.key === "Enter" && filtered.length > 0) {
                addRegion(filtered[0].code);
              } else if (e.key === "Enter" && search.trim().length === 2) {
                addRegion(search.trim().toUpperCase());
              }
            }}
            placeholder="Search countries..."
            className="w-full max-w-xs rounded-md border border-input bg-background px-3 py-1.5 text-sm"
          />
          {dropdownOpen && filtered.length > 0 && (
            <div className="absolute z-20 mt-1 w-full max-w-xs rounded-md border border-border bg-card shadow-lg max-h-48 overflow-y-auto">
              {filtered.map((c) => (
                <button
                  key={c.code}
                  type="button"
                  onMouseDown={(e) => e.preventDefault()}
                  onClick={() => addRegion(c.code)}
                  className="flex w-full items-center gap-2 px-3 py-1.5 text-sm hover:bg-muted text-left"
                >
                  <span className="font-mono text-muted-foreground w-6">{c.code}</span>
                  <span>{c.name}</span>
                </button>
              ))}
            </div>
          )}
        </div>

        {updateRegions.isError && (
          <p className="text-xs text-destructive">
            {(updateRegions.error as Error)?.message || "Failed to update regions"}
          </p>
        )}

        {currentRegions.length === 0 && (
          <p className="text-xs text-muted-foreground">
            No regions monitored. All countries are treated equally.
          </p>
        )}
      </div>
    </div>
  );
}

// ── Connection History Section ──────────────────────────────────

function ConnectionHistorySection() {
  const { data, isLoading } = useConnectionHistoryStats();

  if (isLoading) return <LoadingSpinner />;
  if (!data) return null;

  return (
    <div className="rounded-lg border border-border bg-card">
      <div className="flex items-center gap-3 border-b border-border p-4">
        <Database className="h-5 w-5 text-primary" />
        <h2 className="text-lg font-semibold">Connection History</h2>
      </div>

      <div className="p-4 space-y-3">
        <div className="flex items-center justify-between">
          <span className="text-sm text-muted-foreground">Retention</span>
          <span className="text-sm">{data.retention_days} days</span>
        </div>
        <div className="flex items-center justify-between">
          <span className="text-sm text-muted-foreground">Records</span>
          <span className="text-sm">{formatNumber(data.row_count)}</span>
        </div>
        <div className="flex items-center justify-between">
          <span className="text-sm text-muted-foreground">Database Size</span>
          <span className="text-sm">{formatBytes(data.db_size_bytes)}</span>
        </div>
        <div className="flex items-center justify-between">
          <span className="text-sm text-muted-foreground">Oldest Record</span>
          <span className="text-sm">
            {data.oldest_record
              ? new Date(data.oldest_record).toLocaleDateString(undefined, {
                  month: "short",
                  day: "numeric",
                  year: "numeric",
                })
              : "No records yet"}
          </span>
        </div>
      </div>
    </div>
  );
}

// ── Behavior Engine Reset Section ────────────────────────────────

function ResetCountsTable({ counts, label }: { counts: BehaviorResetCounts; label: string }) {
  const rows = [
    ["Anomalies", counts.anomalies],
    ["Baselines", counts.baselines],
    ["Observations", counts.observations],
    ["Device Profiles", counts.profiles],
    ["Priority Boosts", counts.boosts],
    ["Scheduler Watermarks", counts.watermarks],
    ["Policy Deviations", counts.policy_deviations],
  ] as const;
  const total = rows.reduce((sum, [, n]) => sum + n, 0);

  return (
    <div className="rounded-md border border-border bg-muted/30 p-3 text-sm">
      <p className="font-medium mb-2">{label}</p>
      <div className="grid grid-cols-2 gap-x-6 gap-y-1">
        {rows.map(([name, n]) => (
          <div key={name} className="flex items-center justify-between">
            <span className="text-muted-foreground">{name}</span>
            <span className="font-mono tabular-nums">{formatNumber(n)}</span>
          </div>
        ))}
      </div>
      <div className="mt-2 pt-2 border-t border-border flex items-center justify-between font-medium">
        <span>Total</span>
        <span className="font-mono tabular-nums">{formatNumber(total)}</span>
      </div>
    </div>
  );
}

function BehaviorResetSection() {
  const resetMutation = useResetBehavior();
  const preview = useResetPreview();
  const [confirming, setConfirming] = useState(false);
  const [result, setResult] = useState<BehaviorResetCounts | null>(null);

  const handleInitiate = async () => {
    setResult(null);
    setConfirming(true);
    preview.refetch();
  };

  const handleConfirm = async () => {
    try {
      const res = await resetMutation.mutateAsync();
      setResult(res);
      setConfirming(false);
    } catch {
      // error handled by TanStack
    }
  };

  const handleCancel = () => {
    setConfirming(false);
  };

  return (
    <div className="rounded-lg border bg-card p-6">
      <div className="flex items-center gap-3 mb-4">
        <Brain className="h-5 w-5 text-destructive" />
        <h2 className="text-lg font-semibold">Anomaly Detection &amp; Baselines</h2>
      </div>
      <p className="text-sm text-muted-foreground mb-4">
        Full reset of anomaly detection, device traffic baselines, and learned behavior profiles.
        Deletes all anomalies, baselines, observations, device profiles, priority boosts, and
        scheduler watermarks. Suppression rules are kept. The engine will restart its learning
        period and rebuild baselines from scratch.
      </p>

      {!confirming && !result && (
        <button
          className="inline-flex items-center gap-2 rounded-md bg-destructive px-4 py-2 text-sm font-medium text-destructive-foreground shadow hover:bg-destructive/90 transition-colors"
          onClick={handleInitiate}
        >
          <Trash2 className="h-4 w-4" />
          Reset Baselines &amp; Anomalies
        </button>
      )}

      {confirming && (
        <div className="space-y-4">
          {preview.isFetching && (
            <p className="text-sm text-muted-foreground">Loading counts...</p>
          )}
          {preview.data && <ResetCountsTable counts={preview.data} label="The following data will be permanently deleted:" />}
          <div className="flex items-center gap-3">
            <button
              className="inline-flex items-center gap-2 rounded-md bg-destructive px-4 py-2 text-sm font-medium text-destructive-foreground shadow hover:bg-destructive/90 transition-colors"
              onClick={handleConfirm}
              disabled={resetMutation.isPending || preview.isFetching}
            >
              <AlertTriangle className="h-4 w-4" />
              {resetMutation.isPending ? "Resetting..." : "Confirm Reset"}
            </button>
            <button
              className="inline-flex items-center gap-2 rounded-md border border-border px-4 py-2 text-sm font-medium hover:bg-muted transition-colors"
              onClick={handleCancel}
              disabled={resetMutation.isPending}
            >
              Cancel
            </button>
          </div>
        </div>
      )}

      {result && (
        <div className="space-y-4">
          <ResetCountsTable counts={result} label="Reset complete. Deleted:" />
          <button
            className="text-sm text-muted-foreground underline hover:text-foreground"
            onClick={() => setResult(null)}
          >
            Dismiss
          </button>
        </div>
      )}

      {resetMutation.error && (
        <p className="mt-2 text-sm text-destructive">
          {resetMutation.error.message}
        </p>
      )}
    </div>
  );
}

// ── Exported composite component ─────────────────────────────────

export function SettingsSystem() {
  return (
    <div className="space-y-6">
      <AboutSection />
      <SyslogSection />
      <GeoIpSection />
      <MonitoredRegionsSection />
      <ConnectionHistorySection />
      <BehaviorResetSection />
    </div>
  );
}
