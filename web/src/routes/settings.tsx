import { Link, useSearch } from "@tanstack/react-router";
import { PageShell } from "@/components/layout/page-shell";
import { SettingsHelp } from "@/components/help-content";
import { SettingsAlerts } from "@/features/settings/settings-alerts";
import { SettingsDevices } from "@/features/settings/settings-devices";
import { SettingsVlans } from "@/features/settings/settings-vlans";
import { SettingsSecurity } from "@/features/settings/settings-security";
import { SettingsSystem } from "@/features/settings/settings-system";
import {
  Wand2,
  Bell,
  Network,
  Shield,
  Server,
} from "lucide-react";

const TABS = [
  { id: "alerts", label: "Alerts", icon: Bell },
  { id: "devices", label: "Devices", icon: Network },
  { id: "vlans", label: "VLANs", icon: Server },
  { id: "security", label: "Security", icon: Shield },
  { id: "system", label: "System", icon: Wand2 },
] as const;

type TabId = (typeof TABS)[number]["id"];

function isValidTab(value: unknown): value is TabId {
  return typeof value === "string" && TABS.some((t) => t.id === value);
}

export function SettingsPage() {
  const search = useSearch({ from: "/settings" });
  const activeTab: TabId = isValidTab(search.tab) ? search.tab : "alerts";

  return (
    <PageShell title="Settings" help={<SettingsHelp />}>
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          {/* Tab bar */}
          <nav className="flex gap-1 rounded-lg border border-border bg-muted/30 p-1">
            {TABS.map(({ id, label, icon: Icon }) => (
              <Link
                key={id}
                to="/settings"
                search={{ tab: id }}
                className={`flex items-center gap-1.5 rounded-md px-3 py-1.5 text-sm font-medium transition-colors ${
                  activeTab === id
                    ? "bg-background text-foreground shadow-sm"
                    : "text-muted-foreground hover:text-foreground hover:bg-background/50"
                }`}
              >
                <Icon className="h-4 w-4" />
                {label}
              </Link>
            ))}
          </nav>

          <Link
            to={"/setup-wizard" as "/"}
            className="inline-flex items-center gap-2 rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground shadow hover:bg-primary/90 transition-colors"
          >
            <Wand2 className="h-4 w-4" />
            Setup Wizard
          </Link>
        </div>

        {/* Tab content */}
        {activeTab === "alerts" && <SettingsAlerts />}
        {activeTab === "devices" && <SettingsDevices />}
        {activeTab === "vlans" && <SettingsVlans />}
        {activeTab === "security" && <SettingsSecurity />}
        {activeTab === "system" && <SettingsSystem />}
      </div>
    </PageShell>
  );
}
