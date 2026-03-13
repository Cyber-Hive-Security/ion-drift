import { LoadingSpinner } from "@/components/loading-spinner";
import { ErrorDisplay } from "@/components/error-display";
import {
  useVlanConfigs,
  useUpdateVlanConfig,
} from "@/api/queries";
import type { VlanConfig } from "@/api/types";
import { Network } from "lucide-react";

export function SettingsVlans() {
  const { data: configs, isLoading, error } = useVlanConfigs();
  const updateConfig = useUpdateVlanConfig();

  if (isLoading) return <LoadingSpinner />;
  if (error) return <ErrorDisplay message={error.message} />;
  if (!configs || configs.length === 0) return null;

  function handleMediaTypeChange(config: VlanConfig, newType: "wired" | "wireless" | "mixed") {
    updateConfig.mutate({ ...config, media_type: newType });
  }

  function handleNameChange(config: VlanConfig, newName: string) {
    updateConfig.mutate({ ...config, name: newName });
  }

  function handleSubnetChange(config: VlanConfig, newSubnet: string) {
    updateConfig.mutate({ ...config, subnet: newSubnet || null });
  }

  function handleColorChange(config: VlanConfig, newColor: string) {
    updateConfig.mutate({ ...config, color: newColor });
  }

  return (
    <div className="rounded-lg border border-border bg-card p-4">
      <div className="mb-4 flex items-center gap-2">
        <Network className="h-5 w-5 text-primary" />
        <h2 className="text-lg font-semibold">VLAN Configuration</h2>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-border text-left text-xs text-muted-foreground">
              <th className="px-2 py-2">VLAN</th>
              <th className="px-2 py-2">Name</th>
              <th className="px-2 py-2">Media Type</th>
              <th className="px-2 py-2">Subnet</th>
              <th className="px-2 py-2">Color</th>
            </tr>
          </thead>
          <tbody>
            {configs.map((cfg) => (
              <tr key={cfg.vlan_id} className="border-b border-border/50">
                <td className="px-2 py-2 font-mono">{cfg.vlan_id}</td>
                <td className="px-2 py-2">
                  <input
                    type="text"
                    defaultValue={cfg.name}
                    onBlur={(e) => {
                      if (e.target.value !== cfg.name) handleNameChange(cfg, e.target.value);
                    }}
                    className="w-full rounded border border-border bg-background px-2 py-1 text-xs"
                  />
                </td>
                <td className="px-2 py-2">
                  <select
                    value={cfg.media_type}
                    onChange={(e) => handleMediaTypeChange(cfg, e.target.value as "wired" | "wireless" | "mixed")}
                    className="rounded border border-border bg-background px-2 py-1 text-xs"
                  >
                    <option value="wired">Wired</option>
                    <option value="wireless">Wireless</option>
                    <option value="mixed">Mixed</option>
                  </select>
                </td>
                <td className="px-2 py-2">
                  <input
                    type="text"
                    defaultValue={cfg.subnet ?? ""}
                    onBlur={(e) => {
                      if (e.target.value !== (cfg.subnet ?? "")) handleSubnetChange(cfg, e.target.value);
                    }}
                    className="w-full rounded border border-border bg-background px-2 py-1 text-xs font-mono"
                  />
                </td>
                <td className="px-2 py-2">
                  <input
                    type="color"
                    value={cfg.color ?? "#888888"}
                    onChange={(e) => handleColorChange(cfg, e.target.value)}
                    className="h-7 w-10 cursor-pointer rounded border border-border bg-background"
                  />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
