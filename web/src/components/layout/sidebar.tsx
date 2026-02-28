import { Link, useRouterState } from "@tanstack/react-router";
import { cn } from "@/lib/utils";
import { useConnectionSummary, useBehaviorAlerts, useDevices } from "@/api/queries";
import {
  LayoutDashboard,
  Network,
  Globe,
  Shield,
  Plug2,
  ScrollText,
  Activity,
  Map,
  Settings,
  History,
  Fingerprint,
  Radar,
} from "lucide-react";

const navItems = [
  { to: "/", label: "Dashboard", icon: LayoutDashboard },
  { to: "/interfaces", label: "Interfaces", icon: Network },
  { to: "/ip", label: "IP", icon: Globe },
  { to: "/firewall", label: "Firewall", icon: Shield },
  { to: "/connections", label: "Connections", icon: Plug2 },
  { to: "/behavior", label: "Behavior", icon: Activity },
  { to: "/history", label: "History", icon: History },
  { to: "/logs", label: "Logs", icon: ScrollText },
  { to: "/network-map", label: "Network Map", icon: Map },
] as const;

interface SidebarProps {
  open?: boolean;
  onClose?: () => void;
}

export function Sidebar({ open, onClose }: SidebarProps) {
  const routerState = useRouterState();
  const currentPath = routerState.location.pathname;
  const connectionSummary = useConnectionSummary();
  const hasFlagged = (connectionSummary.data?.flagged_count ?? 0) > 0;
  const behaviorAlerts = useBehaviorAlerts();
  const pendingAnomalies = behaviorAlerts.data?.pending_count ?? 0;
  const { data: devices = [] } = useDevices();
  const switchDevices = devices.filter((d) => d.device_type === "switch");

  const navContent = (
    <>
      <div className="flex h-14 flex-col justify-center border-b border-border px-4">
        <span className="text-lg font-bold leading-tight text-primary">Ion Drift</span>
        <span className="text-[10px] leading-tight text-muted-foreground">by Cyber Hive Security</span>
      </div>
      <nav className="flex-1 space-y-1 p-3">
        {navItems.map(({ to, label, icon: Icon }) => {
          const active = to === "/" ? currentPath === "/" : currentPath.startsWith(to);
          const showDot = to === "/connections" && hasFlagged;
          const showBehaviorBadge = to === "/behavior" && pendingAnomalies > 0;
          return (
            <Link
              key={to}
              to={to}
              onClick={onClose}
              className={cn(
                "flex items-center gap-3 rounded-md px-3 py-2 text-sm font-medium transition-colors",
                active
                  ? "bg-primary/10 text-primary"
                  : "text-muted-foreground hover:bg-muted hover:text-foreground",
              )}
            >
              <Icon className="h-4 w-4" />
              {label}
              {showDot && (
                <span className="ml-auto h-2 w-2 rounded-full bg-red-500" />
              )}
              {showBehaviorBadge && (
                <span className="ml-auto inline-flex h-4 min-w-4 items-center justify-center rounded-full bg-amber-500 px-1 text-[10px] font-bold text-white">
                  {pendingAnomalies}
                </span>
              )}
            </Link>
          );
        })}
      </nav>
      <div className="border-t border-border px-3 py-2">
        <span className="px-3 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
          Discovery
        </span>
        <div className="mt-1 space-y-0.5">
          {[
            { to: "/network/identities", label: "Identities", icon: Fingerprint },
            { to: "/network/scans", label: "Network Scans", icon: Radar },
          ].map(({ to, label, icon: Icon }) => {
            const active = currentPath.startsWith(to);
            return (
              <Link
                key={to}
                to={to as "/"}
                onClick={onClose}
                className={cn(
                  "flex items-center gap-3 rounded-md px-3 py-2 text-sm font-medium transition-colors",
                  active
                    ? "bg-primary/10 text-primary"
                    : "text-muted-foreground hover:bg-muted hover:text-foreground",
                )}
              >
                <Icon className="h-4 w-4" />
                {label}
              </Link>
            );
          })}
        </div>
      </div>
      {switchDevices.length > 0 && (
        <div className="border-t border-border px-3 py-2">
          <span className="px-3 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
            Switches
          </span>
          <div className="mt-1 space-y-0.5">
            {switchDevices.map((device) => {
              const active = currentPath === `/switches/${device.id}`;
              return (
                <Link
                  key={device.id}
                  to={`/switches/${device.id}` as "/"}
                  onClick={onClose}
                  className={cn(
                    "flex items-center gap-3 rounded-md px-3 py-2 text-sm font-medium transition-colors",
                    active
                      ? "bg-primary/10 text-primary"
                      : "text-muted-foreground hover:bg-muted hover:text-foreground",
                  )}
                >
                  <span
                    className={cn(
                      "inline-block h-2 w-2 rounded-full flex-shrink-0",
                      device.status === "Online"
                        ? "bg-green-500"
                        : device.status === "Offline"
                          ? "bg-red-500"
                          : "bg-gray-400",
                    )}
                  />
                  <span className="truncate">{device.name}</span>
                </Link>
              );
            })}
          </div>
        </div>
      )}
      <div className="border-t border-border p-3">
        <Link
          to="/settings"
          onClick={onClose}
          className={cn(
            "flex items-center gap-3 rounded-md px-3 py-2 text-sm font-medium transition-colors",
            currentPath.startsWith("/settings")
              ? "bg-primary/10 text-primary"
              : "text-muted-foreground hover:bg-muted hover:text-foreground",
          )}
        >
          <Settings className="h-4 w-4" />
          Settings
        </Link>
      </div>
    </>
  );

  return (
    <>
      {/* Desktop sidebar — always visible */}
      <aside className="hidden md:flex h-full w-56 flex-col border-r border-border bg-card">
        {navContent}
      </aside>

      {/* Mobile overlay sidebar */}
      {open && (
        <div
          className="fixed inset-0 z-40 bg-black/50 md:hidden"
          onClick={onClose}
        />
      )}
      <aside
        className={cn(
          "fixed inset-y-0 left-0 z-50 flex w-[280px] flex-col border-r border-border bg-card transition-transform duration-300 ease-in-out md:hidden",
          open ? "translate-x-0" : "-translate-x-full",
        )}
      >
        {navContent}
      </aside>
    </>
  );
}
