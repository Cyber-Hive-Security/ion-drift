import { Link, useRouterState } from "@tanstack/react-router";
import { cn } from "@/lib/utils";
import { useConnectionSummary, useBehaviorAlerts } from "@/api/queries";
import {
  LayoutDashboard,
  Network,
  Globe,
  Shield,
  Plug2,
  ScrollText,
  Gauge,
  Activity,
  Map,
  Settings,
} from "lucide-react";

const navItems = [
  { to: "/", label: "Dashboard", icon: LayoutDashboard },
  { to: "/interfaces", label: "Interfaces", icon: Network },
  { to: "/ip", label: "IP", icon: Globe },
  { to: "/firewall", label: "Firewall", icon: Shield },
  { to: "/connections", label: "Connections", icon: Plug2 },
  { to: "/behavior", label: "Behavior", icon: Activity },
  { to: "/logs", label: "Logs", icon: ScrollText },
  { to: "/speedtest", label: "Speedtest", icon: Gauge },
  { to: "/network-map", label: "Network Map", icon: Map },
] as const;

export function Sidebar() {
  const routerState = useRouterState();
  const currentPath = routerState.location.pathname;
  const connectionSummary = useConnectionSummary();
  const hasFlagged = (connectionSummary.data?.flagged_count ?? 0) > 0;
  const behaviorAlerts = useBehaviorAlerts();
  const pendingAnomalies = behaviorAlerts.data?.pending_count ?? 0;

  return (
    <aside className="flex h-full w-56 flex-col border-r border-border bg-card">
      <div className="flex h-14 items-center border-b border-border px-4">
        <span className="text-lg font-bold text-primary">ion-drift</span>
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
      <div className="border-t border-border p-3">
        <Link
          to="/settings"
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
    </aside>
  );
}
