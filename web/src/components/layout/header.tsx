import { useState, useCallback, useMemo } from "react";
import { useAuth } from "@/hooks/use-auth";
import { useSystemIdentity, useAlertStatus, useAlertHistory } from "@/api/queries";
import { LogOut, Menu, PanelLeftClose, PanelLeftOpen, Router, Bell, X } from "lucide-react";
import { cn } from "@/lib/utils";

const LAST_READ_KEY = "ion-drift-alert-last-read";

function timeAgo(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

const severityIcon: Record<string, string> = {
  critical: "\u{1F534}",
  warning: "\u{1F7E1}",
  info: "\u26A0\uFE0F",
};

interface HeaderProps {
  onMenuToggle?: () => void;
  pendingAnomalies?: number;
  sidebarOpen?: boolean;
}

export function Header({ onMenuToggle, pendingAnomalies = 0, sidebarOpen }: HeaderProps) {
  const { user, logout } = useAuth();
  const { data: identity } = useSystemIdentity();
  const alertStatus = useAlertStatus();
  const [panelOpen, setPanelOpen] = useState(false);

  const unreadCount = alertStatus.data?.unread_count_24h ?? alertStatus.data?.alerts_fired_today ?? 0;

  const lastRead = useMemo(() => {
    try { return localStorage.getItem(LAST_READ_KEY) ?? ""; }
    catch { return ""; }
  }, [panelOpen]);

  const badgeCount = useMemo(() => {
    if (!lastRead) return unreadCount;
    return unreadCount;
  }, [unreadCount, lastRead]);

  const markAllRead = useCallback(() => {
    try { localStorage.setItem(LAST_READ_KEY, new Date().toISOString()); }
    catch { /* ignore */ }
    setPanelOpen(false);
  }, []);

  return (
    <>
      <header className="flex h-14 items-center justify-between border-b border-border bg-card px-4 md:px-6">
        <div className="flex items-center gap-2 text-sm text-muted-foreground">
          {/* Mobile hamburger */}
          <button
            type="button"
            onClick={onMenuToggle}
            className="relative mr-1 flex h-11 w-11 items-center justify-center rounded-md text-muted-foreground hover:bg-muted hover:text-foreground md:hidden"
            aria-label="Toggle menu"
          >
            <Menu className="h-6 w-6" />
            {pendingAnomalies > 0 && (
              <span className="absolute top-1 right-1 flex h-4 min-w-4 items-center justify-center rounded-full bg-amber-500 px-0.5 text-[9px] font-bold text-white">
                {pendingAnomalies > 99 ? "99+" : pendingAnomalies}
              </span>
            )}
          </button>
          {/* Desktop sidebar toggle */}
          <button
            type="button"
            onClick={onMenuToggle}
            className="hidden md:flex mr-1 h-8 w-8 items-center justify-center rounded-md text-muted-foreground hover:bg-muted hover:text-foreground"
            aria-label="Toggle sidebar"
          >
            {sidebarOpen ? <PanelLeftClose className="h-4 w-4" /> : <PanelLeftOpen className="h-4 w-4" />}
          </button>
          <Router className="h-4 w-4" />
          {identity ? (
            <span className="font-medium text-foreground">{identity.name}</span>
          ) : (
            <span>Connecting...</span>
          )}
        </div>
        {user && (
          <div className="flex items-center gap-4">
            {/* Alert Bell */}
            <button
              onClick={() => setPanelOpen((v) => !v)}
              className="relative flex items-center justify-center rounded-md p-1.5 text-muted-foreground transition-colors hover:bg-muted hover:text-foreground"
              aria-label="Alerts"
            >
              <Bell className="h-4 w-4" />
              {badgeCount > 0 && (
                <span className="absolute -top-0.5 -right-0.5 flex h-4 min-w-4 items-center justify-center rounded-full bg-red-500 px-0.5 text-[9px] font-bold text-white">
                  {badgeCount > 99 ? "99+" : badgeCount}
                </span>
              )}
            </button>
            <span className="hidden text-sm text-muted-foreground sm:inline">{user.username}</span>
            <button
              onClick={logout}
              className="flex items-center gap-1.5 rounded-md px-2 py-1 text-xs text-muted-foreground transition-colors hover:bg-muted hover:text-foreground"
            >
              <LogOut className="h-3.5 w-3.5" />
              <span className="hidden sm:inline">Logout</span>
            </button>
          </div>
        )}
      </header>

      {/* Alert slide-in panel */}
      {panelOpen && (
        <>
          <div className="fixed inset-0 z-40 bg-black/30" onClick={() => setPanelOpen(false)} />
          <AlertPanel onClose={() => setPanelOpen(false)} onMarkAllRead={markAllRead} />
        </>
      )}
    </>
  );
}

function AlertPanel({ onClose, onMarkAllRead }: { onClose: () => void; onMarkAllRead: () => void }) {
  const { data: history } = useAlertHistory(20);

  return (
    <aside className="fixed inset-y-0 right-0 z-50 flex w-[360px] flex-col border-l border-border bg-card shadow-xl">
      <div className="flex h-14 items-center justify-between border-b border-border px-4">
        <span className="text-sm font-semibold">Recent Alerts</span>
        <div className="flex items-center gap-2">
          <button
            onClick={onMarkAllRead}
            className="rounded px-2 py-1 text-[10px] font-medium text-primary hover:bg-primary/10"
          >
            Mark All Read
          </button>
          <button onClick={onClose} className="text-muted-foreground hover:text-foreground">
            <X className="h-4 w-4" />
          </button>
        </div>
      </div>
      <div className="flex-1 overflow-y-auto divide-y divide-border">
        {history && history.length > 0 ? (
          history.map((alert) => (
            <div key={alert.id} className="px-4 py-3 hover:bg-accent/30">
              <div className="flex items-start gap-2">
                <span className="text-sm">{severityIcon[alert.severity] ?? severityIcon.info}</span>
                <div className="flex-1 min-w-0">
                  <div className="text-xs font-medium truncate">{alert.title}</div>
                  <div className="text-[10px] text-muted-foreground mt-0.5">
                    {alert.device_hostname && <span>{alert.device_hostname} · </span>}
                    {timeAgo(alert.fired_at)}
                  </div>
                </div>
                <div className="flex gap-0.5">
                  {JSON.parse(alert.channels_succeeded || "[]").length > 0 ? (
                    <span className="text-[10px] text-green-500" title="Delivered">&#x2713;</span>
                  ) : (
                    <span className="text-[10px] text-red-400" title="Failed">&#x2717;</span>
                  )}
                </div>
              </div>
            </div>
          ))
        ) : (
          <div className="flex items-center justify-center h-32 text-sm text-muted-foreground">
            No recent alerts
          </div>
        )}
      </div>
      <div className="border-t border-border p-3">
        <a
          href="/settings"
          className={cn(
            "block w-full rounded-md py-2 text-center text-xs font-medium",
            "text-primary hover:bg-primary/10 transition-colors",
          )}
        >
          View All in Settings
        </a>
      </div>
    </aside>
  );
}
