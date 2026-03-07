import { useAuth } from "@/hooks/use-auth";
import { useSystemIdentity } from "@/api/queries";
import { LogOut, Menu, Router } from "lucide-react";

interface HeaderProps {
  onMenuToggle?: () => void;
  pendingAnomalies?: number;
}

export function Header({ onMenuToggle, pendingAnomalies = 0 }: HeaderProps) {
  const { user, logout } = useAuth();
  const { data: identity } = useSystemIdentity();

  return (
    <header className="flex h-14 items-center justify-between border-b border-border bg-card px-4 md:px-6">
      <div className="flex items-center gap-2 text-sm text-muted-foreground">
        <button
          type="button"
          onClick={onMenuToggle}
          className="relative mr-1 flex h-11 w-11 items-center justify-center rounded-md text-muted-foreground hover:bg-muted hover:text-foreground"
          aria-label="Toggle menu"
        >
          <Menu className="h-6 w-6" />
          {pendingAnomalies > 0 && (
            <span className="absolute top-1 right-1 flex h-4 min-w-4 items-center justify-center rounded-full bg-warning px-0.5 text-[9px] font-bold text-background">
              {pendingAnomalies > 99 ? "99+" : pendingAnomalies}
            </span>
          )}
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
  );
}
