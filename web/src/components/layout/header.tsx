import { useAuth } from "@/hooks/use-auth";
import { useSystemIdentity } from "@/api/queries";
import { LogOut, Router } from "lucide-react";

export function Header() {
  const { user, logout } = useAuth();
  const { data: identity } = useSystemIdentity();

  return (
    <header className="flex h-14 items-center justify-between border-b border-border bg-card px-6">
      <div className="flex items-center gap-2 text-sm text-muted-foreground">
        <Router className="h-4 w-4" />
        {identity ? (
          <span className="font-medium text-foreground">{identity.name}</span>
        ) : (
          <span>Connecting...</span>
        )}
      </div>
      {user && (
        <div className="flex items-center gap-4">
          <span className="text-sm text-muted-foreground">{user.username}</span>
          <button
            onClick={logout}
            className="flex items-center gap-1.5 rounded-md px-2 py-1 text-xs text-muted-foreground transition-colors hover:bg-muted hover:text-foreground"
          >
            <LogOut className="h-3.5 w-3.5" />
            Logout
          </button>
        </div>
      )}
    </header>
  );
}
