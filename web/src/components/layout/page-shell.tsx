import type { ReactNode } from "react";
import { RefreshCw } from "lucide-react";

interface PageShellProps {
  title: string;
  children: ReactNode;
  onRefresh?: () => void;
  isRefreshing?: boolean;
}

export function PageShell({
  title,
  children,
  onRefresh,
  isRefreshing,
}: PageShellProps) {
  return (
    <div className="flex-1 overflow-auto p-6">
      <div className="mb-6 flex items-center justify-between">
        <h1 className="text-2xl font-bold">{title}</h1>
        {onRefresh && (
          <button
            onClick={onRefresh}
            disabled={isRefreshing}
            className="flex items-center gap-1.5 rounded-md border border-border px-3 py-1.5 text-xs text-muted-foreground transition-colors hover:bg-muted hover:text-foreground disabled:opacity-50"
          >
            <RefreshCw
              className={`h-3.5 w-3.5 ${isRefreshing ? "animate-spin" : ""}`}
            />
            Refresh
          </button>
        )}
      </div>
      {children}
    </div>
  );
}
