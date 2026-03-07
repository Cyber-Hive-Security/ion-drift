import { useState, type ReactNode } from "react";
import { RefreshCw, HelpCircle, X } from "lucide-react";

interface PageShellProps {
  title: string;
  children: ReactNode;
  onRefresh?: () => void;
  isRefreshing?: boolean;
  help?: ReactNode;
}

export function PageShell({
  title,
  children,
  onRefresh,
  isRefreshing,
  help,
}: PageShellProps) {
  const [helpOpen, setHelpOpen] = useState(false);

  return (
    <div className="flex-1 overflow-auto p-4 md:p-6">
      <div className="mb-6 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <h1 className="text-2xl font-bold">{title}</h1>
          {help && (
            <button
              onClick={() => setHelpOpen((v) => !v)}
              className="rounded-full p-1 text-muted-foreground transition-colors hover:bg-muted hover:text-foreground"
              aria-label="Page help"
            >
              <HelpCircle className="h-5 w-5" />
            </button>
          )}
        </div>
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
      {helpOpen && help && (
        <div className="mb-6 rounded-lg border border-primary/30 bg-primary/5 p-4">
          <div className="mb-2 flex items-center justify-between">
            <span className="text-sm font-semibold text-primary">Help</span>
            <button
              onClick={() => setHelpOpen(false)}
              className="rounded p-0.5 text-muted-foreground hover:text-foreground"
            >
              <X className="h-4 w-4" />
            </button>
          </div>
          <div className="space-y-2 text-sm text-muted-foreground [&_h3]:font-semibold [&_h3]:text-foreground [&_h3]:mt-3 [&_h3]:mb-1 [&_dt]:font-medium [&_dt]:text-foreground [&_dd]:ml-4 [&_dd]:mb-1.5 [&_ul]:ml-4 [&_ul]:list-disc [&_ul]:space-y-0.5 [&_code]:rounded [&_code]:bg-muted [&_code]:px-1 [&_code]:py-0.5 [&_code]:text-xs [&_code]:font-mono">
            {help}
          </div>
        </div>
      )}
      {children}
    </div>
  );
}
