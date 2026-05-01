// Shared severity color tokens.
//
// Two vocabularies coexist in the app:
//
// - Anomaly severities: "critical" | "alert" | "warning" | "info"
//   Emitted by the in-process behavior engine.
//
// - Finding severities: "critical" | "high" | "medium" | "low" | "info"
//   Emitted by external modules over the inbound publish endpoint.
//
// These functions return Tailwind utility class strings so callers can
// drop them straight into `cn(...)`.

export function anomalySeverityColor(severity: string): string {
  switch (severity) {
    case "critical":
      return "text-destructive";
    case "alert":
      return "text-orange-500";
    case "warning":
      return "text-warning";
    case "info":
      return "text-primary";
    default:
      return "text-muted-foreground";
  }
}

export function anomalySeverityBg(severity: string): string {
  switch (severity) {
    case "critical":
      return "bg-destructive/10 border-destructive/30";
    case "alert":
      return "bg-orange-500/10 border-orange-500/30";
    case "warning":
      return "bg-warning/10 border-warning/30";
    case "info":
      return "bg-primary/10 border-primary/30";
    default:
      return "bg-muted border-border";
  }
}

export function findingSeverityColor(severity: string): string {
  switch (severity) {
    case "critical":
      return "text-destructive";
    case "high":
      return "text-orange-500";
    case "medium":
      return "text-warning";
    case "low":
      return "text-primary";
    case "info":
      return "text-muted-foreground";
    default:
      return "text-muted-foreground";
  }
}

export function findingSeverityBg(severity: string): string {
  switch (severity) {
    case "critical":
      return "bg-destructive/10 border-destructive/30";
    case "high":
      return "bg-orange-500/10 border-orange-500/30";
    case "medium":
      return "bg-warning/10 border-warning/30";
    case "low":
      return "bg-primary/10 border-primary/30";
    case "info":
      return "bg-muted border-border";
    default:
      return "bg-muted border-border";
  }
}
