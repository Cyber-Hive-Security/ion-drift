import { cn } from "@/lib/utils";

export function Badge({
  active,
  label,
}: {
  active: boolean;
  label: string;
}) {
  return (
    <span
      className={cn(
        "inline-flex rounded-full px-2 py-0.5 text-xs font-medium",
        active ? "bg-success/15 text-success" : "bg-muted text-muted-foreground",
      )}
    >
      {label}
    </span>
  );
}
