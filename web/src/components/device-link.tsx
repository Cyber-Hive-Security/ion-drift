import { Link } from "@tanstack/react-router";
import { Microscope } from "lucide-react";
import { cn } from "@/lib/utils";

interface DeviceLinkProps {
  /** MAC address to investigate — used as the primary key. */
  mac: string;
  /** Display label — defaults to the MAC address. */
  label?: string;
  /** Additional CSS classes for the link. */
  className?: string;
  /** Show the microscope icon. Defaults to false. */
  icon?: boolean;
  children?: React.ReactNode;
}

/**
 * Universal click-through link to the device investigation (Sankey) page.
 *
 * Use this anywhere a device MAC or hostname appears to provide one-click
 * investigation access.
 */
export function DeviceLink({ mac, label, className, icon = false, children }: DeviceLinkProps) {
  if (!mac) return <>{children ?? label ?? "—"}</>;

  return (
    <Link
      to="/sankey"
      search={{ mac }}
      className={cn(
        "inline-flex items-center gap-1 text-primary/80 hover:text-primary hover:underline",
        className,
      )}
      title={`Investigate ${mac}`}
      onClick={(e: React.MouseEvent) => e.stopPropagation()}
    >
      {children ?? label ?? mac}
      {icon && <Microscope className="h-3 w-3 shrink-0" />}
    </Link>
  );
}
