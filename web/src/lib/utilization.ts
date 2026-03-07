/**
 * Utilization display helpers for Link Saturation feature.
 */

/** Returns a Tailwind-compatible CSS color string for a utilization ratio (0.0–1.0). */
export function utilizationColor(util: number): string {
  if (util <= 0) return "rgb(64, 64, 64)";       // idle: dark gray
  if (util < 0.3) return "rgb(34, 197, 94)";     // green
  if (util < 0.6) return "rgb(250, 204, 21)";    // yellow
  if (util < 0.8) return "rgb(249, 115, 22)";    // orange
  if (util < 0.95) return "rgb(239, 68, 68)";    // red
  return "rgb(220, 38, 38)";                       // saturated: dark red
}

/** Returns a human-readable label for a utilization ratio. */
export function utilizationLabel(util: number): string {
  if (util <= 0) return "Idle";
  if (util < 0.3) return `${(util * 100).toFixed(0)}%`;
  if (util < 0.8) return `${(util * 100).toFixed(0)}%`;
  if (util < 0.95) return `${(util * 100).toFixed(1)}% High`;
  return `${(util * 100).toFixed(1)}% Saturated`;
}

/** Formats a bits-per-second value into human-readable bitrate. */
export function formatBitrate(bps: number): string {
  if (bps <= 0) return "0 bps";
  if (bps < 1_000) return `${bps.toFixed(0)} bps`;
  if (bps < 1_000_000) return `${(bps / 1_000).toFixed(1)} Kbps`;
  if (bps < 1_000_000_000) return `${(bps / 1_000_000).toFixed(1)} Mbps`;
  return `${(bps / 1_000_000_000).toFixed(2)} Gbps`;
}
