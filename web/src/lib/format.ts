export function formatBytes(bytes: number, decimals = 2): string {
  if (bytes === 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB", "TB", "PB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${(bytes / Math.pow(k, i)).toFixed(decimals)} ${sizes[i]}`;
}

export function formatUptime(uptime: string): string {
  // RouterOS format: "14d03:22:01" or "3w2d03:22:01" or "03:22:01"
  const match = uptime.match(
    /(?:(\d+)w)?(?:(\d+)d)?(\d{2}):(\d{2}):(\d{2})/,
  );
  if (!match) return uptime;
  const [, weeks, days, hours, minutes] = match;
  const parts: string[] = [];
  if (weeks) parts.push(`${weeks}w`);
  if (days) parts.push(`${days}d`);
  parts.push(`${parseInt(hours)}h`);
  parts.push(`${parseInt(minutes)}m`);
  return parts.join(" ");
}

export function formatMbps(mbps: number): string {
  if (mbps >= 1000) return `${(mbps / 1000).toFixed(1)} Gbps`;
  return `${mbps.toFixed(1)} Mbps`;
}

export function formatTimestamp(ts: number): string {
  return new Date(ts * 1000).toLocaleString();
}

export function percentColor(pct: number): string {
  if (pct >= 90) return "text-destructive";
  if (pct >= 70) return "text-warning";
  return "text-success";
}

export function formatNumber(n: number): string {
  return n.toLocaleString();
}
