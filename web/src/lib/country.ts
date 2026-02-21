/** Convert a 2-letter ISO country code to a flag emoji. */
export function countryFlag(code: string): string {
  const upper = code.toUpperCase();
  if (upper.length !== 2) return "";
  const codePoints = [...upper].map(
    (c) => 0x1f1e6 + c.charCodeAt(0) - 65,
  );
  return String.fromCodePoint(...codePoints);
}

/** Check if an IP is in RFC1918 private range. */
export function isPrivateIp(ip: string): boolean {
  const parts = ip.split(".").map(Number);
  if (parts.length !== 4) return false;
  return (
    parts[0] === 10 ||
    (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) ||
    (parts[0] === 192 && parts[1] === 168) ||
    parts[0] === 127
  );
}
