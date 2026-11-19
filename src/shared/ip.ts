/**
 * Normalizes an IP address string so that equivalent spellings compare equal.
 *
 * - lower-cases the address and strips an IPv6 zone id (`fe80::1%en0`)
 * - unwraps IPv4-mapped IPv6 addresses (`::ffff:1.2.3.4` and `::ffff:0102:0304`)
 *   to plain IPv4 so a blacklist entry `1.2.3.4` matches both spellings.
 */
export function normalizeIp(ip: string | undefined | null): string {
  if (!ip) return "";
  let value = ip.trim().toLowerCase();
  const zone = value.indexOf("%");
  if (zone !== -1) value = value.slice(0, zone);

  const dotted = /^(?:0{0,4}:){0,5}:?ffff:(\d{1,3}(?:\.\d{1,3}){3})$/.exec(value);
  if (dotted) return dotted[1];

  const hex = /^(?:0{0,4}:){0,5}:?ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/.exec(value);
  if (hex) {
    const hi = parseInt(hex[1], 16);
    const lo = parseInt(hex[2], 16);
    return `${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`;
  }

  return value;
}

/** Builds a Set of normalized IPs from a user-supplied blacklist. */
export function buildIpSet(list: string[]): Set<string> {
  return new Set(list.map((ip) => normalizeIp(ip)).filter(Boolean));
}
