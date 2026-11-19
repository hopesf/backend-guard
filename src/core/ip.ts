import { BlockList, isIP } from "node:net";

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

export type IpMatcher = ((ip: string | undefined | null) => boolean) & {
  /** Entries that could not be parsed (they never match). */
  readonly invalid: string[];
};

/**
 * Builds a matcher for a list of exact IPs and CIDR ranges (IPv4 and IPv6).
 * Input addresses are normalized first, so `::ffff:10.1.2.3` matches `10.0.0.0/8`.
 */
export function createIpMatcher(list: string[]): IpMatcher {
  const blocks = new BlockList();
  const invalid: string[] = [];

  for (const raw of list) {
    const entry = raw.trim();
    const slash = entry.indexOf("/");
    const addrPart = slash === -1 ? entry : entry.slice(0, slash);
    let addr = normalizeIp(addrPart);
    const family = isIP(addr);
    if (!family) { invalid.push(raw); continue; }

    if (slash === -1) {
      blocks.addAddress(addr, family === 4 ? "ipv4" : "ipv6");
      continue;
    }

    let prefix = Number(entry.slice(slash + 1));
    // an IPv4-mapped IPv6 range such as ::ffff:10.0.0.0/104 → IPv4 /8
    if (family === 4 && isIP(addrPart.trim()) === 6) prefix -= 96;
    const max = family === 4 ? 32 : 128;
    if (!Number.isInteger(prefix) || prefix < 0 || prefix > max) { invalid.push(raw); continue; }
    blocks.addSubnet(addr, prefix, family === 4 ? "ipv4" : "ipv6");
  }

  const matcher = ((ip: string | undefined | null) => {
    const n = normalizeIp(ip);
    const fam = isIP(n);
    return fam !== 0 && blocks.check(n, fam === 4 ? "ipv4" : "ipv6");
  }) as IpMatcher;
  Object.defineProperty(matcher, "invalid", { value: invalid, enumerable: true });
  return matcher;
}

/** Builds a Set of normalized IPs from a user-supplied blacklist. */
export function buildIpSet(list: string[]): Set<string> {
  return new Set(list.map((ip) => normalizeIp(ip)).filter(Boolean));
}
