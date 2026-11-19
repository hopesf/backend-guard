import { describe, it, expect } from "vitest";
import { normalizeIp, createIpMatcher } from "../src/core/ip";

describe("normalizeIp", () => {
  it("unwraps IPv4-mapped IPv6", () => {
    expect(normalizeIp("::ffff:1.2.3.4")).toBe("1.2.3.4");
    expect(normalizeIp("::FFFF:1.2.3.4")).toBe("1.2.3.4");
    expect(normalizeIp("::ffff:0102:0304")).toBe("1.2.3.4");
    expect(normalizeIp("0:0:0:0:0:ffff:1.2.3.4")).toBe("1.2.3.4");
  });
  it("leaves other addresses alone (lower-cased, zone stripped)", () => {
    expect(normalizeIp("1.2.3.4")).toBe("1.2.3.4");
    expect(normalizeIp("2001:DB8::1")).toBe("2001:db8::1");
    expect(normalizeIp("fe80::1%en0")).toBe("fe80::1");
    expect(normalizeIp(undefined)).toBe("");
  });
});

describe("createIpMatcher", () => {
  it("matches exact IPs and CIDR ranges (v4 and v6)", () => {
    const m = createIpMatcher(["1.2.3.4", "10.0.0.0/8", "192.168.1.0/24", "2001:db8::/32", "::1"]);
    expect([m("1.2.3.4"), m("10.20.30.40"), m("192.168.1.77"), m("2001:db8:1::5"), m("::1")]).toEqual([true, true, true, true, true]);
    expect([m("1.2.3.5"), m("11.0.0.1"), m("192.168.2.1"), m("2001:db9::1"), m(undefined), m("garbage")]).toEqual([false, false, false, false, false, false]);
  });
  it("normalizes IPv4-mapped input and mapped ranges", () => {
    expect(createIpMatcher(["10.0.0.0/8"])("::ffff:10.1.2.3")).toBe(true);
    expect(createIpMatcher(["::ffff:10.0.0.0/104"])("10.9.9.9")).toBe(true);
    expect(createIpMatcher(["1.2.3.4"])("::ffff:0102:0304")).toBe(true);
  });
  it("collects invalid entries instead of throwing", () => {
    const m = createIpMatcher(["10.0.0.0/33", "nope", "1.1.1.1/x", "8.8.8.8"]);
    expect(m.invalid).toEqual(["10.0.0.0/33", "nope", "1.1.1.1/x"]);
    expect(m("8.8.8.8")).toBe(true);
  });
});
