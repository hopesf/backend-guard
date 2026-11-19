import { describe, it, expect } from "vitest";
import { normalizeIp } from "../src/core/ip";

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
