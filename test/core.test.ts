import { describe, it, expect } from "vitest";
import { validateOptions, BackendGuardConfigError } from "../src/core/options";
import { redactUrl, formatLogLine } from "../src/core/logger";
import { MemoryStore, RateLimiter } from "../src/core/rate-limit";
import { resolveLogging } from "../src/core/options";

describe("validateOptions", () => {
  it("accepts valid configs", () => {
    expect(() => validateOptions({ rateLimit: { limit: 5, windowMs: 1000 }, cors: ["https://a.com"], xss: true, ipBlacklist: ["1.2.3.4"] })).not.toThrow();
    expect(() => validateOptions({})).not.toThrow();
  });
  it("rejects typos with a suggestion", () => {
    expect(() => validateOptions({ rateLimt: true })).toThrow(/did you mean "rateLimit"/);
  });
  it("lists every problem at once", () => {
    try {
      validateOptions({ rateLimit: { limit: -1, windowMs: "x" }, ipBlacklist: "1.2.3.4", requestLogging: { fields: ["nope"] } });
      throw new Error("should have thrown");
    } catch (e) {
      expect(e).toBeInstanceOf(BackendGuardConfigError);
      expect((e as BackendGuardConfigError).problems).toHaveLength(4);
    }
  });
  it("rejects the removed validate option", () => {
    expect(() => validateOptions({ validate: "zod" })).toThrow(/unknown option "validate"/);
  });
});

describe("redactUrl", () => {
  it("masks sensitive query params only", () => {
    expect(redactUrl("/cb?code=abc&page=2&Token=xyz", true)).toBe("/cb?code=[REDACTED]&page=2&Token=[REDACTED]");
    expect(redactUrl("/x?foo=1", ["foo"])).toBe("/x?foo=[REDACTED]");
    expect(redactUrl("/x?token=1", false)).toBe("/x?token=1");
    expect(redactUrl("/plain", true)).toBe("/plain");
  });
  it("formats log lines with redaction", () => {
    const cfg = resolveLogging(true)!;
    const line = formatLogLine(cfg, { method: "GET", url: "/a?password=hunter2", ip: "1.1.1.1", statusCode: 200, responseTimeMs: 3.4 });
    expect(line).toBe("[backend-guard] GET | /a?password=[REDACTED] | 1.1.1.1 | 200 | 3ms");
  });
});

describe("RateLimiter", () => {
  it("allows up to the limit then blocks, per key", async () => {
    const rl = new RateLimiter(60000, 2);
    expect([await rl.allow("a"), await rl.allow("a"), await rl.allow("a"), await rl.allow("b")]).toEqual([true, true, false, true]);
  });
  it("sweeps expired entries", async () => {
    const store = new MemoryStore();
    for (let i = 0; i < 50; i++) store.hit(`k${i}`, 10);
    await new Promise((r) => setTimeout(r, 25));
    store.hit("fresh", 10);
    expect(store.size).toBe(1);
  });
  it("supports async stores", async () => {
    const rl = new RateLimiter(1000, 1, { hit: async () => ({ count: 2, resetAt: Date.now() + 1000 }) });
    expect(await rl.allow("x")).toBe(false);
  });
});
