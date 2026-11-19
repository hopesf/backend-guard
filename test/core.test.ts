import { describe, it, expect } from "vitest";
import { validateOptions, BackendGuardConfigError } from "../src/core/options";
import { redactUrl, formatLogLine } from "../src/core/logger";
import { MemoryStore, RateLimiter } from "../src/core/rate-limit";
import { resolveLogging } from "../src/core/options";
import { findOperatorKeys, stripOperatorKeys, applyHpp, resolveHpp } from "../src/core/input";
import { toSafeError, resolveSafeErrors } from "../src/core/errors";

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

describe("input helpers", () => {
  it("finds operator keys at any depth, including arrays", () => {
    expect(findOperatorKeys({ a: { $ne: 1 }, b: [{ $gt: 2 }], c: "$ne" })).toEqual(["a.$ne", "b[0].$gt"]);
    expect(findOperatorKeys({ "e[$gt]": "1" })).toEqual(["e[$gt]"]);
    expect(findOperatorKeys({ "a.b": 1 })).toEqual([]);
    expect(findOperatorKeys({ "a.b": 1 }, true)).toEqual(["a.b"]);
  });
  it("flags absurd nesting instead of overflowing the stack", () => {
    let deep: Record<string, unknown> = {};
    for (let i = 0; i < 100; i++) deep = { n: deep };
    expect(findOperatorKeys(deep).some((p) => p.includes("too deep"))).toBe(true);
  });
  it("strips operators and __proto__", () => {
    const parsed = JSON.parse('{"a":{"$ne":1,"k":2},"__proto__":{"x":1}}');
    expect(stripOperatorKeys(parsed)).toEqual({ a: { k: 2 } });
  });
  it("applyHpp respects whitelist and object values", () => {
    const cfg = resolveHpp({ whitelist: ["t"] })!;
    expect(applyHpp({ r: ["a", "b"], t: ["x", "y"], o: [{ k: 1 }] }, cfg)).toEqual({ r: "b", t: ["x", "y"], o: [{ k: 1 }] });
  });
});

describe("toSafeError", () => {
  const cfg = resolveSafeErrors(true)!;
  it("hides 5xx details, keeps 4xx messages", () => {
    expect(toSafeError(new Error("secret"), cfg).body.message).toBe("Something went wrong.");
    expect(toSafeError({ status: 404, message: "no such user" }, cfg)).toEqual({ status: 404, body: { error: "Not Found", message: "no such user" } });
  });
  it("can hide 4xx messages too", () => {
    const c = resolveSafeErrors({ expose4xx: false })!;
    expect(toSafeError({ status: 400, message: "field x" }, c).body.message).toBe("Bad Request");
  });
  it("ignores bogus status values", () => {
    expect(toSafeError({ status: 99999 }, cfg).status).toBe(500);
  });
});
