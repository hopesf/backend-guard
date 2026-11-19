import { describe, it, expect } from "vitest";
import { RedisRateLimitStore } from "../src/core/redis-store";
import { BruteForceProtector } from "../src/core/brute-force";
import { MemoryStore } from "../src/core/rate-limit";

/** In-memory fake that mimics Redis semantics (TTL in ms). */
function fakeRedis(style: "ioredis" | "node-redis") {
  const data = new Map<string, { v: number; exp: number | null }>();
  const live = (k: string) => {
    const e = data.get(k);
    if (e && e.exp !== null && Date.now() > e.exp) { data.delete(k); return undefined; }
    return e;
  };
  const impl = {
    incr: async (k: string) => { const e = live(k) ?? { v: 0, exp: null }; e.v++; data.set(k, e); return e.v; },
    pttl: async (k: string) => { const e = live(k); return !e ? -2 : e.exp === null ? -1 : e.exp - Date.now(); },
    pexpire: async (k: string, ms: number) => { const e = live(k); if (e) e.exp = Date.now() + ms; return 1; },
    get: async (k: string) => { const e = live(k); return e ? String(e.v) : null; },
    del: async (k: string) => data.delete(k) ? 1 : 0,
  };
  const client = style === "ioredis"
    ? impl
    : { incr: impl.incr, pTTL: impl.pttl, pExpire: impl.pexpire, get: impl.get, del: impl.del };
  return { client, data };
}

describe.each(["ioredis", "node-redis"] as const)("RedisRateLimitStore (%s client)", (style) => {
  it("counts within a window, exposes get/reset and expires", async () => {
    const { client } = fakeRedis(style);
    const store = new RedisRateLimitStore(client);
    expect((await store.hit("k", 40)).count).toBe(1);
    expect((await store.hit("k", 40)).count).toBe(2);
    expect((await store.get("k"))?.count).toBe(2);
    await store.reset("k");
    expect(await store.get("k")).toBeNull();
    await store.hit("e", 20);
    await new Promise((r) => setTimeout(r, 35));
    expect((await store.hit("e", 20)).count).toBe(1);
  });
  it("repairs a key that was left without a TTL", async () => {
    const { client, data } = fakeRedis(style);
    data.set("bg:orphan", { v: 5, exp: null });
    const store = new RedisRateLimitStore(client);
    const r = await store.hit("orphan", 1000);
    expect(r.count).toBe(6);
    expect(data.get("bg:orphan")!.exp).not.toBeNull();
  });
});

describe("RedisRateLimitStore failures", () => {
  const broken = { incr: async () => { throw new Error("ECONNREFUSED"); } };
  it("fails open by default and reports the error", async () => {
    const errors: unknown[] = [];
    const store = new RedisRateLimitStore(broken, { onError: (e) => errors.push(e) });
    expect((await store.hit("k", 1000)).count).toBe(0);
    expect(errors).toHaveLength(1);
  });
  it("can fail closed", async () => {
    await expect(new RedisRateLimitStore(broken, { failOpen: false }).hit("k", 1000)).rejects.toThrow("ECONNREFUSED");
  });
  it("rejects clients missing required commands", async () => {
    const store = new RedisRateLimitStore({}, { failOpen: false });
    await expect(store.hit("k", 1000)).rejects.toThrow(/none of/);
  });
});

describe("BruteForceProtector", () => {
  it("blocks after maxAttempts per IP+account and clears on success", async () => {
    const p = new BruteForceProtector({ maxAttempts: 3, maxAttemptsPerAccount: false });
    for (let i = 0; i < 3; i++) expect((await p.attempt("1.1.1.1", "Bob@x.com")).blocked).toBe(false);
    const blocked = await p.attempt("1.1.1.1", " bob@X.com ");
    expect(blocked.blocked).toBe(true);
    expect(blocked.retryAfterSec).toBeGreaterThan(0);
    // another IP is unaffected
    const ok = await p.attempt("2.2.2.2", "bob@x.com");
    expect(ok.blocked).toBe(false);
    await p.success(ok.keys);
    expect((await p.attempt("2.2.2.2", "bob@x.com")).blocked).toBe(false);
  });
  it("catches distributed guessing via the per-account counter", async () => {
    const p = new BruteForceProtector({ maxAttempts: 5, maxAttemptsPerAccount: 6 });
    const results = [];
    for (let i = 0; i < 8; i++) results.push((await p.attempt(`9.9.9.${i}`, "victim")).blocked);
    expect(results).toEqual([false, false, false, false, false, false, true, true]);
  });
  it("is race-free: parallel guesses cannot exceed the limit", async () => {
    const p = new BruteForceProtector({ maxAttempts: 5, maxAttemptsPerAccount: false });
    const all = await Promise.all(Array.from({ length: 50 }, () => p.attempt("3.3.3.3", "a")));
    expect(all.filter((r) => !r.blocked)).toHaveLength(5);
  });
  it("requires a store with reset()", () => {
    expect(() => new BruteForceProtector({ store: { hit: () => ({ count: 1, resetAt: 0 }) } })).toThrow(/reset/);
    expect(() => new BruteForceProtector({ maxAttempts: 0 })).toThrow();
    expect(() => new BruteForceProtector({ store: new MemoryStore() })).not.toThrow();
  });
});
