import type { HitResult, RateLimitStore } from "./rate-limit";

/**
 * Minimal Redis client surface. Works with `ioredis` (incr, pttl, pexpire, get, del)
 * and `redis` / node-redis v4 (incr, pTTL, pExpire, get, del) without importing either.
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type RedisLikeClient = Record<string, any>;

export interface RedisStoreOptions {
  /** Key prefix. Default: "bg:" */
  prefix?: string;
  /**
   * When Redis fails: `true` (default) lets the request through (availability),
   * `false` rethrows so the request errors out (fail-closed).
   */
  failOpen?: boolean;
  /** Called with Redis errors (log them!). */
  onError?: (error: unknown) => void;
}

/**
 * Shared rate-limit / brute-force counter store backed by Redis, so limits
 * hold across several app instances.
 *
 * ```ts
 * import Redis from "ioredis";
 * import { RedisRateLimitStore } from "backend-guard/core";
 * backendGuard({ rateLimit: { limit: 100, store: new RedisRateLimitStore(new Redis()) } });
 * ```
 */
export class RedisRateLimitStore implements RateLimitStore {
  private readonly prefix: string;
  private readonly failOpen: boolean;
  private readonly onError?: (error: unknown) => void;

  constructor(private readonly client: RedisLikeClient, options: RedisStoreOptions = {}) {
    this.prefix = options.prefix ?? "bg:";
    this.failOpen = options.failOpen !== false;
    this.onError = options.onError;
  }

  private call(names: string[], ...args: unknown[]): Promise<unknown> {
    for (const n of names) {
      if (typeof this.client[n] === "function") return Promise.resolve(this.client[n](...args));
    }
    return Promise.reject(new Error(`[backend-guard] Redis client has none of: ${names.join(", ")}`));
  }

  async hit(key: string, windowMs: number): Promise<HitResult> {
    const k = this.prefix + key;
    try {
      const count = Number(await this.call(["incr"], k));
      let ttl = Number(await this.call(["pTTL", "pttl"], k));
      // First hit, or a key left without TTL by a crash between INCR and EXPIRE
      if (!(ttl > 0)) {
        await this.call(["pExpire", "pexpire"], k, windowMs);
        ttl = windowMs;
      }
      return { count, resetAt: Date.now() + ttl };
    } catch (err) {
      return this.handle(err, windowMs);
    }
  }

  async get(key: string): Promise<HitResult | null> {
    const k = this.prefix + key;
    try {
      const raw = await this.call(["get"], k);
      if (raw === null || raw === undefined) return null;
      const ttl = Number(await this.call(["pTTL", "pttl"], k));
      return { count: Number(raw), resetAt: Date.now() + Math.max(0, ttl) };
    } catch (err) {
      return this.handle(err, 0, true);
    }
  }

  async reset(key: string): Promise<void> {
    try {
      await this.call(["del"], this.prefix + key);
    } catch (err) {
      this.handle(err, 0);
    }
  }

  private handle(err: unknown, windowMs: number, nullable = false): HitResult & null {
    this.onError?.(err);
    if (!this.failOpen) throw err;
    return (nullable ? null : { count: 0, resetAt: Date.now() + windowMs }) as HitResult & null;
  }
}
