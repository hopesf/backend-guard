import { rateLimit } from "express-rate-limit";
import type { Store } from "express-rate-limit";
import type { RequestHandler } from "express";
import type { BackendGuardOptions } from "../../types";
import { resolveRateLimit } from "../../core/options";
import type { RateLimitStore } from "../../core/rate-limit";

/** Adapts a backend-guard store to express-rate-limit's `Store` interface. */
export function toExpressStore(store: RateLimitStore, windowMs: number, prefix = "bg:rl:"): Store {
  return {
    localKeys: false,
    async increment(key: string) {
      const r = await store.hit(prefix + key, windowMs);
      return { totalHits: r.count, resetTime: new Date(r.resetAt) };
    },
    async decrement() {
      /* counters are not decremented (skipFailedRequests is unsupported with custom stores) */
    },
    async resetKey(key: string) {
      await store.reset?.(prefix + key);
    },
  };
}

/**
 * Creates the rate limit middleware (powered by express-rate-limit).
 *
 * Defaults: 100 requests per 15-minute window, HTTP 429 when exceeded.
 * Counters live in process memory unless `store` is given (e.g. Redis).
 */
export function createRateLimitMiddleware(
  option: BackendGuardOptions["rateLimit"]
): RequestHandler {
  const { store, ...config } = resolveRateLimit(option ?? true)!;
  return rateLimit({
    ...config,
    ...(store ? { store: toExpressStore(store, config.windowMs) } : {}),
  });
}
