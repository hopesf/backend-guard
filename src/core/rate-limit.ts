export interface HitResult {
  /** Requests counted in the current window, including this one. */
  count: number;
  /** Epoch ms at which the current window ends. */
  resetAt: number;
}

/**
 * Storage contract for the rate limiter. `hit` registers one request for `key`
 * and returns the updated counter. May be async so Redis-style stores can plug in.
 */
export interface RateLimitStore {
  hit(key: string, windowMs: number): HitResult | Promise<HitResult>;
}

/** In-process store. Expired entries are swept at most once per window. */
export class MemoryStore implements RateLimitStore {
  private readonly records = new Map<string, HitResult>();
  private lastSweep = Date.now();

  hit(key: string, windowMs: number): HitResult {
    const now = Date.now();

    if (now - this.lastSweep >= windowMs) {
      for (const [k, rec] of this.records) {
        if (now > rec.resetAt) this.records.delete(k);
      }
      this.lastSweep = now;
    }

    const rec = this.records.get(key);
    if (!rec || now > rec.resetAt) {
      const fresh = { count: 1, resetAt: now + windowMs };
      this.records.set(key, fresh);
      return fresh;
    }
    rec.count++;
    return rec;
  }

  get size(): number {
    return this.records.size;
  }
}

export class RateLimiter {
  constructor(
    private readonly windowMs: number,
    private readonly limit: number,
    readonly store: RateLimitStore = new MemoryStore()
  ) {}

  /** Registers a request; resolves to `true` when it is within the limit. */
  async allow(key: string): Promise<boolean> {
    const { count } = await this.store.hit(key, this.windowMs);
    return count <= this.limit;
  }
}
