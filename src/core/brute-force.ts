import { MemoryStore } from "./rate-limit";
import type { RateLimitStore } from "./rate-limit";

export interface BruteForceOptions {
  /** Max attempts per (IP + account) within the window. Default: 5 */
  maxAttempts?: number;
  /**
   * Max attempts per account across ALL IPs within the window (catches distributed
   * guessing). Default: maxAttempts × 5. `false` disables it — recommended if you
   * fear attackers deliberately locking out a victim account.
   */
  maxAttemptsPerAccount?: number | false;
  /** Counting window = lockout duration (fixed window). Default: 15 minutes */
  windowMs?: number;
  /** Counter store. Needs `reset`. Default: in-memory (use Redis for multiple instances). */
  store?: RateLimitStore;
  /** Response status codes that count as a successful login (counters are cleared). Default: 2xx and 3xx */
  isSuccess?: (statusCode: number) => boolean;
  /** Message of the 429 response. */
  message?: string;
}

export interface AttemptResult {
  blocked: boolean;
  /** Seconds until the lock expires (when blocked). */
  retryAfterSec: number;
  /** Counter keys to clear after a successful login. */
  keys: string[];
}

const normalizeAccount = (account: unknown): string | null => {
  if (typeof account !== "string") return null;
  const a = account.trim().toLowerCase().slice(0, 256);
  return a.length ? a : null;
};

/**
 * Framework-agnostic login brute-force limiter. Every login attempt is
 * counted BEFORE the handler runs (so parallel guesses cannot race past the
 * limit); a successful login clears the counters.
 */
export class BruteForceProtector {
  readonly windowMs: number;
  readonly maxAttempts: number;
  readonly maxAttemptsPerAccount: number | false;
  readonly isSuccess: (status: number) => boolean;
  readonly message: string;
  private readonly store: RateLimitStore;

  constructor(options: BruteForceOptions = {}) {
    this.windowMs = options.windowMs ?? 15 * 60 * 1000;
    this.maxAttempts = options.maxAttempts ?? 5;
    this.maxAttemptsPerAccount =
      options.maxAttemptsPerAccount === undefined ? this.maxAttempts * 5 : options.maxAttemptsPerAccount;
    this.store = options.store ?? new MemoryStore();
    this.isSuccess = options.isSuccess ?? ((s) => s >= 200 && s < 400);
    this.message = options.message ?? "Too many failed attempts, please try again later.";

    if (typeof this.store.reset !== "function") {
      throw new Error("[backend-guard] bruteForce store must implement reset(key) (MemoryStore and RedisRateLimitStore do).");
    }
    if (!(this.windowMs > 0) || !Number.isInteger(this.maxAttempts) || this.maxAttempts < 1) {
      throw new Error("[backend-guard] bruteForce: windowMs must be > 0 and maxAttempts a positive integer.");
    }
  }

  /** Registers one login attempt and tells whether it must be blocked. */
  async attempt(ip: string, account?: unknown): Promise<AttemptResult> {
    const acct = normalizeAccount(account);
    const ipKey = `bf:ip:${ip}|${acct ?? ""}`;
    const keys = [ipKey];

    const ipHit = await this.store.hit(ipKey, this.windowMs);
    if (ipHit.count > this.maxAttempts) return this.blocked(ipHit.resetAt, keys);

    if (acct && this.maxAttemptsPerAccount !== false) {
      const acctKey = `bf:acct:${acct}`;
      keys.push(acctKey);
      const acctHit = await this.store.hit(acctKey, this.windowMs);
      if (acctHit.count > this.maxAttemptsPerAccount) return this.blocked(acctHit.resetAt, keys);
    }
    return { blocked: false, retryAfterSec: 0, keys };
  }

  /** Clears the counters after a successful login. */
  async success(keys: string[]): Promise<void> {
    await Promise.all(keys.map((k) => this.store.reset!(k)));
  }

  private blocked(resetAt: number, keys: string[]): AttemptResult {
    return { blocked: true, retryAfterSec: Math.max(1, Math.ceil((resetAt - Date.now()) / 1000)), keys };
  }
}

/** Default identifier lookup for login bodies: email / username / login. */
export function defaultIdentifier(body: unknown): unknown {
  if (body && typeof body === "object") {
    const b = body as Record<string, unknown>;
    return b.email ?? b.username ?? b.login ?? b.user;
  }
  return undefined;
}
