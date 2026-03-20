import {
  CanActivate,
  ExecutionContext,
  HttpException,
  Inject,
  Injectable,
} from "@nestjs/common";

import type { BackendGuardOptions, RateLimitConfig } from "../../types";
import { BACKEND_GUARD_OPTIONS } from "../nestjs.constants";

interface RateLimitRecord {
  count: number;
  resetAt: number;
}

/**
 * Guard that applies in-memory rate limiting, compatible with both
 * Express and Fastify adapters.
 *
 * Uses the same RateLimitConfig interface as the Express integration:
 * - windowMs → sliding window duration in milliseconds (default: 15 min)
 * - limit    → max requests per window per IP (default: 100)
 *
 * Storage: Map<ip, record> — resets on application restart, which is
 * intentional for stateless/single-instance deployments. For multi-instance
 * deployments users should add their own Redis-backed throttler.
 *
 * @example
 * // Activated automatically when rateLimit option is set:
 * BackendGuardModule.forRoot({ rateLimit: { windowMs: 60_000, limit: 20 } })
 */
@Injectable()
export class RateLimitGuard implements CanActivate {
  private readonly windowMs: number;
  private readonly limit: number;
  private readonly store = new Map<string, RateLimitRecord>();

  constructor(
    @Inject(BACKEND_GUARD_OPTIONS)
    options: BackendGuardOptions,
  ) {
    const config: RateLimitConfig =
      options.rateLimit === true ? {} : (options.rateLimit as RateLimitConfig);

    this.windowMs = config.windowMs ?? 15 * 60 * 1000;
    this.limit = config.limit ?? 100;
  }

  canActivate(context: ExecutionContext): boolean {
    const req = context
      .switchToHttp()
      .getRequest<{ ip?: string; socket?: { remoteAddress?: string } }>();

    const key = req.ip ?? req.socket?.remoteAddress ?? "unknown";
    const now = Date.now();

    const record = this.store.get(key);

    if (!record || now > record.resetAt) {
      // New window — reset counter
      this.store.set(key, { count: 1, resetAt: now + this.windowMs });
      return true;
    }

    if (record.count >= this.limit) {
      throw new HttpException("Too Many Requests", 429);
    }

    record.count++;
    return true;
  }
}
