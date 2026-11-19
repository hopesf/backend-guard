import {
  CanActivate,
  ExecutionContext,
  HttpException,
  Inject,
  Injectable,
} from "@nestjs/common";

import { normalizeIp } from "../../core/ip";
import { resolveRateLimit } from "../../core/options";
import { MemoryStore, RateLimiter } from "../../core/rate-limit";
import type { BackendGuardOptions } from "../../types";
import { BACKEND_GUARD_OPTIONS } from "../nestjs.constants";

/**
 * Guard that applies per-IP rate limiting, compatible with both Express and
 * Fastify adapters. Uses the shared in-memory `RateLimiter` from core
 * (expired entries are swept automatically; counters are per process).
 *
 * @example
 * BackendGuardModule.forRoot({ rateLimit: { windowMs: 60_000, limit: 20 } })
 */
@Injectable()
export class RateLimitGuard implements CanActivate {
  private readonly limiter: RateLimiter;
  private readonly statusCode: number;
  private readonly message: string;

  constructor(
    @Inject(BACKEND_GUARD_OPTIONS)
    options: BackendGuardOptions,
  ) {
    const config = resolveRateLimit(options.rateLimit ?? true)!;
    this.limiter = new RateLimiter(config.windowMs, config.limit, new MemoryStore());
    this.statusCode = config.statusCode;
    this.message = config.message;
  }

  /** Number of tracked keys (exposed for tests/diagnostics). */
  get size(): number {
    return (this.limiter.store as MemoryStore).size;
  }

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const req = context
      .switchToHttp()
      .getRequest<{ ip?: string; socket?: { remoteAddress?: string } }>();

    const key = normalizeIp(req.ip ?? req.socket?.remoteAddress) || "unknown";

    if (!(await this.limiter.allow(key))) {
      throw new HttpException(this.message, this.statusCode);
    }
    return true;
  }
}
