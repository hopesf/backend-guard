import { DynamicModule, Inject, MiddlewareConsumer, Module, NestModule } from "@nestjs/common";
import { APP_GUARD, APP_INTERCEPTOR } from "@nestjs/core";
import helmet from "helmet";
import cors from "cors";
import type { CorsOptions } from "cors";
import type { HelmetOptions } from "helmet";

import type { BackendGuardOptions } from "../types";
import { BACKEND_GUARD_OPTIONS } from "./nestjs.constants";
import { IpBlacklistGuard } from "./guards/ip-blacklist.guard";
import { RateLimitGuard } from "./guards/rate-limit.guard";
import { XssInterceptor } from "./interceptors/xss.interceptor";
import { RequestLoggingInterceptor } from "./interceptors/request-logger.interceptor";

function resolveCorsOptions(option: BackendGuardOptions["cors"]): CorsOptions {
  if (option === true) return {};
  if (Array.isArray(option)) return { origin: option };
  return option as CorsOptions;
}

function resolveHelmetOptions(
  option: BackendGuardOptions["protectHeaders"],
): HelmetOptions {
  return option === true ? {} : (option as HelmetOptions);
}

/**
 * Backend Guard — NestJS Dynamic Module.
 *
 * Provides all-in-one security for NestJS apps using the same
 * BackendGuardOptions interface as the Express and Fastify integrations.
 *
 * Security features and how they're applied:
 * - protectHeaders  → NestJS middleware (helmet)               Express adapter only
 * - cors            → NestJS middleware (cors)                 Express adapter only
 * - rateLimit       → RateLimitGuard APP_GUARD (in-memory)    adapter-agnostic
 * - ipBlacklist     → IpBlacklistGuard APP_GUARD              adapter-agnostic
 * - xss             → XssInterceptor APP_INTERCEPTOR          adapter-agnostic
 * - requestLogging  → RequestLoggingInterceptor               adapter-agnostic
 *
 * Peer dependencies:
 * - @nestjs/common + @nestjs/core   → always required for NestJS integration
 * - rxjs                            → required for interceptors
 *
 * @example
 * ```ts
 * // app.module.ts
 * import { Module } from "@nestjs/common";
 * import { BackendGuardModule } from "backend-guard";
 *
 * @Module({
 *   imports: [
 *     BackendGuardModule.forRoot({
 *       protectHeaders: true,
 *       cors: ["https://myapp.com"],
 *       rateLimit: true,
 *       xss: true,
 *       requestLogging: true,
 *       ipBlacklist: ["1.2.3.4"],
 *     }),
 *   ],
 * })
 * export class AppModule {}
 * ```
 */
@Module({})
export class BackendGuardModule implements NestModule {
  constructor(
    @Inject(BACKEND_GUARD_OPTIONS)
    private readonly options: BackendGuardOptions,
  ) {}

  static forRoot(options: BackendGuardOptions = {}): DynamicModule {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const providers: any[] = [
      { provide: BACKEND_GUARD_OPTIONS, useValue: options },
    ];

    // ── Rate limiting via in-memory RateLimitGuard ───────────────────────────
    // Uses @nestjs/common's HttpException for 429 responses — no external
    // peer dependencies, works with both Express and Fastify adapters.
    if (options.rateLimit) {
      providers.push(RateLimitGuard);
      providers.push({ provide: APP_GUARD, useExisting: RateLimitGuard });
    }

    // ── IP blacklist via Guard ────────────────────────────────────────────────
    if (options.ipBlacklist && options.ipBlacklist.length > 0) {
      providers.push(IpBlacklistGuard);
      providers.push({ provide: APP_GUARD, useExisting: IpBlacklistGuard });
    }

    // ── XSS protection via Interceptor ───────────────────────────────────────
    if (options.xss) {
      providers.push(XssInterceptor);
      providers.push({ provide: APP_INTERCEPTOR, useExisting: XssInterceptor });
    }

    // ── Request logging via Interceptor ──────────────────────────────────────
    if (options.requestLogging) {
      providers.push(RequestLoggingInterceptor);
      providers.push({
        provide: APP_INTERCEPTOR,
        useExisting: RequestLoggingInterceptor,
      });
    }

    return {
      module: BackendGuardModule,
      global: true,    // security applies to ALL routes without re-importing
      providers,
      exports: [BACKEND_GUARD_OPTIONS],
    };
  }

  /**
   * Applies helmet and cors as Express middleware.
   *
   * NOTE: These middlewares only work with NestJS's default Express adapter.
   * If you use the Fastify adapter, register @fastify/helmet and @fastify/cors
   * manually in main.ts instead.
   */
  configure(consumer: MiddlewareConsumer): void {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const middlewares: any[] = [];

    // Order matches the Express integration:
    // 1. Security headers first
    if (this.options.protectHeaders) {
      middlewares.push(helmet(resolveHelmetOptions(this.options.protectHeaders)));
    }

    // 2. CORS
    if (this.options.cors) {
      middlewares.push(cors(resolveCorsOptions(this.options.cors)));
    }

    if (middlewares.length > 0) {
      consumer.apply(...middlewares).forRoutes("*");
    }
  }
}
