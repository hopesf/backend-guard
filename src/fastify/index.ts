import fp from "fastify-plugin";
import type { FastifyPluginAsync } from "fastify";
import type { BackendGuardOptions, RateLimitConfig } from "../types";
import type { CorsOptions } from "cors";
import type { HelmetOptions } from "helmet";

import { createIpBlacklistHook } from "./hooks/ip-blacklist";
import { createXssHook } from "./hooks/xss";
import { createRequestLoggingHook } from "./hooks/request-logger";
import { createHppHook, createNoSqlHook } from "./hooks/input";
import type { RateLimitStore } from "../core/rate-limit";
import { resolveSafeErrors, toSafeError } from "../core/errors";
import { resolveRateLimit } from "../core/options";
import { validateOptions } from "../core/options";
import { createProxyWatcher, reportAtStartup } from "../core/doctor";

// eslint-disable-next-line @typescript-eslint/no-require-imports
function requireOptional(mod: unknown, name: string): unknown {
  if (mod === undefined) {
    throw new Error(
      `[backend-guard] "${name}" is required for this feature. Install it: npm install ${name}`
    );
  }
  return mod;
}

/**
 * Handles both CJS modules (exports directly) and
 * ESM-compiled-to-CJS modules (exports via .default).
 */
function getDefault(mod: unknown): unknown {
  if (
    mod &&
    typeof mod === "object" &&
    "default" in (mod as Record<string, unknown>)
  ) {
    return (mod as Record<string, unknown>).default;
  }
  return mod;
}

// ── Option builders: translate BackendGuardOptions to @fastify/* plugin APIs ──

/**
 * @fastify/rate-limit uses different option names than express-rate-limit:
 * - windowMs → timeWindow
 * - limit    → max
 */
/** Adapts a backend-guard store to @fastify/rate-limit's custom store contract. */
function toFastifyStore(store: RateLimitStore, prefix = "bg:rl:") {
  class BackendGuardFastifyStore {
    incr(key: string, cb: (err: Error | null, res?: { current: number; ttl: number }) => void, timeWindow: number) {
      Promise.resolve(store.hit(prefix + key, timeWindow)).then(
        (r) => cb(null, { current: r.count, ttl: Math.max(0, r.resetAt - Date.now()) }),
        (err) => cb(err as Error),
      );
    }
    child() {
      return new BackendGuardFastifyStore();
    }
  }
  return BackendGuardFastifyStore;
}

function buildRateLimitOpts(option: true | RateLimitConfig) {
  const c = resolveRateLimit(option)!;
  return {
    timeWindow: c.windowMs,
    max: c.limit,
    ...(c.store ? { store: toFastifyStore(c.store) } : {}),
    errorResponseBuilder: () => ({
      statusCode: c.statusCode,
      error: "Too Many Requests",
      message: c.message,
    }),
  };
}

/** @fastify/helmet accepts the same HelmetOptions as the helmet package */
function buildHelmetOpts(option: true | HelmetOptions) {
  return option === true ? {} : option;
}

/** @fastify/cors accepts the same options as the cors package */
function buildCorsOpts(option: true | string[] | CorsOptions) {
  if (option === true) return {};
  if (Array.isArray(option)) return { origin: option };
  return option;
}

/**
 * Backend Guard Fastify plugin factory.
 *
 * Returns a Fastify plugin that applies security using:
 * - @fastify/helmet     → security headers     (protectHeaders option)
 * - @fastify/cors       → CORS                 (cors option)
 * - @fastify/rate-limit → rate limiting        (rateLimit option)
 * - Fastify hooks       → XSS, IP blacklist, request logging
 *
 * Why fastify-plugin (fp)?
 * By default, Fastify encapsulates plugins — hooks/decorators registered
 * inside a plugin only apply to routes inside that plugin's scope.
 * fp() removes this encapsulation so security applies to ALL routes.
 *
 * Required peer dependencies:
 * - `fastify-plugin`        — always required for Fastify integration
 * - `@fastify/helmet`       — only if protectHeaders is enabled
 * - `@fastify/cors`         — only if cors is enabled
 * - `@fastify/rate-limit`   — only if rateLimit is enabled
 *
 * @example
 * ```ts
 * import Fastify from "fastify";
 * import { backendGuardFastify } from "backend-guard";
 *
 * const fastify = Fastify();
 *
 * await fastify.register(backendGuardFastify({
 *   protectHeaders: true,
 *   cors: ["https://myapp.com"],
 *   rateLimit: true,
 *   xss: true,
 *   requestLogging: true,
 *   ipBlacklist: ["1.2.3.4"],
 * }));
 * ```
 */
export function backendGuardFastify(options: BackendGuardOptions = {}): FastifyPluginAsync {
  validateOptions(options);
  const watchProxy = createProxyWatcher(options);

  const plugin: FastifyPluginAsync = async (fastify) => {
    reportAtStartup(options);

    // Warn once if X-Forwarded-For shows up while trustProxy is off
    if (options.rateLimit || options.ipBlacklist?.length) {
      fastify.addHook("onRequest", async (request) => {
        const cfg = (request.server as unknown as { initialConfig?: { trustProxy?: unknown } }).initialConfig;
        watchProxy(Boolean(request.headers["x-forwarded-for"]), Boolean(cfg?.trustProxy));
      });
    }

    // Order matters — same reasoning as the Express version:

    // 1. IP blacklist first — reject blocked IPs with zero further processing
    if (options.ipBlacklist && options.ipBlacklist.length > 0) {
      fastify.addHook("onRequest", createIpBlacklistHook(options.ipBlacklist));
    }

    // 2. Rate limiting — cut excessive requests early
    if (options.rateLimit) {
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      const rl = (() => { try { return require("@fastify/rate-limit"); } catch { return undefined; } })();
      const mod = requireOptional(rl, "@fastify/rate-limit");
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      await fastify.register(getDefault(mod) as any, buildRateLimitOpts(options.rateLimit as true | RateLimitConfig) as any);
    }

    // 3. Security headers
    if (options.protectHeaders) {
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      const hl = (() => { try { return require("@fastify/helmet"); } catch { return undefined; } })();
      const mod = requireOptional(hl, "@fastify/helmet");
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      await fastify.register(getDefault(mod) as any, buildHelmetOpts(options.protectHeaders as true | HelmetOptions) as any);
    }

    // 4. CORS
    if (options.cors) {
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      const co = (() => { try { return require("@fastify/cors"); } catch { return undefined; } })();
      const mod = requireOptional(co, "@fastify/cors");
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      await fastify.register(getDefault(mod) as any, buildCorsOpts(options.cors as true | string[] | CorsOptions) as any);
    }

    // 5a/5b. Parameter pollution, then NoSQL operator check (before XSS sees the data)
    if (options.parameterPollution) {
      fastify.addHook("preHandler", createHppHook(options.parameterPollution));
    }
    if (options.noSqlInjection) {
      fastify.addHook("preHandler", createNoSqlHook(options.noSqlInjection));
    }

    // 5c. Safe error responses (no stack traces / internals)
    const safe = resolveSafeErrors(options.safeErrors);
    if (safe) {
      fastify.setErrorHandler((err, _request, reply) => {
        safe.logger(err);
        const { status, body } = toSafeError(err, safe);
        return reply.status(status).send(body);
      });
    }

    // 5. XSS sanitization (preHandler — after body parsing, before the route handler)
    if (options.xss) {
      fastify.addHook("preHandler", createXssHook(options.xss));
    }

    // 6. Request logging (onResponse — after the response is fully sent)
    if (options.requestLogging) {
      fastify.addHook("onResponse", createRequestLoggingHook(options.requestLogging));
    }
  };

  // fp() removes Fastify's default plugin encapsulation so that
  // all hooks and plugin registrations apply globally to every route.
  return fp(plugin, { fastify: ">=4.0.0", name: "backend-guard" });
}

export { createBruteForceHooks } from "./hooks/brute-force";
export type { FastifyBruteForceOptions } from "./hooks/brute-force";
export type { BackendGuardOptions, RateLimitConfig, XssConfig, RequestLoggingConfig } from "../types";
