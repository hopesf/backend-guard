import fp from "fastify-plugin";
import type { FastifyPluginAsync } from "fastify";
import type { BackendGuardOptions, RateLimitConfig } from "../types";
import type { CorsOptions } from "cors";
import type { HelmetOptions } from "helmet";

import { createIpBlacklistHook } from "./hooks/ip-blacklist";
import { createXssHook } from "./hooks/xss";
import { createRequestLoggingHook } from "./hooks/request-logger";

/**
 * Dynamically requires a package and throws a helpful error if not installed.
 *
 * This is how we make @fastify/* packages optional at runtime:
 * - They are devDependencies (TypeScript can compile against their types)
 * - They are optional peerDependencies (users install only what they need)
 * - Express-only users never need to install any @fastify/* packages
 */
function tryRequire(name: string): unknown {
  try {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    return require(name);
  } catch {
    throw new Error(
      `[backend-guard] "${name}" is required for this feature. Install it: npm install ${name}`
    );
  }
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
function buildRateLimitOpts(option: true | RateLimitConfig) {
  if (option === true) {
    return { timeWindow: 15 * 60 * 1000, max: 100 };
  }
  return {
    timeWindow: option.windowMs ?? 15 * 60 * 1000,
    max: option.limit ?? 100,
    ...(option.message && {
      errorResponseBuilder: () => ({
        statusCode: option.statusCode ?? 429,
        error: "Too Many Requests",
        message: option.message,
      }),
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
  const plugin: FastifyPluginAsync = async (fastify) => {
    // Order matters — same reasoning as the Express version:

    // 1. IP blacklist first — reject blocked IPs with zero further processing
    if (options.ipBlacklist && options.ipBlacklist.length > 0) {
      fastify.addHook("onRequest", createIpBlacklistHook(options.ipBlacklist));
    }

    // 2. Rate limiting — cut excessive requests early
    if (options.rateLimit) {
      const mod = tryRequire("@fastify/rate-limit");
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      await fastify.register(getDefault(mod) as any, buildRateLimitOpts(options.rateLimit as true | RateLimitConfig) as any);
    }

    // 3. Security headers
    if (options.protectHeaders) {
      const mod = tryRequire("@fastify/helmet");
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      await fastify.register(getDefault(mod) as any, buildHelmetOpts(options.protectHeaders as true | HelmetOptions) as any);
    }

    // 4. CORS
    if (options.cors) {
      const mod = tryRequire("@fastify/cors");
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      await fastify.register(getDefault(mod) as any, buildCorsOpts(options.cors as true | string[] | CorsOptions) as any);
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
