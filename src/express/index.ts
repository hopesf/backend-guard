import { Router } from "express";
import type { RequestHandler } from "express";

// Types
import type { BackendGuardOptions } from "../types";

// Middleware factories
import { createHelmetMiddleware } from "./middleware/helmet";
import { createCorsMiddleware } from "./middleware/cors";
import { createRateLimitMiddleware } from "./middleware/rate-limit";
import { createXssMiddleware } from "./middleware/xss";
import { createRequestLoggingMiddleware } from "./middleware/request-logger";
import { createIpBlacklistMiddleware } from "./middleware/ip-blacklist";
import { validateOptions } from "../core/options";
import { createProxyWatcher, reportAtStartup } from "../core/doctor";

/**
 * Backend Guard — All-in-one security middleware for Express.js.
 *
 * Activates helmet, cors, rate-limit, XSS protection,
 * request logging and IP blacklist with a single config object.
 *
 * How it works:
 * 1. Checks each option in the config object
 * 2. Creates the corresponding middleware for enabled options
 * 3. Mounts them all on an Express Router
 * 4. Returns the Router as a single middleware
 *
 * Why use a Router?
 * Express `app.use()` takes a single function, but we have 6 middlewares.
 * A Router groups them — `app.use(backendGuard({...}))` works in one line.
 *
 * @example
 * ```ts
 * import express from "express";
 * import { backendGuard } from "backend-guard";
 *
 * const app = express();
 *
 * app.use(backendGuard({
 *   protectHeaders: true,
 *   cors: ["https://myapp.com"],
 *   rateLimit: true,
 *   xss: true,
 *   requestLogging: true,
 *   ipBlacklist: ["1.2.3.4"],
 * }));
 * ```
 */
export function backendGuard(options: BackendGuardOptions = {}): RequestHandler {
  validateOptions(options);
  reportAtStartup(options);

  const router = Router();

  // Warn once if X-Forwarded-For shows up while "trust proxy" is off
  const watchProxy = createProxyWatcher(options);
  if (options.rateLimit || options.ipBlacklist?.length) {
    router.use((req, _res, next) => {
      watchProxy(Boolean(req.headers["x-forwarded-for"]), Boolean(req.app?.get("trust proxy")));
      next();
    });
  }

  // Order matters!
  // 1. IP blacklist first — reject blocked IPs immediately
  if (options.ipBlacklist && options.ipBlacklist.length > 0) {
    router.use(createIpBlacklistMiddleware(options.ipBlacklist));
  }

  // 2. Rate limit — cut off excessive requests early
  if (options.rateLimit) {
    router.use(createRateLimitMiddleware(options.rateLimit));
  }

  // 3. Security headers
  if (options.protectHeaders) {
    router.use(createHelmetMiddleware(options.protectHeaders));
  }

  // 4. CORS
  if (options.cors) {
    router.use(createCorsMiddleware(options.cors));
  }

  // 5. XSS protection
  if (options.xss) {
    router.use(createXssMiddleware(options.xss));
  }

  // 6. Request logging last — so it can capture info added by
  //    other middlewares
  if (options.requestLogging) {
    router.use(createRequestLoggingMiddleware(options.requestLogging));
  }

  return router as unknown as RequestHandler;
}

export { backendGuard as default };

// Individual Express middleware factories
export { createHelmetMiddleware } from "./middleware/helmet";
export { createCorsMiddleware } from "./middleware/cors";
export { createRateLimitMiddleware } from "./middleware/rate-limit";
export { createXssMiddleware } from "./middleware/xss";
export { createRequestLoggingMiddleware } from "./middleware/request-logger";
export { createIpBlacklistMiddleware } from "./middleware/ip-blacklist";

export type {
  BackendGuardOptions,
  RateLimitConfig,
  XssConfig,
  RequestLoggingConfig,
} from "../types";
