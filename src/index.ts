// ============================================================
// Express
// ============================================================
export { backendGuard, backendGuard as default } from "./express/index";

// Individual Express middleware factories
export { createHelmetMiddleware } from "./express/middleware/helmet";
export { createCorsMiddleware } from "./express/middleware/cors";
export { createRateLimitMiddleware } from "./express/middleware/rate-limit";
export { createXssMiddleware } from "./express/middleware/xss";
export { createRequestLoggingMiddleware } from "./express/middleware/request-logger";
export { createIpBlacklistMiddleware } from "./express/middleware/ip-blacklist";
export { createValidator } from "./express/middleware/validate";

// ============================================================
// Fastify
// ============================================================
export { backendGuardFastify } from "./fastify/index";
export { createFastifyValidator } from "./fastify/hooks/validate";

// ============================================================
// NestJS
// ============================================================
export {
  BackendGuardModule,
  BACKEND_GUARD_OPTIONS,
  IpBlacklistGuard,
  RateLimitGuard,
  XssInterceptor,
  RequestLoggingInterceptor,
} from "./nestjs/index";

// ============================================================
// Shared types
// ============================================================
export type {
  BackendGuardOptions,
  RateLimitConfig,
  XssConfig,
  RequestLoggingConfig,
} from "./types";
