import type { CorsOptions } from "cors";
import type { HelmetOptions } from "helmet";

/**
 * Rate limiting configuration.
 * Wraps the main options of the express-rate-limit package.
 */
export interface RateLimitConfig {
  /** Time window in milliseconds. Default: 15 minutes */
  windowMs?: number;
  /** Maximum number of requests allowed in this window. Default: 100 */
  limit?: number;
  /** Message returned when the limit is exceeded */
  message?: string;
  /** HTTP status code. Default: 429 */
  statusCode?: number;
}

/**
 * XSS protection configuration.
 * Sanitizes req.body, req.query and req.params against XSS attacks.
 */
export interface XssConfig {
  /** Sanitize req.body? Default: true */
  body?: boolean;
  /** Sanitize req.query? Default: true */
  query?: boolean;
  /** Sanitize req.params? Default: true */
  params?: boolean;
}

/**
 * Request logging configuration.
 */
export interface RequestLoggingConfig {
  /** Which fields to log. Default: all */
  fields?: Array<"method" | "url" | "ip" | "statusCode" | "responseTime">;
  /** Custom log function. Default: console.log */
  logger?: (message: string) => void;
  /**
   * Mask sensitive query-string values (token, password, api_key, ...) in the logged URL.
   * - `true` (default) → built-in list of sensitive parameter names
   * - `string[]` → your own list (case-insensitive) in addition to the built-in list
   * - `false` → log URLs untouched (not recommended)
   */
  redactQuery?: boolean | string[];
}

/**
 * NoSQL operator injection protection (e.g. `{ "email": { "$ne": null } }`).
 * Checks req.body and req.query for keys that start with `$`.
 */
export interface NoSqlConfig {
  /**
   * - `"reject"` (default) → respond 400 when an operator key is found
   * - `"strip"` → silently remove the offending keys
   */
  mode?: "reject" | "strip";
  /** Check req.body? Default: true */
  body?: boolean;
  /** Check req.query? Default: true */
  query?: boolean;
  /** Also treat keys containing "." as operators (Mongo path injection). Default: false */
  dots?: boolean;
}

/**
 * HTTP parameter pollution protection for the query string.
 * `?role=user&role=admin` arrives as an array; unless whitelisted, only one value is kept.
 */
export interface ParameterPollutionConfig {
  /** Query parameters that legitimately accept several values (kept as arrays). */
  whitelist?: string[];
  /** Which value to keep for non-whitelisted repeated parameters. Default: "last" */
  keep?: "first" | "last";
}

/**
 * Safe error responses: no stack traces or internal messages to clients.
 * Fastify: applied automatically. Express: mount `backendGuardErrors(options)` after your routes.
 * (NestJS already hides non-HTTP exceptions by default.)
 */
export interface SafeErrorsConfig {
  /** Keep `err.message` for 4xx errors (client errors). Default: true. 5xx are always generic. */
  expose4xx?: boolean;
  /** Called with the real error so it can be logged server-side. Default: console.error */
  logger?: (error: unknown) => void;
}

/**
 * Startup report ("doctor") configuration.
 * By default backend-guard prints a one-time summary of what is enabled plus
 * warnings about risky configuration. It is silent when NODE_ENV is "test".
 */
export interface DoctorConfig {
  /** Custom log function for the report. Default: console.log / console.warn */
  logger?: (message: string) => void;
}

/**
 * Main configuration interface for the backendGuard() function.
 *
 * Each option can be used in 3 ways:
 * - `true` → enable with sensible defaults
 * - `false` or undefined → disabled
 * - object → enable with custom settings
 *
 * @example
 * ```ts
 * app.use(backendGuard({
 *   rateLimit: true,
 *   cors: ["https://example.com"],
 *   protectHeaders: true,
 *   xss: true,
 * }));
 * ```
 */
export interface BackendGuardOptions {
  /**
   * Rate limiting.
   * - `true` → 100 requests per 15 minutes (default)
   * - object → custom configuration
   */
  rateLimit?: boolean | RateLimitConfig;

  /**
   * CORS (Cross-Origin Resource Sharing) configuration.
   * - `true` → allow all origins
   * - `string[]` → allow only specified origins
   * - object → full CorsOptions
   */
  cors?: boolean | string[] | CorsOptions;

  /**
   * Security headers (helmet).
   * - `true` → helmet default settings
   * - object → custom HelmetOptions
   */
  protectHeaders?: boolean | HelmetOptions;

  /**
   * XSS protection — sanitizes malicious HTML/scripts from incoming requests.
   * - `true` → sanitize body, query, and params
   * - object → choose which fields to sanitize
   */
  xss?: boolean | XssConfig;

  /**
   * Request logging.
   * - `true` → log all requests via console.log
   * - object → custom configuration
   */
  requestLogging?: boolean | RequestLoggingConfig;

  /**
   * IP blacklist — requests from these IPs will be rejected with 403.
   */
  ipBlacklist?: string[];

  /** NoSQL operator injection protection (`$ne`, `$gt`, ...). `true` → reject with 400. */
  noSqlInjection?: boolean | NoSqlConfig;

  /** HTTP parameter pollution protection for the query string. */
  parameterPollution?: boolean | ParameterPollutionConfig;

  /** Generic error responses (no stack traces / internals). */
  safeErrors?: boolean | SafeErrorsConfig;

  /**
   * Startup report. `false` disables it; an object customizes the logger.
   * Default: enabled (silent when NODE_ENV === "test").
   */
  doctor?: boolean | DoctorConfig;
}
