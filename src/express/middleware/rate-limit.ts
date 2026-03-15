import { rateLimit } from "express-rate-limit";
import type { RequestHandler } from "express";
import type { BackendGuardOptions, RateLimitConfig } from "../../types";

/**
 * Creates the rate limit middleware.
 *
 * Limits the number of requests from the same IP within a time window.
 * This is the most fundamental way to prevent brute-force attacks and API abuse.
 *
 * Default settings:
 * - Maximum 100 requests per 15-minute window
 * - Returns HTTP 429 (Too Many Requests) when limit is exceeded
 *
 * Why is this needed?
 * Without rate limiting, an attacker can make thousands of login attempts per second
 * or overload your API causing a denial-of-service (DoS).
 */
export function createRateLimitMiddleware(
  option: BackendGuardOptions["rateLimit"]
): RequestHandler {
  const defaults: RateLimitConfig = {
    windowMs: 15 * 60 * 1000, // 15 minutes
    limit: 100,
    message: "Too many requests, please try again later.",
    statusCode: 429,
  };

  if (option === true) {
    return rateLimit(defaults);
  }

  // Merge user config with defaults (user config takes priority)
  const config = option as RateLimitConfig;
  return rateLimit({
    ...defaults,
    ...config,
  });
}
