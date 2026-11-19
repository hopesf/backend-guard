import { rateLimit } from "express-rate-limit";
import type { RequestHandler } from "express";
import type { BackendGuardOptions } from "../../types";
import { resolveRateLimit } from "../../core/options";

/**
 * Creates the rate limit middleware (powered by express-rate-limit).
 *
 * Defaults: 100 requests per 15-minute window, HTTP 429 when exceeded.
 * Counters live in process memory; behind several instances plug a shared
 * store into express-rate-limit directly.
 */
export function createRateLimitMiddleware(
  option: BackendGuardOptions["rateLimit"]
): RequestHandler {
  const config = resolveRateLimit(option ?? true)!;
  return rateLimit(config);
}
