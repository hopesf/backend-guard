import helmet from "helmet";
import type { HelmetOptions } from "helmet";
import type { RequestHandler } from "express";
import type { BackendGuardOptions } from "../../types";

/**
 * Creates the Helmet middleware.
 *
 * Helmet secures your app by setting various HTTP response headers:
 * - Removes X-Powered-By (prevents attackers from identifying the framework)
 * - Adds Content-Security-Policy (prevents XSS and data injection)
 * - Adds X-Frame-Options (prevents clickjacking attacks)
 * - Adds Strict-Transport-Security (enforces HTTPS)
 * - and 10+ more headers...
 */
export function createHelmetMiddleware(
  option: BackendGuardOptions["protectHeaders"]
): RequestHandler {
  if (option === true) {
    // Default settings — helmet's own defaults are already good
    return helmet();
  }

  // User provided custom options (HelmetOptions)
  return helmet(option as HelmetOptions);
}
