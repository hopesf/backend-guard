import type { Request, Response, NextFunction, RequestHandler } from "express";
import type { BackendGuardOptions } from "../../types";
import { resolveXss } from "../../core/options";
import { sanitize } from "../../core/sanitize";

/**
 * Creates the XSS sanitization middleware.
 *
 * Sanitizes string values in req.body, req.query and req.params with the
 * `xss` package. NOTE: this is input *sanitization*, not a replacement for
 * context-aware output encoding when rendering user data.
 *
 * Express specifics:
 * - `req.body`   → mount this AFTER `express.json()` / `express.urlencoded()`.
 * - `req.query`  → in Express 5 this is a getter that re-parses the URL on
 *                  every access, so we shadow it on the request instance.
 * - `req.params` → Express assigns `req.params` per matched route *after*
 *                  this middleware ran, so we install an accessor whose
 *                  setter sanitizes whatever Express assigns later.
 */
export function createXssMiddleware(
  option: BackendGuardOptions["xss"]
): RequestHandler {
  const config = resolveXss(option ?? true)!;

  return (req: Request, _res: Response, next: NextFunction): void => {
    if (config.body && req.body) {
      req.body = sanitize(req.body);
    }

    if (config.query && req.query) {
      Object.defineProperty(req, "query", {
        value: sanitize(req.query),
        configurable: true,
        writable: true,
        enumerable: true,
      });
    }

    if (config.params) {
      let current: unknown = sanitize(req.params ?? {});
      Object.defineProperty(req, "params", {
        configurable: true,
        enumerable: true,
        get: () => current,
        set: (value: unknown) => {
          current = sanitize(value);
        },
      });
    }

    next();
  };
}
