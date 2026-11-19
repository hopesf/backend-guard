import type { Request, Response, NextFunction, RequestHandler } from "express";
import type { BackendGuardOptions, XssConfig } from "../../types";
import { sanitize } from "../../shared/sanitize";

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
  const config: XssConfig =
    option === true ? { body: true, query: true, params: true } : (option as XssConfig);

  return (req: Request, _res: Response, next: NextFunction): void => {
    if (config.body !== false && req.body) {
      req.body = sanitize(req.body);
    }

    if (config.query !== false && req.query) {
      Object.defineProperty(req, "query", {
        value: sanitize(req.query),
        configurable: true,
        writable: true,
        enumerable: true,
      });
    }

    if (config.params !== false) {
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
