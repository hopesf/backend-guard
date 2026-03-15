import xssFilter from "xss";
import type { Request, Response, NextFunction, RequestHandler } from "express";
import type { BackendGuardOptions, XssConfig } from "../../types";

/**
 * Recursively sanitizes all string values of an object against XSS.
 *
 * How XSS (Cross-Site Scripting) attacks work:
 * An attacker enters `<script>document.cookie</script>` in a form field.
 * This data is saved to the database and when shown to another user,
 * the script executes and steals their cookies.
 *
 * This function sanitizes all string values using xss():
 * `<script>alert('xss')</script>` → `&lt;script&gt;alert('xss')&lt;/script&gt;`
 */
function sanitize(obj: unknown): unknown {
  if (typeof obj === "string") {
    return xssFilter(obj);
  }

  if (Array.isArray(obj)) {
    return obj.map(sanitize);
  }

  if (obj !== null && typeof obj === "object") {
    const result: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(obj)) {
      result[key] = sanitize(value);
    }
    return result;
  }

  // number, boolean, null, undefined → returned as-is
  return obj;
}

/**
 * Creates the XSS protection middleware.
 *
 * Sanitizes all string values in req.body, req.query and req.params
 * from malicious HTML/script tags.
 *
 * Note: We write our own middleware since xss-clean is deprecated.
 * Uses the `xss` package under the hood.
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
      Object.keys(req.query).forEach((key) => {
        (req.query as Record<string, unknown>)[key] = sanitize(req.query[key]);
      });
    }

    if (config.params !== false && req.params) {
      req.params = sanitize(req.params) as typeof req.params;
    }

    next();
  };
}
