import type { Request, Response, NextFunction, RequestHandler } from "express";
import { BruteForceProtector, defaultIdentifier } from "../../core/brute-force";
import type { BruteForceOptions } from "../../core/brute-force";
import { normalizeIp } from "../../core/ip";

export interface ExpressBruteForceOptions extends BruteForceOptions {
  /** Extracts the account identifier (email/username) from the request. Default: body.email / username / login / user */
  identifier?: (req: Request) => unknown;
}

/**
 * Login brute-force protection. Mount it on the login route only, after
 * `express.json()`:
 *
 * ```ts
 * app.post("/login", createBruteForceMiddleware({ maxAttempts: 5 }), loginHandler);
 * ```
 *
 * Every attempt is counted per IP+account (and per account across IPs); after
 * the limit the route answers 429 with `Retry-After`. A 2xx/3xx response clears
 * the counters. Behind a proxy enable `trust proxy` so the real client IP is used.
 */
export function createBruteForceMiddleware(options: ExpressBruteForceOptions = {}): RequestHandler {
  const protector = new BruteForceProtector(options);
  const identify = options.identifier ?? ((req: Request) => defaultIdentifier(req.body));

  return (req: Request, res: Response, next: NextFunction): void => {
    const ip = normalizeIp(req.ip || req.socket.remoteAddress) || "unknown";
    protector
      .attempt(ip, identify(req))
      .then((result) => {
        if (result.blocked) {
          res.set("Retry-After", String(result.retryAfterSec));
          res.status(429).json({ error: "Too Many Requests", message: protector.message });
          return;
        }
        res.on("finish", () => {
          if (protector.isSuccess(res.statusCode)) void protector.success(result.keys).catch(() => undefined);
        });
        next();
      })
      .catch(next);
  };
}
