import type { Request, Response, NextFunction, RequestHandler } from "express";

/**
 * Creates the IP blacklist middleware.
 *
 * Rejects requests from specified IP addresses with 403 Forbidden.
 *
 * Use cases:
 * - Block known attacker IPs
 * - Restrict access from specific regions
 * - Quickly block IPs performing brute-force attacks
 *
 * Note: If running behind a proxy, you need to configure `trust proxy`
 * in Express, otherwise req.ip will always show the proxy IP.
 *
 * @example
 * ```ts
 * app.use(backendGuard({
 *   ipBlacklist: ["1.2.3.4", "5.6.7.8"]
 * }));
 * ```
 */
export function createIpBlacklistMiddleware(
  blacklist: string[]
): RequestHandler {
  // Using Set for O(1) lookup performance.
  // Array.includes() → O(n), Set.has() → O(1)
  // The difference is significant with a list of 1000 IPs.
  const blockedIps = new Set(blacklist);

  return (req: Request, res: Response, next: NextFunction): void => {
    const clientIp = req.ip || req.socket.remoteAddress || "";

    if (blockedIps.has(clientIp)) {
      res.status(403).json({
        error: "Forbidden",
        message: "Your IP address has been blocked.",
      });
      return;
    }

    next();
  };
}
