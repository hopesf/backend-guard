import type { Request, Response, NextFunction, RequestHandler } from "express";
import type { BackendGuardOptions } from "../../types";
import { resolveLogging } from "../../core/options";
import { formatLogLine } from "../../core/logger";

/**
 * Creates the request logging middleware.
 *
 * Logs method, URL, IP, status code and response time once the response
 * finished. Sensitive query-string values (token, password, ...) are masked
 * unless `redactQuery: false`.
 */
export function createRequestLoggingMiddleware(
  option: BackendGuardOptions["requestLogging"]
): RequestHandler {
  const config = resolveLogging(option ?? true)!;

  return (req: Request, res: Response, next: NextFunction): void => {
    const start = Date.now();
    res.on("finish", () => {
      config.logger(
        formatLogLine(config, {
          method: req.method,
          url: req.originalUrl || req.url,
          ip: req.ip,
          statusCode: res.statusCode,
          responseTimeMs: Date.now() - start,
        })
      );
    });
    next();
  };
}
