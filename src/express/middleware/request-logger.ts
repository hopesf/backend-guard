import type { Request, Response, NextFunction, RequestHandler } from "express";
import type { BackendGuardOptions, RequestLoggingConfig } from "../../types";

/**
 * Creates the request logging middleware.
 *
 * Logs every incoming HTTP request: method, URL, IP and response time.
 * Essential for troubleshooting and security auditing in production.
 *
 * Why built-in logging?
 * - See which endpoints receive traffic
 * - Detect slow responses (responseTime)
 * - Identify suspicious IPs
 * - Track errors (log requests that return 500)
 *
 * Note: This is a simple logger. For large projects, winston or pino is recommended.
 * But for most projects, this is sufficient.
 */
export function createRequestLoggingMiddleware(
  option: BackendGuardOptions["requestLogging"]
): RequestHandler {
  const defaultFields: RequestLoggingConfig["fields"] = [
    "method",
    "url",
    "ip",
    "statusCode",
    "responseTime",
  ];

  const config: RequestLoggingConfig =
    option === true
      ? { fields: defaultFields, logger: console.log }
      : {
          fields: (option as RequestLoggingConfig).fields || defaultFields,
          logger: (option as RequestLoggingConfig).logger || console.log,
        };

  return (req: Request, res: Response, next: NextFunction): void => {
    const start = Date.now();

    // res.on("finish") → fires after the response is fully sent
    res.on("finish", () => {
      const duration = Date.now() - start;
      const parts: string[] = [];
      const fields = config.fields!;

      if (fields.includes("method")) parts.push(req.method);
      if (fields.includes("url")) parts.push(req.originalUrl || req.url);
      if (fields.includes("ip")) parts.push(req.ip || "unknown");
      if (fields.includes("statusCode")) parts.push(String(res.statusCode));
      if (fields.includes("responseTime")) parts.push(`${duration}ms`);

      config.logger!(`[backend-guard] ${parts.join(" | ")}`);
    });

    next();
  };
}
