import type { FastifyRequest, FastifyReply } from "fastify";
import type { BackendGuardOptions, RequestLoggingConfig } from "../../types";

/**
 * Creates a Fastify onResponse hook for request logging.
 *
 * onResponse fires after the response is fully sent — at this point
 * reply.statusCode and reply.elapsedTime are both available.
 *
 * reply.elapsedTime is Fastify's built-in high-resolution timer (ms since
 * the request arrived). This replaces the manual Date.now() trick used in
 * the Express version.
 */
export function createRequestLoggingHook(option: BackendGuardOptions["requestLogging"]) {
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
          fields: (option as RequestLoggingConfig).fields ?? defaultFields,
          logger: (option as RequestLoggingConfig).logger ?? console.log,
        };

  return async (request: FastifyRequest, reply: FastifyReply): Promise<void> => {
    const parts: string[] = [];
    const fields = config.fields!;
    const duration = Math.round(reply.elapsedTime);

    if (fields.includes("method")) parts.push(request.method);
    if (fields.includes("url")) parts.push(request.url);
    if (fields.includes("ip")) parts.push(request.ip || "unknown");
    if (fields.includes("statusCode")) parts.push(String(reply.statusCode));
    if (fields.includes("responseTime")) parts.push(`${duration}ms`);

    config.logger!(`[backend-guard] ${parts.join(" | ")}`);
  };
}
