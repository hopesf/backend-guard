import type { FastifyRequest, FastifyReply } from "fastify";
import type { BackendGuardOptions } from "../../types";
import { resolveLogging } from "../../core/options";
import { formatLogLine } from "../../core/logger";

/** Fastify onResponse hook for request logging (uses reply.elapsedTime). */
export function createRequestLoggingHook(option: BackendGuardOptions["requestLogging"]) {
  const config = resolveLogging(option ?? true)!;

  return async (request: FastifyRequest, reply: FastifyReply): Promise<void> => {
    config.logger(
      formatLogLine(config, {
        method: request.method,
        url: request.url,
        ip: request.ip,
        statusCode: reply.statusCode,
        responseTimeMs: reply.elapsedTime,
      })
    );
  };
}
