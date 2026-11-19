import type { FastifyRequest, FastifyReply } from "fastify";
import type { BackendGuardOptions } from "../../types";
import { resolveXss } from "../../core/options";
import { sanitize } from "../../core/sanitize";

/**
 * Creates a Fastify preHandler hook for XSS sanitization.
 *
 * preHandler runs after body parsing but before the route handler —
 * perfect for sanitizing request.body, request.query and request.params.
 *
 * This is equivalent to a body-modifying Express middleware.
 */
export function createXssHook(option: BackendGuardOptions["xss"]) {
  const config = resolveXss(option ?? true)!;

  return async (request: FastifyRequest, _reply: FastifyReply): Promise<void> => {
    if (config.body && request.body) {
      request.body = sanitize(request.body);
    }

    if (config.query && request.query) {
      const q = request.query as Record<string, unknown>;
      for (const key of Object.keys(q)) {
        q[key] = sanitize(q[key]);
      }
    }

    if (config.params && request.params) {
      const p = request.params as Record<string, unknown>;
      for (const key of Object.keys(p)) {
        p[key] = sanitize(p[key]);
      }
    }
  };
}
