import type { FastifyRequest, FastifyReply } from "fastify";
import type { BackendGuardOptions, XssConfig } from "../../types";
import { sanitize } from "../../shared/sanitize";

/**
 * Creates a Fastify preHandler hook for XSS sanitization.
 *
 * preHandler runs after body parsing but before the route handler —
 * perfect for sanitizing request.body, request.query and request.params.
 *
 * This is equivalent to a body-modifying Express middleware.
 */
export function createXssHook(option: BackendGuardOptions["xss"]) {
  const config: XssConfig =
    option === true ? { body: true, query: true, params: true } : (option as XssConfig);

  return async (request: FastifyRequest, _reply: FastifyReply): Promise<void> => {
    if (config.body !== false && request.body) {
      request.body = sanitize(request.body);
    }

    if (config.query !== false && request.query) {
      const q = request.query as Record<string, unknown>;
      for (const key of Object.keys(q)) {
        q[key] = sanitize(q[key]);
      }
    }

    if (config.params !== false && request.params) {
      const p = request.params as Record<string, unknown>;
      for (const key of Object.keys(p)) {
        p[key] = sanitize(p[key]);
      }
    }
  };
}
