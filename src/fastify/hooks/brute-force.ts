import type { FastifyRequest, FastifyReply } from "fastify";
import { BruteForceProtector, defaultIdentifier } from "../../core/brute-force";
import type { BruteForceOptions } from "../../core/brute-force";
import { normalizeIp } from "../../core/ip";

export interface FastifyBruteForceOptions extends BruteForceOptions {
  /** Extracts the account identifier from the request. Default: body.email / username / login / user */
  identifier?: (request: FastifyRequest) => unknown;
}

/**
 * Login brute-force protection hooks for a single route:
 *
 * ```ts
 * const bf = createBruteForceHooks({ maxAttempts: 5 });
 * fastify.post("/login", { preHandler: bf.preHandler, onResponse: bf.onResponse }, handler);
 * ```
 */
export function createBruteForceHooks(options: FastifyBruteForceOptions = {}) {
  const protector = new BruteForceProtector(options);
  const identify = options.identifier ?? ((r: FastifyRequest) => defaultIdentifier(r.body));
  const pending = new WeakMap<FastifyRequest, string[]>();

  return {
    preHandler: async (request: FastifyRequest, reply: FastifyReply): Promise<FastifyReply | void> => {
      const result = await protector.attempt(normalizeIp(request.ip) || "unknown", identify(request));
      if (result.blocked) {
        reply.header("Retry-After", String(result.retryAfterSec));
        return reply.status(429).send({ error: "Too Many Requests", message: protector.message });
      }
      pending.set(request, result.keys);
    },
    onResponse: async (request: FastifyRequest, reply: FastifyReply): Promise<void> => {
      const keys = pending.get(request);
      if (keys && protector.isSuccess(reply.statusCode)) {
        await protector.success(keys).catch(() => undefined);
      }
    },
  };
}
