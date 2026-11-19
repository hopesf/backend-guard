import type { FastifyRequest, FastifyReply } from "fastify";
import { buildIpSet, normalizeIp } from "../../core/ip";

/**
 * Creates a Fastify onRequest hook for IP blacklist checking.
 *
 * Uses the onRequest hook (earliest possible) to reject blocked IPs
 * before any processing happens — saving CPU and memory.
 *
 * Fastify vs Express:
 * - Express: (req, res, next) — call next() to continue
 * - Fastify: async (request, reply) — call reply.send() to stop
 */
export function createIpBlacklistHook(blacklist: string[]) {
  // Set for O(1) lookup — much faster than Array.includes() for large lists
  const blockedIps = buildIpSet(blacklist);

  return async (request: FastifyRequest, reply: FastifyReply): Promise<FastifyReply | void> => {
    const clientIp = normalizeIp(request.ip);

    if (blockedIps.has(clientIp)) {
      // `return reply` tells Fastify the response was already sent
      return reply.status(403).send({
        error: "Forbidden",
        message: "Your IP address has been blocked.",
      });
    }
  };
}
