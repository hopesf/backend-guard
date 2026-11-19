import type { FastifyRequest, FastifyReply } from "fastify";
import type { BackendGuardOptions } from "../../types";
import {
  applyHpp, findOperatorKeys, NOSQL_REJECT_BODY, resolveHpp, resolveNoSql, stripOperatorKeys,
} from "../../core/input";

/** preHandler hook: collapses repeated query parameters. */
export function createHppHook(option: BackendGuardOptions["parameterPollution"]) {
  const cfg = resolveHpp(option ?? true)!;
  return async (request: FastifyRequest): Promise<void> => {
    if (request.query) {
      const next = applyHpp(request.query, cfg) as Record<string, unknown>;
      const q = request.query as Record<string, unknown>;
      for (const k of Object.keys(next)) q[k] = next[k];
    }
  };
}

/** preHandler hook: rejects (or strips) `$`-operator keys in body and query. */
export function createNoSqlHook(option: BackendGuardOptions["noSqlInjection"]) {
  const cfg = resolveNoSql(option ?? true)!;
  return async (request: FastifyRequest, reply: FastifyReply): Promise<FastifyReply | void> => {
    if (cfg.mode === "reject") {
      const hit = [
        ...(cfg.body && request.body ? findOperatorKeys(request.body, cfg.dots) : []),
        ...(cfg.query && request.query ? findOperatorKeys(request.query, cfg.dots) : []),
      ];
      if (hit.length) return reply.status(400).send(NOSQL_REJECT_BODY);
      return;
    }
    if (cfg.body && request.body) request.body = stripOperatorKeys(request.body, cfg.dots);
    if (cfg.query && request.query) {
      const q = request.query as Record<string, unknown>;
      const clean = stripOperatorKeys(q, cfg.dots) as Record<string, unknown>;
      for (const k of Object.keys(q)) if (!(k in clean)) delete q[k];
      for (const k of Object.keys(clean)) q[k] = clean[k];
    }
  };
}
