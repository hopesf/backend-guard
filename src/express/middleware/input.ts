import type { Request, Response, NextFunction, RequestHandler, ErrorRequestHandler } from "express";
import type { BackendGuardOptions } from "../../types";
import {
  applyHpp, findOperatorKeys, NOSQL_REJECT_BODY, resolveHpp, resolveNoSql, stripOperatorKeys,
} from "../../core/input";
import { resolveSafeErrors, toSafeError } from "../../core/errors";

/**
 * Express 5 exposes `req.query` as a getter that re-parses the URL on every
 * access, so replacing it requires shadowing the property on the instance.
 */
function setQuery(req: Request, value: unknown): void {
  Object.defineProperty(req, "query", { value, configurable: true, writable: true, enumerable: true });
}

/** HTTP parameter pollution: collapses repeated query parameters. */
export function createHppMiddleware(option: BackendGuardOptions["parameterPollution"]): RequestHandler {
  const cfg = resolveHpp(option ?? true)!;
  return (req: Request, _res: Response, next: NextFunction): void => {
    if (req.query) setQuery(req, applyHpp(req.query, cfg));
    next();
  };
}

/** Rejects (or strips) `$`-operator keys in body and query. Mount after express.json(). */
export function createNoSqlMiddleware(option: BackendGuardOptions["noSqlInjection"]): RequestHandler {
  const cfg = resolveNoSql(option ?? true)!;
  return (req: Request, res: Response, next: NextFunction): void => {
    if (cfg.mode === "reject") {
      const hit = [
        ...(cfg.body && req.body ? findOperatorKeys(req.body, cfg.dots) : []),
        ...(cfg.query && req.query ? findOperatorKeys(req.query, cfg.dots) : []),
      ];
      if (hit.length) {
        res.status(400).json(NOSQL_REJECT_BODY);
        return;
      }
    } else {
      if (cfg.body && req.body) req.body = stripOperatorKeys(req.body, cfg.dots);
      if (cfg.query && req.query) setQuery(req, stripOperatorKeys(req.query, cfg.dots));
    }
    next();
  };
}

/**
 * Error-handling middleware that never leaks stack traces or internal
 * messages. Mount it AFTER all routes: `app.use(backendGuardErrors(options))`.
 */
export function backendGuardErrors(option: BackendGuardOptions["safeErrors"] = true): ErrorRequestHandler {
  const cfg = resolveSafeErrors(option || true)!;
  return (err: unknown, _req: Request, res: Response, next: NextFunction): void => {
    if (res.headersSent) return next(err);
    cfg.logger(err);
    const { status, body } = toSafeError(err, cfg);
    res.status(status).json(body);
  };
}
