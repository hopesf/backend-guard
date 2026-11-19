import {
  BadRequestException,
  CallHandler,
  ExecutionContext,
  Inject,
  Injectable,
  NestInterceptor,
} from "@nestjs/common";
import type { Observable } from "rxjs";

import type { BackendGuardOptions } from "../../types";
import { BACKEND_GUARD_OPTIONS } from "../nestjs.constants";
import {
  applyHpp, findOperatorKeys, NOSQL_REJECT_BODY, resolveHpp, resolveNoSql, stripOperatorKeys,
} from "../../core/input";

/**
 * Applies HTTP parameter pollution handling and NoSQL operator checks to
 * req.body / req.query before the route handler runs.
 * Activated automatically by `parameterPollution` / `noSqlInjection`.
 */
@Injectable()
export class InputHardeningInterceptor implements NestInterceptor {
  private readonly hpp;
  private readonly nosql;

  constructor(
    @Inject(BACKEND_GUARD_OPTIONS)
    options: BackendGuardOptions,
  ) {
    this.hpp = resolveHpp(options.parameterPollution);
    this.nosql = resolveNoSql(options.noSqlInjection);
  }

  intercept(context: ExecutionContext, next: CallHandler): Observable<unknown> {
    const req = context.switchToHttp().getRequest<Record<string, unknown>>();

    // req.query is a re-parsing getter on Express 5 → shadow it on the instance
    const setQuery = (value: unknown) =>
      Object.defineProperty(req, "query", { value, configurable: true, writable: true, enumerable: true });

    if (this.hpp && req["query"]) setQuery(applyHpp(req["query"], this.hpp));

    if (this.nosql) {
      const cfg = this.nosql;
      if (cfg.mode === "reject") {
        const hit = [
          ...(cfg.body && req["body"] ? findOperatorKeys(req["body"], cfg.dots) : []),
          ...(cfg.query && req["query"] ? findOperatorKeys(req["query"], cfg.dots) : []),
        ];
        if (hit.length) throw new BadRequestException(NOSQL_REJECT_BODY.message);
      } else {
        if (cfg.body && req["body"]) req["body"] = stripOperatorKeys(req["body"], cfg.dots);
        if (cfg.query && req["query"]) setQuery(stripOperatorKeys(req["query"], cfg.dots));
      }
    }

    return next.handle();
  }
}
