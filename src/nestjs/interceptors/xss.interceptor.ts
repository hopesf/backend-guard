import {
  CallHandler,
  ExecutionContext,
  Inject,
  Injectable,
  NestInterceptor,
} from "@nestjs/common";
import { Observable } from "rxjs";
import xssFilter from "xss";

import type { BackendGuardOptions, XssConfig } from "../../types";
import { BACKEND_GUARD_OPTIONS } from "../nestjs.constants";

/**
 * Recursively sanitizes all string values in an object against XSS.
 *
 * `<script>alert('xss')</script>` → `&lt;script&gt;alert('xss')&lt;/script&gt;`
 */
function sanitize(obj: unknown): unknown {
  if (typeof obj === "string") {
    return xssFilter(obj);
  }

  if (Array.isArray(obj)) {
    return obj.map(sanitize);
  }

  if (obj !== null && typeof obj === "object") {
    const result: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(obj)) {
      result[key] = sanitize(value);
    }
    return result;
  }

  // number, boolean, null, undefined → returned as-is
  return obj;
}

/**
 * Interceptor that sanitizes req.body, req.query and req.params against XSS.
 *
 * Runs before the route handler (pre-handler phase) so the controller
 * always receives clean, sanitized data.
 *
 * @example
 * // Activated automatically when xss option is set:
 * BackendGuardModule.forRoot({ xss: true })
 */
@Injectable()
export class XssInterceptor implements NestInterceptor {
  private readonly config: XssConfig;

  constructor(
    @Inject(BACKEND_GUARD_OPTIONS)
    options: BackendGuardOptions,
  ) {
    this.config =
      options.xss === true
        ? { body: true, query: true, params: true }
        : ((options.xss as XssConfig) ?? {});
  }

  intercept(context: ExecutionContext, next: CallHandler): Observable<unknown> {
    const req = context
      .switchToHttp()
      .getRequest<Record<string, unknown>>();

    if (this.config.body !== false && req["body"]) {
      req["body"] = sanitize(req["body"]);
    }

    // req.query in Express is a prototype getter that re-parses the URL on
    // every access — mutating the returned object has no effect on future reads.
    // We shadow the prototype getter at the instance level using defineProperty
    // so that subsequent @Query() calls receive the sanitized copy.
    if (this.config.query !== false && req["query"]) {
      const sanitizedQuery = sanitize(req["query"]) as Record<string, unknown>;
      Object.defineProperty(req, "query", {
        value: sanitizedQuery,
        configurable: true,
        writable: true,
        enumerable: true,
      });
    }

    // Same technique for params (usually a plain object, but be consistent)
    if (this.config.params !== false && req["params"]) {
      const sanitizedParams = sanitize(req["params"]) as Record<string, unknown>;
      Object.defineProperty(req, "params", {
        value: sanitizedParams,
        configurable: true,
        writable: true,
        enumerable: true,
      });
    }

    return next.handle();
  }
}
