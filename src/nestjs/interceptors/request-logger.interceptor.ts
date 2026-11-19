import {
  CallHandler,
  ExecutionContext,
  Inject,
  Injectable,
  NestInterceptor,
} from "@nestjs/common";
import { Observable } from "rxjs";
import { tap } from "rxjs/operators";

import type { BackendGuardOptions } from "../../types";
import { resolveLogging } from "../../core/options";
import type { ResolvedLogging } from "../../core/options";
import { formatLogLine } from "../../core/logger";
import { BACKEND_GUARD_OPTIONS } from "../nestjs.constants";

type HttpRequest = {
  method: string;
  originalUrl?: string;
  url: string;
  ip?: string;
};

type HttpResponse = {
  statusCode: number;
};

/**
 * Interceptor that logs every HTTP request: method, URL, IP, status code,
 * and response time.
 *
 * Uses the `tap` operator so logging happens after the response is sent,
 * giving access to the final status code set by the handler.
 *
 * @example
 * // Activated automatically when requestLogging option is set:
 * BackendGuardModule.forRoot({ requestLogging: true })
 */
@Injectable()
export class RequestLoggingInterceptor implements NestInterceptor {
  private readonly config: ResolvedLogging;

  constructor(
    @Inject(BACKEND_GUARD_OPTIONS)
    options: BackendGuardOptions,
  ) {
    this.config = resolveLogging(options.requestLogging ?? true)!;
  }

  intercept(context: ExecutionContext, next: CallHandler): Observable<unknown> {
    const req = context.switchToHttp().getRequest<HttpRequest>();
    const res = context.switchToHttp().getResponse<HttpResponse>();
    const start = Date.now();

    return next.handle().pipe(
      tap({
        next: () => this.log(req, res.statusCode, Date.now() - start),
        error: () => this.log(req, res.statusCode, Date.now() - start),
      }),
    );
  }

  private log(
    req: HttpRequest,
    statusCode: number,
    duration: number,
  ): void {
    this.config.logger(
      formatLogLine(this.config, {
        method: req.method,
        url: req.originalUrl ?? req.url,
        ip: req.ip,
        statusCode,
        responseTimeMs: duration,
      }),
    );
  }
}
