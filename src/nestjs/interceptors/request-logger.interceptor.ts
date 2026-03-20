import {
  CallHandler,
  ExecutionContext,
  Inject,
  Injectable,
  NestInterceptor,
} from "@nestjs/common";
import { Observable } from "rxjs";
import { tap } from "rxjs/operators";

import type { BackendGuardOptions, RequestLoggingConfig } from "../../types";
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
  private readonly config: RequestLoggingConfig;

  constructor(
    @Inject(BACKEND_GUARD_OPTIONS)
    options: BackendGuardOptions,
  ) {
    const defaultFields: RequestLoggingConfig["fields"] = [
      "method",
      "url",
      "ip",
      "statusCode",
      "responseTime",
    ];

    this.config =
      options.requestLogging === true
        ? { fields: defaultFields, logger: console.log }
        : {
            fields:
              (options.requestLogging as RequestLoggingConfig)?.fields ??
              defaultFields,
            logger:
              (options.requestLogging as RequestLoggingConfig)?.logger ??
              console.log,
          };
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
    const parts: string[] = [];
    const fields = this.config.fields!;

    if (fields.includes("method")) parts.push(req.method);
    if (fields.includes("url")) parts.push(req.originalUrl ?? req.url);
    if (fields.includes("ip")) parts.push(req.ip ?? "unknown");
    if (fields.includes("statusCode")) parts.push(String(statusCode));
    if (fields.includes("responseTime")) parts.push(`${duration}ms`);

    this.config.logger!(`[backend-guard] ${parts.join(" | ")}`);
  }
}
