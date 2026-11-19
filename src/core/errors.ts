import type { BackendGuardOptions, SafeErrorsConfig } from "../types";

export interface ResolvedSafeErrors {
  expose4xx: boolean;
  logger: (error: unknown) => void;
}

export function resolveSafeErrors(option: BackendGuardOptions["safeErrors"]): ResolvedSafeErrors | null {
  if (!option) return null;
  const c: SafeErrorsConfig = option === true ? {} : option;
  return {
    expose4xx: c.expose4xx !== false,
    logger:
      c.logger ??
      ((e) => console.error("[backend-guard] unhandled error:", e instanceof Error ? e.stack ?? e.message : e)),
  };
}

const STATUS_TEXT: Record<number, string> = {
  400: "Bad Request", 401: "Unauthorized", 403: "Forbidden", 404: "Not Found",
  405: "Method Not Allowed", 409: "Conflict", 413: "Payload Too Large", 415: "Unsupported Media Type",
  422: "Unprocessable Entity", 429: "Too Many Requests", 500: "Internal Server Error",
  502: "Bad Gateway", 503: "Service Unavailable", 504: "Gateway Timeout",
};

/** Maps any thrown value to a client-safe `{ status, body }`. */
export function toSafeError(err: unknown, cfg: ResolvedSafeErrors): { status: number; body: { error: string; message: string } } {
  const e = err as { status?: unknown; statusCode?: unknown; message?: unknown } | null;
  const raw = Number(e?.status ?? e?.statusCode);
  const status = Number.isInteger(raw) && raw >= 400 && raw <= 599 ? raw : 500;
  const error = STATUS_TEXT[status] ?? (status >= 500 ? "Internal Server Error" : "Error");

  if (status >= 500 || !cfg.expose4xx || typeof e?.message !== "string") {
    return { status, body: { error, message: status >= 500 ? "Something went wrong." : error } };
  }
  return { status, body: { error, message: e.message } };
}
