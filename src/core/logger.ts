import { SENSITIVE_QUERY_KEYS } from "./defaults";
import type { ResolvedLogging } from "./options";

/** Masks values of sensitive query-string parameters in a URL. */
export function redactUrl(url: string, redact: boolean | string[]): string {
  if (redact === false) return url;
  const q = url.indexOf("?");
  if (q === -1) return url;

  const keys = new Set(
    [...SENSITIVE_QUERY_KEYS, ...(Array.isArray(redact) ? redact : [])].map((k) => k.toLowerCase())
  );
  const masked = url
    .slice(q + 1)
    .split("&")
    .map((pair) => {
      const eq = pair.indexOf("=");
      if (eq === -1) return pair;
      let name = pair.slice(0, eq);
      try { name = decodeURIComponent(name); } catch { /* keep raw */ }
      return keys.has(name.toLowerCase()) ? `${pair.slice(0, eq)}=[REDACTED]` : pair;
    })
    .join("&");
  return `${url.slice(0, q)}?${masked}`;
}

export interface LogRecord {
  method: string;
  url: string;
  ip?: string;
  statusCode: number;
  responseTimeMs: number;
}

/** Builds the `[backend-guard] A | B | C` log line shared by all adapters. */
export function formatLogLine(config: ResolvedLogging, rec: LogRecord): string {
  const parts: string[] = [];
  for (const f of config.fields) {
    if (f === "method") parts.push(rec.method);
    else if (f === "url") parts.push(redactUrl(rec.url, config.redactQuery));
    else if (f === "ip") parts.push(rec.ip || "unknown");
    else if (f === "statusCode") parts.push(String(rec.statusCode));
    else if (f === "responseTime") parts.push(`${Math.round(rec.responseTimeMs)}ms`);
  }
  return `[backend-guard] ${parts.join(" | ")}`;
}
