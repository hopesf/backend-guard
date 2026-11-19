import type { RateLimitConfig, RequestLoggingConfig } from "../types";

export const DEFAULT_RATE_LIMIT: Required<Omit<RateLimitConfig, "store">> = {
  windowMs: 15 * 60 * 1000,
  limit: 100,
  message: "Too many requests, please try again later.",
  statusCode: 429,
};

export const LOG_FIELDS = ["method", "url", "ip", "statusCode", "responseTime"] as const;

export const DEFAULT_LOG_FIELDS: Array<NonNullable<RequestLoggingConfig["fields"]>[number]> = [
  ...LOG_FIELDS,
];

/** Query-string parameter names whose values are masked in request logs. */
export const SENSITIVE_QUERY_KEYS = [
  "token", "access_token", "id_token", "refresh_token", "password", "passwd", "pwd",
  "secret", "client_secret", "api_key", "apikey", "key", "auth", "authorization",
  "code", "session", "sid", "signature", "sig",
];
