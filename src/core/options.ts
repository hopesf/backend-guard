import type {
  BackendGuardOptions,
  RateLimitConfig,
  RequestLoggingConfig,
  XssConfig,
} from "../types";
import { DEFAULT_LOG_FIELDS, DEFAULT_RATE_LIMIT, LOG_FIELDS } from "./defaults";

export class BackendGuardConfigError extends Error {
  constructor(public readonly problems: string[]) {
    super(
      `[backend-guard] Invalid configuration:\n${problems.map((p) => `  - ${p}`).join("\n")}`
    );
    this.name = "BackendGuardConfigError";
  }
}

const KNOWN_KEYS = [
  "rateLimit",
  "cors",
  "protectHeaders",
  "xss",
  "requestLogging",
  "ipBlacklist",
  "doctor",
] as const;

function distance(a: string, b: string): number {
  const dp = Array.from({ length: a.length + 1 }, (_, i) => [i, ...Array(b.length).fill(0)]);
  for (let j = 1; j <= b.length; j++) dp[0][j] = j;
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      dp[i][j] = Math.min(
        dp[i - 1][j] + 1,
        dp[i][j - 1] + 1,
        dp[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1)
      );
    }
  }
  return dp[a.length][b.length];
}

const isObj = (v: unknown): v is Record<string, unknown> =>
  typeof v === "object" && v !== null && !Array.isArray(v);

/**
 * Validates the options object and throws a single BackendGuardConfigError
 * listing every problem (typos, wrong types, out-of-range values).
 */
export function validateOptions(options: unknown): asserts options is BackendGuardOptions {
  const problems: string[] = [];

  if (!isObj(options)) {
    throw new BackendGuardConfigError(["options must be an object"]);
  }

  for (const key of Object.keys(options)) {
    if (!(KNOWN_KEYS as readonly string[]).includes(key)) {
      const near = KNOWN_KEYS.find((k) => distance(k.toLowerCase(), key.toLowerCase()) <= 2);
      problems.push(
        `unknown option "${key}"${near ? ` (did you mean "${near}"?)` : ""}. Valid options: ${KNOWN_KEYS.join(", ")}`
      );
    }
  }

  const boolOrObj = (name: string, v: unknown) => {
    if (v !== undefined && typeof v !== "boolean" && !isObj(v)) {
      problems.push(`${name} must be a boolean or an object`);
      return false;
    }
    return true;
  };

  const { rateLimit, cors, protectHeaders, xss, requestLogging, ipBlacklist, doctor } = options;

  if (boolOrObj("rateLimit", rateLimit) && isObj(rateLimit)) {
    const { windowMs, limit, statusCode, message } = rateLimit;
    if (windowMs !== undefined && !(typeof windowMs === "number" && Number.isFinite(windowMs) && windowMs > 0))
      problems.push("rateLimit.windowMs must be a positive number (milliseconds)");
    if (limit !== undefined && !(typeof limit === "number" && Number.isInteger(limit) && limit > 0))
      problems.push("rateLimit.limit must be a positive integer");
    if (statusCode !== undefined && !(Number.isInteger(statusCode) && (statusCode as number) >= 400 && (statusCode as number) <= 599))
      problems.push("rateLimit.statusCode must be an HTTP error status (400-599)");
    if (message !== undefined && typeof message !== "string")
      problems.push("rateLimit.message must be a string");
  }

  if (cors !== undefined && typeof cors !== "boolean" && !Array.isArray(cors) && !isObj(cors)) {
    problems.push("cors must be a boolean, a string[] of origins, or a CorsOptions object");
  } else if (Array.isArray(cors) && cors.some((o) => typeof o !== "string" || o.length === 0)) {
    problems.push("cors origins must be non-empty strings");
  }

  boolOrObj("protectHeaders", protectHeaders);

  if (boolOrObj("xss", xss) && isObj(xss)) {
    for (const k of ["body", "query", "params"]) {
      if (xss[k] !== undefined && typeof xss[k] !== "boolean")
        problems.push(`xss.${k} must be a boolean`);
    }
  }

  if (boolOrObj("requestLogging", requestLogging) && isObj(requestLogging)) {
    const { fields, logger, redactQuery } = requestLogging;
    if (fields !== undefined) {
      if (!Array.isArray(fields) || fields.some((f) => !(LOG_FIELDS as readonly string[]).includes(f as string)))
        problems.push(`requestLogging.fields must be an array of: ${LOG_FIELDS.join(", ")}`);
    }
    if (logger !== undefined && typeof logger !== "function")
      problems.push("requestLogging.logger must be a function");
    if (redactQuery !== undefined && typeof redactQuery !== "boolean" &&
        !(Array.isArray(redactQuery) && redactQuery.every((k) => typeof k === "string")))
      problems.push("requestLogging.redactQuery must be a boolean or a string[]");
  }

  if (ipBlacklist !== undefined &&
      (!Array.isArray(ipBlacklist) || ipBlacklist.some((ip) => typeof ip !== "string")))
    problems.push("ipBlacklist must be an array of IP address strings");

  if (boolOrObj("doctor", doctor) && isObj(doctor) && doctor.logger !== undefined && typeof doctor.logger !== "function")
    problems.push("doctor.logger must be a function");

  if (problems.length) throw new BackendGuardConfigError(problems);
}

// ── Resolvers: turn `true | object` shorthand into fully-populated config ──

export function resolveRateLimit(option: BackendGuardOptions["rateLimit"]): Required<RateLimitConfig> | null {
  if (!option) return null;
  return { ...DEFAULT_RATE_LIMIT, ...(option === true ? {} : (option as RateLimitConfig)) };
}

export function resolveXss(option: BackendGuardOptions["xss"]): Required<XssConfig> | null {
  if (!option) return null;
  const c = option === true ? {} : option;
  return { body: c.body !== false, query: c.query !== false, params: c.params !== false };
}

export interface ResolvedLogging {
  fields: Array<NonNullable<RequestLoggingConfig["fields"]>[number]>;
  logger: (message: string) => void;
  redactQuery: boolean | string[];
}

export function resolveLogging(option: BackendGuardOptions["requestLogging"]): ResolvedLogging | null {
  if (!option) return null;
  const c: RequestLoggingConfig = option === true ? {} : option;
  return {
    fields: c.fields ?? [...DEFAULT_LOG_FIELDS],
    logger: c.logger ?? console.log,
    redactQuery: c.redactQuery ?? true,
  };
}
