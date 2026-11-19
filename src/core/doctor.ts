import { isIP } from "node:net";
import type { BackendGuardOptions, DoctorConfig } from "../types";
import { normalizeIp } from "./ip";
import { resolveRateLimit, resolveXss } from "./options";

export type Severity = "error" | "warn" | "info";

export interface Finding {
  id: string;
  severity: Severity;
  message: string;
  fix?: string;
}

const isObj = (v: unknown): v is Record<string, unknown> =>
  typeof v === "object" && v !== null && !Array.isArray(v);

/**
 * Statically analyzes a BackendGuardOptions object and reports risky or
 * ineffective configuration. Pure function — no I/O.
 */
export function analyzeOptions(options: BackendGuardOptions): Finding[] {
  const out: Finding[] = [];
  const add = (f: Finding) => out.push(f);

  // ── rate limit ──
  const rl = resolveRateLimit(options.rateLimit);
  if (!rl) {
    add({
      id: "rate-limit-off",
      severity: "warn",
      message: "Rate limiting is disabled: brute-force and abuse are not throttled.",
      fix: "Set `rateLimit: true` (100 req / 15 min) or an object with your own limits.",
    });
  } else {
    add({
      id: "rate-limit-memory",
      severity: "info",
      message: "Rate-limit counters are kept in process memory (not shared between instances).",
      fix: "Behind several instances use a shared store (e.g. Redis) — see the README.",
    });
  }

  // ── headers ──
  if (!options.protectHeaders) {
    add({
      id: "headers-off",
      severity: "warn",
      message: "Security headers (helmet) are disabled.",
      fix: "Set `protectHeaders: true`.",
    });
  } else if (isObj(options.protectHeaders)) {
    const h = options.protectHeaders as Record<string, unknown>;
    if (h.contentSecurityPolicy === false)
      add({ id: "csp-disabled", severity: "warn", message: "Content-Security-Policy is disabled in protectHeaders.", fix: "Keep the default CSP or tighten it instead of disabling." });
    if (h.strictTransportSecurity === false || h.hsts === false)
      add({ id: "hsts-disabled", severity: "warn", message: "Strict-Transport-Security is disabled in protectHeaders.", fix: "Keep HSTS on for HTTPS deployments." });
  }

  // ── CORS ──
  const cors = options.cors;
  if (cors === true) {
    add({
      id: "cors-wildcard",
      severity: "warn",
      message: "`cors: true` allows every origin.",
      fix: 'List allowed origins: `cors: ["https://app.example.com"]`.',
    });
  } else if (Array.isArray(cors)) {
    for (const origin of cors) {
      if (origin !== "*" && origin !== "null" && !/^https?:\/\//i.test(origin)) {
        add({
          id: "cors-origin-no-scheme",
          severity: "warn",
          message: `CORS origin "${origin}" has no scheme, so it will never match (browsers send e.g. "https://${origin}").`,
          fix: `Use "https://${origin}".`,
        });
      }
      if (origin === "*") {
        add({ id: "cors-wildcard", severity: "warn", message: '`cors` contains "*", which allows every origin.' });
      }
    }
  } else if (isObj(cors)) {
    const origin = (cors as Record<string, unknown>).origin;
    const credentials = (cors as Record<string, unknown>).credentials === true;
    const open = origin === true || origin === "*" || origin === undefined;
    if (open && credentials) {
      add({
        id: "cors-credentials-wildcard",
        severity: "error",
        message: "CORS reflects any origin while `credentials: true` — any website can make authenticated requests.",
        fix: "Restrict `origin` to an explicit allow-list.",
      });
    } else if (open) {
      add({ id: "cors-wildcard", severity: "warn", message: "CORS options allow every origin." });
    }
  }

  // ── XSS ──
  if (options.xss) {
    const x = resolveXss(options.xss)!;
    if (!x.body && !x.query && !x.params) {
      add({ id: "xss-noop", severity: "warn", message: "`xss` is enabled but body, query and params are all disabled — nothing is sanitized." });
    }
  }

  // ── logging ──
  if (isObj(options.requestLogging) && options.requestLogging.redactQuery === false) {
    add({
      id: "log-redaction-off",
      severity: "warn",
      message: "Query-string redaction is off: tokens and passwords in URLs will appear in logs.",
      fix: "Remove `redactQuery: false` or list the parameters to mask.",
    });
  }

  // ── IP blacklist ──
  for (const entry of options.ipBlacklist ?? []) {
    if (entry.includes("/")) {
      add({
        id: "blacklist-cidr",
        severity: "warn",
        message: `ipBlacklist entry "${entry}" looks like a CIDR range; only exact IPs are supported, so it blocks nothing.`,
        fix: "List individual IPs (CIDR support is planned).",
      });
    } else if (isIP(normalizeIp(entry)) === 0) {
      add({ id: "blacklist-invalid", severity: "warn", message: `ipBlacklist entry "${entry}" is not a valid IP address and will never match.` });
    }
  }

  return out;
}

/** One-line description of what is enabled. */
export function summarize(options: BackendGuardOptions): string {
  const rl = resolveRateLimit(options.rateLimit);
  const x = resolveXss(options.xss);
  const parts: string[] = [];
  if (options.protectHeaders) parts.push("headers");
  if (options.cors) parts.push(Array.isArray(options.cors) ? `cors(${options.cors.length} origins)` : "cors");
  if (rl) parts.push(`rate-limit(${rl.limit}/${Math.round(rl.windowMs / 1000)}s)`);
  if (x) parts.push("xss");
  if (options.requestLogging) parts.push("logging");
  if (options.ipBlacklist?.length) parts.push(`blacklist(${options.ipBlacklist.length})`);
  return parts.length ? parts.join(", ") : "nothing enabled";
}

/** Human-readable report. `info` findings are included only when `verbose`. */
export function formatReport(
  options: BackendGuardOptions,
  findings: Finding[],
  verbose = false
): string[] {
  const lines = [`[backend-guard] active: ${summarize(options)}`];
  for (const f of findings) {
    if (f.severity === "info" && !verbose) continue;
    const tag = f.severity.toUpperCase();
    lines.push(`[backend-guard] ${tag} ${f.id}: ${f.message}${f.fix ? ` → ${f.fix}` : ""}`);
  }
  return lines;
}

function doctorDisabled(options: BackendGuardOptions): boolean {
  return options.doctor === false || process.env.NODE_ENV === "test";
}

/** Prints the startup report once, unless disabled via `doctor: false` / NODE_ENV=test. */
export function reportAtStartup(options: BackendGuardOptions): void {
  if (doctorDisabled(options)) return;
  const cfg: DoctorConfig = isObj(options.doctor) ? (options.doctor as DoctorConfig) : {};
  const log = cfg.logger;
  const lines = formatReport(options, analyzeOptions(options));
  lines.forEach((line, i) => {
    if (log) log(line);
    else if (i === 0) console.log(line);
    else console.warn(line);
  });
}

/**
 * Runtime check shared by all adapters: warns once when requests carry an
 * X-Forwarded-For header although the framework's "trust proxy" is off —
 * every client then looks like the proxy (rate limit / blacklist break).
 */
export function createProxyWatcher(options: BackendGuardOptions) {
  let warned = false;
  const relevant = Boolean(options.rateLimit || options.ipBlacklist?.length);
  return (hasForwardedHeader: boolean, trustProxyEnabled: boolean): void => {
    if (warned || !relevant || !hasForwardedHeader || trustProxyEnabled || doctorDisabled(options)) return;
    warned = true;
    const cfg: DoctorConfig = isObj(options.doctor) ? (options.doctor as DoctorConfig) : {};
    const msg =
      "[backend-guard] WARN proxy-untrusted: requests carry X-Forwarded-For but \"trust proxy\" is not enabled, " +
      "so all clients share the proxy's IP (rate limit and ipBlacklist act on the wrong address). " +
      "→ Enable trust proxy (Express/Nest: app.set(\"trust proxy\", 1); Fastify: trustProxy: true).";
    (cfg.logger ?? console.warn)(msg);
  };
}
