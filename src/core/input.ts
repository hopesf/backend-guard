import type { BackendGuardOptions, NoSqlConfig, ParameterPollutionConfig } from "../types";

const MAX_DEPTH = 32;

export interface ResolvedNoSql {
  mode: "reject" | "strip";
  body: boolean;
  query: boolean;
  dots: boolean;
}

export interface ResolvedHpp {
  whitelist: Set<string>;
  keep: "first" | "last";
}

export function resolveNoSql(option: BackendGuardOptions["noSqlInjection"]): ResolvedNoSql | null {
  if (!option) return null;
  const c: NoSqlConfig = option === true ? {} : option;
  return { mode: c.mode ?? "reject", body: c.body !== false, query: c.query !== false, dots: c.dots === true };
}

export function resolveHpp(option: BackendGuardOptions["parameterPollution"]): ResolvedHpp | null {
  if (!option) return null;
  const c: ParameterPollutionConfig = option === true ? {} : option;
  return { whitelist: new Set(c.whitelist ?? []), keep: c.keep ?? "last" };
}

// `$ne` (parsed JSON / qs-nested) and `a[$ne]` (flat key from the "simple" query parser,
// which qs-style parsers later expand into `{ a: { $ne } }`).
const isOperatorKey = (key: string, dots: boolean) =>
  key.startsWith("$") || /\[\s*\$/.test(key) || (dots && key.includes("."));

/** Returns the paths of every operator-like key in `value` (e.g. `["email.$ne"]`). */
export function findOperatorKeys(value: unknown, dots = false, path = "", depth = 0, out: string[] = []): string[] {
  if (value === null || typeof value !== "object") return out;
  if (depth > MAX_DEPTH) {
    out.push(`${path || "<root>"} (nesting too deep)`);
    return out;
  }
  if (Array.isArray(value)) {
    value.forEach((v, i) => findOperatorKeys(v, dots, `${path}[${i}]`, depth + 1, out));
    return out;
  }
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
    const p = path ? `${path}.${k}` : k;
    if (isOperatorKey(k, dots)) out.push(p);
    findOperatorKeys(v, dots, p, depth + 1, out);
  }
  return out;
}

/** Returns a copy of `value` without operator-like keys. */
export function stripOperatorKeys(value: unknown, dots = false, depth = 0): unknown {
  if (value === null || typeof value !== "object" || depth > MAX_DEPTH) return value;
  if (Array.isArray(value)) return value.map((v) => stripOperatorKeys(v, dots, depth + 1));
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
    if (k === "__proto__" || isOperatorKey(k, dots)) continue;
    out[k] = stripOperatorKeys(v, dots, depth + 1);
  }
  return out;
}

/** Collapses repeated (array-valued) query parameters unless whitelisted. */
export function applyHpp(query: unknown, cfg: ResolvedHpp): unknown {
  if (query === null || typeof query !== "object" || Array.isArray(query)) return query;
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(query as Record<string, unknown>)) {
    if (Array.isArray(v) && !cfg.whitelist.has(k) && v.every((x) => typeof x === "string")) {
      out[k] = cfg.keep === "first" ? v[0] : v[v.length - 1];
    } else {
      out[k] = v;
    }
  }
  return out;
}

export const NOSQL_REJECT_BODY = {
  error: "Bad Request",
  message: "Request contains disallowed operator keys.",
};
