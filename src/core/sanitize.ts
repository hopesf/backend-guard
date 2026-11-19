import xssFilter from "xss";

/**
 * Recursively sanitizes every string value (and own enumerable keys' values)
 * of a request payload with the `xss` package.
 *
 * The `__proto__` key is dropped to avoid prototype pollution.
 */
export function sanitize(obj: unknown): unknown {
  if (typeof obj === "string") return xssFilter(obj);
  if (Array.isArray(obj)) return obj.map(sanitize);
  if (obj !== null && typeof obj === "object") {
    const result: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(obj)) {
      if (key === "__proto__") continue;
      result[key] = sanitize(value);
    }
    return result;
  }
  return obj;
}
