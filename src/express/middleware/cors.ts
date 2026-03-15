import cors from "cors";
import type { CorsOptions } from "cors";
import type { RequestHandler } from "express";
import type { BackendGuardOptions } from "../../types";

/**
 * Creates the CORS middleware.
 *
 * CORS (Cross-Origin Resource Sharing) controls whether browsers allow
 * requests from different domains to your API.
 *
 * Example: If frontend is at https://myapp.com and API at https://api.myapp.com,
 * the browser blocks requests without CORS.
 *
 * 3 usage modes:
 * - `true` → allow all origins (for development)
 * - `string[]` → allow only specified domains (for production)
 * - `CorsOptions` → full control
 */
export function createCorsMiddleware(
  option: BackendGuardOptions["cors"]
): RequestHandler {
  if (option === true) {
    // Allow all origins
    return cors();
  }

  if (Array.isArray(option)) {
    // string[] → convert to origin list
    // ["example.com", "app.com"] → { origin: ["example.com", "app.com"] }
    return cors({ origin: option });
  }

  // Full CorsOptions object
  return cors(option as CorsOptions);
}
