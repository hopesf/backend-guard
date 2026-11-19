// ============================================================
// Root entry — Express (default) + shared types.
//
// Fastify and NestJS live in their own entry points so that installing
// only one framework never pulls in the others' optional peers:
//   import { backendGuardFastify } from "backend-guard/fastify";
//   import { BackendGuardModule }  from "backend-guard/nestjs";
// ============================================================
export * from "./express/index";
export { backendGuard as default } from "./express/index";

export type {
  BackendGuardOptions,
  RateLimitConfig,
  XssConfig,
  RequestLoggingConfig,
} from "./types";
