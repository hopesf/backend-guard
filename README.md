# 🛡️ Backend Guard

All-in-one security middleware for **Express.js**, **Fastify**, and **NestJS**. Secure-by-default protection for Express, Fastify and NestJS — one config for headers, CORS, rate limiting, XSS sanitization, safe request logging and IP blocking, plus a **doctor** that tells you when your setup is risky.

[![npm version](https://img.shields.io/npm/v/backend-guard.svg)](https://www.npmjs.com/package/backend-guard)
[![npm downloads](https://img.shields.io/npm/dw/backend-guard.svg)](https://www.npmjs.com/package/backend-guard)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Node.js](https://img.shields.io/node/v/backend-guard.svg)](https://nodejs.org)

## The Problem

Every Express or Fastify project needs these security packages:

```bash
npm i helmet cors express-rate-limit xss
```

Then you configure each one separately, manage several dependencies, read several docs...

## The Solution

```bash
npm i backend-guard
```

### Express

```ts
import express from "express";
import { backendGuard } from "backend-guard/express";

const app = express();

app.use(backendGuard({
  protectHeaders: true,        // helmet — security headers
  cors: ["https://example.com"], // cors — allowed origins
  rateLimit: true,             // 100 req / 15 min
  xss: true,                   // sanitize req.body/query/params
  requestLogging: true,        // log every request
  ipBlacklist: ["192.0.2.1"],    // block specific IPs
}));
```

### Fastify

```ts
import Fastify from "fastify";
import { backendGuardFastify } from "backend-guard/fastify";

const fastify = Fastify({ trustProxy: true });

async function start() {
  await fastify.register(backendGuardFastify({
    protectHeaders: true,
    cors: ["https://example.com"],
    rateLimit: true,
    xss: true,
    requestLogging: true,
    ipBlacklist: ["192.0.2.1"],
  }));

  // register your routes after the plugin
  fastify.get("/", async () => ({ status: "ok" }));

  await fastify.listen({ port: 3000 });
}

start();
```

### NestJS

```ts
import { Module } from "@nestjs/common";
import { BackendGuardModule } from "backend-guard/nestjs";

@Module({
  imports: [
    BackendGuardModule.forRoot({
      protectHeaders: true,        // helmet — security headers
      cors: ["https://example.com"], // allowed origins
      rateLimit: true,             // 100 req / 15 min
      xss: true,                   // sanitize req.body/query/params
      requestLogging: true,        // log every request
      ipBlacklist: ["192.0.2.1"],    // block specific IPs
    }),
  ],
})
export class AppModule {}
```

**One package. One config. Full security.**

---

## Installation

```bash
npm install backend-guard
```

### Peer Dependencies — Express

```bash
npm install express
```

### Peer Dependencies — Fastify

```bash
npm install fastify fastify-plugin
```

Enable each feature by installing the corresponding `@fastify/*` plugin:

```bash
npm install @fastify/helmet    # protectHeaders
npm install @fastify/cors      # cors
npm install @fastify/rate-limit # rateLimit
```

> Only install what you use — each plugin is optional.

### Peer Dependencies — NestJS

```bash
npm install @nestjs/common @nestjs/core rxjs reflect-metadata
```

For HTTP platform (Express adapter, default):

```bash
npm install @nestjs/platform-express
```

> `helmet` and `cors` (already bundled) are applied as middleware on the Express adapter.  
> The rate limiter, IP blacklist, XSS protection and request logger use NestJS Guards/Interceptors and work with **both** Express and Fastify adapters.

---

## Entry points

| Import | Use for | Needs |
|--------|---------|-------|
| `backend-guard` or `backend-guard/express` | Express | `express` |
| `backend-guard/fastify` | Fastify | `fastify`, `fastify-plugin` (+ `@fastify/*` plugins you enable) |
| `backend-guard/nestjs` | NestJS | `@nestjs/common`, `@nestjs/core`, `rxjs` |

Each entry loads only its own framework, so installing one framework never requires the others.

## Doctor — know when your setup is risky

**Startup report.** On startup backend-guard prints what is active and warns about risky or ineffective configuration:

```
[backend-guard] active: cors(1 origins), rate-limit(100/900s), blacklist(1)
[backend-guard] WARN headers-off: Security headers (helmet) are disabled. → Set `protectHeaders: true`.
[backend-guard] WARN cors-origin-no-scheme: CORS origin "example.com" has no scheme, so it will never match ...
[backend-guard] WARN blacklist-cidr: ipBlacklist entry "10.0.0.0/8" looks like a CIDR range; only exact IPs are supported ...
```

It also warns once at runtime when requests carry `X-Forwarded-For` but `trust proxy` is off. Silence it with `doctor: false` (it is always silent when `NODE_ENV=test`), or route it with `doctor: { logger }`.

Invalid config fails fast: unknown options (typos such as `rateLimt`), wrong types and out-of-range values throw a `BackendGuardConfigError` listing every problem.

**Programmatic use**

```ts
import { analyzeOptions } from "backend-guard";
const findings = analyzeOptions({ cors: true }); // [{ id, severity, message, fix }]
```

**CLI — static project scan**

```bash
npx backend-guard doctor [path] [--json] [--strict]
```

A heuristic checklist (not a verdict): wildcard CORS (and CORS + credentials), stack traces sent to clients, cookies/sessions without `secure`/`httpOnly`, disabled TLS verification, possible hardcoded secrets, `.env` not in `.gitignore`, missing helmet, deprecated `xss-clean`/`csurf`. Exit code is 1 on errors (and on warnings with `--strict`), so it fits CI.

---

## Security notes (read this)

- **Behind a proxy?** Set `trust proxy` (Express/Nest) or `trustProxy` (Fastify) correctly. Without it every client shares the proxy's IP (rate limit and blacklist break); with a too-permissive value clients can spoof `X-Forwarded-For` and evade both.
- **`xss` is input sanitization**, not a substitute for context-aware output encoding. It cleans HTML in strings, so fields that legitimately contain `<`/`>` (e.g. passwords) may be altered; scope it with `xss: { body: false, ... }` or per-route use if needed. Mount it **after** `express.json()`.
- **Rate limiting is per process** (in memory). For several instances use a shared store (e.g. Redis via `express-rate-limit` stores, `@fastify/rate-limit` `redis` option).
- **IP blacklist** matches exact addresses (IPv4-mapped IPv6 such as `::ffff:1.2.3.4` is normalized). CIDR ranges are not supported yet.
- **Request logging** masks sensitive query values (`token`, `password`, `api_key`, ...) as `[REDACTED]`; extend the list with `redactQuery: ["myParam"]`. Still avoid secrets in URLs.

---

## Configuration

Both `backendGuard()` (Express) and `backendGuardFastify()` (Fastify) accept the same options:

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `protectHeaders` | `boolean \| HelmetOptions` | `false` | Security headers via Helmet |
| `cors` | `boolean \| string[] \| CorsOptions` | `false` | CORS configuration |
| `rateLimit` | `boolean \| RateLimitConfig` | `false` | Rate limiting |
| `xss` | `boolean \| XssConfig` | `false` | XSS sanitization |
| `requestLogging` | `boolean \| RequestLoggingConfig` | `false` | Request logging |
| `ipBlacklist` | `string[]` | `[]` | Blocked IP addresses |
| `doctor` | `boolean \| { logger }` | `true` | Startup report (silent when `NODE_ENV=test`) |

Every option accepts `true` for sensible defaults, or an object for custom configuration.

---

## Detailed Examples

### Rate Limiting

```ts
// Express — default: 100 requests per 15 minutes
app.use(backendGuard({ rateLimit: true }));

// Express — custom
app.use(backendGuard({
  rateLimit: {
    windowMs: 5 * 60 * 1000,  // 5 minutes
    limit: 50,                  // 50 requests
    message: "Slow down!",
  }
}));

// Fastify — same options
await fastify.register(backendGuardFastify({
  rateLimit: { windowMs: 5 * 60 * 1000, limit: 50 },
}));
```

### CORS

```ts
// Allow all origins (development)
app.use(backendGuard({ cors: true }));

// Allow specific origins (production)
app.use(backendGuard({
  cors: ["https://example.com", "https://admin.example.com"]
}));

// Full control
app.use(backendGuard({
  cors: {
    origin: "https://example.com",
    methods: ["GET", "POST"],
    credentials: true,
  }
}));
```

> Fastify uses the same `cors` option — all three variants are supported.

### XSS Protection

```ts
// Sanitize everything
app.use(backendGuard({ xss: true }));

// Only sanitize body
app.use(backendGuard({
  xss: { body: true, query: false, params: false }
}));
```

### Request Logging

```ts
// Default: logs method, url, ip, statusCode, responseTime
app.use(backendGuard({ requestLogging: true }));
// Output: [backend-guard] GET | /api/users | ::1 | 200 | 12ms

// Custom logger
app.use(backendGuard({
  requestLogging: {
    fields: ["method", "url", "responseTime"],
    logger: (msg) => myLogger.info(msg),
  }
}));
```

> Fastify uses the same `requestLogging` option with the same output format.

---

## NestJS

### Module Setup

```ts
// app.module.ts
import { Module } from "@nestjs/common";
import { BackendGuardModule } from "backend-guard/nestjs";

@Module({
  imports: [
    BackendGuardModule.forRoot({
      protectHeaders: true,
      cors: true,
      rateLimit: { windowMs: 60_000, limit: 20 },
      xss: true,
      requestLogging: true,
      ipBlacklist: ["192.0.2.1"],
    }),
  ],
})
export class AppModule {}
```

`BackendGuardModule` is **global** — no need to re-import it in feature modules.

### How Each Feature is Applied

| Option | Mechanism | Adapter |
|--------|-----------|---------|
| `protectHeaders` | NestJS middleware (helmet) | Express only |
| `cors` | NestJS middleware (cors) | Express only |
| `rateLimit` | `RateLimitGuard` — in-memory, per IP | Both |
| `ipBlacklist` | `IpBlacklistGuard` | Both |
| `xss` | `XssInterceptor` — body, query, params | Both |
| `requestLogging` | `RequestLoggingInterceptor` | Both |

> For Fastify adapter: register `@fastify/helmet` and `@fastify/cors` manually in `main.ts`. All other features work out of the box.

### Using Individual Guards / Interceptors

You can import the primitives directly for custom setups:

```ts
import {
  IpBlacklistGuard,
  RateLimitGuard,
  XssInterceptor,
  RequestLoggingInterceptor,
  BACKEND_GUARD_OPTIONS,
} from "backend-guard/nestjs";
```

### Rate Limiter

The built-in `RateLimitGuard` uses an **in-memory store** (per process; expired entries are swept automatically). For multi-instance / Redis-backed rate limiting, use [@nestjs/throttler](https://docs.nestjs.com/security/rate-limiting) alongside or instead.

### main.ts Bootstrap

```ts
import { NestFactory } from "@nestjs/core";
import { AppModule } from "./app.module";

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  app.set("trust proxy", 1); // needed for correct IP behind a proxy
  await app.listen(3000);
}
bootstrap();
```

---

## Using Individual Middlewares

### Express

```ts
import {
  createHelmetMiddleware,
  createCorsMiddleware,
  createRateLimitMiddleware,
  createXssMiddleware,
  createRequestLoggingMiddleware,
  createIpBlacklistMiddleware,
} from "backend-guard/express";

app.use(createRateLimitMiddleware({ windowMs: 60000, limit: 30 }));
app.use(createHelmetMiddleware(true));
```

---

## What's Inside?

Backend Guard wraps these battle-tested packages:

### Express

| Feature | Powered By |
|---------|-----------|
| Security Headers | [helmet](https://www.npmjs.com/package/helmet) |
| CORS | [cors](https://www.npmjs.com/package/cors) |
| Rate Limiting | [express-rate-limit](https://www.npmjs.com/package/express-rate-limit) |
| XSS Protection | [xss](https://www.npmjs.com/package/xss) |

### Fastify

| Feature | Powered By |
|---------|-----------|
| Security Headers | [@fastify/helmet](https://www.npmjs.com/package/@fastify/helmet) |
| CORS | [@fastify/cors](https://www.npmjs.com/package/@fastify/cors) |
| Rate Limiting | [@fastify/rate-limit](https://www.npmjs.com/package/@fastify/rate-limit) |
| XSS Protection | [xss](https://www.npmjs.com/package/xss) |

### NestJS

| Feature | Mechanism |
|---------|----------|
| Security Headers | [helmet](https://www.npmjs.com/package/helmet) via NestJS middleware |
| CORS | [cors](https://www.npmjs.com/package/cors) via NestJS middleware |
| Rate Limiting | Built-in `RateLimitGuard` (in-memory) |
| XSS Protection | Built-in `XssInterceptor` using [xss](https://www.npmjs.com/package/xss) |
| IP Blacklist | Built-in `IpBlacklistGuard` |
| Request Logging | Built-in `RequestLoggingInterceptor` |

---

## TypeScript

Full TypeScript support with built-in type definitions:

```ts
import { backendGuard, type BackendGuardOptions } from "backend-guard";

const config: BackendGuardOptions = {
  protectHeaders: true,
  cors: ["https://example.com"],
  rateLimit: { limit: 200 },
};

app.use(backendGuard(config));
```

The same `BackendGuardOptions` type is shared across Express, Fastify, and NestJS:

```ts
import { backendGuardFastify, type BackendGuardOptions } from "backend-guard/fastify";

const config: BackendGuardOptions = {
  protectHeaders: true,
  cors: ["https://example.com"],
  rateLimit: { limit: 200 },
};

await fastify.register(backendGuardFastify(config));
```

```ts
import { BackendGuardModule, type BackendGuardOptions } from "backend-guard/nestjs";

const config: BackendGuardOptions = {
  protectHeaders: true,
  cors: ["https://example.com"],
  rateLimit: { limit: 200 },
};

BackendGuardModule.forRoot(config);
```

---

## Changelog

### v2.0.0
- **Doctor:** startup report (active protections + warnings for risky config), one-time `X-Forwarded-For`/`trust proxy` warning, `analyzeOptions()` API and `npx backend-guard doctor` project scanner.
- **Breaking:** configuration is validated up front — unknown options (typos) and invalid values now throw `BackendGuardConfigError`.
- **Breaking:** request logs mask sensitive query-string values by default (`redactQuery`).
- New framework-agnostic `core` (shared config resolution, IP handling, sanitizer, logger, `RateLimiter` with pluggable store), also exported as `backend-guard/core`. Nest's `RateLimitGuard` now runs on it.
- Fastify rate-limit now always returns the configured status code/message.

### v1.4.0
- **Fix:** `require("backend-guard")` no longer crashes when optional Fastify/Nest peers are not installed. **Breaking:** Fastify and NestJS exports moved to `backend-guard/fastify` and `backend-guard/nestjs`.
- **Fix:** Express `xss` now actually sanitizes `req.query` and `req.params` (Express 5 getters).
- **Fix:** IP blacklist now matches IPv4-mapped IPv6 addresses (`::ffff:1.2.3.4`); Fastify hook returns the reply properly.
- **Fix:** Nest `RateLimitGuard` no longer leaks memory (expired entries are swept).
- `xss` sanitizer drops `__proto__` keys.
- **Breaking:** removed the `validate` option and `createValidator` / `createFastifyValidator` — use Zod/Joi directly (or Fastify's built-in schemas).
- Added test suite (Vitest), CI, dependency updates (`npm audit` clean).

### v1.3.0
- Added full **NestJS** support via `BackendGuardModule.forRoot()`
- `RateLimitGuard` — in-memory per-IP rate limiting, works with Express & Fastify adapters
- `IpBlacklistGuard` — adapter-agnostic IP blocking
- `XssInterceptor` — sanitizes `body`, `query`, and `params` via NestJS interceptor
- `RequestLoggingInterceptor` — request logging via NestJS interceptor
- `helmet` and `cors` applied as NestJS middleware (Express adapter)
- All options use the same shared `BackendGuardOptions` interface

### v1.2.0
- Added full **Fastify** support via `backendGuardFastify()` — all options shared with Express
- Added `createFastifyValidator()` for Zod/Joi validation in Fastify preHandler hooks
- Uses `@fastify/helmet`, `@fastify/cors`, `@fastify/rate-limit` as optional peer deps
- All Fastify-specific packages remain optional — Express users are unaffected

### v1.1.1
- Initial public release with Express support
- helmet, cors, express-rate-limit, xss, zod/joi validation, IP blacklist, request logging

---

## License

[MIT](LICENSE) © Selim Gecin
