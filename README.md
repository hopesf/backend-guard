# 🛡️ Backend Guard

All-in-one security middleware for **Express.js** and **Fastify**. Stop installing 6 packages — one config, full protection.

[![npm version](https://img.shields.io/npm/v/backend-guard.svg)](https://www.npmjs.com/package/backend-guard)
[![npm downloads](https://img.shields.io/npm/dw/backend-guard.svg)](https://www.npmjs.com/package/backend-guard)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Node.js](https://img.shields.io/node/v/backend-guard.svg)](https://nodejs.org)

## The Problem

Every Express or Fastify project needs these security packages:

```bash
npm i helmet cors express-rate-limit xss-clean joi zod
```

Then you configure each one separately, manage 6 dependencies, read 6 docs...

## The Solution

```bash
npm i backend-guard
```

### Express

```ts
import express from "express";
import { backendGuard } from "backend-guard";

const app = express();

app.use(backendGuard({
  protectHeaders: true,        // helmet — security headers
  cors: ["https://myapp.com"], // cors — allowed origins
  rateLimit: true,             // 100 req / 15 min
  xss: true,                   // sanitize req.body/query/params
  requestLogging: true,        // log every request
  ipBlacklist: ["1.2.3.4"],    // block specific IPs
}));
```

### Fastify

```ts
import Fastify from "fastify";
import { backendGuardFastify } from "backend-guard";

const fastify = Fastify({ trustProxy: true });

async function start() {
  await fastify.register(backendGuardFastify({
    protectHeaders: true,
    cors: ["https://myapp.com"],
    rateLimit: true,
    xss: true,
    requestLogging: true,
    ipBlacklist: ["1.2.3.4"],
  }));

  // register your routes after the plugin
  fastify.get("/", async () => ({ status: "ok" }));

  await fastify.listen({ port: 3000 });
}

start();
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

For input validation (optional):

```bash
npm install zod   # and/or
npm install joi
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
  cors: ["https://myapp.com", "https://admin.myapp.com"]
}));

// Full control
app.use(backendGuard({
  cors: {
    origin: "https://myapp.com",
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

### Input Validation with Zod

**Express:**

```ts
import { createValidator } from "backend-guard";
import { z } from "zod";

const userSchema = z.object({
  name: z.string().min(2),
  email: z.string().email(),
  age: z.number().int().min(0),
});

app.post("/users", createValidator(userSchema), (req, res) => {
  // req.body is validated and typed
  res.json({ user: req.body });
});
```

**Fastify:**

```ts
import { createFastifyValidator } from "backend-guard";
import { z } from "zod";

const userSchema = z.object({
  name: z.string().min(2),
  email: z.string().email(),
  age: z.number().int().min(0),
});

fastify.post("/users", {
  preHandler: [createFastifyValidator(userSchema)],
}, async (request) => {
  return { user: request.body };
});
```

### Input Validation with Joi

```ts
import { createValidator } from "backend-guard"; // Express
// import { createFastifyValidator } from "backend-guard"; // Fastify
import Joi from "joi";

const loginSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().min(8).required(),
});

app.post("/login", createValidator(loginSchema), (req, res) => {
  res.json({ message: "Login successful" });
});
```

Validation errors return `400 Bad Request`:

```json
{
  "error": "Validation Error",
  "details": [
    { "field": "email", "message": "Invalid email" },
    { "field": "password", "message": "String must contain at least 8 character(s)" }
  ]
}
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
  createValidator,
} from "backend-guard";

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
| Validation | [zod](https://www.npmjs.com/package/zod) / [joi](https://www.npmjs.com/package/joi) |

### Fastify

| Feature | Powered By |
|---------|-----------|
| Security Headers | [@fastify/helmet](https://www.npmjs.com/package/@fastify/helmet) |
| CORS | [@fastify/cors](https://www.npmjs.com/package/@fastify/cors) |
| Rate Limiting | [@fastify/rate-limit](https://www.npmjs.com/package/@fastify/rate-limit) |
| XSS Protection | [xss](https://www.npmjs.com/package/xss) |
| Validation | [zod](https://www.npmjs.com/package/zod) / [joi](https://www.npmjs.com/package/joi) |

---

## TypeScript

Full TypeScript support with built-in type definitions:

```ts
import { backendGuard, type BackendGuardOptions } from "backend-guard";

const config: BackendGuardOptions = {
  protectHeaders: true,
  cors: ["https://myapp.com"],
  rateLimit: { limit: 200 },
};

app.use(backendGuard(config));
```

The same `BackendGuardOptions` type is shared between Express and Fastify:

```ts
import { backendGuardFastify, type BackendGuardOptions } from "backend-guard";

const config: BackendGuardOptions = {
  protectHeaders: true,
  cors: ["https://myapp.com"],
  rateLimit: { limit: 200 },
};

await fastify.register(backendGuardFastify(config));
```

---

## Changelog

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
