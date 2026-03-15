/**
 * Full integration test for Fastify + backend-guard
 *
 * Runs all 5 test scenarios in sequence, self-contained.
 * Uses 127.0.0.1 to avoid macOS IPv6 (::1) routing.
 */

const Fastify = require("fastify");
const { backendGuardFastify, createFastifyValidator } = require("backend-guard");
const { z } = require("zod");
const http = require("http");

// Minimal HTTP helper
function req(method, path, body) {
  return new Promise((resolve, reject) => {
    const payload = body ? JSON.stringify(body) : null;
    const options = {
      hostname: "127.0.0.1",
      port: 3001,
      path,
      method,
      headers: { "Content-Type": "application/json" },
    };
    const r = http.request(options, (res) => {
      let data = "";
      res.on("data", (c) => (data += c));
      res.on("end", () =>
        resolve({ status: res.statusCode, headers: res.headers, body: data })
      );
    });
    r.on("error", reject);
    if (payload) r.write(payload);
    r.end();
  });
}

async function run() {
  // ── Setup ────────────────────────────────────────────────
  const fastify = Fastify({ logger: false });

  await fastify.register(
    backendGuardFastify({
      protectHeaders: true,
      cors: true,
      rateLimit: { windowMs: 60 * 1000, limit: 20 },
      xss: true,
      requestLogging: true,
      ipBlacklist: ["9.9.9.9"], // won't match localhost
    })
  );

  fastify.get("/", async () => ({
    status: "ok",
    message: "Fastify + backend-guard works!",
  }));

  fastify.post("/xss-test", async (request) => ({
    message: "XSS sanitization applied",
    received: request.body,
  }));

  const userSchema = z.object({
    name: z.string().min(2),
    email: z.string().email(),
    age: z.number().int().min(18),
  });

  fastify.post(
    "/users",
    { preHandler: [createFastifyValidator(userSchema)] },
    async (request) => ({ message: "User created", user: request.body })
  );

  await fastify.listen({ host: "127.0.0.1", port: 3001 });

  let pass = 0;
  let fail = 0;

  function check(name, condition, got) {
    if (condition) {
      console.log("  PASS  " + name);
      pass++;
    } else {
      console.log("  FAIL  " + name + " — got: " + JSON.stringify(got));
      fail++;
    }
  }

  // ── Test 1: Health check ─────────────────────────────────
  console.log("\nTest 1: Health check");
  const t1 = await req("GET", "/");
  check("Status 200", t1.status === 200, t1.status);
  check("Body contains 'ok'", t1.body.includes("ok"), t1.body);

  // ── Test 2: Helmet security headers ─────────────────────
  console.log("\nTest 2: Helmet security headers");
  const t2 = await req("GET", "/");
  check(
    "content-security-policy present",
    !!t2.headers["content-security-policy"],
    t2.headers["content-security-policy"]
  );
  check(
    "x-frame-options: SAMEORIGIN",
    t2.headers["x-frame-options"] === "SAMEORIGIN",
    t2.headers["x-frame-options"]
  );

  // ── Test 3: XSS sanitization ─────────────────────────────
  console.log("\nTest 3: XSS sanitization");
  const t3 = await req("POST", "/xss-test", {
    name: "<script>alert(1)</script>",
  });
  const t3body = JSON.parse(t3.body);
  check(
    "<script> sanitized to &lt;script&gt;",
    t3body.received.name === "&lt;script&gt;alert(1)&lt;/script&gt;",
    t3body.received.name
  );

  // ── Test 4: Zod validation ───────────────────────────────
  console.log("\nTest 4: Zod validation");
  const t4a = await req("POST", "/users", {
    name: "A",
    email: "not-email",
    age: 5,
  });
  check("Invalid → 400", t4a.status === 400, t4a.status);
  const t4abody = JSON.parse(t4a.body);
  check(
    "Error details array",
    Array.isArray(t4abody.details),
    t4abody.details
  );

  const t4b = await req("POST", "/users", {
    name: "Alice",
    email: "alice@example.com",
    age: 25,
  });
  check("Valid → 200", t4b.status === 200, t4b.status);

  // ── Test 5: Rate limiting ─────────────────────────────────
  console.log("\nTest 5: Rate limiting (limit: 20)");
  // We already sent some requests above; send enough to hit the limit
  let firstBlock = null;
  for (let i = 0; i < 30; i++) {
    const r = await req("GET", "/");
    if (r.status === 429 && firstBlock === null) {
      firstBlock = i + 1; // 1-indexed total request number in this loop
    }
  }
  check(
    "429 received after limit",
    firstBlock !== null,
    firstBlock === null ? "no 429 received in 30 requests" : "OK"
  );

  // ── Summary ───────────────────────────────────────────────
  await fastify.close();
  console.log("\n─────────────────────────────────────");
  console.log("Results: " + pass + " passed, " + fail + " failed");
}

run().catch((err) => {
  console.error("Error:", err.message);
  process.exit(1);
});
