const Fastify = require("fastify");
const { backendGuardFastify, createFastifyValidator } = require("backend-guard");
const { z } = require("zod");

const fastify = Fastify({ logger: false, trustProxy: true });

async function start() {
  // Register backend-guard plugin (await required so hooks apply to all routes below)
  await fastify.register(
    backendGuardFastify({
      protectHeaders: true,
      cors: true,
      rateLimit: { windowMs: 60 * 1000, limit: 20 },
      xss: true,
      requestLogging: true,
      ipBlacklist: ["1.2.3.4"],
    })
  );

  // Test 1: Health check
  fastify.get("/", async () => ({
    status: "ok",
    message: "Fastify + backend-guard works!",
  }));

  // Test 2: XSS sanitization
  fastify.post("/xss-test", async (request) => ({
    message: "XSS sanitization applied",
    received: request.body,
  }));

  // Test 3: Zod validation
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

  await fastify.listen({ port: 3001 });
  console.log("Fastify test app running at http://localhost:3001");
}

start().catch((err) => {
  console.error(err);
  process.exit(1);
});

