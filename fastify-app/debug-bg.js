const Fastify = require("fastify");
const { backendGuardFastify } = require("backend-guard");
const http = require("http");

async function main() {
  const f = Fastify({ logger: false });

  await f.register(
    backendGuardFastify({
      rateLimit: { windowMs: 5000, limit: 3 },
    })
  );

  f.get("/", async () => ({ ok: true }));

  await f.listen({ port: 3005 });
  console.log("ready on 3005");

  for (let i = 1; i <= 5; i++) {
    const status = await new Promise((resolve) => {
      const req = http.get("http://127.0.0.1:3005/", (r) => resolve(r.statusCode));
      req.on("error", () => resolve(0));
    });
    console.log("Request " + i + ": HTTP " + status);
  }

  await f.close();
}

main().catch(console.error);
