const Fastify = require("fastify");
const rl = require("@fastify/rate-limit");
const http = require("http");

async function main() {
  const f = Fastify({ logger: false });

  await f.register(rl, {
    timeWindow: 5000,
    max: 3,
    keyGenerator: (req) => {
      const ip = req.ip;
      process.stderr.write("key: " + ip + "\n");
      return ip;
    },
  });

  f.get("/", async () => ({ ok: true }));

  await f.listen({ port: 3004 });
  console.log("ready on 3004");

  for (let i = 1; i <= 5; i++) {
    const status = await new Promise((resolve) => {
      http.get("http://127.0.0.1:3004/", (r) => resolve(r.statusCode));
    });
    console.log("Request " + i + ": HTTP " + status);
  }

  await f.close();
}

main().catch(console.error);
