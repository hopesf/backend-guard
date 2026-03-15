const Fastify = require("fastify");
const rl = require("@fastify/rate-limit");

const f = Fastify({ logger: false });

f.register(rl, { timeWindow: 5000, max: 3 });

f.get("/", async () => ({ ok: true }));

f.listen({ port: 3003 }, (err) => {
  if (err) {
    console.error("Start error:", err.message);
    process.exit(1);
  }
  console.log("ready on 3003");
});
