import { describe, it, expect } from "vitest";
import Fastify from "fastify";
import { backendGuardFastify } from "../src/fastify/index";

async function makeApp(opts: Parameters<typeof backendGuardFastify>[0]) {
  const app = Fastify({ trustProxy: true });
  await app.register(backendGuardFastify(opts));
  app.get("/", async () => ({ ok: true }));
  app.get("/q", async (r) => ({ query: r.query }));
  app.get("/p/:x", async (r) => ({ params: r.params }));
  app.post("/b", async (r) => ({ body: r.body }));
  await app.ready();
  return app;
}

describe("fastify adapter", () => {
  it("sets helmet headers", async () => {
    const app = await makeApp({ protectHeaders: true });
    const res = await app.inject({ url: "/" });
    expect(res.headers["content-security-policy"]).toBeDefined();
  });

  it("CORS allows only listed origins", async () => {
    const app = await makeApp({ cors: ["https://good.com"] });
    const good = await app.inject({ url: "/", headers: { origin: "https://good.com" } });
    const bad = await app.inject({ url: "/", headers: { origin: "https://evil.com" } });
    expect(good.headers["access-control-allow-origin"]).toBe("https://good.com");
    expect(bad.headers["access-control-allow-origin"]).toBeUndefined();
  });

  it("rate-limits with custom message", async () => {
    const app = await makeApp({ rateLimit: { limit: 3, windowMs: 60000, message: "slow" } });
    const codes: number[] = [];
    let last: { message?: string } = {};
    for (let i = 0; i < 5; i++) {
      const r = await app.inject({ url: "/" });
      codes.push(r.statusCode);
      last = r.json();
    }
    expect(codes).toEqual([200, 200, 200, 429, 429]);
    expect(last.message).toBe("slow");
  });

  it("blocks blacklisted IPs incl. mapped IPv6", async () => {
    const app = await makeApp({ ipBlacklist: ["1.2.3.4"] });
    for (const ip of ["1.2.3.4", "::ffff:1.2.3.4"]) {
      expect((await app.inject({ url: "/", headers: { "x-forwarded-for": ip } })).statusCode).toBe(403);
    }
    // handler must not run for blocked requests
    const post = await app.inject({ method: "POST", url: "/b", payload: { a: 1 }, headers: { "x-forwarded-for": "1.2.3.4" } });
    expect(post.statusCode).toBe(403);
    expect((await app.inject({ url: "/", headers: { "x-forwarded-for": "5.6.7.8" } })).statusCode).toBe(200);
  });

  it("sanitizes body, query and params", async () => {
    const app = await makeApp({ xss: true });
    const b = await app.inject({ method: "POST", url: "/b", payload: { a: "<script>x</script>" } });
    expect(b.json().body.a).not.toContain("<script>");
    const q = await app.inject({ url: "/q?a=%3Cscript%3Ex%3C/script%3E" });
    expect(q.json().query.a).not.toContain("<script>");
    const p = await app.inject({ url: "/p/%3Cscript%3Ex%3C%2Fscript%3E" });
    expect(p.json().params.x).not.toContain("<script>");
  });
});
