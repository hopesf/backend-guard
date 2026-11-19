import { describe, it, expect } from "vitest";
import express from "express";
import request from "supertest";
import { backendGuard, backendGuardErrors } from "../src/index";

function makeApp(opts: Parameters<typeof backendGuard>[0]) {
  const app = express();
  app.set("trust proxy", 1);
  app.use(express.json());
  app.use(backendGuard(opts));
  app.get("/", (_q, r) => r.json({ ok: true }));
  app.get("/q", (q, r) => r.json({ query: q.query }));
  app.get("/p/:x", (q, r) => r.json({ params: q.params }));
  app.post("/b", (q, r) => r.json({ body: q.body }));
  return app;
}

describe("express adapter", () => {
  it("sets helmet headers", async () => {
    const res = await request(makeApp({ protectHeaders: true })).get("/");
    expect(res.headers["content-security-policy"]).toBeDefined();
    expect(res.headers["x-frame-options"]).toBeDefined();
  });

  it("CORS allows only listed origins", async () => {
    const app = makeApp({ cors: ["https://good.com"] });
    const good = await request(app).get("/").set("Origin", "https://good.com");
    const bad = await request(app).get("/").set("Origin", "https://evil.com");
    expect(good.headers["access-control-allow-origin"]).toBe("https://good.com");
    expect(bad.headers["access-control-allow-origin"]).toBeUndefined();
  });

  it("rate-limits after the configured limit", async () => {
    const app = makeApp({ rateLimit: { limit: 3, windowMs: 60000 } });
    const codes: number[] = [];
    for (let i = 0; i < 5; i++) codes.push((await request(app).get("/")).status);
    expect(codes).toEqual([200, 200, 200, 429, 429]);
  });

  it("blocks blacklisted IPs, including IPv4-mapped IPv6 spellings", async () => {
    const app = makeApp({ ipBlacklist: ["1.2.3.4"] });
    for (const ip of ["1.2.3.4", "::ffff:1.2.3.4", "::ffff:0102:0304"]) {
      expect((await request(app).get("/").set("X-Forwarded-For", ip)).status).toBe(403);
    }
    expect((await request(app).get("/").set("X-Forwarded-For", "5.6.7.8")).status).toBe(200);
  });

  it("sanitizes body, query and params", async () => {
    const app = makeApp({ xss: true });
    const body = await request(app).post("/b").send({ a: "<script>x</script>", n: { k: ["<b onmouseover=1>"] } });
    expect(JSON.stringify(body.body)).not.toContain("<script>");
    expect(body.body.body.n.k[0]).not.toContain("onmouseover");
    const q = await request(app).get("/q").query({ a: "<script>x</script>" });
    expect(q.body.query.a).not.toContain("<script>");
    const p = await request(app).get("/p/" + encodeURIComponent("<script>x</script>"));
    expect(p.body.params.x).not.toContain("<script>");
  });

  it("does not let __proto__ keys through", async () => {
    const app = makeApp({ xss: true });
    const res = await request(app).post("/b").set("content-type", "application/json").send('{"__proto__":{"polluted":true},"a":1}');
    expect(res.body.body).toEqual({ a: 1 });
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
  });

  it("logs requests through the custom logger", async () => {
    const lines: string[] = [];
    const app = makeApp({ requestLogging: { logger: (m) => lines.push(m) } });
    await request(app).get("/");
    await new Promise((r) => setTimeout(r, 20));
    expect(lines[0]).toContain("GET");
  });
});

describe("express input hardening", () => {
  it("noSqlInjection rejects operator keys in body and query", async () => {
    const app = makeApp({ noSqlInjection: true });
    const body = await request(app).post("/b").send({ email: { $ne: null } });
    expect(body.status).toBe(400);
    const q = await request(app).get("/q?email[$gt]=");
    expect(q.status).toBe(400);
    expect((await request(app).post("/b").send({ email: "a@b.co" })).status).toBe(200);
  });
  it("noSqlInjection strip mode removes operators", async () => {
    const app = makeApp({ noSqlInjection: { mode: "strip" } });
    const res = await request(app).post("/b").send({ email: { $ne: null }, ok: 1 });
    expect(res.body.body).toEqual({ email: {}, ok: 1 });
    const q = await request(app).get("/q?a[$ne]=1&b=2");
    expect(q.body.query).toEqual({ b: "2" });
  });
  it("noSqlInjection catches nested operators with the extended (qs) query parser", async () => {
    const app = makeApp({ noSqlInjection: true });
    app.set("query parser", "extended");
    expect((await request(app).get("/q?email[$ne]=x")).status).toBe(400);
  });
  it("noSqlInjection dots option", async () => {
    const lax = await request(makeApp({ noSqlInjection: true })).post("/b").send({ "a.b": 1 });
    expect(lax.status).toBe(200);
    const strict = await request(makeApp({ noSqlInjection: { dots: true } })).post("/b").send({ "a.b": 1 });
    expect(strict.status).toBe(400);
  });
  it("parameterPollution keeps one value unless whitelisted", async () => {
    const app = makeApp({ parameterPollution: { whitelist: ["tags"] } });
    const res = await request(app).get("/q?role=user&role=admin&tags=a&tags=b");
    expect(res.body.query).toEqual({ role: "admin", tags: ["a", "b"] });
    const first = await request(makeApp({ parameterPollution: { keep: "first" } })).get("/q?role=user&role=admin");
    expect(first.body.query.role).toBe("user");
  });
  it("backendGuardErrors hides stack traces and internals", async () => {
    const logged: unknown[] = [];
    const app = express();
    app.get("/boom", () => { throw new Error("db password=secret at /srv/app.js"); });
    app.get("/bad", (_q, _r, next) => next(Object.assign(new Error("name is required"), { status: 400 })));
    app.use(backendGuardErrors({ logger: (e) => logged.push(e) }));
    const boom = await request(app).get("/boom");
    expect(boom.status).toBe(500);
    expect(JSON.stringify(boom.body)).not.toContain("secret");
    expect(JSON.stringify(boom.body)).not.toContain("app.js");
    const bad = await request(app).get("/bad");
    expect(bad.status).toBe(400);
    expect(bad.body.message).toBe("name is required");
    expect(logged).toHaveLength(2);
  });
});
