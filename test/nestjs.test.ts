import "reflect-metadata";
import { describe, it, expect, afterEach } from "vitest";
import { Controller, Get, Post, Body, Query, Module, INestApplication } from "@nestjs/common";
import { Test } from "@nestjs/testing";
import request from "supertest";
import { BackendGuardModule } from "../src/nestjs/index";
import { RateLimitGuard } from "../src/nestjs/guards/rate-limit.guard";
import { MemoryStore } from "../src/core/rate-limit";
import type { BackendGuardOptions } from "../src/types";

@Controller()
class TestController {
  @Get() root() { return { ok: true }; }
  @Get("q") q(@Query() query: unknown) { return { query }; }
  @Post("b") b(@Body() body: unknown) { return { body }; }
}

let app: INestApplication | undefined;
afterEach(async () => { await app?.close(); app = undefined; });

async function makeApp(opts: BackendGuardOptions) {
  @Module({ imports: [BackendGuardModule.forRoot(opts)], controllers: [TestController] })
  class AppModule {}
  const moduleRef = await Test.createTestingModule({ imports: [AppModule] }).compile();
  app = moduleRef.createNestApplication();
  (app.getHttpAdapter().getInstance() as import("express").Express).set("trust proxy", 1);
  await app.init();
  return app;
}

describe("nestjs adapter", () => {
  it("sets helmet headers and CORS allow-list", async () => {
    const a = await makeApp({ protectHeaders: true, cors: ["https://good.com"] });
    const res = await request(a.getHttpServer()).get("/").set("Origin", "https://good.com");
    expect(res.headers["content-security-policy"]).toBeDefined();
    expect(res.headers["access-control-allow-origin"]).toBe("https://good.com");
    const bad = await request(a.getHttpServer()).get("/").set("Origin", "https://evil.com");
    expect(bad.headers["access-control-allow-origin"]).toBeUndefined();
  });

  it("rate-limits", async () => {
    const a = await makeApp({ rateLimit: { limit: 3, windowMs: 60000 } });
    const codes: number[] = [];
    for (let i = 0; i < 5; i++) codes.push((await request(a.getHttpServer()).get("/")).status);
    expect(codes).toEqual([200, 200, 200, 429, 429]);
  });

  it("blocks blacklisted IPs incl. mapped IPv6", async () => {
    const a = await makeApp({ ipBlacklist: ["1.2.3.4"] });
    for (const ip of ["1.2.3.4", "::ffff:1.2.3.4"]) {
      expect((await request(a.getHttpServer()).get("/").set("X-Forwarded-For", ip)).status).toBe(403);
    }
    expect((await request(a.getHttpServer()).get("/").set("X-Forwarded-For", "5.6.7.8")).status).toBe(200);
  });

  it("sanitizes body and query", async () => {
    const a = await makeApp({ xss: true });
    const b = await request(a.getHttpServer()).post("/b").send({ a: "<script>x</script>" });
    expect(b.body.body.a).not.toContain("<script>");
    const q = await request(a.getHttpServer()).get("/q").query({ a: "<script>x</script>" });
    expect(q.body.query.a).not.toContain("<script>");
  });
});

describe("nestjs input hardening", () => {
  it("rejects operator keys and collapses repeated params", async () => {
    const a = await makeApp({ noSqlInjection: true, parameterPollution: true });
    expect((await request(a.getHttpServer()).post("/b").send({ e: { $ne: null } })).status).toBe(400);
    expect((await request(a.getHttpServer()).get("/q?e[$gt]=1")).status).toBe(400);
    const res = await request(a.getHttpServer()).get("/q?role=user&role=admin");
    expect(res.body.query.role).toBe("admin");
  });
  it("strip mode removes operators", async () => {
    const a = await makeApp({ noSqlInjection: { mode: "strip" } });
    const res = await request(a.getHttpServer()).post("/b").send({ e: { $ne: null }, ok: 1 });
    expect(res.body.body).toEqual({ e: {}, ok: 1 });
  });
});

describe("nestjs CIDR and custom store", () => {
  it("blocks CIDR ranges", async () => {
    const a = await makeApp({ ipBlacklist: ["10.0.0.0/8"] });
    expect((await request(a.getHttpServer()).get("/").set("X-Forwarded-For", "10.1.1.1")).status).toBe(403);
    expect((await request(a.getHttpServer()).get("/").set("X-Forwarded-For", "11.1.1.1")).status).toBe(200);
  });
  it("rate-limits through a custom store", async () => {
    const store = new MemoryStore();
    let hits = 0;
    const a = await makeApp({ rateLimit: { limit: 2, windowMs: 60000, store: { hit: (k, w) => { hits++; return store.hit(k, w); } } } });
    const codes: number[] = [];
    for (let i = 0; i < 3; i++) codes.push((await request(a.getHttpServer()).get("/")).status);
    expect(codes).toEqual([200, 200, 429]);
    expect(hits).toBe(3);
  });
});

describe("RateLimitGuard memory", () => {
  it("sweeps expired records", async () => {
    const guard = new RateLimitGuard({ rateLimit: { limit: 5, windowMs: 20 } });
    const ctx = (ip: string) => ({ switchToHttp: () => ({ getRequest: () => ({ ip }) }) }) as never;
    for (let i = 0; i < 200; i++) await guard.canActivate(ctx(`10.0.0.${i}`));
    expect(guard.size).toBe(200);
    await new Promise((r) => setTimeout(r, 40));
    await guard.canActivate(ctx("9.9.9.9"));
    expect(guard.size).toBe(1);
  });
});
