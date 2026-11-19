import "reflect-metadata";
import { describe, it, expect, afterEach } from "vitest";
import { Controller, Get, Post, Body, Query, Module, INestApplication } from "@nestjs/common";
import { Test } from "@nestjs/testing";
import request from "supertest";
import { BackendGuardModule } from "../src/nestjs/index";
import { RateLimitGuard } from "../src/nestjs/guards/rate-limit.guard";
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

describe("RateLimitGuard memory", () => {
  it("sweeps expired records", async () => {
    const guard = new RateLimitGuard({ rateLimit: { limit: 5, windowMs: 20 } });
    const ctx = (ip: string) => ({ switchToHttp: () => ({ getRequest: () => ({ ip }) }) }) as never;
    for (let i = 0; i < 200; i++) guard.canActivate(ctx(`10.0.0.${i}`));
    expect(guard.size).toBe(200);
    await new Promise((r) => setTimeout(r, 40));
    guard.canActivate(ctx("9.9.9.9"));
    expect(guard.size).toBe(1);
  });
});
