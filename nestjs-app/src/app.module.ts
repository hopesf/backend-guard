import { Module } from "@nestjs/common";
import { BackendGuardModule } from "backend-guard";
import { AppController } from "./app.controller";

@Module({
  imports: [
    // ── Apply backend-guard with all features enabled ──────────────────────
    // Same BackendGuardOptions interface used by Express and Fastify.
    BackendGuardModule.forRoot({
      protectHeaders: true,        // helmet: sets security headers
      cors: true,                  // allow all origins (dev mode)
      rateLimit: {
        windowMs: 60 * 1000,       // 1 minute window
        limit: 20,                 // max 20 requests per minute (easy to test)
      },
      xss: true,                   // sanitize body/query/params via XssInterceptor
      requestLogging: true,        // log every request via RequestLoggingInterceptor
      ipBlacklist: ["1.2.3.4"],    // test blocked IP
    }),
  ],
  controllers: [AppController],
})
export class AppModule {}
