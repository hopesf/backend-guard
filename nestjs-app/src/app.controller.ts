import { Body, Controller, Get, HttpCode, Post, Query } from "@nestjs/common";

@Controller()
export class AppController {
  // GET / — health check
  @Get()
  healthCheck() {
    return { status: "ok", message: "NestJS + backend-guard works!" };
  }

  // GET /headers — verify helmet security headers in the response
  @Get("headers")
  headers() {
    return {
      message: "Check the response headers in your browser/curl output",
      hint: "You should see: content-security-policy, x-frame-options, etc.",
    };
  }

  // POST /xss-test — demonstrates XSS sanitization via XssInterceptor
  // Try sending: { "name": "<script>alert('xss')</script>", "comment": "hello" }
  // The script tags will be escaped before reaching this handler.
  @Post("xss-test")
  @HttpCode(200)
  xssTest(@Body() body: unknown) {
    return {
      message: "XSS sanitization applied",
      received: body, // script tags will already be escaped here
    };
  }

  // GET /xss-query — demonstrates XSS sanitization on query params
  // Try: /xss-query?q=<script>alert(1)</script>
  @Get("xss-query")
  xssQuery(@Query() query: Record<string, unknown>) {
    return {
      message: "XSS sanitization applied to query params",
      received: query,
    };
  }

  // GET /rate-limit-test — hit this 21 times quickly to trigger throttling
  // Configuration: 20 requests/minute (set in AppModule)
  @Get("rate-limit-test")
  rateLimitTest() {
    return {
      message: "Request counted. Hit this endpoint 21 times to trigger rate limit.",
    };
  }
}
