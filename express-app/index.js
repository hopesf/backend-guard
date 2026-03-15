const express = require("express");
const { backendGuard, createValidator } = require("backend-guard");
const { z } = require("zod");

const app = express();

// Trust proxy headers (needed to test X-Forwarded-For in IP blacklist)
app.set("trust proxy", 1);

// Parse JSON bodies
app.use(express.json());

// ── Apply backend-guard with all features enabled ──────────────────────────
app.use(
  backendGuard({
    protectHeaders: true,         // helmet: sets 13 security headers
    cors: true,                   // allow all origins (dev mode)
    rateLimit: {
      windowMs: 60 * 1000,        // 1 minute window
      limit: 20,                  // max 20 requests per minute (easy to test)
      message: "Too many requests!",
    },
    xss: true,                    // sanitize body/query/params
    requestLogging: true,         // log every request to console
    ipBlacklist: ["1.2.3.4"],     // this IP would be blocked (test IP)
  })
);

// ── Routes ─────────────────────────────────────────────────────────────────

// GET / — health check
app.get("/", (req, res) => {
  res.json({ status: "ok", message: "backend-guard is working!" });
});

// GET /headers — shows which security headers helmet added
app.get("/headers", (req, res) => {
  res.json({
    message: "Check the response headers in your browser/curl output",
    hint: "You should see: content-security-policy, x-frame-options, etc.",
  });
});

// POST /xss-test — demonstrates XSS sanitization
// Try sending: { "name": "<script>alert('xss')</script>", "comment": "hello" }
app.post("/xss-test", (req, res) => {
  res.json({
    message: "XSS sanitization applied",
    received: req.body, // script tags will be escaped
  });
});

// POST /users — demonstrates Zod validation via createValidator()
const createUserSchema = z.object({
  name: z.string().min(2, "Name must be at least 2 characters"),
  email: z.string().email("Invalid email address"),
  age: z.number().int().min(18, "Must be at least 18 years old"),
});

app.post("/users", createValidator(createUserSchema), (req, res) => {
  // Only reaches here if validation passed
  res.status(201).json({
    message: "User created successfully",
    user: req.body,
  });
});

// GET /rate-limit-test — hit this 21 times quickly to trigger rate limiting
app.get("/rate-limit-test", (req, res) => {
  res.json({ message: "Request counted. Hit this endpoint 21 times to trigger rate limit." });
});

// ── Start server ───────────────────────────────────────────────────────────
const PORT = 3000;
app.listen(PORT, () => {
  console.log(`\n✅  Test app running at http://localhost:${PORT}`);
  console.log(`\nEndpoints to test:`);
  console.log(`  GET  http://localhost:${PORT}/`);
  console.log(`  GET  http://localhost:${PORT}/headers`);
  console.log(`  POST http://localhost:${PORT}/xss-test`);
  console.log(`  POST http://localhost:${PORT}/users`);
  console.log(`  GET  http://localhost:${PORT}/rate-limit-test`);
  console.log(`\nSee logs below for incoming requests:\n`);
});
