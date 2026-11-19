import * as fs from "node:fs";
import * as path from "node:path";
import type { Severity } from "../core/doctor";

export interface ScanFinding {
  id: string;
  severity: Severity;
  message: string;
  file?: string;
  line?: number;
}

const SKIP_DIRS = new Set(["node_modules", "dist", "build", "coverage", ".git", ".next", ".turbo", "out"]);
const EXTS = new Set([".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"]);
const MAX_FILES = 3000;
const MAX_BYTES = 512 * 1024;

function walk(dir: string, acc: string[]): void {
  let entries: fs.Dirent[];
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
  for (const e of entries) {
    if (acc.length >= MAX_FILES) return;
    if (e.isDirectory()) {
      if (!SKIP_DIRS.has(e.name) && !e.name.startsWith(".")) walk(path.join(dir, e.name), acc);
    } else if (e.isFile() && EXTS.has(path.extname(e.name)) && !e.name.endsWith(".d.ts")) {
      acc.push(path.join(dir, e.name));
    }
  }
}

const lineOf = (text: string, index: number) => text.slice(0, index).split("\n").length;
const isTestFile = (f: string) => /(\.|\/)(test|spec|fixtures?|examples?|mocks?)(\.|\/)/i.test(f.replace(/\\/g, "/"));

/**
 * Static, heuristic scan of a Node backend project for common security
 * misconfigurations. Pattern-based: it can miss things and can report false
 * positives — treat it as a checklist, not a verdict.
 */
export function scanProject(root: string): ScanFinding[] {
  const out: ScanFinding[] = [];
  const rel = (f: string) => path.relative(root, f) || f;

  // ── package.json ──
  let deps: Record<string, string> = {};
  try {
    const pkg = JSON.parse(fs.readFileSync(path.join(root, "package.json"), "utf8"));
    deps = { ...pkg.dependencies, ...pkg.devDependencies };
  } catch {
    out.push({ id: "no-package-json", severity: "info", message: "No readable package.json found; dependency checks skipped." });
  }
  const has = (...names: string[]) => names.some((n) => n in deps);

  const framework = has("express", "fastify", "@nestjs/core");
  if (framework && !has("backend-guard", "helmet", "@fastify/helmet")) {
    out.push({ id: "no-security-headers", severity: "warn", message: "Web framework found but no helmet / backend-guard dependency: security headers are probably not set." });
  }
  if (has("xss-clean")) out.push({ id: "deprecated-xss-clean", severity: "warn", message: "`xss-clean` is deprecated and unmaintained; use `xss` / backend-guard." });
  if (has("csurf")) out.push({ id: "deprecated-csurf", severity: "warn", message: "`csurf` is deprecated; use a maintained CSRF approach (SameSite cookies, csrf-csrf, ...)." });

  // ── .env hygiene ──
  if (fs.existsSync(path.join(root, ".env"))) {
    let ignored = false;
    try { ignored = /^\s*\.env\s*$/m.test(fs.readFileSync(path.join(root, ".gitignore"), "utf8")); } catch { /* no .gitignore */ }
    if (!ignored) out.push({ id: "env-not-ignored", severity: "error", message: ".env exists but is not listed in .gitignore — secrets may be committed.", file: ".env" });
  }

  // ── source files ──
  const files: string[] = [];
  walk(root, files);
  let sawTrustProxy = false;
  let usesRateLimit = has("backend-guard", "express-rate-limit", "@fastify/rate-limit", "@nestjs/throttler");

  for (const file of files) {
    let text: string;
    try {
      if (fs.statSync(file).size > MAX_BYTES) continue;
      text = fs.readFileSync(file, "utf8");
    } catch { continue; }
    const f = rel(file);
    const add = (id: string, severity: Severity, message: string, index: number) =>
      out.push({ id, severity, message, file: f, line: lineOf(text, index) });

    if (/trust\s?proxy/i.test(text)) sawTrustProxy = true;
    if (/rateLimit\s*[:(]/.test(text)) usesRateLimit = true;

    const testFile = isTestFile(file);

    // CORS
    const corsBare = /\bcors\(\s*\)/.exec(text);
    const corsOpen = /origin\s*:\s*(["']\*["']|true)/.exec(text);
    const corsHit = corsBare ?? corsOpen;
    if (corsHit && !testFile) {
      if (/credentials\s*:\s*true/.test(text) && corsOpen) {
        add("cors-credentials-wildcard", "error", "CORS allows any origin together with credentials: true.", corsHit.index);
      } else {
        add("cors-wildcard", "warn", "CORS allows every origin; restrict it to an allow-list in production.", corsHit.index);
      }
    }

    // Stack traces in responses
    const stack = /\.(json|send)\([^;]{0,200}?\b(err|error|e)\.stack\b/s.exec(text);
    if (stack && !testFile) add("stack-leak", "warn", "Error stack trace appears to be sent to the client.", stack.index);

    // Cookies / sessions
    for (const m of testFile ? [] : text.matchAll(/\bsession\s*\(\s*\{/g)) {
      const body = text.slice(m.index!, m.index! + 500);
      if (!/secure\s*:/.test(body)) add("session-cookie-secure", "warn", "session() config without cookie.secure.", m.index!);
    }
    for (const m of testFile ? [] : text.matchAll(/\.cookie\(\s*[^)]{0,200}\)/g)) {
      if (!/httpOnly/i.test(m[0])) add("cookie-httponly", "warn", "res.cookie() without httpOnly (and likely secure/sameSite).", m.index!);
    }

    // NoSQL injection: request data passed straight into a query
    if (has("mongoose", "mongodb") && !testFile) {
      const q = /\.(find|findOne|findOneAndUpdate|findOneAndDelete|updateOne|updateMany|deleteOne|deleteMany|countDocuments)\(\s*(req|request)\.(body|query)\b/.exec(text);
      if (q) add("nosql-injection-risk", "warn", "Request data is passed directly into a MongoDB query; `{ \"$ne\": null }` style payloads can bypass filters. Validate input or enable backend-guard `noSqlInjection`.", q.index);
    }

    // TLS verification off
    const tls = /rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*["']?0/.exec(text);
    if (tls && !testFile) add("tls-verify-off", "error", "TLS certificate verification is disabled.", tls.index);

    // Hardcoded secrets (heuristic)
    if (!testFile) {
      const secret = /\b(secret|password|passwd|api[_-]?key|token)\b\s*[:=]\s*["'][^"'\s]{8,}["']/i.exec(text);
      if (secret && !/process\.env|import\.meta\.env|example|changeme|your[_-]/i.test(text.slice(Math.max(0, secret.index - 40), secret.index + secret[0].length + 20))) {
        add("hardcoded-secret", "warn", "Possible hardcoded secret/credential (heuristic).", secret.index);
      }
    }
  }

  if (usesRateLimit && !sawTrustProxy) {
    out.push({
      id: "trust-proxy-unset",
      severity: "info",
      message: 'Rate limiting / IP rules are used but no "trust proxy" setting was found. Behind a reverse proxy or load balancer, enable it or all clients share one IP.',
    });
  }

  return out;
}
