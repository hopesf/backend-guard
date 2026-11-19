import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { scanProject } from "../src/cli/scan";
import { main, render } from "../src/cli/index";

let dir: string;
beforeEach(() => { dir = fs.mkdtempSync(path.join(os.tmpdir(), "bg-scan-")); });
afterEach(() => { fs.rmSync(dir, { recursive: true, force: true }); });

const write = (name: string, content: string) => {
  fs.mkdirSync(path.dirname(path.join(dir, name)), { recursive: true });
  fs.writeFileSync(path.join(dir, name), content);
};
const ids = () => scanProject(dir).map((f) => f.id);

describe("scanProject", () => {
  it("flags a bare express app", () => {
    write("package.json", JSON.stringify({ dependencies: { express: "5", "xss-clean": "1" } }));
    write("index.js", 'const cors=require("cors");\napp.use(cors());\napp.use((err,req,res,next)=>res.status(500).json({stack: err.stack}));\nconst apiKey = "sk_live_abcdefgh12345";\n');
    expect(ids()).toEqual(expect.arrayContaining(["no-security-headers", "deprecated-xss-clean", "cors-wildcard", "stack-leak", "hardcoded-secret"]));
  });
  it("detects cors+credentials as an error, with file and line", () => {
    write("package.json", "{}");
    write("a.ts", "x\ncors({ origin: true, credentials: true })");
    const f = scanProject(dir).find((x) => x.id === "cors-credentials-wildcard")!;
    expect(f.severity).toBe("error");
    expect(f.file).toBe("a.ts");
    expect(f.line).toBe(2);
  });
  it("flags .env missing from .gitignore, and not when ignored", () => {
    write("package.json", "{}"); write(".env", "A=1");
    expect(ids()).toContain("env-not-ignored");
    write(".gitignore", "node_modules\n.env\n");
    expect(ids()).not.toContain("env-not-ignored");
  });
  it("flags insecure cookies and disabled TLS verification", () => {
    write("package.json", "{}");
    write("c.js", 'res.cookie("sid", v);\nsession({ secret: process.env.S });\nprocess.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";');
    expect(ids()).toEqual(expect.arrayContaining(["cookie-httponly", "session-cookie-secure", "tls-verify-off"]));
  });
  it("ignores node_modules and test files, and stays clean for a good project", () => {
    write("package.json", JSON.stringify({ dependencies: { express: "5", "backend-guard": "2" } }));
    write("node_modules/x/index.js", "cors()");
    write("app.test.js", "cors()");
    write("app.js", 'app.set("trust proxy", 1);\napp.use(backendGuard({ rateLimit: true }));');
    expect(ids()).toEqual([]);
  });
  it("notes missing trust proxy when rate limiting is used", () => {
    write("package.json", JSON.stringify({ dependencies: { "express-rate-limit": "8" } }));
    write("a.js", "x");
    expect(ids()).toContain("trust-proxy-unset");
  });
});

describe("cli", () => {
  it("exits 1 on errors, 0 on warnings (unless --strict)", () => {
    write("package.json", JSON.stringify({ dependencies: { express: "5" } }));
    expect(main(["doctor", dir])).toBe(0);
    expect(main(["doctor", dir, "--strict"])).toBe(1);
    write(".env", "A=1");
    expect(main(["doctor", dir])).toBe(1);
  });
  it("renders findings", () => {
    expect(render([])).toContain("no issues");
    expect(render([{ id: "x", severity: "warn", message: "m", file: "a.js", line: 3 }])).toContain("a.js:3");
  });
});
