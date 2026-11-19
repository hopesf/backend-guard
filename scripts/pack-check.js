// Clean-install regression test: installing backend-guard with ONLY express
// must not crash on require (optional Fastify/Nest peers must not be loaded).
const { execSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const root = path.resolve(__dirname, "..");
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "bg-pack-"));
const run = (cmd, cwd) => execSync(cmd, { cwd, stdio: "pipe" }).toString().trim();

try {
  const tgz = run(`npm pack --pack-destination "${tmp}" --silent`, root).split("\n").pop();
  fs.writeFileSync(path.join(tmp, "package.json"), '{"name":"t","version":"1.0.0"}');
  run(`npm i --no-audit --no-fund express "${path.join(tmp, tgz)}"`, tmp);
  const out = run(
    `node -e "const m=require('backend-guard');const e=require('backend-guard/express');if(typeof m.backendGuard!=='function'||typeof e.backendGuard!=='function')process.exit(1);console.log('ok')"`,
    tmp
  );
  if (out !== "ok") throw new Error("unexpected output: " + out);
  console.log("pack-check: OK (express-only install loads without optional peers)");
} catch (err) {
  console.error("pack-check FAILED:", err.stderr ? err.stderr.toString() : err);
  process.exitCode = 1;
} finally {
  fs.rmSync(tmp, { recursive: true, force: true });
}
