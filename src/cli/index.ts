#!/usr/bin/env node
import * as path from "node:path";
import { scanProject } from "./scan";
import type { ScanFinding } from "./scan";

const HELP = `backend-guard — security checks for Node backends

Usage:
  backend-guard doctor [path] [--json] [--strict]

  doctor    Heuristic static scan of a project (default: current directory)
  --json    Machine-readable output
  --strict  Exit with code 1 on warnings too (default: only on errors)
`;

export function render(findings: ScanFinding[]): string {
  if (findings.length === 0) return "backend-guard doctor: no issues found.";
  const order = { error: 0, warn: 1, info: 2 } as const;
  const sorted = [...findings].sort((a, b) => order[a.severity] - order[b.severity]);
  const lines = sorted.map((f) => {
    const loc = f.file ? ` ${f.file}${f.line ? `:${f.line}` : ""}` : "";
    return `${f.severity.toUpperCase().padEnd(5)} ${f.id}${loc}\n      ${f.message}`;
  });
  const n = (s: string) => findings.filter((f) => f.severity === s).length;
  lines.push(`\n${n("error")} error(s), ${n("warn")} warning(s), ${n("info")} note(s)`);
  return lines.join("\n");
}

export function main(argv: string[]): number {
  const args = argv.filter((a) => !a.startsWith("--"));
  const flags = new Set(argv.filter((a) => a.startsWith("--")));

  if (flags.has("--help") || args.length === 0 || args[0] === "help") {
    console.log(HELP);
    return args.length === 0 && !flags.has("--help") ? 1 : 0;
  }
  if (args[0] !== "doctor") {
    console.error(`Unknown command "${args[0]}".\n\n${HELP}`);
    return 1;
  }

  const target = path.resolve(args[1] ?? ".");
  const findings = scanProject(target);

  console.log(flags.has("--json") ? JSON.stringify(findings, null, 2) : render(findings));

  const failing = findings.some((f) => f.severity === "error" || (flags.has("--strict") && f.severity === "warn"));
  return failing ? 1 : 0;
}

if (require.main === module) {
  process.exitCode = main(process.argv.slice(2));
}
