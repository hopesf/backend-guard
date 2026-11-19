import { defineConfig } from "vitest/config";

export default defineConfig({
  // Nest needs legacy (experimental) decorators; test/ is outside tsconfig's include.
  oxc: { decorator: { legacy: true } },
  test: { include: ["test/**/*.test.ts"], testTimeout: 15000 },
} as never);
