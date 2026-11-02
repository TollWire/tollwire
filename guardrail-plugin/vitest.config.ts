import { defineConfig } from "vitest/config";

// Coverage thresholds are a proposal; the owner confirms them.
export default defineConfig({
  test: {
    // Self-hosted WSL runner is slower under load than hosted runners; 5 s (default) caused timeouts (#103).
    testTimeout: 20_000,
    include: ["test/**/*.test.ts"],
    setupFiles: ["test/setup.ts"],
    coverage: {
      provider: "v8",
      include: ["src/**/*.ts"],
      // Executable entries (run on import); covered by the smoke test and the manifest test against a build.
      exclude: ["src/hookCli.ts", "src/hookCliWin.ts", "src/hookCliPosix.ts", "src/events/verifyBin.ts"],
      reporter: ["text", "json-summary"],
      thresholds: { statements: 80, branches: 80, functions: 80, lines: 80 },
    },
  },
});
