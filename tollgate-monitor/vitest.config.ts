import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    // Self-hosted WSL runner is slower under load than hosted runners; 5 s (default) caused timeouts (#103).
    testTimeout: 20_000,
    include: ["test/**/*.test.ts"],
    coverage: {
      provider: "v8",
      include: ["src/**/*.ts"],
      // Vendored files are tested where they originate (modules/token, modules/hashchain, guardrail plugin, enterprise
      // package); the entry point only wires arguments to tested functions and runs on import.
      exclude: ["src/vendor/**", "src/common/chainlog.ts", "src/common/fsx.ts", "src/common/ids.ts", "src/main.ts", "src/runtime.ts", "src/admin/main.ts"],
      reporter: ["text", "json-summary"],
      thresholds: { statements: 80, branches: 80, functions: 80, lines: 80 },
    },
  },
});
