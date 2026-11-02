import { describe, expect, it, vi } from "vitest";

vi.mock("node:os", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:os")>();
  const userInfo = (() => {
    throw new Error("no passwd entry");
  }) as unknown as typeof actual.userInfo;
  const hostname = (() => {
    throw new Error("no host name");
  }) as typeof actual.hostname;
  return { ...actual, userInfo, hostname, homedir: () => "/fallback/home", default: { ...actual, userInfo, hostname, homedir: () => "/fallback/home" } };
});

describe("systemRuntime without a user database entry", () => {
  it("falls back to the home directory API and the process uid", async () => {
    const { systemRuntime } = await import("../../src/events/runtime.js");
    const rt = systemRuntime();
    expect(rt.username).toBe("unknown");
    expect(rt.home).toBe("/fallback/home");
    expect(rt.hostname).toBe("unknown");
    expect(rt.uid).toBe(process.getuid?.());
  });
});
