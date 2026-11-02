// Keeps every test away from the real home directory: the hook writes its decision log below the user's home
// (from the user database), so the home directory seen by the code under test is a temporary one.
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { vi } from "vitest";

const home = mkdtempSync(join(tmpdir(), "tg-test-home-"));

vi.mock("node:os", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:os")>();
  const userInfo = ((...args: Parameters<typeof actual.userInfo>) => ({ ...actual.userInfo(...args), homedir: home })) as typeof actual.userInfo;
  // Only userInfo() (getpwuid) is replaced: that is where the code under test takes the home directory from.
  return { ...actual, userInfo, default: { ...actual, userInfo } };
});
