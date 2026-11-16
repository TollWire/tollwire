import { realpathSync } from "node:fs";
import { fileURLToPath } from "node:url";

/**
 * True when the module at moduleUrl is the script Node was started with. If this cannot be determined
 * (realpath fails), it returns true: an entry module must run rather than silently do nothing (a hook
 * that does nothing exits 0, which allows the tool call). The hook's own decision is still 0 or 2.
 */
export function isEntryPoint(moduleUrl: string, argv1: string | undefined = process.argv[1]): boolean {
  if (!argv1) return false;
  try {
    return realpathSync(argv1) === realpathSync(fileURLToPath(moduleUrl));
  } catch {
    return true;
  }
}
