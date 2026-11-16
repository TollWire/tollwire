import { realpathSync } from "node:fs";
import { fileURLToPath } from "node:url";

/** True when the module at moduleUrl is the script Node was started with. */
export function isEntryPoint(moduleUrl: string, argv1: string | undefined = process.argv[1]): boolean {
  if (!argv1) return false;
  try {
    return realpathSync(argv1) === realpathSync(fileURLToPath(moduleUrl));
  } catch {
    return false;
  }
}
