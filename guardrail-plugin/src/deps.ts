export interface DependencyViolation {
  ecosystem: "npm" | "pypi";
  name: string;
}

const NPM_SECTIONS = ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"] as const;
const PEP508_NAME = /^\s*([A-Za-z0-9][A-Za-z0-9._-]*)/;
/** Version specs that install code from outside the npm registry and cannot be checked by name. */
const NPM_NON_REGISTRY =
  /^(git(\+[a-z]+)?:|github:|gitlab:|bitbucket:|https?:|file:|link:|portal:|workspace:|\.{0,2}\/|~\/|[\w.-]+\/[\w.-]+(#.*)?$)|\.(tgz|tar\.gz|tar)$/i;
/** Root keys that redirect transitive packages (npm, yarn, pnpm). */
const OVERRIDE_KEYS = ["overrides", "resolutions"] as const;

export function normalizePypi(name: string): string {
  return name.replace(/[-_.]+/g, "-").toLowerCase();
}

/** npm alias target ("npm:pkg@1" or "npm:@scope/pkg@1" → package name), else null. */
export function npmAliasTarget(spec: string): string | null {
  if (!/^npm:/i.test(spec)) return null;
  const rest = spec.slice(4);
  const at = rest.indexOf("@", rest.startsWith("@") ? 1 : 0);
  return at === -1 ? rest : rest.slice(0, at);
}

/** Each dependency as name plus the package that is actually installed (alias target) or an unverifiable marker. */
export function npmEntries(packageJson: string): { name: string; installs: string }[] {
  const data = JSON.parse(packageJson) as unknown;
  if (!data || typeof data !== "object" || Array.isArray(data)) throw new Error("package.json must be an object");
  const entries: { name: string; installs: string }[] = [];
  for (const section of NPM_SECTIONS) {
    const deps = (data as Record<string, unknown>)[section];
    if (!deps || typeof deps !== "object") continue;
    for (const [name, spec] of Object.entries(deps as Record<string, unknown>)) {
      const value = typeof spec === "string" ? spec : "";
      const alias = npmAliasTarget(value);
      const installs = alias ?? (NPM_NON_REGISTRY.test(value) ? `${name} (${value})` : name);
      entries.push({ name, installs });
    }
  }
  return entries;
}

/** All string specs inside an overrides tree (nested objects allowed), as [path, spec]. */
function overrideSpecs(value: unknown, path: string): [string, string][] {
  if (typeof value === "string") return [[path, value]];
  if (!value || typeof value !== "object") return [];
  return Object.entries(value as Record<string, unknown>).flatMap(([k, v]) => overrideSpecs(v, `${path}>${k}`));
}

/** Override entries that install from unverifiable sources or alias to non-allowlisted packages. */
export function npmOverrideViolations(packageJson: string, allowed: ReadonlySet<string>): string[] {
  const data = JSON.parse(packageJson) as Record<string, unknown>;
  const roots: [string, unknown][] = OVERRIDE_KEYS.map((k) => [k, data[k]]);
  const pnpm = data.pnpm as Record<string, unknown> | undefined;
  if (pnpm && typeof pnpm === "object") roots.push(["pnpm.overrides", pnpm.overrides]);
  const violations: string[] = [];
  for (const [root, value] of roots) {
    for (const [path, spec] of overrideSpecs(value, root)) {
      const alias = npmAliasTarget(spec);
      if (alias !== null) {
        if (!allowed.has(alias)) violations.push(`${path} -> ${alias}`);
      } else if (NPM_NON_REGISTRY.test(spec)) {
        violations.push(`${path} (${spec})`);
      }
    }
  }
  return violations;
}

export function npmDependencies(packageJson: string): string[] {
  return [...new Set(npmEntries(packageJson).map((e) => e.name))].sort();
}

export interface RequirementScan {
  names: string[];
  /** Directives and direct references that pull code from unverifiable sources. */
  unsupported: string[];
}

export function scanRequirements(requirements: string): RequirementScan {
  const names = new Set<string>();
  const unsupported: string[] = [];
  for (const rawLine of requirements.split(/\r?\n/)) {
    const line = rawLine.split(" #", 1)[0]?.replace(/^#.*/, "").trim() ?? "";
    if (!line) continue;
    if (line.startsWith("-")) {
      unsupported.push(line);
      continue;
    }
    // Direct references: "name @ url", compact "name[extra]@url", bare URLs and local paths.
    if (/^[a-z+]+:\/\//i.test(line) || /^[A-Za-z0-9][\w.-]*\s*(\[[^\]]*\])?\s*@/.test(line) || line.startsWith(".") || line.startsWith("/")) {
      unsupported.push(line);
      continue;
    }
    const match = PEP508_NAME.exec(line);
    if (match?.[1]) names.add(normalizePypi(match[1]));
  }
  return { names: [...names].sort(), unsupported };
}

export function requirementNames(requirements: string): string[] {
  return scanRequirements(requirements).names;
}

export function checkNpm(packageJson: string, allowed: readonly string[]): DependencyViolation[] {
  const allow = new Set(allowed);
  const violations = new Map<string, DependencyViolation>();
  for (const { name, installs } of npmEntries(packageJson)) {
    for (const pkg of new Set([name, installs])) {
      if (!allow.has(pkg)) violations.set(pkg, { ecosystem: "npm", name: pkg });
    }
  }
  for (const entry of npmOverrideViolations(packageJson, allow)) {
    violations.set(entry, { ecosystem: "npm", name: `override ${entry}` });
  }
  return [...violations.values()].sort((a, b) => a.name.localeCompare(b.name));
}

export function checkPypi(requirements: string, allowed: readonly string[]): DependencyViolation[] {
  const allow = new Set(allowed.map(normalizePypi));
  const scan = scanRequirements(requirements);
  return [
    ...scan.names.filter((name) => !allow.has(name)).map((name) => ({ ecosystem: "pypi" as const, name })),
    ...scan.unsupported.map((line) => ({ ecosystem: "pypi" as const, name: `unsupported: ${line}` })),
  ];
}
