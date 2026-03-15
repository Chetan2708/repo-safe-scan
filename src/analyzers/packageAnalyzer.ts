import fs from "fs";
import path from "path";
import rules from "../rules/rules";
import type { Finding, Rule } from "../types";

/**
 * npm lifecycle scripts that execute automatically — highest risk category.
 * @see https://docs.npmjs.com/cli/v10/using-npm/scripts#life-cycle-scripts
 */
const LIFECYCLE_HOOKS = new Set<string>([
  "preinstall",
  "install",
  "postinstall",
  "preuninstall",
  "uninstall",
  "postuninstall",
  "prepare",
  "prepublish",
  "prepublishOnly",
  "prepack",
  "postpack",
  "pretest",
  "posttest",
  "prestop",
  "poststop",
  "prestart",
  "poststart",
  "prerestart",
  "postrestart",
]);

interface PackageJson {
  scripts?: Record<string, unknown>;
  [key: string]: unknown;
}

/**
 * Analyze package.json scripts for suspicious patterns.
 */
export async function packageAnalyzer(repoPath: string): Promise<Finding[]> {
  const filePath = path.resolve(repoPath, "package.json");
  const findings: Finding[] = [];

  if (!fs.existsSync(filePath)) {
    return findings;
  }

  // ── Parse (never crash the tool on malformed JSON) ───────────────────────
  let pkg: PackageJson;
  try {
    pkg = JSON.parse(fs.readFileSync(filePath, "utf8")) as PackageJson;
  } catch (err) {
    findings.push({
      file: "package.json",
      scriptName: null,
      command: null,
      rule: {
        id: "malformed-json",
        description: "package.json contains invalid JSON",
        severity: "medium",
        category: "file-integrity",
      },
      lifecycle: false,
      detail: (err as Error).message,
    });
    return findings;
  }

  const scripts: Record<string, unknown> = pkg.scripts ?? {};

  // ── Scan each script ─────────────────────────────────────────────────────
  for (const [scriptName, command] of Object.entries(scripts)) {
    if (typeof command !== "string") continue;

    const isLifecycle = LIFECYCLE_HOOKS.has(scriptName);

    for (const rule of rules) {
      if (rule.regex.test(command)) {
        // Escalate severity for lifecycle hooks (auto-executed on npm install)
        let severity: Rule["severity"] = rule.severity;
        if (isLifecycle && severity === "high") severity = "critical";

        findings.push({
          file: "package.json",
          scriptName,
          command,
          rule: {
            id: rule.id,
            description: rule.description,
            severity,
            category: rule.category,
          },
          lifecycle: isLifecycle,
          detail: null,
        });

        break; // one finding per rule per script
      }
    }
  }

  return findings;
}
