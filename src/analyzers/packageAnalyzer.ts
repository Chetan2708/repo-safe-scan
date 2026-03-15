import fs from "fs";
import path from "path";
import rules from "../rules/rules";
import { normalizeCommand } from "../utils/normalizeCommand";
import type { Finding, Rule, ScanOptions } from "../types";

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

export async function packageAnalyzer(repoPath: string, opts?: ScanOptions): Promise<Finding[]> {
  const filePath = path.resolve(repoPath, "package.json");
  const findings: Finding[] = [];

  if (!fs.existsSync(filePath)) {
    return findings;
  }

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

  for (const [scriptName, command] of Object.entries(scripts)) {
    if (typeof command !== "string") continue;

    const isLifecycle = LIFECYCLE_HOOKS.has(scriptName);
    const normalizedCmd = normalizeCommand(command);

    for (const rule of rules) {
      if (rule.pattern && rule.pattern.test(normalizedCmd)) {
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
          lifecycleMessage: isLifecycle 
            ? "⚠ This script runs automatically on `npm install` — no user confirmation required. This is the primary supply-chain attack vector." 
            : undefined,
          detail: null,
        });

        break;
      }
    }
  }

  return findings;
}
