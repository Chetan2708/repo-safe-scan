import fs from "fs";
import path from "path";
import { glob } from "glob";
import rules from "../rules/rules";
import { normalizeCommand } from "../utils/normalizeCommand";
import type { Finding } from "../types";

const LIFECYCLE_HOOKS = new Set<string>([
  "preinstall",
  "install",
  "postinstall",
  "prepare",
]);

interface PackageJson {
  scripts?: Record<string, unknown>;
  [key: string]: unknown;
}

/**
 * Scans dependencies in node_modules for malicious lifecycle scripts.
 */
export async function nodeModulesAnalyzer(repoPath: string): Promise<Finding[]> {
  const findings: Finding[] = [];
  const nmPath = path.resolve(repoPath, "node_modules");

  if (!fs.existsSync(nmPath)) {
    return findings;
  }

  let pkgFiles: string[];
  try {
    pkgFiles = await glob("**/package.json", {
      cwd: nmPath,
      absolute: true,
    });
  } catch {
    return findings;
  }

  for (const filePath of pkgFiles) {
    let pkg: PackageJson;
    try {
      pkg = JSON.parse(fs.readFileSync(filePath, "utf8")) as PackageJson;
    } catch {
      continue; // Skip malformed package.json in node_modules
    }

    const scripts = pkg.scripts ?? {};

    for (const [scriptName, originalCommand] of Object.entries(scripts)) {
      if (typeof originalCommand !== "string") continue;

      const isLifecycle = LIFECYCLE_HOOKS.has(scriptName);
      if (!isLifecycle) continue; // In node_modules, we mostly care about auto-executing things

      const normalizedCmd = normalizeCommand(originalCommand);
      const relPath = path.relative(repoPath, filePath);

      for (const rule of rules) {
        if (rule.pattern && rule.pattern.test(normalizedCmd)) {
          findings.push({
            file: relPath,
            scriptName,
            command: originalCommand,
            rule: {
              id: rule.id,
              description: rule.description,
              severity: "critical", // Dependency lifecycle hooks are highly suspicious
              category: rule.category,
            },
            lifecycle: true,
            lifecycleMessage: "⚠ This dependency script ran automatically during `npm install`.",
            detail: null,
          });
          break;
        }
      }
    }
  }

  return findings;
}
