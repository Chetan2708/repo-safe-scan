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
 * Extract the top-level package name from a node_modules file path.
 * e.g. "node_modules/@scope/pkg/package.json" → "@scope/pkg"
 *      "node_modules/pkg/package.json"         → "pkg"
 *      "node_modules/pkg/node_modules/sub/package.json" → "sub"
 */
function extractPkgName(filePath: string, nmPath: string): string | null {
  const rel = path.relative(nmPath, filePath).replace(/\\/g, "/");
  // rel is like "pkg/package.json" or "@scope/pkg/package.json"
  // or nested: "parent/node_modules/child/package.json"
  // We want the *immediate* package — the last node_modules segment's child
  const parts = rel.split("/");

  // Walk backwards to find the last node_modules boundary, or use root
  let startIdx = 0;
  for (let i = parts.length - 1; i >= 0; i--) {
    if (parts[i] === "node_modules") {
      startIdx = i + 1;
      break;
    }
  }

  if (startIdx >= parts.length) return null;

  // Scoped package: starts with @
  if (parts[startIdx]?.startsWith("@") && parts[startIdx + 1]) {
    return `${parts[startIdx]}/${parts[startIdx + 1]}`;
  }
  return parts[startIdx] ?? null;
}

/**
 * Scans dependencies in node_modules for malicious lifecycle scripts.
 * Optionally accepts a set of newly added dependency names to flag.
 */
export async function nodeModulesAnalyzer(
  repoPath: string,
  _opts?: unknown,
  newDeps?: Set<string>,
): Promise<Finding[]> {
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
    const pkgName = extractPkgName(filePath, nmPath);
    const isNewDep = pkgName ? (newDeps?.has(pkgName) ?? false) : false;

    for (const [scriptName, originalCommand] of Object.entries(scripts)) {
      if (typeof originalCommand !== "string") continue;

      const isLifecycle = LIFECYCLE_HOOKS.has(scriptName);
      if (!isLifecycle) continue; // In node_modules, we mostly care about auto-executing things

      const normalizedCmd = normalizeCommand(originalCommand);
      const relPath = path.relative(repoPath, filePath);

      let matched = false;
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
            isNewDep,
          });
          matched = true;
          break;
        }
      }

      // Even if no malicious pattern matched, flag newly added deps with lifecycle hooks
      if (!matched && isNewDep && isLifecycle) {
        findings.push({
          file: relPath,
          scriptName,
          command: originalCommand,
          rule: {
            id: "newly-added-lifecycle",
            description: "Newly added dependency contains a lifecycle hook",
            severity: "high",
            category: "supply-chain",
          },
          lifecycle: true,
          lifecycleMessage: "⚠ This is a newly added dependency with an auto-executing lifecycle hook. Review carefully.",
          detail: `Package "${pkgName}" was recently added and has a "${scriptName}" script.`,
          isNewDep: true,
        });
      }
    }
  }

  return findings;
}
