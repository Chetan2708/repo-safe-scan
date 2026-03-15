import fs from "fs";
import path from "path";
import { glob } from "glob";
import rules from "../rules/rules";
import type { Finding } from "../types";

/**
 * Analyze shell scripts (*.sh, *.bash) in the repository for suspicious patterns.
 */
export async function shellScriptAnalyzer(repoPath: string): Promise<Finding[]> {
  const findings: Finding[] = [];
  const resolvedRoot = path.resolve(repoPath);

  let scriptFiles: string[];
  try {
    scriptFiles = await glob("**/*.{sh,bash}", {
      cwd: resolvedRoot,
      absolute: true,
      ignore: [
        "**/node_modules/**",
        "**/.git/**",
        "**/vendor/**",
        "**/dist/**",
        "**/build/**",
      ],
      maxDepth: 3,
    });
  } catch {
    return findings;
  }

  for (const filePath of scriptFiles) {
    const relFile = path.relative(resolvedRoot, filePath);

    let lines: string[];
    try {
      lines = fs.readFileSync(filePath, "utf8").split(/\r?\n/);
    } catch {
      findings.push({
        file: relFile,
        scriptName: null,
        command: null,
        rule: {
          id: "file-read-error",
          description: "Could not read shell script",
          severity: "medium",
          category: "file-integrity",
        },
        lifecycle: false,
        detail: null,
      });
      continue;
    }

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i]!.trim();
      if (!line || line.startsWith("#")) continue;

      for (const rule of rules) {
        if (rule.regex.test(line)) {
          findings.push({
            file: relFile,
            scriptName: `line ${i + 1}`,
            command: line,
            rule: { id: rule.id, description: rule.description, severity: rule.severity, category: rule.category },
            lifecycle: false,
            detail: null,
          });
          break;
        }
      }
    }
  }

  return findings;
}
