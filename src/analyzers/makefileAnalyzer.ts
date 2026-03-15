import fs from "fs";
import path from "path";
import rules from "../rules/rules";
import { normalizeCommand } from "../utils/normalizeCommand";
import type { Finding, ScanOptions } from "../types";

export async function makefileAnalyzer(repoPath: string, opts?: ScanOptions): Promise<Finding[]> {
  const findings: Finding[] = [];
  const filePath = path.resolve(repoPath, "Makefile");

  if (!fs.existsSync(filePath)) {
    return findings;
  }

  let lines: string[];
  try {
    lines = fs.readFileSync(filePath, "utf8").split(/\r?\n/);
  } catch (err) {
    findings.push({
      file: "Makefile",
      scriptName: null,
      command: null,
      rule: {
        id: "file-read-error",
        description: "Could not read Makefile",
        severity: "medium",
        category: "file-integrity",
      },
      lifecycle: false,
      detail: (err as Error).message,
    });
    return findings;
  }

  let currentTarget = "(unknown)";

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;

    const targetMatch = line.match(/^([a-zA-Z0-9_.\-/]+)\s*:/);
    if (targetMatch) {
      currentTarget = targetMatch[1]!;
      continue;
    }

    if (!line.startsWith("\t")) continue;

    const command = line.trimStart();
    if (!command) continue;

    const normalizedCmd = normalizeCommand(command);

    for (const rule of rules) {
      if (rule.pattern && rule.pattern.test(normalizedCmd)) {
        findings.push({
          file: "Makefile",
          scriptName: `target: ${currentTarget}`,
          command,
          rule: { id: rule.id, description: rule.description, severity: rule.severity, category: rule.category },
          lifecycle: false,
          detail: `Line ${i + 1}`,
        });
        break;
      }
    }
  }

  return findings;
}
