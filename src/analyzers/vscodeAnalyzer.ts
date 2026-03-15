import fs from "fs";
import path from "path";
import rules from "../rules/rules";
import { normalizeCommand } from "../utils/normalizeCommand";
import type { Finding, ScanOptions } from "../types";

const DANGEROUS_SETTINGS_KEYS: Record<string, string | false> = {
  "terminal.integrated.env.linux": "Injects env vars into Linux terminals",
  "terminal.integrated.env.osx": "Injects env vars into macOS terminals",
  "terminal.integrated.env.windows": "Injects env vars into Windows terminals",
  "terminal.integrated.shell.linux": "Overrides Linux shell executable",
  "terminal.integrated.shell.osx": "Overrides macOS shell executable",
  "terminal.integrated.shell.windows": "Overrides Windows shell executable",
  "terminal.integrated.shellArgs.linux": "Injects Linux shell start args",
  "terminal.integrated.shellArgs.osx": "Injects macOS shell start args",
  "terminal.integrated.shellArgs.windows": "Injects Windows shell start args",
  "python.pythonPath": "Custom Python path could be malicious binary",
  "python.terminal.activateEnvInCurrentTerminal": "Auto-runs activate scripts",
  "code-runner.executorMap": "Can run arbitrary commands",
  "code-runner.runInTerminal": "Terminal mode code runner",
};

const SUSPICIOUS_EXTENSION_IDS = new Set<string>([
  "prettier.prettier-vscode-malicious",
  "vscodevim.vim-malicious",
  "ms-vscode.vscode-extension-samples-malicious",
]);

export async function vscodeAnalyzer(repoPath: string, opts?: ScanOptions): Promise<Finding[]> {
  const findings: Finding[] = [];
  const vscodeDir = path.resolve(repoPath, ".vscode");

  if (!fs.existsSync(vscodeDir)) return findings;

  findings.push(...scanTasksJson(vscodeDir));
  findings.push(...scanSettingsJson(vscodeDir));
  findings.push(...scanExtensionsJson(vscodeDir));

  return findings;
}

function scanTasksJson(vscodeDir: string): Finding[] {
  const findings: Finding[] = [];
  const filePath = path.join(vscodeDir, "tasks.json");

  if (!fs.existsSync(filePath)) return findings;

  let tasksConfig: Record<string, unknown>;
  try {
    tasksConfig = JSON.parse(fs.readFileSync(filePath, "utf8")) as Record<string, unknown>;
  } catch (err) {
    findings.push(parseErrorFinding(".vscode/tasks.json", err as Error));
    return findings;
  }

  const tasks = (tasksConfig["tasks"] as Record<string, unknown>[] | undefined) ?? [];

  for (const task of tasks) {
    const win = task["windows"] as Record<string, unknown> | undefined;
    const lin = task["linux"] as Record<string, unknown> | undefined;
    const osx = task["osx"] as Record<string, unknown> | undefined;

    const commandSources = [task["command"], win?.["command"], lin?.["command"], osx?.["command"]]
      .filter((c): c is string => typeof c === "string");

    const label = typeof task["label"] === "string" ? task["label"] : typeof task["taskName"] === "string" ? task["taskName"] : "(unnamed task)";

    for (const command of commandSources) {
      const normalizedCmd = normalizeCommand(command);
      for (const rule of rules) {
        if (rule.pattern && rule.pattern.test(normalizedCmd)) {
          findings.push({
            file: ".vscode/tasks.json",
            scriptName: label,
            command,
            rule: { id: rule.id, description: rule.description, severity: rule.severity, category: rule.category },
            lifecycle: false,
            detail: null,
          });
          break;
        }
      }
    }

    const rawArgs = [...((task["args"] as unknown[]) ?? []), ...((win?.["args"] as unknown[]) ?? [])]
      .filter((a): a is string => typeof a === "string");

    const fullCmd = rawArgs.join(" ");
    if (fullCmd) {
      const normalizedFullCmd = normalizeCommand(fullCmd);
      for (const rule of rules) {
        if (rule.pattern && rule.pattern.test(normalizedFullCmd)) {
          findings.push({
            file: ".vscode/tasks.json",
            scriptName: `${label} — args`,
            command: fullCmd,
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

function scanSettingsJson(vscodeDir: string): Finding[] {
  const findings: Finding[] = [];
  const filePath = path.join(vscodeDir, "settings.json");

  if (!fs.existsSync(filePath)) return findings;

  let settings: Record<string, unknown>;
  try {
    settings = JSON.parse(fs.readFileSync(filePath, "utf8")) as Record<string, unknown>;
  } catch (err) {
    findings.push(parseErrorFinding(".vscode/settings.json", err as Error));
    return findings;
  }

  for (const [key, description] of Object.entries(DANGEROUS_SETTINGS_KEYS)) {
    if (description === false || !(key in settings)) continue;

    const value = settings[key];
    if (value === null || value === "" || (typeof value === "object" && Object.keys(value).length === 0)) continue;

    const valueStr = typeof value === "string" ? value : JSON.stringify(value);
    const normalizedValue = normalizeCommand(valueStr);

    let matchedRule: Finding["rule"] | null = null;
    for (const rule of rules) {
      if (rule.pattern && rule.pattern.test(normalizedValue)) {
        matchedRule = { id: rule.id, description: rule.description, severity: rule.severity, category: rule.category };
        break;
      }
    }

    findings.push({
      file: ".vscode/settings.json",
      scriptName: key,
      command: valueStr,
      rule: matchedRule ?? {
        id: "dangerous-vscode-setting",
        description: description as string,
        severity: "high",
        category: "vscode-config",
      },
      lifecycle: false,
      detail: null,
    });
  }
  return findings;
}

function scanExtensionsJson(vscodeDir: string): Finding[] {
  const findings: Finding[] = [];
  const filePath = path.join(vscodeDir, "extensions.json");

  if (!fs.existsSync(filePath)) return findings;

  let extConfig: Record<string, unknown>;
  try {
    extConfig = JSON.parse(fs.readFileSync(filePath, "utf8")) as Record<string, unknown>;
  } catch (err) {
    findings.push(parseErrorFinding(".vscode/extensions.json", err as Error));
    return findings;
  }

  const recommendations = (extConfig["recommendations"] as string[] | undefined) ?? [];

  for (const extId of recommendations) {
    if (SUSPICIOUS_EXTENSION_IDS.has(extId)) {
      findings.push({
        file: ".vscode/extensions.json",
        scriptName: "recommendations",
        command: extId,
        rule: {
          id: "suspicious-extension",
          description: `Extension "${extId}" is known to be malicious or suspicious`,
          severity: "critical",
          category: "vscode-extension",
        },
        lifecycle: false,
        detail: null,
      });
    }
  }
  return findings;
}

function parseErrorFinding(file: string, err: Error): Finding {
  return {
    file,
    scriptName: null,
    command: null,
    rule: {
      id: "malformed-json",
      description: "File contains invalid JSON",
      severity: "medium",
      category: "file-integrity",
    },
    lifecycle: false,
    detail: err.message,
  };
}
