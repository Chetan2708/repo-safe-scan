import fs from "fs";
import path from "path";
import rules from "../rules/rules";
import type { Finding } from "../types";

/**
 * .vscode/settings.json keys that are known to be dangerous.
 * Values are descriptions of why they are risky. false = explicitly excluded.
 */
const DANGEROUS_SETTINGS_KEYS: Record<string, string | false> = {
  "terminal.integrated.env.linux":
    "Injects environment variables into all integrated terminals (Linux)",
  "terminal.integrated.env.osx":
    "Injects environment variables into all integrated terminals (macOS)",
  "terminal.integrated.env.windows":
    "Injects environment variables into all integrated terminals (Windows)",
  "terminal.integrated.shell.linux":
    "Overrides the shell executable for all terminals (Linux)",
  "terminal.integrated.shell.osx":
    "Overrides the shell executable for all terminals (macOS)",
  "terminal.integrated.shell.windows":
    "Overrides the shell executable for all terminals (Windows)",
  "terminal.integrated.shellArgs.linux":
    "Passes arguments to the shell — can inject startup commands",
  "terminal.integrated.shellArgs.osx":
    "Passes arguments to the shell — can inject startup commands",
  "terminal.integrated.shellArgs.windows":
    "Passes arguments to the shell — can inject startup commands",
  "python.pythonPath":
    "Custom Python interpreter path — could point to a malicious binary",
  "python.terminal.activateEnvInCurrentTerminal":
    "Auto-activates venv in terminal — runs activate scripts",
  "editor.formatOnSave": false,
  "code-runner.executorMap":
    "Overrides per-language executors — can run arbitrary commands",
  "code-runner.runInTerminal":
    "Enables code-runner terminal mode — combined with executorMap is dangerous",
};

/** Known malicious or suspicious VS Code extension IDs. */
const SUSPICIOUS_EXTENSION_IDS = new Set<string>([
  "prettier.prettier-vscode-malicious",
  "vscodevim.vim-malicious",
  "ms-vscode.vscode-extension-samples-malicious",
]);

/**
 * Analyze .vscode/ directory for suspicious configurations.
 */
export async function vscodeAnalyzer(repoPath: string): Promise<Finding[]> {
  const findings: Finding[] = [];
  const vscodeDir = path.resolve(repoPath, ".vscode");

  if (!fs.existsSync(vscodeDir)) {
    return findings;
  }

  findings.push(...scanTasksJson(vscodeDir));
  findings.push(...scanSettingsJson(vscodeDir));
  findings.push(...scanExtensionsJson(vscodeDir));

  return findings;
}

// ── tasks.json ─────────────────────────────────────────────────────────────

function scanTasksJson(vscodeDir: string): Finding[] {
  const findings: Finding[] = [];
  const filePath = path.join(vscodeDir, "tasks.json");

  if (!fs.existsSync(filePath)) return findings;

  let tasksConfig: Record<string, unknown>;
  try {
    tasksConfig = JSON.parse(fs.readFileSync(filePath, "utf8")) as Record<
      string,
      unknown
    >;
  } catch (err) {
    findings.push(parseErrorFinding(".vscode/tasks.json", err as Error));
    return findings;
  }

  const tasks = (tasksConfig["tasks"] as Record<string, unknown>[] | undefined) ?? [];

  for (const task of tasks) {
    const win = task["windows"] as Record<string, unknown> | undefined;
    const lin = task["linux"] as Record<string, unknown> | undefined;
    const osx = task["osx"] as Record<string, unknown> | undefined;

    const commandSources = [
      task["command"],
      win?.["command"],
      lin?.["command"],
      osx?.["command"],
    ].filter((c): c is string => typeof c === "string");

    const label =
      typeof task["label"] === "string"
        ? task["label"]
        : typeof task["taskName"] === "string"
        ? task["taskName"]
        : "(unnamed task)";

    for (const command of commandSources) {
      for (const rule of rules) {
        if (rule.regex.test(command)) {
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

    // Also scan args array
    const rawArgs = [
      ...((task["args"] as unknown[]) ?? []),
      ...((win?.["args"] as unknown[]) ?? []),
    ].filter((a): a is string => typeof a === "string");

    const fullCmd = rawArgs.join(" ");
    if (fullCmd) {
      for (const rule of rules) {
        if (rule.regex.test(fullCmd)) {
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

// ── settings.json ──────────────────────────────────────────────────────────

function scanSettingsJson(vscodeDir: string): Finding[] {
  const findings: Finding[] = [];
  const filePath = path.join(vscodeDir, "settings.json");

  if (!fs.existsSync(filePath)) return findings;

  let settings: Record<string, unknown>;
  try {
    settings = JSON.parse(fs.readFileSync(filePath, "utf8")) as Record<
      string,
      unknown
    >;
  } catch (err) {
    findings.push(parseErrorFinding(".vscode/settings.json", err as Error));
    return findings;
  }

  for (const [key, description] of Object.entries(DANGEROUS_SETTINGS_KEYS)) {
    if (description === false) continue;
    if (!(key in settings)) continue;

    const value = settings[key];
    if (
      value === null ||
      value === "" ||
      (typeof value === "object" &&
        value !== null &&
        Object.keys(value).length === 0)
    ) {
      continue;
    }

    const valueStr =
      typeof value === "string" ? value : JSON.stringify(value);

    let matchedRule: Finding["rule"] | null = null;
    for (const rule of rules) {
      if (rule.regex.test(valueStr)) {
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

// ── extensions.json ────────────────────────────────────────────────────────

function scanExtensionsJson(vscodeDir: string): Finding[] {
  const findings: Finding[] = [];
  const filePath = path.join(vscodeDir, "extensions.json");

  if (!fs.existsSync(filePath)) return findings;

  let extConfig: Record<string, unknown>;
  try {
    extConfig = JSON.parse(fs.readFileSync(filePath, "utf8")) as Record<
      string,
      unknown
    >;
  } catch (err) {
    findings.push(parseErrorFinding(".vscode/extensions.json", err as Error));
    return findings;
  }

  const recommendations =
    (extConfig["recommendations"] as string[] | undefined) ?? [];

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

// ── helpers ────────────────────────────────────────────────────────────────

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
