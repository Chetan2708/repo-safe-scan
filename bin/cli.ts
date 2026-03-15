#!/usr/bin/env node
import path from "path";
import { program } from "commander";
import chalk from "chalk";
import { scanRepo } from "../src/scanner";
import type { Finding } from "../src/types";

// Resolve package.json relative to the compiled file's location at runtime
// Works correctly from both bin/ (ts-node) and dist/bin/ (node)
// eslint-disable-next-line @typescript-eslint/no-var-requires
const { version } = require(path.resolve(__dirname, "../../package.json")) as { version: string };

type Severity = "medium" | "high" | "critical";

const SEVERITY_ORDER: Record<Severity, number> = {
  medium: 1,
  high: 2,
  critical: 3,
};

const SEVERITY_ICONS: Record<Severity, string> = {
  critical: chalk.bgRed.white.bold(" CRITICAL "),
  high: chalk.bgYellow.black.bold("  HIGH   "),
  medium: chalk.bgBlue.white.bold(" MEDIUM  "),
};

const SEVERITY_COLORS: Record<Severity, chalk.Chalk> = {
  critical: chalk.red.bold,
  high: chalk.yellow.bold,
  medium: chalk.cyan.bold,
};

function isSeverity(value: string): value is Severity {
  return value === "medium" || value === "high" || value === "critical";
}

program
  .name("repo-safe-scan")
  .description(
    "Audit package.json scripts, VSCode tasks, Makefiles and shell scripts for supply-chain attack patterns"
  )
  .version(version)
  .argument("[path]", "Path to repository root", ".")
  .option("--json", "Output findings as JSON (machine-readable, for CI)")
  .option(
    "--severity <level>",
    "Minimum severity to report: medium | high | critical",
    "medium"
  )
  .option("--include-node-modules", "Scan dependencies in node_modules for malicious lifecycle hooks")
  .option("--no-color", "Disable colored output")
  .action(async (repoPath: string, options: { json?: boolean; severity: string; includeNodeModules?: boolean }) => {
    const minSeverity = options.severity.toLowerCase();

    if (!isSeverity(minSeverity)) {
      console.error(
        chalk.red(
          `Invalid severity "${minSeverity}". Use: medium, high, or critical`
        )
      );
      process.exit(2);
    }

    // ── Run Scan ─────────────────────────────────────────────────────────
    let result: Awaited<ReturnType<typeof scanRepo>>;
    try {
      result = await scanRepo(repoPath, { includeNodeModules: options.includeNodeModules });
    } catch (err) {
      console.error(
        chalk.red(`\nFatal error during scan: ${(err as Error).message}`)
      );
      process.exit(2);
    }

    const { findings, riskScore } = result;

    // ── Filter by severity ────────────────────────────────────────────────
    const minScore = SEVERITY_ORDER[minSeverity];
    const filtered = findings.filter((f) => {
      const sev = f.rule.severity as Severity;
      return (SEVERITY_ORDER[sev] ?? 0) >= minScore;
    });

    // ── Sort: critical → high → medium, lifecycle first ───────────────────
    filtered.sort((a: Finding, b: Finding) => {
      const sevDiff =
        (SEVERITY_ORDER[b.rule.severity as Severity] ?? 0) -
        (SEVERITY_ORDER[a.rule.severity as Severity] ?? 0);
      if (sevDiff !== 0) return sevDiff;
      return b.lifecycle ? 1 : -1;
    });

    // ── JSON output ───────────────────────────────────────────────────────
    if (options.json) {
      process.stdout.write(
        JSON.stringify({ scannedPath: repoPath, riskScore, findings: filtered }, null, 2) + "\n"
      );
      if (filtered.length > 0) process.exitCode = 1;
      return;
    }

    // ── Pretty output ─────────────────────────────────────────────────────
    console.log(
      chalk.bold.white(`\n  repo-safe-scan`) +
        chalk.gray(` v${version}`) +
        `  🔍 Scanning: ${chalk.cyan(repoPath)}\n`
    );

    if (filtered.length === 0) {
      console.log(
        chalk.green("  ✔ No suspicious patterns found") +
          chalk.gray(` (severity >= ${minSeverity})\n`)
      );
      
      console.log(chalk.gray(`  ${"═".repeat(50)}`));
      console.log(`  ${chalk.bold("Repository Risk Score:")} ${chalk.green.bold(riskScore.score + " / 10")}  ${chalk.bgGreen.black.bold(" " + riskScore.label + " ")}\n`);
      return;
    }

    // Group by file
    const byFile = new Map<string, Finding[]>();
    for (const finding of filtered) {
      if (!byFile.has(finding.file)) byFile.set(finding.file, []);
      byFile.get(finding.file)!.push(finding);
    }

    for (const [file, fileFindings] of byFile) {
      console.log(chalk.bold.white(`  📄 ${file}`));
      console.log(chalk.gray("  " + "─".repeat(60)));

      for (const finding of fileFindings) {
        const sev = finding.rule.severity as Severity;
        const icon = SEVERITY_ICONS[sev] ?? chalk.gray(" UNKNOWN ");
        const colorFn = SEVERITY_COLORS[sev] ?? chalk.white;
        const lifecycleBadge = finding.lifecycle
          ? chalk.bgMagenta.white.bold(" LIFECYCLE ") + " "
          : "";

        console.log(`\n  ${icon} ${lifecycleBadge}${colorFn(finding.rule.id)}`);
        console.log(`  ${chalk.gray("Description:")} ${finding.rule.description}`);
        console.log(`  ${chalk.gray("Category:   ")} ${finding.rule.category}`);

        if (finding.scriptName) {
          console.log(`  ${chalk.gray("Script:     ")} ${finding.scriptName}`);
        }
        if (finding.command) {
          const truncated =
            finding.command.length > 120
              ? finding.command.slice(0, 117) + "..."
              : finding.command;
          console.log(
            `  ${chalk.gray("Command:    ")} ${chalk.red(truncated)}`
          );
        }
        if (finding.detail) {
          console.log(`  ${chalk.gray("Detail:     ")} ${finding.detail}`);
        }
        
        if (finding.lifecycleMessage) {
          console.log(`\n  ${chalk.yellow.dim("   " + finding.lifecycleMessage)}`);
        }
      }

      console.log();
    }

    // ── Summary ───────────────────────────────────────────────────────────
    const critCount = filtered.filter((f) => f.rule.severity === "critical").length;
    const highCount = filtered.filter((f) => f.rule.severity === "high").length;
    const medCount  = filtered.filter((f) => f.rule.severity === "medium").length;
    const lifecycleCount = filtered.filter((f) => f.lifecycle).length;

    console.log(chalk.gray("  " + "═".repeat(60)));
    console.log(
      `  ${chalk.bold("SUMMARY")}  ` +
        chalk.red.bold(`${critCount} critical`) +
        "  " +
        chalk.yellow.bold(`${highCount} high`) +
        "  " +
        chalk.cyan.bold(`${medCount} medium`) +
        (lifecycleCount > 0
          ? "  " +
            chalk.magenta.bold(
              `(${lifecycleCount} auto-executed lifecycle hooks)`
            )
          : "")
    );
    console.log(chalk.gray(`  Scanned path: ${repoPath}`) + "\n");

    // ── Risk Score ────────────────────────────────────────────────────────
    let rsColor = chalk.green;
    if (riskScore.label === "CRITICAL") rsColor = chalk.red;
    else if (riskScore.label === "HIGH") rsColor = chalk.yellow;
    else if (riskScore.label === "MODERATE") rsColor = chalk.cyan;

    const barLength = 20;
    const filledLength = Math.round((riskScore.score / 10) * barLength);
    const filled = "█".repeat(filledLength);
    const empty = "░".repeat(barLength - filledLength);
    const bar = rsColor(filled) + chalk.gray(empty);

    console.log(chalk.bold.white(`  ╔═════════════════════════════════════════╗`));
    console.log(chalk.bold.white(`  ║  Repository Risk Score:  ${rsColor.bold(riskScore.score.toFixed(1) + " / 10".padEnd(5))}     ║`));
    console.log(chalk.bold.white(`  ║  ${bar}  ${rsColor.bold(riskScore.label.padEnd(8))} ║`));
    console.log(chalk.bold.white(`  ╚═════════════════════════════════════════╝\n`));

    process.exitCode = 1;
  });

program.parse();
