#!/usr/bin/env node
import { execSync, SpawnSyncReturns } from "child_process";
import path from "path";
import chalk from "chalk";
import { scanRepo } from "../src/scanner";

// eslint-disable-next-line @typescript-eslint/no-var-requires
const { version } = require(path.resolve(__dirname, "../../package.json")) as { version: string };

// ── Helpers ────────────────────────────────────────────────────────────────

function run(cmd: string, label: string): void {
  console.log(chalk.gray(`  $ ${cmd}\n`));
  try {
    execSync(cmd, { stdio: "inherit" });
  } catch (err) {
    const exitCode = (err as SpawnSyncReturns<Buffer>).status ?? 1;
    console.error(chalk.red(`\n  ✖ "${label}" failed (exit ${exitCode}). Aborting.\n`));
    process.exit(exitCode);
  }
}

// ── Banner ─────────────────────────────────────────────────────────────────

console.log(
  "\n" +
  chalk.bold.white("  ╔══════════════════════════════════════════════╗\n") +
  chalk.bold.white("  ║") + chalk.bold.cyan("  🛡  repo-safe-install") + chalk.gray(` v${version}`) + chalk.bold.white("              ║\n") +
  chalk.bold.white("  ║") + chalk.gray("  Install npm packages — safely.") + chalk.bold.white("             ║\n") +
  chalk.bold.white("  ╚══════════════════════════════════════════════╝\n")
);

// ── Step 1: npm install --ignore-scripts ───────────────────────────────────

console.log(chalk.bold.white("  ── Step 1/3 ") + chalk.cyan("Install dependencies (scripts disabled)") + "\n");
run("npm install --ignore-scripts", "npm install --ignore-scripts");

// ── Step 2: repo-safe-scan with node_modules ─────────────────────────────

console.log(chalk.bold.white("\n  ── Step 2/3 ") + chalk.cyan("Scan for malicious patterns") + "\n");

async function main(): Promise<void> {
  const { findings, riskScore } = await scanRepo(".", { includeNodeModules: true });

  const critical = findings.filter((f) => f.rule.severity === "critical");
  const high = findings.filter((f) => f.rule.severity === "high");
  const lifecycleCount = findings.filter((f) => f.lifecycle).length;
  const newDepCount = findings.filter((f) => f.isNewDep).length;

  if (critical.length > 0 || high.length > 0) {
    // ── BLOCKED ──────────────────────────────────────────────────────────
    console.log(chalk.red.bold("\n  ╔══════════════════════════════════════════════╗"));
    console.log(chalk.red.bold("  ║  ✖  INSTALL BLOCKED — threats detected       ║"));
    console.log(chalk.red.bold("  ╚══════════════════════════════════════════════╝\n"));

    console.log(
      `  ${chalk.red.bold(`${critical.length} critical`)}  ` +
      `${chalk.yellow.bold(`${high.length} high`)}` +
      (lifecycleCount > 0 ? `  ${chalk.magenta.bold(`${lifecycleCount} lifecycle hooks`)}` : "") +
      (newDepCount > 0 ? `  ${chalk.green.bold(`${newDepCount} new deps`)}` : "")
    );
    console.log(chalk.gray(`  Risk Score: ${riskScore.score}/10 (${riskScore.label})\n`));

    // Show individual findings
    for (const f of [...critical, ...high]) {
      const icon = f.rule.severity === "critical"
        ? chalk.red("  ✖")
        : chalk.yellow("  ⚠");
      const badges = [
        f.isNewDep ? chalk.bgGreen.black.bold(" NEW DEP ") : "",
        f.lifecycle ? chalk.bgMagenta.white.bold(" LIFECYCLE ") : "",
      ].filter(Boolean).join(" ");

      console.log(`${icon} ${badges} ${chalk.bold(f.rule.id)}`);
      console.log(chalk.gray(`    ${f.file}`) + (f.scriptName ? chalk.gray(` → ${f.scriptName}`) : ""));
      if (f.command) {
        const truncated = f.command.length > 100 ? f.command.slice(0, 97) + "..." : f.command;
        console.log(chalk.red(`    ${truncated}`));
      }
      console.log();
    }

    console.log(chalk.yellow("  To review all findings in detail, run:"));
    console.log(chalk.cyan("  npx repo-safe-scan . --include-node-modules\n"));
    console.log(chalk.gray("  Your dependencies are installed but their scripts have NOT been executed."));
    console.log(chalk.gray("  Run ") + chalk.white("npm rebuild") + chalk.gray(" manually after resolving the threats.\n"));

    process.exit(1);
  }

  // ── SAFE — proceed to rebuild ──────────────────────────────────────────
  console.log(chalk.green.bold("\n  ╔══════════════════════════════════════════════╗"));
  console.log(chalk.green.bold("  ║  ✔  Scan passed — no threats detected        ║"));
  console.log(chalk.green.bold("  ╚══════════════════════════════════════════════╝\n"));
  console.log(chalk.gray(`  Risk Score: ${riskScore.score}/10 (${riskScore.label})\n`));

  // ── Step 3: npm rebuild ─────────────────────────────────────────────────
  console.log(chalk.bold.white("  ── Step 3/3 ") + chalk.cyan("Rebuild (run lifecycle scripts)") + "\n");
  run("npm rebuild", "npm rebuild");

  console.log(chalk.green.bold("\n  ✔ Safe install complete!\n"));
}

main().catch((err) => {
  console.error(chalk.red(`\n  Fatal error: ${(err as Error).message}\n`));
  process.exit(2);
});
