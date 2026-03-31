# Contributing to repo-safe-scan

Thanks for your interest in contributing! 🛡

## Quick Start

```bash
git clone https://github.com/Chetan2708/repo-safe-scan.git
cd repo-safe-scan
npm install
npm run build
npm test
```

## How to Contribute

### Adding Detection Rules

The easiest way to contribute — add new rules in `src/rules/`:

1. Pick a category file (e.g., `execution.rules.ts`, `exfiltration.rules.ts`)
2. Add a new rule object with `id`, `description`, `severity`, `category`, and a `pattern` (regex)
3. Add a test case in `tests/`

### Bug Fixes & Features

1. Fork the repo
2. Create a branch: `git checkout -b feature/your-feature`
3. Make your changes
4. Run tests: `npm test`
5. Submit a PR

## Code Style

- TypeScript strict mode
- No `any` types unless absolutely necessary
- All analyzers implement the `Analyzer` type from `src/analyzers/index.ts`

## Reporting Issues

Found a false positive? A pattern that slips through? Open an issue with:
- The command or script that was flagged (or missed)
- Expected vs actual behavior
