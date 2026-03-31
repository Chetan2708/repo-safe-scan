import { execSync } from "child_process";

/**
 * Parses `git diff HEAD -- package-lock.json` to identify newly added
 * dependencies. Returns a Set of package names that appear in the working
 * tree's lockfile but not in the last commit.
 *
 * Lockfile v3 (npm ≥ 7) uses top-level keys like:
 *   "node_modules/evil-pkg": { ... }
 *   "node_modules/@scope/pkg": { ... }
 *
 * We look for *added* lines that match this pattern.
 */
export function getNewDeps(repoPath: string): Set<string> {
  const newDeps = new Set<string>();

  let diff: string;
  try {
    diff = execSync("git diff HEAD -- package-lock.json", {
      cwd: repoPath,
      encoding: "utf8",
      maxBuffer: 10 * 1024 * 1024, // 10 MB — lockfiles can be large
      stdio: ["pipe", "pipe", "pipe"],
    });
  } catch {
    // Not a git repo, no git installed, no lockfile, or no previous commit
    return newDeps;
  }

  if (!diff) return newDeps;

  // Match added lines like:  +    "node_modules/pkg-name": {
  // Handles scoped packages:  +    "node_modules/@scope/pkg": {
  const addedKeyRe = /^\+\s+"node_modules\/([^"]+)":\s*\{/;

  for (const line of diff.split("\n")) {
    const m = addedKeyRe.exec(line);
    if (m && m[1]) {
      newDeps.add(m[1]);
    }
  }

  return newDeps;
}
