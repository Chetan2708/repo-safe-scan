import { packageAnalyzer } from "./analyzers/packageAnalyzer";
import { vscodeAnalyzer } from "./analyzers/vscodeAnalyzer";
import { makefileAnalyzer } from "./analyzers/makefileAnalyzer";
import { shellScriptAnalyzer } from "./analyzers/shellScriptAnalyzer";
import type { ScanResult } from "./types";

/**
 * Orchestrate all analyzers and return a unified result object.
 */
export async function scanRepo(repoPath: string): Promise<ScanResult> {
  const [pkgFindings, vscodeFindings, makefileFindings, shellFindings] =
    await Promise.all([
      packageAnalyzer(repoPath),
      vscodeAnalyzer(repoPath),
      makefileAnalyzer(repoPath),
      shellScriptAnalyzer(repoPath),
    ]);

  const findings = [
    ...pkgFindings,
    ...vscodeFindings,
    ...makefileFindings,
    ...shellFindings,
  ];

  const scannedFiles = [...new Set(findings.map((f) => f.file))];

  return { findings, scannedFiles };
}
