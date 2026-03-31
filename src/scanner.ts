import { analyzers as coreAnalyzers, optionalAnalyzers } from "./analyzers/index";
import { calculateRiskScore } from "./scoring";
import { getNewDeps } from "./utils/getNewDeps";
import type { ScanResult, ScanOptions } from "./types";

/**
 * Orchestrate all analyzers and return a unified result object.
 */
export async function scanRepo(repoPath: string, opts: ScanOptions = {}): Promise<ScanResult> {
  const activeAnalyzers = [...coreAnalyzers];
  let newDeps: Set<string> | undefined;

  if (opts.includeNodeModules) {
    const nmAnalyzer = optionalAnalyzers["include-node-modules"];
    if (nmAnalyzer) {
      // Detect newly added dependencies via git diff
      newDeps = getNewDeps(repoPath);
      activeAnalyzers.push((repoPath, scanOpts) => nmAnalyzer(repoPath, scanOpts, newDeps));
    }
  }

  const results = await Promise.all(activeAnalyzers.map((a) => a(repoPath, opts)));
  const findings = results.flat();
  const scannedFiles = [...new Set(findings.map((f) => f.file))];

  return { findings, scannedFiles, riskScore: calculateRiskScore(findings) };
}
