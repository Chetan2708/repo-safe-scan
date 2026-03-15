import { analyzers, optionalAnalyzers } from "./analyzers/index";
import { calculateRiskScore } from "./scoring";
import type { ScanResult, ScanOptions } from "./types";

/**
 * Orchestrate all analyzers and return a unified result object.
 */
export async function scanRepo(repoPath: string, opts: ScanOptions = {}): Promise<ScanResult> {
  const activeAnalyzers = [...analyzers];
  if (opts.includeNodeModules) {
    const nmAnalyzer = optionalAnalyzers["include-node-modules"];
    if (nmAnalyzer) activeAnalyzers.push(nmAnalyzer);
  }

  const results = await Promise.all(activeAnalyzers.map((a) => a(repoPath, opts)));
  const findings = results.flat();
  const scannedFiles = [...new Set(findings.map((f) => f.file))];

  return { findings, scannedFiles, riskScore: calculateRiskScore(findings) };
}
