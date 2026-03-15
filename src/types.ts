/**
 * Shared type definitions for repo-safe-scan.
 */

export interface EvaluatorContext {
  file: string;
  command: string;
  scriptName?: string | null;
}

export interface Rule {
  id: string;
  description: string;
  severity: "critical" | "high" | "medium";
  category: string;
  pattern?: RegExp;
  evaluator?: (context: EvaluatorContext) => Finding | null;
}

export interface Finding {
  file: string;
  scriptName: string | null;
  command: string | null;
  rule: Omit<Rule, "pattern" | "evaluator">;
  lifecycle: boolean;
  detail: string | null;
  lifecycleMessage?: string;
}

export interface RiskScore {
  score: number;
  label: "CLEAN" | "LOW" | "MODERATE" | "HIGH" | "CRITICAL";
  breakdown: {
    critical: number;
    high: number;
    medium: number;
    lifecycleBonus: number;
  };
}

export interface ScanOptions {
  includeNodeModules?: boolean;
}

export interface ScanResult {
  findings: Finding[];
  scannedFiles: string[];
  riskScore: RiskScore;
}
