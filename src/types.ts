/**
 * Shared type definitions for repo-safe-scan.
 */

export interface Rule {
  id: string;
  description: string;
  regex: RegExp;
  severity: "medium" | "high" | "critical";
  category: string;
}

export interface Finding {
  file: string;
  scriptName: string | null;
  command: string | null;
  rule: Omit<Rule, "regex">;
  lifecycle: boolean;
  detail: string | null;
}

export interface ScanResult {
  findings: Finding[];
  scannedFiles: string[];
}
