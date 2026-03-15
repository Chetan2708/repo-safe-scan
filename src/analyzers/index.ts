import type { Finding, ScanOptions } from "../types";
import { packageAnalyzer } from "./packageAnalyzer";
import { vscodeAnalyzer } from "./vscodeAnalyzer";
import { makefileAnalyzer } from "./makefileAnalyzer";
import { shellScriptAnalyzer } from "./shellScriptAnalyzer";
import { jsAstAnalyzer } from "./jsAstAnalyzer";
import { nodeModulesAnalyzer } from "./nodeModulesAnalyzer";

export type Analyzer = (path: string, opts?: ScanOptions) => Promise<Finding[]>;

export const analyzers: Analyzer[] = [
  packageAnalyzer,
  vscodeAnalyzer,
  makefileAnalyzer,
  shellScriptAnalyzer,
  jsAstAnalyzer,
];

export const optionalAnalyzers: Record<string, Analyzer> = {
  "include-node-modules": nodeModulesAnalyzer,
};
