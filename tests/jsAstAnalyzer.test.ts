import path from "path";
import { jsAstAnalyzer } from "../src/analyzers/jsAstAnalyzer";

const FIXTURES = path.resolve(__dirname, "./fixtures");

describe("jsAstAnalyzer", () => {
  it("detects malicious JS via AST parsing, bypassing regex", async () => {
    const findings = await jsAstAnalyzer(path.join(FIXTURES, "malicious-js"));
    expect(findings.length).toBeGreaterThan(0);

    const ruleIds = findings.map(f => f.rule.id);
    expect(ruleIds).toContain("child-process"); 
    expect(ruleIds).toContain("eval-usage");
    expect(ruleIds).toContain("dynamic-child-process-require");
  });
});
