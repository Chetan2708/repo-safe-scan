import path from "path";
import os from "os";
import fs from "fs";
import { packageAnalyzer } from "../src/analyzers/packageAnalyzer";

const FIXTURES = path.resolve(__dirname, "./fixtures");

describe("packageAnalyzer", () => {
  describe("malicious-repo", () => {
    let findings: Awaited<ReturnType<typeof packageAnalyzer>>;

    beforeAll(async () => {
      findings = await packageAnalyzer(path.join(FIXTURES, "malicious-repo"));
    });

    it("returns findings for malicious scripts", () => {
      expect(findings.length).toBeGreaterThan(0);
    });

    it("flags curl|bash in preinstall as a lifecycle finding", () => {
      const f = findings.find(
        (f) => f.scriptName === "preinstall" && f.rule.id === "curl-pipe-shell"
      );
      expect(f).toBeDefined();
      expect(f!.lifecycle).toBe(true);
    });

    it("escalates severity to critical for high-rule in lifecycle hooks", () => {
      const f = findings.find((f) => f.scriptName === "postinstall");
      if (f) {
        expect(f.rule.severity).toBe("critical");
        expect(f.lifecycle).toBe(true);
      }
    });

    it("flags eval() in prepare as critical", () => {
      const f = findings.find(
        (f) => f.scriptName === "prepare" && f.rule.severity === "critical"
      );
      expect(f).toBeDefined();
    });

    it("does not flag the safe-script", () => {
      const f = findings.find((f) => f.scriptName === "safe-script");
      expect(f).toBeUndefined();
    });

    it("returns structured finding objects", () => {
      expect(findings[0]).toBeDefined();
      const f = findings[0]!;
      expect(f).toHaveProperty("file");
      expect(f).toHaveProperty("scriptName");
      expect(f).toHaveProperty("command");
      expect(f).toHaveProperty("rule");
      expect(f).toHaveProperty("lifecycle");
      expect(f.rule).toHaveProperty("id");
      expect(f.rule).toHaveProperty("severity");
      expect(f.rule).toHaveProperty("category");
    });
  });

  describe("clean-repo", () => {
    it("returns no findings for a clean package.json", async () => {
      const findings = await packageAnalyzer(
        path.join(FIXTURES, "clean-repo")
      );
      expect(findings).toHaveLength(0);
    });
  });

  describe("edge cases", () => {
    it("returns no findings if package.json does not exist", async () => {
      const findings = await packageAnalyzer(
        path.join(FIXTURES, "nonexistent-dir")
      );
      expect(findings).toHaveLength(0);
    });

    it("handles malformed JSON gracefully without throwing", async () => {
      const tmpDir = path.join(os.tmpdir(), "rss-test-malformed-ts");
      fs.mkdirSync(tmpDir, { recursive: true });
      fs.writeFileSync(
        path.join(tmpDir, "package.json"),
        "{ invalid json }",
        "utf8"
      );

      let findings: Awaited<ReturnType<typeof packageAnalyzer>> = [];
      await expect(async () => {
        findings = await packageAnalyzer(tmpDir);
      }).not.toThrow();

      expect(findings[0]?.rule.id).toBe("malformed-json");
      fs.rmSync(tmpDir, { recursive: true, force: true });
    });

    it("does not produce false positives for 'curl' inside word like 'recursively'", async () => {
      const tmpDir = path.join(os.tmpdir(), "rss-test-false-pos-ts");
      fs.mkdirSync(tmpDir, { recursive: true });
      fs.writeFileSync(
        path.join(tmpDir, "package.json"),
        JSON.stringify({ scripts: { build: "copy-recursively ./src ./dist" } }),
        "utf8"
      );

      const findings = await packageAnalyzer(tmpDir);
      expect(findings).toHaveLength(0);
      fs.rmSync(tmpDir, { recursive: true, force: true });
    });
  });
});
