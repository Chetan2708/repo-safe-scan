import path from "path";
import os from "os";
import fs from "fs";
import { vscodeAnalyzer } from "../src/analyzers/vscodeAnalyzer";

const FIXTURES = path.resolve(__dirname, "./fixtures");

describe("vscodeAnalyzer", () => {
  describe("malicious-vscode", () => {
    let findings: Awaited<ReturnType<typeof vscodeAnalyzer>>;

    beforeAll(async () => {
      findings = await vscodeAnalyzer(
        path.join(FIXTURES, "malicious-vscode")
      );
    });

    it("returns findings from a malicious .vscode directory", () => {
      expect(findings.length).toBeGreaterThan(0);
    });

    it("flags curl|bash in tasks.json", () => {
      const f = findings.find(
        (f) =>
          f.file === ".vscode/tasks.json" && f.rule.id === "curl-pipe-shell"
      );
      expect(f).toBeDefined();
    });

    it("flags dangerous terminal.integrated.env in settings.json", () => {
      const f = findings.find(
        (f) =>
          f.file === ".vscode/settings.json" &&
          f.scriptName?.includes("terminal.integrated.env")
      );
      expect(f).toBeDefined();
      expect(["high", "critical"]).toContain(f!.rule.severity);
    });

    it("returns structured finding objects", () => {
      expect(findings[0]).toBeDefined();
      const f = findings[0]!;
      expect(f).toHaveProperty("file");
      expect(f).toHaveProperty("rule");
      expect(f.rule).toHaveProperty("id");
      expect(f.rule).toHaveProperty("severity");
    });
  });

  describe("clean-repo (no .vscode)", () => {
    it("returns no findings when .vscode directory is absent", async () => {
      const findings = await vscodeAnalyzer(
        path.join(FIXTURES, "clean-repo")
      );
      expect(findings).toHaveLength(0);
    });
  });

  describe("edge cases", () => {
    it("returns no findings for nonexistent directory", async () => {
      const findings = await vscodeAnalyzer(
        path.join(FIXTURES, "nonexistent-dir")
      );
      expect(findings).toHaveLength(0);
    });

    it("handles malformed tasks.json gracefully", async () => {
      const tmpDir = path.join(os.tmpdir(), "rss-vscode-malformed-ts");
      const vscodeDir = path.join(tmpDir, ".vscode");
      fs.mkdirSync(vscodeDir, { recursive: true });
      fs.writeFileSync(
        path.join(vscodeDir, "tasks.json"),
        "{ not valid json",
        "utf8"
      );

      let findings: Awaited<ReturnType<typeof vscodeAnalyzer>> = [];
      await expect(async () => {
        findings = await vscodeAnalyzer(tmpDir);
      }).not.toThrow();

      expect(findings[0]?.rule.id).toBe("malformed-json");
      fs.rmSync(tmpDir, { recursive: true, force: true });
    });
  });
});
