import { getNewDeps } from "../src/utils/getNewDeps";
import * as childProcess from "child_process";

jest.mock("child_process");

const mockedExecSync = childProcess.execSync as jest.MockedFunction<typeof childProcess.execSync>;

describe("getNewDeps", () => {
  afterEach(() => {
    jest.resetAllMocks();
  });

  it("extracts newly added package names from git diff output", () => {
    mockedExecSync.mockReturnValue(
      `diff --git a/package-lock.json b/package-lock.json
index abc1234..def5678 100644
--- a/package-lock.json
+++ b/package-lock.json
@@ -100,6 +100,20 @@
     "node_modules/existing-pkg": {
       "version": "1.0.0"
     },
+    "node_modules/evil-new-pkg": {
+      "version": "0.1.0",
+      "resolved": "https://registry.npmjs.org/evil-new-pkg/-/evil-new-pkg-0.1.0.tgz"
+    },
+    "node_modules/@malicious/scoped-pkg": {
+      "version": "2.0.0"
+    },
`
    );

    const result = getNewDeps("/fake/repo");

    expect(result).toBeInstanceOf(Set);
    expect(result.has("evil-new-pkg")).toBe(true);
    expect(result.has("@malicious/scoped-pkg")).toBe(true);
    expect(result.has("existing-pkg")).toBe(false); // not an added line
    expect(result.size).toBe(2);
  });

  it("returns empty set when git is not available", () => {
    mockedExecSync.mockImplementation(() => {
      throw new Error("Command failed: git diff");
    });

    const result = getNewDeps("/fake/repo");
    expect(result.size).toBe(0);
  });

  it("returns empty set when there is no diff", () => {
    mockedExecSync.mockReturnValue("");

    const result = getNewDeps("/fake/repo");
    expect(result.size).toBe(0);
  });

  it("ignores removed lines (lines starting with -)", () => {
    mockedExecSync.mockReturnValue(
      `--- a/package-lock.json
+++ b/package-lock.json
-    "node_modules/removed-pkg": {
-      "version": "1.0.0"
-    },
+    "node_modules/added-pkg": {
+      "version": "1.0.0"
+    },
`
    );

    const result = getNewDeps("/fake/repo");
    expect(result.has("added-pkg")).toBe(true);
    expect(result.has("removed-pkg")).toBe(false);
    expect(result.size).toBe(1);
  });
});
