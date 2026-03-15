import fs from "fs";
import path from "path";
import { glob } from "glob";
import * as acorn from "acorn";
import type { Finding } from "../types";

const MAX_FILE_SIZE = 2 * 1024 * 1024; // 2MB
const MAX_FILES = 10000;

export async function jsAstAnalyzer(repoPath: string): Promise<Finding[]> {
  const findings: Finding[] = [];
  const resolvedRoot = path.resolve(repoPath);

  let jsFiles: string[];
  try {
    jsFiles = await glob("**/*.{js,mjs,cjs,ts}", {
      cwd: resolvedRoot,
      absolute: true,
      ignore: [
        "**/node_modules/**",
        "**/.git/**",
        "**/dist/**",
        "**/build/**",
        "**/coverage/**",
      ],
    });
  } catch {
    return findings;
  }

  // Cap at 10k files
  if (jsFiles.length > MAX_FILES) {
    jsFiles = jsFiles.slice(0, MAX_FILES);
  }

  for (const filePath of jsFiles) {
    try {
      const stats = fs.statSync(filePath);
      if (stats.size > MAX_FILE_SIZE) continue;

      const code = fs.readFileSync(filePath, "utf8");
      
      // Parse with acorn loose configuration (handles basic TS by ignoring types if possible, though acorn is JS only. 
      // For real TS, an AST stripper would be needed, but we'll try parsing as latest JS).
      const ast = acorn.parse(code, {
        ecmaVersion: "latest",
        sourceType: "module",
        allowHashBang: true,
      });

      const boundChildProcess = new Set<string>();
      const boundExec = new Set<string>();

      // A simple recursive walker
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const walk = (node: any) => {
        if (!node) return;

        // ES6 Imports
        if (node.type === "ImportDeclaration" && node.source.value === "child_process") {
          for (const spec of node.specifiers) {
            if (spec.type === "ImportDefaultSpecifier" || spec.type === "ImportNamespaceSpecifier") {
              boundChildProcess.add(spec.local.name);
            } else if (spec.type === "ImportSpecifier" && spec.imported.name === "exec") {
              boundExec.add(spec.local.name);
            }
          }
        }

        // Variable bindings
        if (node.type === "VariableDeclarator" && node.init && node.init.type === "CallExpression") {
          const callee = node.init.callee;
          if (callee.type === "Identifier" && callee.name === "require" && node.init.arguments[0]) {
            const arg = node.init.arguments[0];
            if (arg.type === "Literal" && arg.value === "child_process") {
              if (node.id.type === "Identifier") {
                boundChildProcess.add(node.id.name);
              } else if (node.id.type === "ObjectPattern") {
                for (const prop of node.id.properties) {
                  if (prop.key && prop.key.type === "Identifier" && ["exec", "spawn", "execSync", "spawnSync"].includes(prop.key.name)) {
                    if (prop.value.type === "Identifier") boundExec.add(prop.value.name);
                  }
                }
              }
            }
          }
        }

        // Function Calls
        if (node.type === "CallExpression") {
          const callee = node.callee;

          // Catch require("child_" + "process")
          if (callee.type === "Identifier" && callee.name === "require" && node.arguments[0]) {
            const arg = node.arguments[0];
            if (arg.type === "BinaryExpression" && arg.operator === "+") {
              if (arg.left.type === "Literal" && arg.right.type === "Literal") {
                const combined = String(arg.left.value) + String(arg.right.value);
                if (combined === "child_process") {
                  findings.push(createAstFinding(filePath, "dynamic-child-process-require", "Dynamically concatenated child_process require"));
                }
              }
            }
          }
          
          if (callee.type === "Identifier") {
            if (callee.name === "eval") {
              findings.push(createAstFinding(filePath, "eval-usage", "eval() executes arbitrary strings"));
            } else if (boundExec.has(callee.name)) {
              findings.push(createAstFinding(filePath, "child-process-exec", "child_process execution called via bound variable"));
            }
          }

          if (callee.type === "MemberExpression") {
            if (callee.object.type === "Identifier" && boundChildProcess.has(callee.object.name)) {
              const propName = callee.property.name || (callee.property.value);
              if (["exec", "spawn", "execSync", "spawnSync"].includes(propName)) {
                findings.push(createAstFinding(filePath, "child-process", `child_process.${propName}() called`));
              }
            }
          }
        }

        // 3. new Function()
        if (node.type === "NewExpression" && node.callee.type === "Identifier" && node.callee.name === "Function") {
          findings.push(createAstFinding(filePath, "function-constructor", "new Function() is equivalent to eval"));
        }

        for (const key in node) {
          if (node[key] && typeof node[key] === "object") {
            if (Array.isArray(node[key])) {
              node[key].forEach(walk);
            } else {
              walk(node[key]);
            }
          }
        }
      };

      walk(ast);

    } catch {
      // Ignore parse errors (e.g. strict TS syntax that acorn rejects)
    }
  }

  // Deduplicate findings per file
  const unique = [];
  const seen = new Set();
  for (const f of findings) {
    const hash = f.file + ":" + f.rule.id;
    if (!seen.has(hash)) {
      seen.add(hash);
      unique.push(f);
    }
  }

  return unique;
}

function createAstFinding(absolutePath: string, ruleId: string, desc: string): Finding {
  // Use a heuristic relative path if we can't get root easily here, or just basename
  const p = absolutePath.split(path.sep).slice(-3).join(path.sep);
  return {
    file: p, // Not strictly relative to root, but decent enough for AST findings
    scriptName: "AST Match",
    command: null,
    rule: {
      id: ruleId,
      description: desc,
      severity: "high",
      category: "ast-code-execution",
    },
    lifecycle: false,
    detail: "Detected via JavaScript AST parsing",
  };
}
